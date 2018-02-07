package dds.http

import akka.util.Timeout
import akka.actor.ActorSystem
import akka.http.scaladsl.model._
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.Directives
import akka.pattern.ask
import scala.collection.JavaConverters._
import scala.concurrent.Future
import scala.concurrent.duration._
import scala.util.Random
import scala.collection.immutable.HashSet
import spray.json._
import akka.http.scaladsl.model.HttpMethods._
import akka.http.scaladsl.model.MediaTypes._
import spray.json.DefaultJsonProtocol._
import dds.api.{ Envelope, IRead, IWrite, IReadReply, IWriteReply }
import dds.core.models.DDSSet
import utils.Utils
import scala.concurrent.ExecutionContext.Implicits.global
import scala.collection.mutable.Buffer
import dds.exceptions.ByzFailedNonceChallengeException
import dds.exceptions.ByzInvalidSignatureException
import dds.exceptions.ByzUnknownReplyException
import akka.http.scaladsl.server.ExceptionHandler
import java.io.FileInputStream
import akka.http.scaladsl.Http
import akka.http.scaladsl.HttpsConnectionContext
import javax.net.ssl.KeyManagerFactory
import java.security.KeyStore
import akka.stream.scaladsl.{Flow, Sink, Source}
import java.io.InputStream
import java.io.File
import akka.http.scaladsl.ConnectionContext
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import java.security.SecureRandom
import akka.stream.ActorMaterializer
import utils.FutureRetry
import akka.actor.Scheduler
import scala.util.Failure
import scala.util.Success
import scala.concurrent.Promise
import akka.pattern.AskTimeoutException
import akka.pattern.AskTimeoutException
import akka.stream.TLSClientAuth
import com.typesafe.sslconfig.akka.AkkaSSLConfig
import com.typesafe.sslconfig.ssl.ClientAuth
import dds.exceptions.ByzInvalidKeyException
import utils.TrustedNodesList
import hlib.hj.mlib._
import java.math.BigInteger
import javax.xml.bind.DatatypeConverter
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import java.security.KeyFactory
import scala.util.control.Breaks._
import dds.api.ActiveReplicas
import dds.api.RequestReplicas

class DDSRestServer(_system: ActorSystem, _replicas: List[String]) extends Directives with DDSJsonProtocol with FutureRetry {

  implicit val system = _system
  implicit val s = system.scheduler
  final implicit val materializer = ActorMaterializer()
  
  private var ddsReplicas = new TrustedNodesList(_replicas)
  private var proxyPeers = Map[String, Flow[HttpRequest, HttpResponse, Future[Http.OutgoingConnection]]]()
  private var storedKeys = Set[String]()
  
  private val PROXY_HOSTNAME = system.settings.config.getString("proxy.hostname")
  private val PROXY_PORT = system.settings.config.getInt("proxy.port")
  private val PROXY_KEY_STORE = system.settings.config.getString("proxy.security.key-store")
  private val PROXY_KEY_STORE_PW = system.settings.config.getString("proxy.security.key-store-password").toCharArray
  private val PROXY_MAC_SECRET_KEY = system.settings.config.getString("proxy.security.mac-signature-secret-key")
  private val PROXY_MAC_DIGEST = system.settings.config.getString("proxy.security.mac-signature-digest")
  private val PROXY_SSL_CONTEXT = system.settings.config.getString("proxy.security.ssl-context-protocol")
  private val PROXY_ENABLED_PROTOCOLS = system.settings.config.getStringList("proxy.security.enabled-protocols").asScala.toIndexedSeq
  private val PROXY_ENABLED_CIPHERS = system.settings.config.getStringList("proxy.security.enabled-ciphersuites").asScala.toIndexedSeq
  private val PROXY_PEERS = system.settings.config.getStringList("proxy.remote-peers").asScala.toIndexedSeq
  private val PROXY_KEY_SYNC_ENABLED = system.settings.config.getBoolean("proxy.key-sync.enabled")
  private val PROXY_KEY_SYNC_WARM_UP = system.settings.config.getDouble("proxy.key-sync.warm-up")
  private val PROXY_KEY_SYNC_INTERVAL = system.settings.config.getDouble("proxy.key-sync.interval")
  
  private val INTRA_SUPERVISOR = system.settings.config.getString("replicas.supervisor.endpoint")
  private val INTRA_NONCE_INCREMENT = system.settings.config.getInt("proxy.security.nonce-challenge-increment")
  private val INTRA_REQUEST_TIMEOUT = system.settings.config.getInt("proxy.intranet-request-timeout")
  private val INTRA_RETRY_ATTEMPTS = system.settings.config.getInt("proxy.intranet-faulty-retry-attempts")
  private val INTRA_RETRY_BACKOFF = system.settings.config.getInt("proxy.intranet-faulty-retry-backoff")
  private val KEY_DIGEST = system.settings.config.getString("proxy.key-generation-digest")

  // binding function to start listening via HTTPS and schedule needed routines
  def bind = {
    // load keystore according to config
    val ks: KeyStore = KeyStore.getInstance("JKS")
    val keystore: InputStream = new FileInputStream(new File(PROXY_KEY_STORE))
    ks.load(keystore, PROXY_KEY_STORE_PW)

    // init key manager
    val keyManagerFactory: KeyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm)
    keyManagerFactory.init(ks, PROXY_KEY_STORE_PW)

    // init trust manager
    val tmf: TrustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
    tmf.init(ks)

    // setup HTTPS with TLS
    val sslContext: SSLContext = SSLContext.getInstance(PROXY_SSL_CONTEXT)
    sslContext.init(keyManagerFactory.getKeyManagers, tmf.getTrustManagers, new SecureRandom)
    val httpsContext: HttpsConnectionContext = ConnectionContext.https(sslContext, Some(PROXY_ENABLED_CIPHERS), Some(PROXY_ENABLED_PROTOCOLS), Some(TLSClientAuth.Need), None)

    // bind to ip address
    Http().setDefaultServerHttpContext(httpsContext)
    val bindingFuture = Http().bindAndHandle(route, PROXY_HOSTNAME, PROXY_PORT, connectionContext = httpsContext)
    
    // establish keysync if needed
    if (PROXY_KEY_SYNC_ENABLED) {
        // establish a tunnel to each proxy peer
        for (peer <- PROXY_PEERS) {
          proxyPeers += peer -> Http().outgoingConnectionHttps(peer, connectionContext = httpsContext)
        }
        
        // schedule a key sync control
        system.scheduler.schedule(PROXY_KEY_SYNC_WARM_UP seconds, PROXY_KEY_SYNC_INTERVAL seconds) {
          for ((url, flow) <- proxyPeers) {
              Source.single(HttpRequest(
                  POST, 
                  uri = "https://" + url + "/_sync/", 
                  entity = HttpEntity(`application/json`, storedKeys.mkString("{\"keyset\": [\"", "\", \"", "\"] }")))
              )
              .via(flow)
              .runWith(Sink.head)
          }
        }
    }
    
    // schedule active replicas sync with supervisor
    system.scheduler.schedule(0 seconds, 5 seconds) {
      implicit val timeout = Timeout(INTRA_REQUEST_TIMEOUT milliseconds)
      val future = system.actorSelection(INTRA_SUPERVISOR) ? RequestReplicas()
      
      future onSuccess {
        case ActiveReplicas(replicas) =>
          ddsReplicas = new TrustedNodesList(replicas)
      }
    }
  }
  


  // REST routes
  val route =
    get {
      pathPrefix("GetSet" / Segment) { key =>

        val future = retry(fetchSet(key), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS)

        onComplete(future) {
          case Success(option) =>
            option match {
              case None => complete(StatusCodes.NotFound)
              case Some(contents) => complete(contents.toJson)
            }
          case Failure(ex) =>
            complete(StatusCodes.InternalServerError)
        }
      }
    } ~
      post {
        path("PutSet") {

          entity(as[DDSSet]) { set =>

            // compute sha512 key
            val key = Utils.getKeyFromSet(set, KEY_DIGEST)

            val future = retry(writeSet(key, Some(set)), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS)

            onComplete(future) {
              case Success(ack) =>
                storedKeys += key  // save sha512 for later usage
                complete(key)      // return sha512 to client
              case Failure(ex) =>
                complete(StatusCodes.InternalServerError)
            }
          }
        }
      } ~
      post {
        path("PutSet") {

            // compute sha512 key randomly, since the set is empty
            val key = Utils.getKeyRandomly(KEY_DIGEST)

            val future = retry(writeSet(key, None), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS)

            onComplete(future) {
              case Success(ack) =>
                storedKeys += key  // save sha512 for later usage
                complete(key)      // return sha512 to client
              case Failure(ex) =>
                complete(StatusCodes.InternalServerError)
            }
          }
      } ~
      delete {
        pathPrefix("RemoveSet" / Segment) { key =>

          val future = retry(writeSet(key, None), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS)

          onComplete(future) {
            case Success(ack) =>
              complete(StatusCodes.OK)
            case Failure(ex) =>
              complete(StatusCodes.InternalServerError)
          }
        }
      } ~
      put {
        pathPrefix("AddElement" / Segment) { key =>

          entity(as[DDSItem]) { item =>

            val future = retry(fetchSet(key), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS)

            onComplete(future) {
              case Success(option) =>

                option match {
                  
                  case Some(set) =>
                    
                    var newContents: List[Any] = (set.contents.reverse.::(item.value)).reverse

                    val future = retry(writeSet(key, Some(DDSSet(newContents))), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS)

                    onComplete(future) {
                      case Success(ack) =>
                        complete(StatusCodes.OK)
                      case Failure(ex) =>
                        complete(StatusCodes.InternalServerError)
                    }

                  case None =>
                    complete(StatusCodes.NotFound)
                }

              case Failure(ex) =>
                complete(StatusCodes.InternalServerError)
            }

          }
        }
      } ~
      get {
        pathPrefix("ReadElement" / Segment) { key =>

          parameter("position".as[Int]) { position =>

            val future = retry(fetchSet(key), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS)

            onComplete(future) {
              case Success(option) =>
                option match {
                  case Some(set) =>
                    if (position > set.contents.length-1)
                      complete(StatusCodes.NotFound)
                    else
                      complete(DDSItem(set.contents.apply(position)))

                  case None =>
                    complete(StatusCodes.NotFound)
                }
              case Failure(ex) =>
                complete(StatusCodes.InternalServerError)
            }
          }
        }
      } ~
      put {
        pathPrefix("WriteElement" / Segment) { key =>

          parameter("position".as[Int]) { position =>
            entity(as[DDSItem]) { item =>
              
              val future = retry(fetchSet(key), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS)
  
              onComplete(future) {
                case Success(option) =>
                  option match {
                    case Some(set) =>
                      
                      var buffer = Buffer[Any]()
                      set.contents.copyToBuffer(buffer)
  
                      if (position > buffer.size-1)
                        buffer.append(item.value)
                      else
                        buffer(position) = item.value
  
                      val future = retry(writeSet(key, Some(DDSSet(buffer.toList))), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS)
  
                      onComplete(future) {
                        case Success(ack) =>
                          complete(StatusCodes.OK)
                        case Failure(ex) =>
                          complete(StatusCodes.InternalServerError)
                      }
  
                    case None =>
                      complete(StatusCodes.NotFound)
                  }
  
                case Failure(ex) =>
                  complete(StatusCodes.InternalServerError)
              }
  
            }
          }
        }
      } ~
      post {
        pathPrefix("IsElement" / Segment) { key =>

          entity(as[DDSItem]) { item =>

            val future = retry(fetchSet(key), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS)

            onComplete(future) {
              case Success(option) =>
                option match {
                  
                  case Some(set) => 
                    
                    var found = false
                    for (elem <- set.contents) {
                      if (HomoDet.compare(elem.toString, item.value.toString)) {
                          found = true
                          break
                      }
                    }
                    
                    complete(DDSValueResult(found))
                    
                  case None => 
                    complete(StatusCodes.NotFound)
                }
              case Failure(ex) =>
                complete(StatusCodes.InternalServerError)
            }
          }
        }
      } ~
      get {
        pathPrefix("Sum") {
          parameter("key1", "key2", "position".as[Int], "nsqr".?) { (key1, key2, position, nsqr) =>
            
              val futures = Future.sequence(List(
                   retry(fetchSet(key1), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS),
                   retry(fetchSet(key2), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS)
              ))
               
              onComplete(futures) {
                 case Success(results) =>
                   
                   results match {
                     case List(None, None) =>
                       complete(StatusCodes.NotFound)
                     case List(None, set2) =>
                       complete(StatusCodes.NotFound)
                     case List(set1, None) =>
                       complete(StatusCodes.NotFound)
                     case List(set1, set2) =>
                      
                       if (set1.get.contents.length-1 < position || set2.get.contents.length-1 < position) {
                         complete(StatusCodes.NotFound)
                       } else {
                         
                         val operand1 = new BigInteger(set1.get.contents(position).toString)
                         val operand2 = new BigInteger(set2.get.contents(position).toString)
                         
                         if (nsqr.nonEmpty) {
                           val nsquare = new BigInteger(nsqr.get)
                           complete(DDSValueResult(HomoAdd.sum(operand1, operand2, nsquare).toString))
                         } else {
                           complete(DDSValueResult(operand1.add(operand2).toString))
                         }
                       }
                   }
                 case Failure(ex) =>
                   complete(StatusCodes.InternalServerError)
              }
          }
        }
      } ~
      get {
        pathPrefix("SumAll") {
          parameter("position".as[Int], "nsqr".?) { (position, nsqr) =>
            
              val futures = Future.sequence(
                  storedKeys.map { key => retry(fetchSet(key), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS) }
              )
               
              onComplete(futures) {
                 case Success(results) =>
                   
                   val filtered = results.filter { result => result.nonEmpty }
                   
                   if (filtered.size > 0) {
                     
                     var sum : Option[BigInteger] = None
                     for (ddsSet <- filtered.toList) {
                       
                       if (ddsSet.get.contents.length-1 > position) {
                           sum = if (sum.isEmpty) {
                               Some(new BigInteger(ddsSet.get.contents(position).toString))
                           } else {
                               val operand = new BigInteger(ddsSet.get.contents(position).toString)
                               
                               if (nsqr.nonEmpty) {
                                 val nsquare = new BigInteger(nsqr.get)
                                 Some(HomoAdd.sum(sum.get, operand, nsquare))
                               } else {
                                 Some(sum.get.add(operand))
                               }
                           }
                       }
                         
                     }
                     
                     if (sum.isEmpty) {
                       complete(StatusCodes.NotFound)
                     } else {
                       complete(DDSValueResult(sum.get.toString))
                     }
                   } else {
                     complete(StatusCodes.NotFound)
                   }
                   
                 case Failure(ex) =>
                   complete(StatusCodes.InternalServerError)
              }
          }
        }
      } ~
      get {
        pathPrefix("Mult") {
          parameter("key1", "key2", "position".as[Int], "pubkey".?) { (key1, key2, position, pubkey) =>
            
              val futures = Future.sequence(List(
                   retry(fetchSet(key1), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS),
                   retry(fetchSet(key2), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS)
              ))
               
              onComplete(futures) {
                 case Success(results) =>
                   
                   results match {
                     case List(None, None) =>
                       complete(StatusCodes.NotFound)
                     case List(None, set2) =>
                       complete(StatusCodes.NotFound)
                     case List(set1, None) =>
                       complete(StatusCodes.NotFound)
                     case List(set1, set2) =>
                      
                       if (set1.get.contents.length-1 < position || set2.get.contents.length-1 < position) {
                         complete(StatusCodes.NotFound)
                       } else {
                                                
                         val operand1 = new BigInteger(set1.get.contents(position).toString)
                         val operand2 = new BigInteger(set2.get.contents(position).toString)
                           
                         if (pubkey.nonEmpty) {
                           val publicKey = KeyFactory.getInstance("RSA").generatePublic(
                                 new X509EncodedKeySpec(DatatypeConverter.parseHexBinary(pubkey.get))
                           )
                           complete(DDSValueResult(HomoMult.multiply(operand1, operand2, publicKey.asInstanceOf[RSAPublicKey]).toString))
                         } else {
                           complete(DDSValueResult(operand1.multiply(operand2).toString))
                         }                         
                       }
                   }
                 case Failure(ex) =>
                   complete(StatusCodes.InternalServerError)
              }
          }
        }
      } ~
      get {
        pathPrefix("MultAll") {
          parameter("position".as[Int], "pubkey".?) { (position, pubkey) =>
              
              val futures = Future.sequence(
                  storedKeys.map { key => retry(fetchSet(key), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS) }
              )
               
              onComplete(futures) {
                 case Success(results) =>

                   val filtered = results.filter { result => result.nonEmpty }
                   
                   if (filtered.size > 0) {
                     
                     var mult : Option[BigInteger] = None
                     for (ddsSet <- filtered.toList) {
                       
                       if (ddsSet.get.contents.length-1 > position) {
                           mult = if (mult.isEmpty) {
                               Some(new BigInteger(ddsSet.get.contents(position).toString))
                           } else {
                               val operand = new BigInteger(ddsSet.get.contents(position).toString)
                               if (pubkey.nonEmpty) {
                                 val publicKey = KeyFactory.getInstance("RSA").generatePublic(
                                       new X509EncodedKeySpec(DatatypeConverter.parseHexBinary(pubkey.get))
                                 )
                                 Some(HomoMult.multiply(mult.get, operand, publicKey.asInstanceOf[RSAPublicKey]))
                               } else {
                                 Some(mult.get.multiply(operand))
                               }
                           }
                       }
                     }
                     
                     if (mult.isEmpty) {
                       complete(StatusCodes.NotFound)
                     } else {
                       complete(DDSValueResult(mult.get.toString))
                     }
                   } else {
                     complete(StatusCodes.NotFound)
                   }
                   
                 case Failure(ex) =>
                   complete(StatusCodes.InternalServerError)
              }
          }
        }
      } ~
      get {
        pathPrefix("OrderLS") {
          parameter("position".as[Int]) { position =>
            
              val futures = Future.sequence(
                  storedKeys.map { key => 
                      retry(fetchSet(key), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS).map { set => (key, set) }
                  }
              )
               
              onComplete(futures) {
                 case Success(results) =>
                   
                   val filtered = results.filter { result => result._2.nonEmpty }
                   
                   val orderedKeys = filtered.toList.sortWith((a, b) => {
                       if (a._2.get.contents.length-1 < position) {
                           false
                       } else if (b._2.get.contents.length-1 < position) {
                           true
                       } else {
                           a._2.get.contents(position).asInstanceOf[String].toLong > b._2.get.contents(position).asInstanceOf[String].toLong
                       }
                   }).map { keyval => keyval._1 }
                   
                   complete(DDSKeysResult(orderedKeys))
                   
                 case Failure(ex) =>
                   complete(StatusCodes.InternalServerError)
              }
          }
        }
      } ~
      get {
        pathPrefix("OrderSL") {
          parameter("position".as[Int]) { position =>
            
              val futures = Future.sequence(
                  storedKeys.map { key => 
                      retry(fetchSet(key), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS).map { set => (key, set) }
                  }
              )
               
              onComplete(futures) {
                 case Success(results) =>
                   
                   val filtered = results.filter { result => result._2.nonEmpty }
                   
                   val orderedKeys = filtered.toList.sortWith((a, b) => {
                       if (a._2.get.contents.length-1 < position) {
                           true
                       } else if (b._2.get.contents.length-1 < position) {
                           false
                       } else {
                           a._2.get.contents(position).asInstanceOf[String].toLong < b._2.get.contents(position).asInstanceOf[String].toLong
                       }
                   }).map { keyval => keyval._1 }
                   
                   complete(DDSKeysResult(orderedKeys))
                   
                 case Failure(ex) =>
                   complete(StatusCodes.InternalServerError)
              }
          }
        }
      } ~
      post {
        pathPrefix("SearchEq") {
          parameter("position".as[Int]) { position =>
            entity(as[DDSItem]) { item => 
              
              val futures = Future.sequence(
                  storedKeys.map { key =>
                      retry(fetchSet(key), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS).map { set => (key, set) }
                  }
              )
              
              onComplete(futures) {
                case Success(results) =>
                  
                  val filtered = results.filter { result => result._2.nonEmpty }
                  
                  var keyset = List[String]()
                  for (pair <- filtered.toList) {
                    
                    val ddsSet = pair._2.get
                    
                    if (ddsSet.contents.length-1 > position && 
                        // applies to both CHE and OPE
                        HomoDet.compare(ddsSet.contents(position).toString, item.value.toString)) {
                        keyset ::= pair._1
                    }
                  }
                  
                  complete(DDSKeysResult(keyset))

                case Failure(ex) => 
                  complete(StatusCodes.InternalServerError)

              }
            }
          }
        }
      } ~
      post {
        pathPrefix("SearchNEq") {
          parameter("position".as[Int]) { position =>
            entity(as[DDSItem]) { item => 
              val futures = Future.sequence(
                  storedKeys.map { key =>
                      retry(fetchSet(key), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS).map { set => (key, set) }
                  }
              )
              
              onComplete(futures) {
                case Success(results) =>
                  
                  val filtered = results.filter { result => result._2.nonEmpty }
                  
                  var keyset = List[String]()
                  for (pair <- filtered.toList) {
                    
                    val ddsSet = pair._2.get
                    
                    if (ddsSet.contents.length-1 > position && 
                        // applies to both CHE and OPE
                        !HomoDet.compare(ddsSet.contents(position).toString, item.value.toString)) {
                        keyset ::= pair._1
                    }
                  }
                  
                  complete(DDSKeysResult(keyset))

                case Failure(ex) => 
                  complete(StatusCodes.InternalServerError)

              }
            }
          }
        }
      } ~
      post {
        pathPrefix("SearchGt") {
          parameter("position".as[Int]) { position =>
            entity(as[DDSItem]) { item => 
              
              val futures = Future.sequence(
                  storedKeys.map { key =>
                      retry(fetchSet(key), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS).map { set => (key, set) }
                  }
              )
              
              onComplete(futures) {
                case Success(results) =>
                  
                  val filtered = results.filter { result => result._2.nonEmpty }
                  
                  var keyset = List[String]()
                  for (pair <- filtered.toList) {
                    
                    val ddsSet = pair._2.get
                    if (ddsSet.contents.length-1 > position && 
                        // applies only to OPE
                        new BigInteger(item.value.toString).compareTo(new BigInteger(ddsSet.contents(position).toString)) < 0) {
                        keyset ::= pair._1
                    }
                  }
                  
                  complete(DDSKeysResult(keyset))

                case Failure(ex) => 
                  complete(StatusCodes.InternalServerError)

              }
            }
          }
        }
      } ~
      post {
        pathPrefix("SearchGtEq") {
          parameter("position".as[Int]) { position =>
            entity(as[DDSItem]) { item => 
              
              val futures = Future.sequence(
                  storedKeys.map { key =>
                      retry(fetchSet(key), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS).map { set => (key, set) }
                  }
              )
              
              onComplete(futures) {
                case Success(results) =>
                  
                  val filtered = results.filter { result => result._2.nonEmpty }
                  
                  var keyset = List[String]()
                  for (pair <- filtered.toList) {
                    
                    val ddsSet = pair._2.get
                    
                    if (ddsSet.contents.length-1 > position && 
                        // applies only to OPE
                        new BigInteger(item.value.toString).compareTo(new BigInteger(ddsSet.contents(position).toString)) <= 0) {
                        keyset ::= pair._1
                    }
                  }
                  
                  complete(DDSKeysResult(keyset))

                case Failure(ex) => 
                  complete(StatusCodes.InternalServerError)

              }
            }
          }
        }
      } ~
      post {
        pathPrefix("SearchLt") {
          parameter("position".as[Int]) { position =>
            entity(as[DDSItem]) { item => 
              val futures = Future.sequence(
                  storedKeys.map { key =>
                      retry(fetchSet(key), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS).map { set => (key, set) }
                  }
              )
              
              onComplete(futures) {
                case Success(results) =>
                  
                  val filtered = results.filter { result => result._2.nonEmpty }
                  
                  var keyset = List[String]()
                  for (pair <- filtered.toList) {
                    
                    val ddsSet = pair._2.get
                    
                    if (ddsSet.contents.length-1 > position && 
                        // applies only to OPE
                        new BigInteger(item.value.toString).compareTo(new BigInteger(ddsSet.contents(position).toString)) > 0) {
                        keyset ::= pair._1
                    }
                  }
                  
                  complete(DDSKeysResult(keyset))

                case Failure(ex) => 
                  complete(StatusCodes.InternalServerError)

              }
            }
          }
        }
      } ~
      post {
        pathPrefix("SearchLtEq") {
          parameter("position".as[Int]) { position =>
            entity(as[DDSItem]) { item => 
                val futures = Future.sequence(
                  storedKeys.map { key =>
                      retry(fetchSet(key), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS).map { set => (key, set) }
                  }
              )
              
              onComplete(futures) {
                case Success(results) =>
                  
                  val filtered = results.filter { result => result._2.nonEmpty }
                  
                  var keyset = List[String]()
                  for (pair <- filtered.toList) {
                    
                    val ddsSet = pair._2.get
                    
                    if (ddsSet.contents.length-1 > position && 
                        // applies only to OPE
                        new BigInteger(item.value.toString).compareTo(new BigInteger(ddsSet.contents(position).toString)) >= 0) {
                        keyset ::= pair._1
                    }
                  }
                  
                  complete(DDSKeysResult(keyset))

                case Failure(ex) => 
                  complete(StatusCodes.InternalServerError)

              }
            }
          }
        }
      } ~
      post {
        pathPrefix("SearchEntry") {
          entity(as[DDSItem]) { item => 
            
            val futures = Future.sequence(
                storedKeys.map { key =>
                  retry(fetchSet(key), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS).map { set => (key, set) }
                }
            )
              
            onComplete(futures) {
              case Success(results) =>
                
                val filtered = results.filter { result => result._2.nonEmpty }
                
                var keyset = List[String]()
                for (ddsSet <- filtered.toList) {
                  for (elem <- ddsSet._2.get.contents) {
                    if (HomoDet.compare(item.toString, elem.toString)) {
                        keyset ::= ddsSet._1
                        break
                    }
                  }
                }
                
                complete(DDSKeysResult(keyset))

              case Failure(ex) => 
                complete(StatusCodes.InternalServerError)
            }
          }
        }
      } ~
      post {
        pathPrefix("SearchEntryOR") {
          entity(as[DDSItemTriplet]) { triplet => 
            
            val futures = Future.sequence(
                storedKeys.map { key =>
                  retry(fetchSet(key), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS).map { set => (key, set) }
                }
            )
              
            onComplete(futures) {
              case Success(results) =>
                
                val filtered = results.filter { result => result._2.nonEmpty }
                
                var keyset = List[String]()
                for (ddsSet <- filtered.toList) {
                  for (elem <- ddsSet._2.get.contents) {
                    if (HomoDet.compare(triplet.value1.toString, elem.toString) ||
                        HomoDet.compare(triplet.value2.toString, elem.toString) || 
                        HomoDet.compare(triplet.value3.toString, elem.toString)) {
                        keyset ::= ddsSet._1
                        break
                    }
                  }
                }
                
                complete(DDSKeysResult(keyset))

              case Failure(ex) => 
                complete(StatusCodes.InternalServerError)
            }
          }
        }
      } ~
      post {
        pathPrefix("SearchEntryAND") {
          entity(as[DDSItemTriplet]) { triplet =>
              
            val futures = Future.sequence(
                storedKeys.map { key =>
                  retry(fetchSet(key), INTRA_RETRY_BACKOFF millis, INTRA_RETRY_ATTEMPTS).map { set => (key, set) }
                }
            )
              
            onComplete(futures) {
              case Success(results) =>
                
                val filtered = results.filter { result => result._2.nonEmpty }
                
                var keyset = List[String]()
                for (ddsSet <- filtered.toList) {
                  
                  var foundValues = Set[String]()
                  for (elem <- ddsSet._2.get.contents) {
                    if (HomoDet.compare(triplet.value1.toString, elem.toString) ||
                        HomoDet.compare(triplet.value2.toString, elem.toString) || 
                        HomoDet.compare(triplet.value3.toString, elem.toString)) {
                        
                        foundValues += elem.toString
                        if (foundValues.size == 3) {
                            keyset ::= ddsSet._1
                            break
                        }
                    }
                  }
                }
                
                complete(DDSKeysResult(keyset))

              case Failure(ex) => 
                complete(StatusCodes.InternalServerError)
            }
          }
        }
      } ~ 
      post {
        pathPrefix("_sync") {
           entity(as[DDSKeysResult]) { keys =>
             // sync mechanism between proxies
             storedKeys ++= keys.keyset
             complete(StatusCodes.NoContent)
           }
        }
      }
      
      
  // abd read/write functions
  def fetchSet(key: String) : Future[Option[DDSSet]] = {
    
    // assemble the fetch request
    val requestKey = key
    val originNonce = Utils.generateNonce
    val signature = Utils.generateProxySignature(PROXY_MAC_SECRET_KEY, key, originNonce, PROXY_MAC_DIGEST)
    val request = Envelope(IRead(key), originNonce, signature)
    
    // instantiate the promise that we will return
    val promise = Promise[Option[DDSSet]]()
    
    // start by request the supervisor for a fresh replica
    implicit val timeout = Timeout(INTRA_REQUEST_TIMEOUT milliseconds)
    val replica = ddsReplicas.deferTo
    
    // send it away
    val future = system.actorSelection(replica) ? request 
    
    future onSuccess {
      case Envelope(IReadReply(key, option), nonce, signature) =>

        // check nonce and signature and key
        if (nonce != originNonce + INTRA_NONCE_INCREMENT) {
          ddsReplicas.incrementSuspicion(replica)
          promise failure new ByzFailedNonceChallengeException
        } else if (!Utils.validateProxySignature(PROXY_MAC_SECRET_KEY, key, option, nonce, signature, PROXY_MAC_DIGEST)) {
          ddsReplicas.incrementSuspicion(replica)
          promise failure new ByzInvalidSignatureException
        } else if (requestKey != key) {
          ddsReplicas.incrementSuspicion(replica)
          promise failure new ByzInvalidKeyException
        } else {
          promise success option
        }
      case _ =>
        ddsReplicas.incrementSuspicion(replica)
        promise failure new ByzUnknownReplyException
    }

    future onFailure {
      case t: AskTimeoutException =>
        // the replica may have crashed or the message may have been lost over network
        // or in an extreme case, it might be byzantine
        ddsReplicas.incrementSuspicion(replica)
        promise failure t
    }
    
    promise.future
  }

  def writeSet(key: String, set: Option[DDSSet]) : Future[Unit] = {
    
    // assemble the fetch request
    val requestKey = key
    val originNonce = Utils.generateNonce
    val signature = Utils.generateProxySignature(PROXY_MAC_SECRET_KEY, key, set, originNonce, PROXY_MAC_DIGEST)
    val request = Envelope(IWrite(key, set), originNonce, signature)
    
    // instantiate the promise that we will return
    val promise = Promise[Unit]()
    
    // start by request the supervisor for a fresh replica
    implicit val timeout = Timeout(INTRA_REQUEST_TIMEOUT milliseconds)
    val replica = ddsReplicas.deferTo
    
    // send it away
    val future = system.actorSelection(replica) ? request 

    future onSuccess {
      case Envelope(IWriteReply(key), nonce, signature) =>

        // check nonce and signature and key
        if (nonce != originNonce + INTRA_NONCE_INCREMENT) {
          ddsReplicas.incrementSuspicion(replica)
          promise failure new ByzFailedNonceChallengeException
        } else if (!Utils.validateProxySignature(PROXY_MAC_SECRET_KEY, key, nonce, signature, PROXY_MAC_DIGEST)) {
          ddsReplicas.incrementSuspicion(replica)
          promise failure new ByzInvalidSignatureException
        } else if (requestKey != key) {
          ddsReplicas.incrementSuspicion(replica)
          promise failure new ByzInvalidKeyException
        } else {
          promise success ()
        }
      case _ =>
        ddsReplicas.incrementSuspicion(replica)
        promise failure new ByzUnknownReplyException
    }

    future onFailure {
      case t: AskTimeoutException =>
        // the replica may have crashed or the message may have been lost over network
        // or in an extreme case, it might be byzantine
        ddsReplicas.incrementSuspicion(replica)
        promise failure t
    }

    promise.future
  }

}