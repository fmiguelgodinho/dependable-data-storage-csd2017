import java.io.File
import java.util.concurrent.TimeoutException
import java.security.{ SecureRandom, KeyStore }
import javax.net.ssl.{ SSLContext, TrustManagerFactory, KeyManagerFactory }

import akka.pattern.ask
import akka.util.Timeout
import akka.actor.{ ActorSystem, Actor, ActorRef, Props }
import akka.http.scaladsl.{ ConnectionContext, HttpsConnectionContext, Http }
import akka.http.scaladsl.model._
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.Directives
import akka.http.scaladsl.marshallers.sprayjson.SprayJsonSupport
import akka.stream.ActorMaterializer

import scala.io.StdIn
import scala.collection.JavaConverters._
import scala.concurrent.Future
import scala.concurrent.duration._
import scala.util.Random

import com.typesafe.config.ConfigFactory
import com.typesafe.sslconfig.akka.AkkaSSLConfig

import spray.json._
import spray.json.DefaultJsonProtocol._

import dds.api.{ Envelope, IRead, IWrite, IReadReply }
import dds.core.BFTABDNode
import utils.Utils
import clt.{ DDSHttpClient, DDSDataGenerator, Digest }
import dds.http.DDSRestServer
import dds.core.BFTSupervisor
import java.io.InputStream
import java.io.FileInputStream
import malicious.MaliciousAttack
import malicious.Trigger
import malicious.Trudy
import dds.api.Sleep

object Main {

  def main(args: Array[String]) {

    // Load application configurations
    val systemConfig = ConfigFactory.parseFile(new File("src/main/resources/dds-system.conf"))
    val clientConfig = ConfigFactory.parseFile(new File("src/main/resources/client.conf"))

    // read DDS settings
    val createSupervisor = systemConfig getBoolean "replicas.supervisor.create-supervisor"   
    val supervisorEndpoint = systemConfig getString "replicas.supervisor.endpoint"
    val localReplicas = (systemConfig getConfigList "replicas.local").asScala.toList
    val externalReplicas = (systemConfig getConfigList "replicas.external").asScala.toList
    val byzQuorumSz = systemConfig getInt "replicas.security.byz-quorum-size"
    val byzMaxFaults = systemConfig getInt "replicas.security.byz-max-faults"
    val localReplicasHost = systemConfig getString "akka.remote.netty.ssl.hostname"
    val localReplicasPort = systemConfig getInt "akka.remote.netty.ssl.port"
    val proxyHostname = systemConfig getString "proxy.hostname"
    val proxyPort = systemConfig getInt "proxy.port"

    // read fault simulation settings
    val attacksEnabled = systemConfig getBoolean "replicas.intruder-attacks.enable-simulation"
    val nrOfAttacks = systemConfig getInt "replicas.intruder-attacks.nr-of-attacks"
    val typeOfAttacks = systemConfig getString "replicas.intruder-attacks.type-of-attacks"

    // read client settings
    val localClients = clientConfig getInt "topology.nr-of-local-clients"
    val nrOfOperations = clientConfig getInt "io.nr-of-operations"
    val nrOfColumns = clientConfig getInt "io.data-table.max-nr-of-columns"
    val fixedColumnMappings = (clientConfig getStringList "io.data-table.fixed-columns-mappings").asScala.toList
    val fixedColumnHCrypt = (clientConfig getStringList "io.data-table.fixed-columns-hcrypt").asScala.toList
    val proxyEndpoints = (clientConfig getStringList "proxy-endpoints").asScala.toList
      
    // initialize actor system and materializer
    implicit val system = ActorSystem("dds-system", systemConfig)

    // needed for the future flatMap/onComplete in the end
    implicit val executionContext = system.dispatcher
    
    // load replica lists
    var DDSReplicas = localReplicas ++ externalReplicas 
    var DDSReplicaEndpoints = DDSReplicas map { r => r.getString("endpoint") }
    var DDSActiveReplicasEndpoints = DDSReplicas filter { r => !r.getBoolean("sentinent") } map { r => r.getString("endpoint") }
    
    // instantiate supervisor if specified
    if (createSupervisor) {
      system.actorOf(Props(new BFTSupervisor(DDSReplicas)), supervisorEndpoint.split("/").last) 
    }
    // instantiate local ABD replicas
    for (replica <- localReplicas) {
      val node = system.actorOf(
          BFTABDNode.props(DDSReplicaEndpoints, supervisorEndpoint), 
          replica.getString("endpoint").split("/").last
      )
      
      if (replica.getBoolean("sentinent")) {
        node ! Sleep(Map(), Set())
      }
    }
    // initiate REST proxy server with HTTPS settings
    new DDSRestServer(system, DDSActiveReplicasEndpoints).bind

    println("Dependable Data Store system at https://" + proxyHostname + ":" + proxyPort + "/")
    println("Implementation: BFT-ABD in Scala w/ Akka\n")

    // list all replicas (remote)
    println("\nDDS remote replicas:")
    externalReplicas map { replica => 
      print("\t" + replica.getString("endpoint")) 
      if(replica.getBoolean("sentinent")) print(" (sentinent)")
      println
    }
    if (externalReplicas.length == 0) println("\t(none)")

    // list all replicas (local)
    println("\nDDS local replicas:")
    localReplicas map { replica => 
      print("\t" + replica.getString("endpoint")) 
      if(replica.getBoolean("sentinent")) print(" (sentinent)")
      println
    }
    if (localReplicas.length == 0) println("\t(none)")

    if (attacksEnabled) {
      // give info about attack specs
      println("\nATTENTION: malicious attack simulation is on!")
      println("\t#replicas that will be affected = " + nrOfAttacks)
      println("\tType of induced faults = " + typeOfAttacks)
    }

    // create clients and benchmark sets
    println("\nClients:")
    println("\t#local clients = " + localClients)

    if (localClients > 0) {

      println("\t#operations = " + nrOfOperations + "\n")

      // Load operation proportions
      var proportions = Map[String, Double] (
          "get-set" -> clientConfig.getDouble("io.proportion.get-set"),
          "put-set" -> clientConfig.getDouble("io.proportion.put-set"),
          "remove-set" -> clientConfig.getDouble("io.proportion.remove-set"),
          "add-element" -> clientConfig.getDouble("io.proportion.add-element"),
          "write-element" -> clientConfig.getDouble("io.proportion.write-element"),
          "read-element" -> clientConfig.getDouble("io.proportion.read-element"),
          "is-element" -> clientConfig.getDouble("io.proportion.is-element"),
          "sum" -> clientConfig.getDouble("io.proportion.sum"),
          "sum-all" -> clientConfig.getDouble("io.proportion.sum-all"),
          "mult" -> clientConfig.getDouble("io.proportion.mult"),
          "mult-all" -> clientConfig.getDouble("io.proportion.mult-all"),
          "search-eq" -> clientConfig.getDouble("io.proportion.search-eq"),
          "search-neq" -> clientConfig.getDouble("io.proportion.search-neq"),
          "search-gt" -> clientConfig.getDouble("io.proportion.search-gt"),
          "search-gteq" -> clientConfig.getDouble("io.proportion.search-gteq"),
          "search-lt" -> clientConfig.getDouble("io.proportion.search-lt"),
          "search-lteq" -> clientConfig.getDouble("io.proportion.search-lteq"),
          "order-ls" -> clientConfig.getDouble("io.proportion.order-ls"),
          "order-sl" -> clientConfig.getDouble("io.proportion.order-sl"),
          "search-entry" -> clientConfig.getDouble("io.proportion.search-entry"),
          "search-entry-and" -> clientConfig.getDouble("io.proportion.search-entry-and"),
          "search-entry-or" -> clientConfig.getDouble("io.proportion.search-entry-or")
      )

      // create client actors
      val clientSystem = ActorSystem("dds-client", clientConfig)
      var clientList = List[ActorRef]()
      for (i <- 1 to localClients) {
        clientList ::= clientSystem.actorOf(Props(new DDSHttpClient(proxyEndpoints)), "http-client-" + i)
      }

      println("Press ENTER to start.")
      StdIn.readLine()

      // start http requests to proxy
      for (client <- clientList) {
        // generate instruction set 
        val payload = DDSDataGenerator.generate(nrOfOperations, proportions, nrOfColumns, fixedColumnMappings, fixedColumnHCrypt)
        // send it away!
        client ! Digest(payload)
      }

      println("Running...")
    }

    // simulate malicious intents
    if (attacksEnabled) {
      val trudy = system.actorOf(Props(new Trudy(
          Random.shuffle(DDSActiveReplicasEndpoints).take(nrOfAttacks)
      )), "trudy")
      
      trudy ! Trigger(MaliciousAttack.getAttackType(typeOfAttacks))
    }

  }
}