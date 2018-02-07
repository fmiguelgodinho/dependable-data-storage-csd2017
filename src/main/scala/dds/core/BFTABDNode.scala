package dds.core

import scala.util.Random
import scala.collection.mutable
import akka.actor.{ Actor, ActorRef }

import utils.Utils
import dds.api._
import dds.core.models.IncomingRequestState
import dds.core.models.OutgoingRequestState
import dds.core.models.ABDState
import dds.core.models.ABDTag
import dds.core.models.DDSSet
import dds.api.Suspect
import malicious.Compromise
import utils.TrustedNodesList
import java.io.FileInputStream
import java.security.KeyStore
import java.io.InputStream
import java.io.File
import java.security.Key
import dds.core.models.IncomingRequestState
import akka.actor.Props

object BFTABDNode {
  // factory object for this actor
  def props(replicas: List[String], supervisor: String): Props = Props(new BFTABDNode(replicas, supervisor))
}

class BFTABDNode(replicas: List[String], supervisor: String) extends Actor {

  // Constants
  private val FAULT_DETECTION_DEBUGGING = context.system.settings.config.getBoolean("fault-detection-debugging")
  private val DEBUGGING_ENABLED = context.system.settings.config.getBoolean("server-side-debugging")
  private val PROXY_MAC_SECRET_KEY = context.system.settings.config.getString("proxy.security.mac-signature-secret-key")
  private val PROXY_MAC_DIGEST = context.system.settings.config.getString("proxy.security.mac-signature-digest")
  private val INTRA_KEY_STORE = context.system.settings.config.getString("akka.remote.netty.ssl.security.key-store")
  private val INTRA_KEY_STORE_PW = context.system.settings.config.getString("akka.remote.netty.ssl.security.key-store-password").toCharArray
  private val NONCE_INCREMENT = context.system.settings.config.getInt("proxy.security.nonce-challenge-increment")
  private val BYZ_QUORUM_SIZE = context.system.settings.config.getInt("replicas.security.byz-quorum-size")
  private val MAC_DIGEST = context.system.settings.config.getString("replicas.security.mac-signature-digest")

  // Objects stored in this replica
  private var repository = Map[String, ABDState]()

  // Register of outgoing/incoming requests through the algorithm, key is nonce
  private var outgoingRequests = Map[Long, OutgoingRequestState]()
  private var incomingRequests = Map[Long, IncomingRequestState]()

  // Sibling replicas
  private var siblings = new TrustedNodesList(replicas)

  // HMac key
  private var macKey: Key = null

  // on pre start get private key to sign hmacs
  override def preStart = {
    val ks: KeyStore = KeyStore.getInstance("JKS")
    val keystore: InputStream = new FileInputStream(new File(INTRA_KEY_STORE))
    ks.load(keystore, INTRA_KEY_STORE_PW)

    macKey = ks.getKey("server", INTRA_KEY_STORE_PW)
  }

  // set receive to default to healthy behaviour - abd algorithm - or to sentinent behaviour (only receives writes, in dormant state)
  def receive = healthy

  // healthy abd algorithm node behaviour
  def healthy: Receive = {

    // ------------------------------------------------------------------------------

    // Client messages entry point
    case Envelope(message, nonce, signature) =>

      // check if proxy already sent us this nonce
      if (outgoingRequests contains nonce) {

        // someone is sending a message nonce that we've seen before, possible replay
        if (DEBUGGING_ENABLED) println(self.path.name + ": Invalid nonce received from Proxy - Repeated.")

      } else {

        var req = new OutgoingRequestState(sender, message, nonce)

        message match {

          case IRead(key) =>

            if (!Utils.validateProxySignature(PROXY_MAC_SECRET_KEY, key, nonce, signature, PROXY_MAC_DIGEST)) {

              // someone tampered with message contents
              if (DEBUGGING_ENABLED) println(self.path.name + ": Invalid signature received from Proxy.")

            } else {

              val trusted = siblings.getTrusted
              for (sibling <- trusted) {
                context.actorSelection(sibling) ! Read(key, nonce)
              }
            }

          case IWrite(key, set) =>

            if (!Utils.validateProxySignature(PROXY_MAC_SECRET_KEY, key, set, nonce, signature, PROXY_MAC_DIGEST)) {

              // someone tampered with message contents
              if (DEBUGGING_ENABLED) println(self.path.name + ": Invalid signature received from Proxy.")

            } else {

              req.setToWrite = set // save the set we're writing for later

              val trusted = siblings.getTrusted
              for (sibling <- trusted) {
                context.actorSelection(sibling) ! ReadTag(key, nonce)
              }
            }

          case _ =>
            System.err.println("Unexpected API call from client.")

        }
        outgoingRequests += nonce -> req

      }

    // ------------------------------------------------------------------------------

    case ReadTag(key, nonce) =>

      if (incomingRequests contains nonce) {

        // someone is sending a message nonce that we've seen before, possible replay
        if (DEBUGGING_ENABLED) println(self.path.name + ": Invalid nonce received - Repeated.")

        context.actorSelection(supervisor) ! Suspect(sender, Utils.generateNonce) 

      } else {

        // register nonce
        incomingRequests += nonce -> new IncomingRequestState(false)

        // get repository contents and sign them
        val state = getState(key)
        var newSignature = Utils.generateABDSignature(macKey.getEncoded, state.contents, state.tag, nonce, MAC_DIGEST)
        sender ! TagReply(state.tag, key, state.contents, newSignature, nonce)

      }

    case TagReply(tag, key, set, signature, nonce) =>

      if (!Utils.validateABDSignature(macKey.getEncoded, set, tag, nonce, signature, MAC_DIGEST)) {

        // someone tampered with message contents
        if (DEBUGGING_ENABLED) println(self.path.name + ": Invalid signature received.")
        
        context.actorSelection(supervisor) ! Suspect(sender, Utils.generateNonce)

      } else if (!outgoingRequests.contains(nonce)) {

        // someone changed the message nonce, this isn't our nonce
        if (DEBUGGING_ENABLED) println(self.path.name + ": Invalid nonce received - Unknown.")
        
        context.actorSelection(supervisor) ! Suspect(sender, Utils.generateNonce) 

      } else if (outgoingRequests.contains(nonce) && outgoingRequests.get(nonce).get.expired) {

        //this nonce is ours but it's expired
        if (DEBUGGING_ENABLED) println(self.path.name + ": Invalid nonce received - Expired."
          + "\nPlease note that this can be a late response to a quorum.")
          
      } else {

        // wait for quorum
        var req = outgoingRequests.get(nonce).get

        req.readQuorum += ((tag, set, signature))
        outgoingRequests += nonce -> req

        if (req.readQuorum.size >= BYZ_QUORUM_SIZE) {

          // reached quorum
          // let seqmax = max{sn : <sn,id,sig> belonging to Q }
          val (maxtag, _, _) = req.readQuorum.reduce((a, b) => {
            val (tag1, tag2) = (a._1.asInstanceOf[ABDTag], b._1.asInstanceOf[ABDTag])
            if (tag1.seq > tag2.seq) a else b
          })
          // clear quorum
          req.readQuorum = Set()
          outgoingRequests += nonce -> req

          // construct the new tag to write and sign it
          val newTag = ABDTag(maxtag.seq + 1, self.path.name)
          var newSignature = Utils.generateABDSignature(macKey.getEncoded, req.setToWrite, newTag, nonce, MAC_DIGEST)

          // call write
          val trusted = siblings.getTrusted
          for (sibling <- trusted) {
            context.actorSelection(sibling) ! Write(newTag, key, req.setToWrite, newSignature, nonce)
          }
        }
      }

    case Write(tag, key, set, signature, nonce) =>

      if (!Utils.validateABDSignature(macKey.getEncoded, set, tag, nonce, signature, MAC_DIGEST)) {

        // someone tampered with message contents
        if (DEBUGGING_ENABLED) println(self.path.name + ": Invalid signature received.")
        
        context.actorSelection(supervisor) ! Suspect(sender, Utils.generateNonce) 

      } else if (!incomingRequests.contains(nonce)) {

        // someone is sending a message nonce that we've never seen before, and we should've in ReadTag
        if (DEBUGGING_ENABLED) println(self.path.name + ": Invalid nonce received - Unknown.")
        
        context.actorSelection(supervisor) ! Suspect(sender, Utils.generateNonce) 

      } else if (incomingRequests.contains(nonce) && incomingRequests.get(nonce).get.expired) {

        // someone is sending a message nonce we've seen before, but it's expired, possible replay
        if (DEBUGGING_ENABLED) println(self.path.name + ": Invalid nonce received - Expired at Write."
          + "\nPlease note that this can be a late response to a quorum.")

      } else {

        // register that this nonce is expired
        incomingRequests += nonce -> IncomingRequestState(true)

        // compare received tag with current, and update if needed
        val state = getState(key)
        if (state.tag.seq < tag.seq) {
          state.contents = set
          state.tag = tag
          repository += key -> state
        }
        sender ! WriteAck(key, nonce)

      }

    case WriteAck(key, nonce) =>

      if (!outgoingRequests.contains(nonce)) {

        // someone is sending a message nonce that we've supposedly sent, but we have no record, it's forged
        if (DEBUGGING_ENABLED) println(self.path.name + ": Invalid nonce received - Unknown.")

        context.actorSelection(supervisor) ! Suspect(sender, Utils.generateNonce) 

      } else if (outgoingRequests.contains(nonce) && outgoingRequests.get(nonce).get.expired) {

        // someone is sending a message nonce that we've sent, but it's expired, possible replay
        // NOTE: it can also be a replica that came too late for the quorum
        if (DEBUGGING_ENABLED) println(self.path.name + ": Invalid nonce received - Expired at WriteAck."
          + "\nPlease note that this can be a late response to a quorum.")

      } else {

        var req = outgoingRequests.get(nonce).get
        // wait for quorum
        req.writeQuorum += sender
        outgoingRequests += nonce -> req

        if (req.writeQuorum.size >= BYZ_QUORUM_SIZE) {

          // reached quorum
          req.writeQuorum = Set()
          req.expired = true
          outgoingRequests += nonce -> req

          // respond to the proxy challenge nonce by generating one with the specified increment
          val challengeNonce = req.clientNonce + NONCE_INCREMENT

          // end bft abd
          req.clientCall match {

            case IRead(key) =>
              val signature = Utils.generateProxySignature(PROXY_MAC_SECRET_KEY, key, req.setToRead, challengeNonce, PROXY_MAC_DIGEST)
              req.clientRef ! Envelope(IReadReply(key, req.setToRead), challengeNonce, signature)

            case IWrite(key, set) =>
              val signature = Utils.generateProxySignature(PROXY_MAC_SECRET_KEY, key, challengeNonce, PROXY_MAC_DIGEST)
              req.clientRef ! Envelope(IWriteReply(key), challengeNonce, signature)

          }
        }
      }

    case Read(key, nonce) =>

      if (incomingRequests.contains(nonce)) {

        // someone is sending a message nonce that we've seen before, possible replay
        if (DEBUGGING_ENABLED) println(self.path.name + ": Invalid nonce received - Repeated.")

        context.actorSelection(supervisor) ! Suspect(sender, Utils.generateNonce) 

      } else {

        // register nonce
        incomingRequests += nonce -> new IncomingRequestState

        // get repository contents and sign them
        val state = getState(key)
        var newSignature = Utils.generateABDSignature(macKey.getEncoded, state.contents, state.tag, nonce, MAC_DIGEST)
        sender ! ReadReply(state.tag, key, state.contents, newSignature, nonce)

      }

    case ReadReply(tag, key, set, signature, nonce) =>

      if (!Utils.validateABDSignature(macKey.getEncoded, set, tag, nonce, signature, MAC_DIGEST)) {

        // someone tampered with message contents
        if (DEBUGGING_ENABLED) println(self.path.name + ": Invalid signature received.")
        
        context.actorSelection(supervisor) ! Suspect(sender, Utils.generateNonce) 

      } else if (!outgoingRequests.contains(nonce)) {

        // someone is sending a message nonce that we've never seen before, and it's supposed to be ours
        if (DEBUGGING_ENABLED) println(self.path.name + ": Invalid nonce received - Unknown.")
        
        context.actorSelection(supervisor) ! Suspect(sender, Utils.generateNonce) 

      } else if (outgoingRequests.contains(nonce) && outgoingRequests.get(nonce).get.expired) {

        // someone is sending a message nonce that's expired
        if (DEBUGGING_ENABLED) println(self.path.name + ": Invalid nonce received - Expired at ReadReply." 
            + "\nPlease note that this can be a late response to a quorum.")

      } else {

        var req = outgoingRequests get nonce get

        // wait for quorum
        req.readQuorum += ((tag, set, signature))
        outgoingRequests += nonce -> req

        if (req.readQuorum.size >= BYZ_QUORUM_SIZE) {

          // reached quorum

          // let seqmax = max{sn : <sn,id,sig> belonging to Q }
          val (maxTag, maxSet, maxSignature) = req.readQuorum.reduce((a, b) => {
            val (tag1, tag2) = (a._1.asInstanceOf[ABDTag], b._1.asInstanceOf[ABDTag])
            if (tag1.seq > tag2.seq) a else b
          })

          req.readQuorum = Set()
          req.setToRead = maxSet
          outgoingRequests += nonce -> req

          // write back
          val trusted = siblings.getTrusted
          for (sibling <- trusted) {
            context.actorSelection(sibling) ! Write(maxTag, key, maxSet, maxSignature, nonce)
          }
        }

      }
      

    // ------------------------------ BEHAVIOUR CHANGE MESSAGES ------------------------------------------------

    case Sleep(data, nonces) => 
      repository = data
      nonces foreach { nonce => 
        incomingRequests += nonce -> IncomingRequestState(true)
      } 
      if (FAULT_DETECTION_DEBUGGING) println("[ABD REPLICA] " + self.path.name + " going to sleep!")
      sender ! Complying()
      context.become(sentinent)
      
      
      
    // ONLY TO SIMULATE BYZANTINE BEHAVIOUR  
    case Compromise() => 
      context.become(byzantine)
  }

  // sentinent replica behaviour 
  def sentinent: Receive = {
    
    case Write(tag, key, set, signature, nonce) =>

      if (!Utils.validateABDSignature(macKey.getEncoded, set, tag, nonce, signature, MAC_DIGEST)) {

        // someone tampered with message contents
        if (DEBUGGING_ENABLED) println(self.path.name + ": Invalid signature received.")

      } else if (incomingRequests.contains(nonce)) {

        // someone is sending a message nonce that we've seen before, possible message replaying
        if (DEBUGGING_ENABLED) println(self.path.name + ": Invalid nonce received - Repeated.")

      } else {

        // register this nonce (also register it as expired just to be sure)
        incomingRequests += nonce -> IncomingRequestState(true)

        // compare received tag with current, and update if needed
        val state = getState(key)
        if (state.tag.seq < tag.seq) {
          state.contents = set
          state.tag = tag
          repository += key -> state
        }
      }
        
    case Awake() => 
      if (FAULT_DETECTION_DEBUGGING) println("[ABD REPLICA] " + self.path.name + " waking up!")
      sender ! State(repository, incomingRequests.keySet)
      context.become(healthy)      // transitions to normal ABD state
  }
  
  // compromised node behaviour
  def byzantine: Receive = {

    case Envelope(message, nonce, signature) =>
      // respond immediatly with random long
      sender ! IReadReply("2eikd094akldslcnu94342", None)

    case ReadTag(key, nonce) =>

      val garbageSet = DDSSet(List(1, "i am ", "trudy", null))
      // message replay with garbage content
      for (i <- 0 to 3) {
        sender ! TagReply(ABDTag(0, self.path.name), key, Some(garbageSet), Array[Byte](), nonce)
      }

    case TagReply(tag, key, set, signature, nonce) =>

      // generate garbage data to write on all the replicas
      val garbageTag = ABDTag(Random.nextInt, sender.path.name)
      val garbageSignature = Utils.generateABDSignature(macKey.getEncoded, None, garbageTag, nonce + 1, MAC_DIGEST)
      
      for (replica <- replicas) {
        context.actorSelection(replica) ! Write(garbageTag, key, None, garbageSignature, nonce + 1)
      }

    case Write(tag, key, set, signature, nonce) =>

      // send a protocol message
      sender ! WriteAck(key, nonce)

    case WriteAck(key, nonce) =>
      // don't do anything

    case Read(key, nonce) =>
            
      // generate garbage data to read
      val garbageTag = ABDTag(Random.nextInt, sender.path.name)
      val garbageSet = Some(DDSSet(List(",test,", 31, true)))
      sender ! ReadReply(garbageTag, key, garbageSet, "10010100110010".getBytes, nonce)

    case ReadReply(tag, key, set, signature, nonce) =>
      
      // generate garbage data to write on all the replicas
      val garbageTag = ABDTag(Random.nextInt, sender.path.name)
      val garbageSignature = Utils.generateABDSignature(macKey.getEncoded, None, garbageTag, nonce + 1, MAC_DIGEST)
      
      for (replica <- replicas) {
        context.actorSelection(replica) ! Write(garbageTag, key, None, garbageSignature, nonce + 1)
      }

  }

  def getState(key: String) = {
    // get the associated state to received key
    // if no state exists, create an empty one
    repository get key match {
      case Some(existingState) =>
        existingState

      case None =>
        val newState = ABDState(self)
        repository += key -> newState
        newState
    }
  }
}