package dds.api

import akka.actor.ActorRef
import dds.core.models.ABDState

// used by replicas to trigger a quorum over a suspicious byzantine replica
case class Suspect(replica:ActorRef, nonce:Long)

// used to convert a sentinent replica into an active replicas, i.e. waking it up
case class Awake()

// response to the previous message, used to get state from sentinent replicas
case class State(data:Map[String, ABDState], nonces:Set[Long])

// used to transfer state from sentinent replicas to newly restarted active ones
case class Sleep(data:Map[String, ABDState], nonces:Set[Long])

// used after the previous message to signal that the replica is alive and is going 
// to comply with the sleep order, waiting to be awaken when needed
case class Complying()

// used by the proxy to request a set of active replicas
case class RequestReplicas()

// response from the supervisor to the previous request
case class ActiveReplicas(replicas:List[String])
