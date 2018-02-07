package dds.core.models

import akka.actor.ActorRef


class OutgoingRequestState(_clientRef:ActorRef, _clientCall:Any, _clientNonce:Long) {
  
  var expired      : Boolean            = false
  
  var clientRef    : ActorRef           = _clientRef
  var clientCall   : Any                = _clientCall
  var clientNonce  : Long               = _clientNonce
  
  var readQuorum    = Set[(ABDTag, Option[DDSSet], Array[Byte])]()
  var writeQuorum   = Set[ActorRef]()
  
  var setToRead        : Option[DDSSet] = None
  var setToWrite       : Option[DDSSet] = None
  
  
}