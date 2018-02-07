package dds.core.models

import akka.actor.ActorRef

case class ABDState(self:ActorRef) {
  
  var contents  : Option[DDSSet]    = None                            // the actual big-table set
  var tag       : ABDTag            = ABDTag(0, self.path.name)
  
}