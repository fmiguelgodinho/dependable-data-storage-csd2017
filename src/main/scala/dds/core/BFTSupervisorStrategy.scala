package dds.core

import akka.actor.{ OneForOneStrategy, SupervisorStrategy, SupervisorStrategyConfigurator }
import akka.actor.SupervisorStrategy.Restart
import akka.actor.ActorKilledException

class BFTSupervisorStrategy extends SupervisorStrategyConfigurator {
  def create = OneForOneStrategy() {
    case _ : ActorKilledException => Restart
  }
}