package malicious

import akka.actor.Actor

import scala.util.Random
import akka.actor.PoisonPill

class Trudy(targetReplicas:List[String]) extends Actor {

  private val FAULT_DETECTION_DEBUGGING = context.system.settings.config.getBoolean("fault-detection-debugging")
  
  def receive = {

    case Trigger(attack) =>
      
      if (attack.equals(MaliciousAttack.Crash)) {

        // shut down the replicas
        for (replica <- targetReplicas) {
          Thread.sleep(500)
          if (FAULT_DETECTION_DEBUGGING) println("[TRUDY] Crashing replica " + replica + "!")
          context.actorSelection(replica) ! PoisonPill
        }
      } else if (attack.equals(MaliciousAttack.Byzantine)) {
        
        // trigger byzantine behaviour
        for (replica <- targetReplicas) {
          if (FAULT_DETECTION_DEBUGGING) println("[TRUDY] Corrupting replica " + replica + "!")
          Thread.sleep(500)      
          context.actorSelection(replica) ! Compromise()
        }
      }

  }

}