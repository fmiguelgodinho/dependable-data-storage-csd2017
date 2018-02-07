package malicious

import akka.ConfigurationException


// type of attacks to induce
object MaliciousAttack extends Enumeration       {
    
    type AttackType = Value
    val 
        // causes replicas to crash
        Crash, 
        
        // byzantine attacks that make a replica misbehave (sending arbitrary data, omitting responses, 
        // responding with incorrect protocol messages, message replaying)
        Byzantine
       
        = Value
        
    def getAttackType(name:String) : MaliciousAttack.Value = {
      if (name equals "crash")
        Crash
      else if (name equals "byzantine")
        Byzantine
      // defaults to crash if user input is misconstructed
      else Crash
    }
}

// message that requests a malicious actor to attack
case class Trigger(attack:MaliciousAttack.Value)

// backdoor for testing purposes
case class Compromise()
