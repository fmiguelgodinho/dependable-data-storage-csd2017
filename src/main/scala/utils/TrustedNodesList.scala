package utils

import scala.util.Random

class TrustedNodesList(nodes:List[String] = List()) {
  
  // register of all replicas
  private var trustedNodes = Map[String, Int]()
  // fill register with provided list
  for (node <- nodes)
    trustedNodes += node -> 0
  
  // increments suspicion on a replica
  def incrementSuspicion(replica:String) = {
    if (trustedNodes.contains(replica)) {
      val strikes = trustedNodes.get(replica).get
      trustedNodes += replica -> (strikes + 1)
    } else {
      trustedNodes += replica -> 1
    }
  }

  def getUntrusted = {
    trustedNodes.filter(node => node._2 >= 3).keySet.toList
  }
  
  def getTrusted = {
    trustedNodes.filter(node => node._2 < 3).keySet.toList
  }
  
  def getAll = {
    trustedNodes.keySet.toList
  }
   
   // random loading balancing function between trusted nodes
  def deferTo = {
    val listOfNodes = getTrusted.toList
    listOfNodes(Random nextInt( listOfNodes size ))
  }
}