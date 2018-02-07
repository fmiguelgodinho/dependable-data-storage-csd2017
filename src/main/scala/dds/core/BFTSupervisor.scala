package dds.core

import akka.actor.Actor
import akka.actor.ActorRef
import dds.api.Suspect
import scala.collection.immutable.HashSet
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration._
import akka.actor.PoisonPill
import com.typesafe.config.Config
import scala.util.Random
import dds.api.Awake
import dds.api.Sleep
import akka.actor.Kill
import akka.util.Timeout
import scala.concurrent.Future
import scala.concurrent.duration._
import akka.pattern.ask
import dds.api.State
import dds.api.RequestReplicas
import dds.api.ActiveReplicas
import shapeless.Succ
import dds.api.Complying
import akka.actor.Deploy
import akka.actor.Props
import akka.remote.RemoteScope
import akka.actor.Address
import akka.actor.AddressFromURIString
import akka.pattern.AskTimeoutException

class BFTSupervisor(replicas: List[Config]) extends Actor {

  private val SUPERVISOR_ENDPOINT = context.system.settings.config.getString("replicas.supervisor.endpoint")
  private val FAULT_DETECTION_DEBUGGING = context.system.settings.config.getBoolean("fault-detection-debugging")
  private val LOCAL_HOSTNAME = context.system.settings.config.getString("akka.remote.netty.ssl.hostname")
  private val LOCAL_PORT = context.system.settings.config.getString("akka.remote.netty.ssl.port")
  private val BYZ_QUORUM_SIZE = context.system.settings.config.getInt("replicas.security.byz-quorum-size")
  private val PROACTIVE_RECOVERY_WARM_UP = context.system.settings.config.getInt("replicas.security.proactive-recovery.warm-up")
  private val PROACTIVE_RECOVERY_INTERVAL = context.system.settings.config.getInt("replicas.security.proactive-recovery.interval")
  private val SENTINENT_AWAKE_TIMEOUT = context.system.settings.config.getInt("replicas.security.sentinent-awake-timeout")
  private val CRASHED_RECOVERY_TIMEOUT = context.system.settings.config.getInt("replicas.security.crashed-recovery-timeout")  
 
  // sentinent and active replicas
  private var activeReplicas = replicas filter { r => !r.getBoolean("sentinent") } map { r => (r.getString("endpoint"), System.nanoTime) }
  private var sentinentReplicas = replicas filter { r => r.getBoolean("sentinent") } map { r => r.getString("endpoint") }

  // registered nonces
  private var nonces = HashSet[Long]()
  // quorums over ABD replicas
  private var quorum = Map[String, Set[String]]()

  override def preStart = {
    // proactive recovery mechanism
    context.system.scheduler.schedule(PROACTIVE_RECOVERY_WARM_UP seconds, PROACTIVE_RECOVERY_INTERVAL seconds) {
      // get the oldest running replica to restart
      val (endpoint, _) = activeReplicas.reduce((r1, r2) => {
        if (r1._2 < r2._2) r1 else r2
      })
      recover(endpoint)
      
      if (FAULT_DETECTION_DEBUGGING) println("[SUPERVISOR] Replica " + endpoint + " is being proactively recovered.")
    }
  }

  def receive = {
    
    case RequestReplicas() =>
      // get the freshest replicas, with the least chances of being restarted
      val newestReplicas = activeReplicas.sortWith(_._2 > _._2).splitAt(activeReplicas.length/2)._1
      sender ! ActiveReplicas(newestReplicas map { r => r._1 })

    case Suspect(replica, nonce) =>

      if (!(nonces contains nonce)) {
        // register nonce for future checking
        nonces += nonce
        val endpoint = parseEndpoint(replica)
       
        quorum get endpoint match {
          case None =>
            quorum += endpoint -> Set[String](parseEndpoint(replica))
          case Some(voters) =>
            val updatedVoters = voters + parseEndpoint(sender)
            quorum += endpoint -> updatedVoters

            // check if we've reached a quorum
            if (updatedVoters.size >= BYZ_QUORUM_SIZE) {
              if (FAULT_DETECTION_DEBUGGING) println("[SUPERVISOR] Replica " + endpoint + " is suspected of being faulty. Recovering...")
              recover(endpoint)
            }
        }
      }
  }

  // TODO: 4. Proactive recovery - restart older replicas

  def recover(byzantine: String) = {
    
    if (sentinentReplicas nonEmpty) {
  
      // awake a sentinent replica
      val sleepingBeauty = sentinentReplicas(Random.nextInt(sentinentReplicas length))
      
      implicit val timeout = Timeout(SENTINENT_AWAKE_TIMEOUT milliseconds)
      val future = context.actorSelection(sleepingBeauty) ? Awake()
  
      future onSuccess {
        case State(data, nonces) =>
          
          // switch the sentinent replica to the active list
          sentinentReplicas = sentinentReplicas.filterNot { r => r equals sleepingBeauty }
          activeReplicas ::= (sleepingBeauty, System.nanoTime)
          
          // kill (and restart) the misbehaving replica
          context.actorSelection(byzantine) ! Kill
          activeReplicas = activeReplicas.filterNot { r => r._1 equals byzantine }
  
          // put the restarted replica in dormant state
          val compliance = context.actorSelection(byzantine) ? Sleep(data, nonces)
          
          compliance onSuccess {
              case Complying() => 
                // switch restarted replica to sentinent list
                sentinentReplicas ::= byzantine
        
                // clear quorum since replica is now healthy
                quorum += byzantine -> Set()
          }
          
          compliance onFailure {
              // the replica was dead and was unable to restart
              case _ : AskTimeoutException => 
                // recreate the replica remotely
                val remoteAddress = AddressFromURIString(byzantine.substring(0, byzantine.indexOf("/user")))
                val rebooted = context.system.actorOf(BFTABDNode.props(replicas map { r => r.getString("endpoint") }, SUPERVISOR_ENDPOINT)
                    .withDeploy(Deploy(scope = RemoteScope(remoteAddress))), byzantine.split("/").last
                )
                
                if (FAULT_DETECTION_DEBUGGING) println("[SUPERVISOR] Replica " + byzantine + " is crashed! Rebooting replica...")
                
                // fire the dormant triger again and switch the replica to the sentinent list
                // the timeout here is usually bigger because the node itself had to be completely rebooted
                implicit val timeout = Timeout(CRASHED_RECOVERY_TIMEOUT milliseconds)
                context.actorSelection(rebooted.path) ! Sleep(data, nonces)
                sentinentReplicas ::= parseEndpoint(rebooted)
      
                // clear quorum since replica is now healthy
                quorum += byzantine -> Set()
          }
      }
    }

  }

  // parses replica's actor ref into their string address representation
  def parseEndpoint(replica: ActorRef) =
    if (replica.path.address.host.nonEmpty) replica.path.toString
    else "akka.ssl.tcp://" + replica.path.address.system + "@" + LOCAL_HOSTNAME + ":" + LOCAL_PORT + "/user/" + replica.path.name

}