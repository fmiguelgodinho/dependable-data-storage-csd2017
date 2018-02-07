package dds.api

import dds.core.models.DDSSet

case class Envelope(apiCall:Any, nonce:Long, signature:Array[Byte])

// Intermediate API between client calls and ABT internal API
case class IRead(key:String)

case class IWrite(key:String, set:Option[DDSSet])

case class IReadReply(key:String, set:Option[DDSSet])

case class IWriteReply(key:String)