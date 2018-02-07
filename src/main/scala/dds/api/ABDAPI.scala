package dds.api

import dds.core.models.{ DDSSet, ABDState, ABDTag }

// BFT ABD message exchange protocol definition

/** 
 *  Invocation:	ReadTag
 *  Return: 		ReplyTag
 */  
case class ReadTag(key:String, nonce:Long)
 
case class TagReply(tag:ABDTag, key:String, value:Option[DDSSet], signature:Array[Byte], nonce:Long)

/** 
 *  Invocation:	Write
 *  Return:   if valid(newsig,<new-tag, new-val>) new-tag	>	tag-i then
 *  							tag-i =	new-tag
 *								val-i =	new-val
 *								sig-i =	new-sig
 * 						AckWrite
 */  
case class Write(tag:ABDTag, key:String, value:Option[DDSSet], signature:Array[Byte], nonce:Long)

case class WriteAck(key:String, nonce:Long)

/**
 * Invocation: Read
 * Return: 		 ReplyRead
 */
case class Read(key:String, nonce:Long)

case class ReadReply(tag:ABDTag, key:String, value:Option[DDSSet], signature:Array[Byte], nonce:Long)

