package utils

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import dds.core.models.ABDTag
import java.security.SecureRandom
import dds.core.models.DDSSet
import java.util.Base64
import javax.xml.bind.DatatypeConverter

object Utils {
  
  // generates sha512key for server to use when dealing with a set
  def getKeyFromSet(set:DDSSet, digest:String) = {
          val md = MessageDigest.getInstance(digest)
          DatatypeConverter.printHexBinary(md.digest(set.toString.getBytes))
  }
  
  // generates random sha512key for server to use
  def getKeyRandomly(digest:String) = {
          val md = MessageDigest.getInstance(digest)
          val buf = Array.ofDim[Byte](100)
          (new SecureRandom).nextBytes(buf)
          DatatypeConverter.printHexBinary(md.digest(buf))
  }
  
  // allows to generate nonces using a secure random
  def generateNonce = new SecureRandom nextLong
  
  // allows to generate HMAC signatures, used in intranet in ABD nodes
  def generateABDSignature(secret:Array[Byte], value:Object, tag:ABDTag, nonce:Long, digest:String) = {
          var macBytes = (value.toString() + (tag.seq + 1).toString() + tag.id.toString() + nonce).getBytes
          generateSignature(secret, macBytes, digest)
  }
  def validateABDSignature(secret:Array[Byte], value:Object, tag:ABDTag, rnonce:Long, givenHmac:Array[Byte], digest:String) = {
         val generatedHmac = generateABDSignature(secret, value, tag, rnonce, digest)
         MessageDigest.isEqual(generatedHmac, givenHmac)
  }
  
  // allows to generate HMAC signatures, used between ABD nodes and the REST proxy
  def generateProxySignature(secret:String, key:String, nonce:Long, digest:String) = {
          var macBytes = (key + nonce.toString()).getBytes
          generateSignature(secret.getBytes, macBytes, digest)
  }
  def generateProxySignature(secret:String, key:String, value:Object, nonce:Long, digest:String) = {
          var macBytes = (key + value.toString() + nonce).getBytes
          generateSignature(secret.getBytes, macBytes, digest)
  }
  def validateProxySignature(secret:String, key:String, nonce:Long, givenHmac:Array[Byte], digest:String) = {
         val generatedHmac = generateProxySignature(secret, key, nonce, digest)
         MessageDigest.isEqual(generatedHmac, givenHmac)
  }
  def validateProxySignature(secret:String, key:String, value:Object, nonce:Long, givenHmac:Array[Byte], digest:String) = {
         val generatedHmac = generateProxySignature(secret, key, value, nonce, digest)
         MessageDigest.isEqual(generatedHmac, givenHmac)
  }
  
  // private aux fns
  private def generateSignature(secret:Array[Byte], content:Array[Byte], digest:String) = {
         val secretKey = new SecretKeySpec(secret, digest)
         var mac = Mac.getInstance(digest)
         mac.init(secretKey)
         mac.doFinal(content)
  }
  
  
}