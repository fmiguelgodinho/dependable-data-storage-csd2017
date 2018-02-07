package utils

import hlib.hj.mlib.RandomKeyIv
import hlib.hj.mlib.HomoOpeInt
import java.security.KeyPair
import hlib.hj.mlib.HomoRand
import hlib.hj.mlib.HomoAdd
import hlib.hj.mlib.HomoSearch
import hlib.hj.mlib.HomoDet
import hlib.hj.mlib.PaillierKey
import javax.crypto.SecretKey
import hlib.hj.mlib.HomoMult
import java.security.interfaces.RSAPublicKey
import java.security.interfaces.RSAPrivateKey
import java.math.BigInteger
import scala.util.Random

trait SJHomoLibProvider {
  
  // Homomorphic encryption keys --------------------------------------------------------------------------------------------------------
  
  var OPEKey    : Option[Long]        = None
  var CHEKey    : Option[SecretKey]   = None
  var LSEKey    : Option[SecretKey]   = None
  var PSSEKey   : Option[PaillierKey] = None
  var MSEKey    : Option[KeyPair]     = None
  var NoneKeyIv : Option[RandomKeyIv] = None
  
  
  // Homomorphic encryption functions ---------------------------------------------------------------------------------------------------
  
  // generate keys from scratch
  def generateKeys = {
      OPEKey = Some(new HomoOpeInt().generateKey(Random.nextString(Random.nextInt)))
      CHEKey = Some(HomoDet.generateKey)
      LSEKey = Some(HomoSearch.generateKey)
      PSSEKey = Some(HomoAdd.generateKey)
      MSEKey = Some(HomoMult.generateKey)
      NoneKeyIv = Some(HomoRand.generateKeyIv)
  }
  
  // load encryptions keys from existing serialized source
  def loadKeys(homomorphicKeys:java.util.Map[String, Object]) = {
      OPEKey = Some(new HomoOpeInt().generateKey(homomorphicKeys.get("OPE").asInstanceOf[String]))
      CHEKey = Some(HomoDet.keyFromString(homomorphicKeys.get("CHE").asInstanceOf[String]))
      LSEKey = Some(HomoSearch.keyFromString(homomorphicKeys.get("LSE").asInstanceOf[String]))
      PSSEKey = Some(HomoAdd.keyFromString(homomorphicKeys.get("PSSE").asInstanceOf[String]))
      MSEKey = Some(HomoMult.keyFromString(homomorphicKeys.get("MSE").asInstanceOf[String]))
      NoneKeyIv = Some(HomoRand.keyIvFromString(homomorphicKeys.get("None").asInstanceOf[String]))
  }
  
  // encrypt homomorphically
  def encrypt(data: Any, encriptType: String) = encriptType match {
      // encrypted output has to be prepended and appended with quotes due to conflicting java and scala types
      case "OPE"  => new HomoOpeInt(OPEKey.get).encrypt(data.asInstanceOf[Int])
      case "LSE"  => HomoSearch.encrypt(LSEKey.get, data.asInstanceOf[String])
      case "CHE"  => HomoDet.encrypt(CHEKey.get, data.asInstanceOf[String])
      case "PSSE" => HomoAdd.encrypt(new BigInteger(data.asInstanceOf[Int].toString), PSSEKey.get)
      case "MSE"  => HomoMult.encrypt(MSEKey.get.getPublic.asInstanceOf[RSAPublicKey], new BigInteger(data.asInstanceOf[Int].toString))
      case "None" => HomoRand.encrypt(NoneKeyIv.get.getKey, NoneKeyIv.get.getiV, data.asInstanceOf[String])
  }
  
  // decrypt homomorphically
  def decrypt(data: Any, encriptType: String) = encriptType match {
      case "OPE"  => new HomoOpeInt(OPEKey.get).decrypt(data.asInstanceOf[Long])
      case "LSE"  => HomoSearch.decrypt(LSEKey.get, data.asInstanceOf[String])
      case "CHE"  => HomoDet.decrypt(CHEKey.get, data.asInstanceOf[String])
      case "PSSE" => HomoAdd.decrypt(data.asInstanceOf[BigInteger], PSSEKey.get)
      case "MSE"  => HomoMult.decrypt(MSEKey.get.getPrivate.asInstanceOf[RSAPrivateKey], data.asInstanceOf[BigInteger])
      case "None" => HomoRand.decrypt(NoneKeyIv.get.getKey, NoneKeyIv.get.getiV, data.asInstanceOf[String])
  }
  
  // fully encrypt a set
  def encryptFully(plainSet: List[Any], until:Int, homomorphicColumns:List[String]) = {
    var encryptedSet = List[Any]()
    for (i <- 0 to math.min(until-1, plainSet.length-1)) {
      encryptedSet ::= encrypt(plainSet(i), homomorphicColumns(i))
    }
    // encrypt variable part
    if (plainSet.length > until) {
      for (i <- until to plainSet.length) {
        encryptedSet ::= encrypt(plainSet(i), "None")
      }
    }
    encryptedSet.reverse
  }
  
  // fully decrypt a set
  def decryptFully(encryptedSet: List[Any], until:Int, homomorphicColumns:List[String]) = {
    var decryptedSet = List[Any]()
    for (i <- 0 to math.min(until-1, encryptedSet.length-1)) {
      decryptedSet ::= decrypt(encryptedSet(i), homomorphicColumns(i))
    }
    // decrypt variable part
    if (encryptedSet.length > until) {
      for (i <- until to encryptedSet.length) {
        decryptedSet ::= decrypt(encryptedSet(i), "None")
      }
    }
    decryptedSet.reverse
  }
}