package dds.http

import akka.http.scaladsl.marshallers.sprayjson.SprayJsonSupport
import spray.json._
import dds.core.models.DDSSet

final case class DDSItem(value:Any)
final case class DDSItemTriplet(value1:Any, value2:Any, value3:Any)
final case class DDSValueResult(result:Any)
final case class DDSKeysResult(keyset:List[String])

trait DDSJsonProtocol extends SprayJsonSupport with DefaultJsonProtocol {

  implicit object AnyJsonFormat extends JsonFormat[Any] {
    def write(x: Any) = x match {
      case n: Int => JsNumber(n)
      case s: String => JsString(s)
      case b: Boolean if b == true => JsTrue
      case b: Boolean if b == false => JsFalse
      case None => JsNull
    }
    def read(value: JsValue) = value match {
      case JsNumber(n) => n.intValue()
      case JsString(s) => s
      case JsTrue => true
      case JsFalse => false
      case JsNull => None
    }
  }
  
  implicit val DDSSetFormat = jsonFormat1(DDSSet)
  implicit val DDSItemFormat = jsonFormat1(DDSItem)
  implicit val DDSItemTripletFormat = jsonFormat3(DDSItemTriplet)
  implicit val DDSValueResultFormat = jsonFormat1(DDSValueResult)
  implicit val DDSKeysResultFormat = jsonFormat1(DDSKeysResult)
}
