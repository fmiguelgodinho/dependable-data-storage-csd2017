package clt

import scala.collection.mutable.Queue

case class Digest(payload:Queue[Any])


// basic API -----------------------------------------------  
  
case class PutSet(set:Option[List[Any]])

case class GetSet()

case class AddElement(elem:Any)     

case class RemoveSet()

case class WriteElem(elem:Any, pos:Int)

case class ReadElem(pos:Int)

case class IsElement(elem:Any)
  

  
// extended API  -------------------------------------------
  
case class Sum(pos:Int)

case class SumAll(pos:Int)

case class Mult(pos:Int)

case class MultAll(pos:Int)

case class SearchEq(pos:Int, elem:Any)

case class SearchNEq(pos:Int, elem:Any)

case class SearchGt(pos:Int, elem:Any)

case class SearchGtEq(pos:Int, elem:Any)

case class SearchLt(pos:Int, elem:Any)
 
case class SearchLtEq(pos:Int, elem:Any)

case class SearchEntry(elem:Any)

case class SearchEntryOR(elem1:Any, elem2:Any, elem3:Any)

case class SearchEntryAND(elem1:Any, elem2:Any, elem3:Any)

case class OrderLS(pos:Int)

case class OrderSL(pos:Int)
