package clt

import scala.util.Random
import scala.collection.immutable.List
import scala.collection.mutable.ArrayBuffer
import scala.collection.mutable.Queue
import java.util.Base64
import javax.xml.bind.DatatypeConverter

// This class allows to preserve the following the following key-set structure during client http requests,
// 
//    key -> (v1, v2, v3, v4, v5, v6, v7, v8)
//
//    Parameter      Type      Homomorphic encryption           Implemented by      Operations supported
// --------------------------------------------------------------------------------------------------------------------------------------------------------------
//    v1             Int       Order Preserved                  HomoOpeInt          OrderLS/OrderSL/SearchEq/SearchNEq/SearchGt/SearchGtEq/SearchLt/SearchLtEq
//    v2             String    Linear Searchable                HomoSearch          SearchEntry/SearchEntryAND/SearchEntryOR              
//    v3             Int       Paillier Sum Supported           HomoAdd             Sum/SumAll
//    v4             Int       Multiplication Supported         HomoMult            Mult/MultAll
//    v5             String    Linear Searchable                HomoSearch          SearchEntry/SearchEntryAND/SearchEntryOR
//    v6             String    Linear Searchable                HomoSearch          SearchEntry/SearchEntryAND/SearchEntryOR
//    v7             Int       Comparative Homomorphic          HomoDet             IsElement/SearchEq/SearchNEq
//    v8             Blob      -                                HomoRand            -

object DDSDataGenerator {
  
  val ALLOWED_DATA_TYPES = Array("String", "Char", "Int", "Long", "Float", "Double", "Boolean", "Blob")
  
  private var _payload: Queue[Any] = Queue.empty

  def generate(nrofoperations: Int, proportions: Map[String, Double], maxnrofcolumns: Int, columnmappings: List[String], columnencryptions: List[String]) = {
    
    // empty queue
    _payload = Queue.empty
    
    // find all homomorphic operation supported columns
    var homomorphicColumns = Map[String, List[Int]](
      "OPE" -> List(), "CHE" -> List(), "LSE" -> List(), "PSSE" -> List(), "MSE" -> List(), "None" -> List()
    )
    for (j <- 0 to columnencryptions.length-1) {
      homomorphicColumns += columnencryptions(j) -> homomorphicColumns.get(columnencryptions(j)).get.::(j)
    }
    val opeColumns = homomorphicColumns.get("OPE").get
    val cheColumns = homomorphicColumns.get("CHE").get
    val lseColumns = homomorphicColumns.get("LSE").get
    val psseColumns = homomorphicColumns.get("PSSE").get
    val mseColumns = homomorphicColumns.get("MSE").get
    val noneColumns = homomorphicColumns.get("None").get

    val totalgetsetops = math.round(nrofoperations * proportions.get("get-set").getOrElse(0.0)) toInt
    val totalputsetops = math.round(nrofoperations * proportions.get("put-set").getOrElse(0.0)) toInt
    val totalremovesetops = math.round(nrofoperations * proportions.get("remove-set").getOrElse(0.0)) toInt
    val totaladdelementops = math.round(nrofoperations * proportions.get("add-element").getOrElse(0.0)) toInt
    val totalwriteelementops = math.round(nrofoperations * proportions.get("write-element").getOrElse(0.0)) toInt
    val totalreadelementops = math.round(nrofoperations * proportions.get("read-element").getOrElse(0.0)) toInt
    val totaliselementops = math.round(nrofoperations * proportions.get("is-element").getOrElse(0.0)) toInt
    val totalsumops = math.round(nrofoperations * proportions.get("sum").getOrElse(0.0)) toInt
    val totalsumallops = math.round(nrofoperations * proportions.get("sum-all").getOrElse(0.0)) toInt
    val totalmultops = math.round(nrofoperations * proportions.get("mult").getOrElse(0.0)) toInt
    val totalmultallops = math.round(nrofoperations * proportions.get("mult-all").getOrElse(0.0)) toInt
    val totalsearcheqops = math.round(nrofoperations * proportions.get("search-eq").getOrElse(0.0)) toInt
    val totalsearchneqops = math.round(nrofoperations * proportions.get("search-neq").getOrElse(0.0)) toInt
    val totalsearchgtops = math.round(nrofoperations * proportions.get("search-gt").getOrElse(0.0)) toInt
    val totalsearchgteqops = math.round(nrofoperations * proportions.get("search-gteq").getOrElse(0.0)) toInt
    val totalsearchltops = math.round(nrofoperations * proportions.get("search-lt").getOrElse(0.0)) toInt
    val totalsearchlteqops = math.round(nrofoperations * proportions.get("search-lteq").getOrElse(0.0)) toInt
    val totalorderlsops = math.round(nrofoperations * proportions.get("order-ls").getOrElse(0.0)) toInt
    val totalorderslops = math.round(nrofoperations * proportions.get("order-sl").getOrElse(0.0)) toInt
    val totalsearchentryops = math.round(nrofoperations * proportions.get("search-entry").getOrElse(0.0)) toInt
    val totalsearchentryandops = math.round(nrofoperations * proportions.get("search-entry-and").getOrElse(0.0)) toInt
    val totalsearchentryorops = math.round(nrofoperations * proportions.get("search-entry-or").getOrElse(0.0)) toInt

    // enqueue getset ops
    for (i <- 1 to totalgetsetops) {
      _payload enqueue GetSet()
    }

    // enqueue putset ops
    for (i <- 1 to totalputsetops) {
      
      var set: Option[List[Any]] = None

      val diceroll = Random.nextInt(6)
      if (diceroll >= 1) {
        // init fixed size array
        val contents : ArrayBuffer[Any] = ArrayBuffer.fill[Any](columnmappings.length)(None)
        // fill with random content
        for (j <- 0 to columnmappings.length-1) {
          contents(j) = generateColumnData(columnmappings(j))
        }

        set = Some(contents.toList)
      }

      _payload enqueue PutSet(set)
    }

    // enqueue removeset ops
    for (i <- 1 to totalremovesetops) {
      _payload enqueue RemoveSet()
    }
    
    val randomizableDataTypes = List("String", "Char", "Blob")
    // enqueue addelement ops
    for (i <- 1 to totaladdelementops) {
      val ix = Random.nextInt(randomizableDataTypes.length)
      _payload enqueue AddElement(generateColumnData(randomizableDataTypes(ix)))
    }

    // enqueue writeelement ops
    for (i <- 1 to totalwriteelementops) {
      val position = Random.nextInt(maxnrofcolumns) // note: if > than the set length, server will add to the max pos
      val value = if (position >= columnmappings.length) {
                      val ix = Random.nextInt(randomizableDataTypes.length)
                      generateColumnData(randomizableDataTypes(ix))
                  } else {
                      generateColumnData(columnmappings(position))
                  }
      
      _payload enqueue WriteElem(value, position)
    }

    // enqueue readelement ops
    for (i <- 1 to totalreadelementops) {
      val position = Random.nextInt(maxnrofcolumns) // note: if > than the set length, server will read from the max pos
      _payload enqueue ReadElem(position)
    }
    
    // enqueue iselement ops
    for (i <- 1 to totaliselementops) {
      if (cheColumns.nonEmpty) {
        // only perform is element if there's a comparable field
        val comparableDataTypes = List("String", "Char", "Blob")
        val rndComparableDataType = comparableDataTypes(Random.nextInt(comparableDataTypes.length))
        _payload enqueue IsElement(generateColumnData(rndComparableDataType))
      }
    }
    
    if (psseColumns.nonEmpty) {
      
      // enqueue sum ops
      for (i <- 1 to totalsumops) {
        // get a random summable column position
        val position = psseColumns(Random.nextInt(psseColumns.length))
        _payload enqueue Sum(position)
      }
    
      // enqueue sumall ops
      for (i <- 1 to totalsumallops) {
        // get a random summable column position
        val position = psseColumns(Random.nextInt(psseColumns.length))
        _payload enqueue SumAll(position)
      }
    }
    
    if (mseColumns.nonEmpty) {
      
      // enqueue mult ops
      for (i <- 1 to totalsumallops) {
        
          // get a random multiplicable column position
          val position = mseColumns(Random.nextInt(mseColumns.length))
          _payload enqueue Mult(position)
      }
      
      // enqueue multall ops
      for (i <- 1 to totalsumallops) {
          // get a random multiplicable column position
          val position = mseColumns(Random.nextInt(mseColumns.length))
          _payload enqueue MultAll(position)
      }
    }
    
    if (opeColumns.nonEmpty) {
      // enqueue orderls ops
      for (i <- 1 to totalorderlsops) {
        // get a random orderable column position
        val position = opeColumns(Random.nextInt(opeColumns.length))
        _payload enqueue OrderLS(position)
      }
    
      // enqueue orderls ops
      for (i <- 1 to totalorderslops) {
        // get a random orderable column position
        val position = opeColumns(Random.nextInt(opeColumns.length))
        _payload enqueue OrderSL(position)
      }
      
      // enqueue searcheq ops
      for (i <- 1 to totalsearcheqops) {
        // get a random searchable order column position
        val position = opeColumns(Random.nextInt(opeColumns.length))
        _payload enqueue SearchEq(position, generateColumnData("Int"))
      }
      
      // enqueue searchneq ops
      for (i <- 1 to totalsearchneqops) {
        // get a random searchable order column position
        val position = opeColumns(Random.nextInt(opeColumns.length))
        _payload enqueue SearchNEq(position, generateColumnData("Int"))
      }
      
      // enqueue searchgt ops
      for (i <- 1 to totalsearchgtops) {
        // get a random searchable order column position
        val position = opeColumns(Random.nextInt(opeColumns.length))
        _payload enqueue SearchGt(position, generateColumnData("Int"))
      }
      
      // enqueue searchgteq ops
      for (i <- 1 to totalsearchgteqops) {
        // get a random searchable order column position
        val position = opeColumns(Random.nextInt(opeColumns.length))
        _payload enqueue SearchGtEq(position, generateColumnData("Int"))
      }
      
      // enqueue searchlt ops
      for (i <- 1 to totalsearchltops) {
        // get a random searchable order column position
        val position = opeColumns(Random.nextInt(opeColumns.length))
        _payload enqueue SearchLt(position, generateColumnData("Int"))
      }
      
      // enqueue searchlteq ops
      for (i <- 1 to totalsearchlteqops) {
        // get a random searchable order column position
        val position = opeColumns(Random.nextInt(opeColumns.length))
        _payload enqueue SearchLtEq(position, generateColumnData("Int"))
      }
    }
    
    if (cheColumns.nonEmpty) {
      
      val searchableDataTypes = List("String", "Char", "Blob")
      
      // enqueue searchentry ops
      for (i <- 1 to totalsearchentryops) {
        val rndSearchableDataType = searchableDataTypes(Random.nextInt(searchableDataTypes.length))
        _payload enqueue SearchEntry(generateColumnData(rndSearchableDataType))
      }
      
      // enqueue searchentryand ops
      for (i <- 1 to totalsearchentryandops) {
        val rndSearchableDataType = searchableDataTypes(Random.nextInt(searchableDataTypes.length))
        _payload enqueue SearchEntryAND(
            generateColumnData(rndSearchableDataType), 
            generateColumnData(rndSearchableDataType),
            generateColumnData(rndSearchableDataType)
        )
      }
          
      // enqueue searchentryor ops
      for (i <- 1 to totalsearchentryops) {
        val rndSearchableDataType = searchableDataTypes(Random.nextInt(searchableDataTypes.length))
        _payload enqueue SearchEntryOR(
            generateColumnData(rndSearchableDataType), 
            generateColumnData(rndSearchableDataType),
            generateColumnData(rndSearchableDataType)
        )
      }
    }
    
    
    // finally, shuffle instructions in order to have random io
    _payload = Random.shuffle(_payload)

    // return itself
    _payload
  }
  
  def generateColumnData(dataType:String) = dataType match {
      case "String"   =>    Random.alphanumeric.take(10).mkString
      case "Char"     =>    Random.alphanumeric.take(1).mkString
      case "Int"      =>    Random.nextInt(10000)
      case "Long"     =>    Random.nextLong
      case "Float"    =>    Random.nextFloat
      case "Double"   =>    Random.nextDouble
      case "Boolean"  =>    Random.nextBoolean
      case "Blob"     =>    val buf = Array.ofDim[Byte](100)
                            Random.nextBytes(buf)
                            DatatypeConverter.printHexBinary(buf)
    }
  
}