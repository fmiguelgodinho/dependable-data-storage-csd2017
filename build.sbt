name := "dependable-storage-system"

version := "1.0"

scalaVersion := "2.11.8"

val akkaVersion = "2.4.17"
val akkaHttpVersion = "10.0.0"
val akkaSslConfigVersion = "0.2.1"
val sprayVersion = "1.3.2"
val sprayJsonVersion = "1.3.1"

libraryDependencies ++= Seq(
  "com.typesafe.akka" %% "akka-actor" 			% akkaVersion,
  "com.typesafe.akka" %% "akka-remote" 			% akkaVersion,
  "com.typesafe.akka" %% "akka-http" 			% akkaHttpVersion,
  "com.typesafe.akka" %% "akka-http-spray-json" % akkaHttpVersion,
  "com.typesafe" 	  %% "ssl-config-akka" 		% akkaSslConfigVersion,
  "io.spray"          %% "spray-can"      		% sprayVersion,
  "io.spray"          %% "spray-routing"  		% sprayVersion,
  "io.spray"          %% "spray-client"   		% sprayVersion,
  "io.spray"          %% "spray-json"     		% sprayJsonVersion
)

resolvers ++= Seq(
	"Akka Snapshot Repository" at "http://repo.akka.io/snapshots/",
	"spray" at "http://repo.spray.io/"
)
