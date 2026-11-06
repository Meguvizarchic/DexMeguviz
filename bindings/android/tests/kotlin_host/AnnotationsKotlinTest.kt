package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path

fun main(args:Array<String>){
 val dex=Files.readAllBytes(Path.of(args[0]));val limits=Annotations.Limits(256,1000000,100000,0)
 NativeEngine.openRawDex(dex,"one").use { snapshot ->
  val result=AnnotationExecution.inspect(snapshot,Annotations.Target.classType(2),limits)
  check(result.itemCount()==2 && result.item(0).element(2).valueKind==0x1dL && result.item(0).element(2).encodedValue().size>1)
 }
 NativeEngine.openRawDexSet(arrayOf(dex,dex),arrayOf("a","b")).use { snapshot ->
  val result=AnnotationExecution.inspect(snapshot,1,Annotations.Target.parameter(2,0),limits)
  check(result.sourceIndex==1L && result.itemCount()==1)
 }
 println("PASS Kotlin annotation target and both snapshot overloads")
}
