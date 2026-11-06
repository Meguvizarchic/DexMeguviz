package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path

fun main(args:Array<String>) {
 val dex=Files.readAllBytes(Path.of(args[0]));val selected=linkedSetOf(MethodFactsResult.Category.STRINGS,MethodFactsResult.Category.FIELDS)
 val request=MethodFactsRequest(selected,128,1000000,0);selected.clear();check(request.categories.size==2)
 NativeEngine.openRawDex(dex,"one").use { snapshot ->
  val facts=MethodFactsExecution.inspect(snapshot,3,request)
  check(facts.stringCount()==1&&facts.fieldCount()==1&&facts.availability(MethodFactsResult.Category.INVOKES)==MethodFactsResult.Availability.NOT_REQUESTED)
 }
 NativeEngine.openRawDexSet(arrayOf(dex,dex),arrayOf("a","b")).use { snapshot ->
  val facts=MethodFactsExecution.inspect(snapshot,1,3,request);check(facts.sourceIndex==1L&&facts.string(0).value=="used-string")
 }
 try{MethodFactsRequest(emptySet(),128,1000000,0);error("empty categories accepted")}catch(_:IllegalArgumentException){}
 println("PASS Kotlin generic method facts request and both snapshot overloads")
}
