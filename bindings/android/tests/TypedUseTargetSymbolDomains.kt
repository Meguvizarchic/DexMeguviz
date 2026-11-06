package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
fun main(args: Array<String>) {
 check(args.size==4)
 val field=Files.readAllBytes(Path.of(args[0]));val string=Files.readAllBytes(Path.of(args[1]));val poly=Files.readAllBytes(Path.of(args[2]));val output=Path.of(args[3])
 val cases=listOf(
  Triple("field_ref",field,UseSymbolTarget.FIELD_REFERENCE),Triple("field_def",field,UseSymbolTarget.FIELD_DEFINITION),
  Triple("string",string,UseSymbolTarget.STRING_VALUE),Triple("poly",poly,UseSymbolTarget.METHOD_REFERENCE))
 for((label,bytes,target) in cases) {
  NativeEngine.openRawDexSet(arrayOf(bytes,bytes),arrayOf("one","two")).use { snapshot ->
   for(direction in UseSymbolDirection.entries) {
    val condition=if(label=="poly") UseEventPredicate.targetDomain(UseEventTargetDomain.METHOD_AND_PROTO) else UseEventPredicate.constant(true)
    val q=UseTargetSymbolQuery(target,useWhere=condition,direction=direction,maxResults=100)
    val name=label+if(direction==UseSymbolDirection.USE_FIRST) "_forward" else "_reverse"
    Files.writeString(output.resolve("$name.query.json"),q.toQueryIrJson(),StandardOpenOption.CREATE_NEW)
    val result=TypedUseTargetSymbolExecution.execute(snapshot,q)
    check(result.queryId.startsWith("query:v16:")&&!result.profile.scopeComplete)
    val expected=if(label=="poly") 4 else 8
    check(result.rowCount()==expected){"$name ${result.rowCount()} != $expected"}
    repeat(result.rowCount()){i->check(result.row(i).linkCount()==1&&result.row(i).link(0).key==6L)}
    println("CASE $name ${result.queryId} ${result.rowCount()}")
   }
  }
 }
 println("PASS typed v16 field, string and polymorphic source set")
}
