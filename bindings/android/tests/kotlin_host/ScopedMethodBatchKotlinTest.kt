package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path
fun main(args:Array<String>){
 check(args.size==1)
 val dex=Files.readAllBytes(Path.of(args[0]))
 val q="""{"schema_version":1,"relation":"method_defs","scope":{"slots":["kotlin"]},"where":{"using_strings":{"all":[{"op":"exact","value":"code-use-q03"}]}}}""".toByteArray(Charsets.UTF_8)
 NativeEngine.openRawDex(dex,"kotlin").use { snapshot ->
  val result=ScopedMethodBatchQuery.execute(snapshot,arrayOf(q,q),0,0)
  val single=ScopedMethodQuery.execute(snapshot,q)
  check(result.size()==2 && result.get(0).queryId==single.query.queryId && result.get(0).candidateCount()==single.query.candidateCount())
  check(result.scope.inputSlotCount()==1 && result.scope.inputSlot(0)=="kotlin" && result.scope.sourceCount()==1)
 }
 println("PASS scoped method batch Kotlin JNI")
}
