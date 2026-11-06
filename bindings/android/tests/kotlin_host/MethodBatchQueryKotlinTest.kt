package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path
fun main(args:Array<String>){
 check(args.size==1);val dex=Files.readAllBytes(Path.of(args[0]))
 val q="""{"schema_version":1,"relation":"method_defs","where":{"using_strings":{"all":[{"op":"exact","value":"code-use-q03"}]}}}""".toByteArray(Charsets.UTF_8)
 NativeEngine.openRawDex(dex,"kotlin").use { snapshot ->
  val result=MethodBatchQuery.execute(snapshot,arrayOf(q,q),0,0)
  check(result.size()==2 && result.get(0).queryId==result.get(1).queryId && result.get(0).candidateCount()==1)
 }
 println("PASS method batch Kotlin-to-Java JNI")
}
