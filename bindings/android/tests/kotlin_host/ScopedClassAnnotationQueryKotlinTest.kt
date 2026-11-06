package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path
fun main(args:Array<String>) {
 check(args.size == 1)
 val dex=Files.readAllBytes(Path.of(args[0]))
 val q="""{"schema_version":1,"relation":"class_defs","required_capabilities":["class_annotation_static"],"scope":{"slots":["kotlin"]},"where":{"annotation":{"type":"Lfixture/Complex;","element":{"name":"n","int":-7}}}}""".toByteArray(Charsets.UTF_8)
 NativeEngine.openRawDex(dex,"kotlin").use { snapshot ->
  val r=ScopedClassAnnotationQuery.execute(snapshot,q)
  check(r.query.queryId.startsWith("query:v24:") && r.query.candidateCount()==1 && r.query.unknownRows==0L)
  check(r.scope.inputSlotCount()==1 && r.scope.inputSlot(0)=="kotlin" && r.scope.sourceIndex(0)==0 && !r.scope.sourceScopeAuthenticated)
 }
 println("PASS scoped v24 class annotation Kotlin-to-Java JNI")
}
