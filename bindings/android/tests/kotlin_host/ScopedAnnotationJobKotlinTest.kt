package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path
fun main(args:Array<String>){
 val dex=Files.readAllBytes(Path.of(args[0]))
 val q="""{"schema_version":1,"relation":"class_defs","required_capabilities":["class_annotation_static"],"scope":{"slots":["kotlin"]},"where":{"annotation":{"type":"Lfixture/Complex;","element":{"name":"n","int":-7}}}}""".toByteArray()
 NativeEngine.openRawDex(dex,"kotlin").use { s -> ScopedClassAnnotationQuery.start(s,q,1,1,0).use { job ->
  var count=0;var done=false;repeat(50){if(!done){val p=job.next(1000);if(p.kind==0)count+=p.batch.candidateCount() else if(p.kind==2)done=true}}
  val end=job.waitFor(10000);check(done&&count==1&&end.terminal&&end.executionStatus==0&&job.scope.sourceIndex(0)==0)
 }}
 println("PASS scoped annotation EntityJob Kotlin")
}
