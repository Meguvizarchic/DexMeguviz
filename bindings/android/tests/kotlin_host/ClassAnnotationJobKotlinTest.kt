package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path
fun main(args:Array<String>){
 check(args.size==1);val dex=Files.readAllBytes(Path.of(args[0]))
 val q="""{"schema_version":1,"relation":"class_defs","required_capabilities":["class_annotation_static"],"where":{"annotation":{"type":"Lfixture/Complex;","element":{"name":"n","int":-7}}}}""".toByteArray(Charsets.UTF_8)
 NativeEngine.openRawDex(dex,"kotlin").use { snapshot -> ClassAnnotationQuery.startJob(snapshot,q,1,1,0).use { job ->
  var rows=0;var done=false;repeat(50){if(!done){val p=job.next(1000);if(p.kind==0)rows+=p.batch.candidateCount() else if(p.kind==2)done=true}}
  check(done&&rows==1);val s=job.waitFor(10000);check(s.terminal&&s.executionStatus==0&&s.queryId.startsWith("query:v24:"))
 }}
 println("PASS v24 EntityJob Kotlin-to-Java JNI")
}
