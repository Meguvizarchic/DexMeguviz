package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path
fun main(args:Array<String>) {
 check(args.size==1);val dex=Files.readAllBytes(Path.of(args[0]))
 val q="""{"schema_version":1,"relation":"class_defs","required_capabilities":["class_annotation_static","class_annotation_string_static"],"where":{"annotation":{"type":"Lstringfixture/Tag;","element":{"name":"value","string":"aaaa"}}}}""".toByteArray(Charsets.UTF_8)
 NativeEngine.openRawDex(dex,"kotlin").use { snapshot ->
  val result=ClassAnnotationStringQuery.execute(snapshot,q)
  check(result.queryId.startsWith("query:v25:")&&result.candidateCount()==1&&result.candidate(0).typeDescriptor=="Lstringfixture/Collision;")
  ClassAnnotationStringQuery.startJob(snapshot,q,1,1,0).use { job ->
   var count=0;var done=false;repeat(50){if(!done){val p=job.next(1000);if(p.kind==0)count+=p.batch.candidateCount() else if(p.kind==2)done=true}}
   val status=job.waitFor(10000);check(done&&count==1&&status.terminal&&status.executionStatus==0&&status.queryId.startsWith("query:v25:"))
  }
 }
 println("PASS v25 string Kotlin-to-Java JNI")
}
