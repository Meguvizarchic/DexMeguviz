package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path
import java.nio.charset.StandardCharsets
fun main(args: Array<String>) {
    val dex=Files.readAllBytes(Path.of(args[0]))
    val q="""{"schema_version":1,"relation":{"op":"scan","relation":"field_refs","where":{"flags":{"domain":"reflection","mode":"contains","value":1}}},"required_capabilities":["reflection_flags_static","reflection_relational"]}""".toByteArray(StandardCharsets.UTF_8)
    NativeEngine.openRawDexSet(arrayOf(dex,dex),arrayOf("one","two")).use { snapshot ->
        val expected=GraphQueryExecution.execute(snapshot,q)
        check(expected.queryId.startsWith("query:v14:") && expected.rowCount()==6 && expected.unknownRows==2L)
        GraphQueryExecution.startGraphJob(snapshot,q,1,1,0).use { job ->
            var count=0
            while(true){val p=job.next(10000);if(p.kind==2)break;check(p.kind==0&&p.batch.coverage==1);count+=p.batch.rowCount()}
            val status=job.waitFor(10000);check(status.terminal&&status.executionStatus==0&&status.unknownRows==2L&&status.candidateCount==count&&count==6)
        }
    }
    println("PASS Kotlin v14 reflection graph and Job")
}
