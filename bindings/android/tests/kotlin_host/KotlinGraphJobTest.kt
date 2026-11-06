package io.github.jichuo1.dexmeguviz
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
fun main(args: Array<String>) {
    val dex = Files.readAllBytes(Path.of(args[0]))
    val query = """{"schema_version":1,"relation":{"op":"scan","relation":"method_defs"}}""".toByteArray(StandardCharsets.UTF_8)
    NativeEngine.openRawDex(dex,"one").use { snapshot ->
        val expected=GraphQueryExecution.execute(snapshot,query)
        GraphQueryExecution.startGraphJob(snapshot,query,1,1,0).use { job ->
            var rows=0
            while(true){val p=job.next(10000);if(p.kind==2)break;check(p.kind==0 && p.batch.coverage==1);rows+=p.batch.rowCount()}
            val terminal=job.waitFor(10000)
            check(terminal.terminal && terminal.executionStatus==0 && terminal.coverage==1 && rows==expected.rowCount() && terminal.candidateCount==rows)
        }
    }
    NativeEngine.openRawDexSet(arrayOf(dex,dex),arrayOf("one","two")).use { snapshot ->
        GraphQueryExecution.startGraphJob(snapshot,query,1,1,0).use { job ->
            var rows=0;while(true){val p=job.next(10000);if(p.kind==2)break;check(p.kind==0);rows+=p.batch.rowCount()}
            val terminal=job.waitFor(10000);check(terminal.terminal && terminal.executionStatus==0 && rows==2)
        }
    }
    println("PASS Kotlin graph Job single and multi-source")
}
