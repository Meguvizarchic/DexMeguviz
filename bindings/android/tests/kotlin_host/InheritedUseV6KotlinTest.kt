package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path

fun main(args:Array<String>) {
    val child=Files.readAllBytes(Path.of(args[0]));val parent=Files.readAllBytes(Path.of(args[1]))
    val query=AdvancedQuery(String(InheritedUseV6Test.query("\"scope\":{\"slots\":[\"a\",\"b\",\"root\"]},"),Charsets.UTF_8))
    NativeEngine.openRawDexSet(arrayOf(child,child,parent),arrayOf("a","b","root")).use { snapshot ->
        val result=InheritedUseGraphExecution.execute(snapshot,query)
        check(result.queryId.startsWith("query:v6:") && result.rowCount()>0)
        InheritedUseGraphExecution.startJob(snapshot,query,2,4,0).use { job ->
            var count=0
            while(true) {val poll=job.next(1000);if(poll.kind==2)break;if(poll.kind==0)count+=poll.batch.rowCount()}
            check(job.waitFor(10000).terminal && count==result.rowCount())
        }
    }
    println("PASS Kotlin inherited use graph")
}
