package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path

fun main(args: Array<String>) {
    val dex=Files.readAllBytes(Path.of(args[0])); val query=Files.readAllBytes(Path.of(args[1]))
    NativeEngine.openRawDex(dex,"single").use { snapshot ->
        val result=ReflectionMethodUsesExecution.execute(snapshot,query)
        check(result.queryId.startsWith("query:v15:") && result.candidateCount()==1 && result.coverage==1)
        ReflectionMethodUsesExecution.startJob(snapshot,query,1,1,0).use { job ->
            var n=0
            while(true){val p=job.next(10000);if(p.kind==2)break;check(p.kind==0);n+=p.batch.candidateCount()}
            val s=job.waitFor(10000);check(s.terminal && s.executionStatus==0 && s.candidateCount==n && n==result.candidateCount() && s.unknownRows==result.unknownRows)
        }
    }
    NativeEngine.openRawDexSet(arrayOf(dex,dex),arrayOf("a","b")).use { snapshot ->
        val result=ReflectionMethodUsesExecution.execute(snapshot,query)
        check(result.candidateCount()==2 && result.candidate(0).sourceIndex!=result.candidate(1).sourceIndex)
        ReflectionMethodUsesExecution.startJob(snapshot,query,1,1,0).use { job ->
            var n=0
            while(true){val p=job.next(10000);if(p.kind==2)break;check(p.kind==0);n+=p.batch.candidateCount()}
            val s=job.waitFor(10000);check(s.terminal && s.executionStatus==0 && n==2 && s.candidateCount==n)
        }
    }
    println("PASS Kotlin v15 sync and Job on single and repeated sources")
}
