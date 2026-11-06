package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path

fun main(args:Array<String>) {
 val files=args.map { Files.readAllBytes(Path.of(it)) }.toTypedArray()
 NativeEngine.openRawDexSet(files,arrayOf("child","left","alt","top","root")).use { snapshot ->
  for(resolved in listOf(false,true)) {
   val query=AdvancedQuery(String(InterfaceUseGraphTest.query(resolved,resolved),Charsets.UTF_8))
   val result=InterfaceUseGraphExecution.execute(snapshot,query)
   check(result.rowCount()==1)
   InterfaceUseGraphExecution.startJob(snapshot,query,1,4,0).use { job ->
    var count=0
    while(true) { val poll=job.next(1000);if(poll.kind==2)break;if(poll.kind==0)count+=poll.batch.rowCount() }
    check(job.waitFor(10000).terminal && count==result.rowCount())
   }
  }
 }
 println("PASS Kotlin v8/v11 interface use graph")
}
