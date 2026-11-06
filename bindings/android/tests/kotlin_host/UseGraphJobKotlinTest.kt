package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path
fun main(args:Array<String>) {
 val bytes=Files.readAllBytes(Path.of(args[0]));val q="""{"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"}}""".toByteArray()
 NativeEngine.openRawDex(bytes,"kotlin").use { s -> UseGraphQueryExecution.startJob(s,q,1,4,0).use { j ->
  var n=0;while(true){val p=j.next(1000);if(p.kind==2)break;if(p.kind==0){check(p.batch.coverage==1);n+=p.batch.rowCount()}}
  check(n==2&&j.waitFor(10000).terminal)
 }}
 println("PASS Kotlin use-graph Job facade")
}
