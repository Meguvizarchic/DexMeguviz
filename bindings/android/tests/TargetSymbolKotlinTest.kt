package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path

fun main(args: Array<String>) {
 val bytes = Array(3) { Files.readAllBytes(Path.of(args[it])) }
 val query = """{"schema_version":1,"required_capabilities":["use_target_symbol"],"relation":{"op":"join","on":"target_symbol","left":{"op":"scan","relation":"invoke_sites"},"right":{"op":"scan","relation":"method_defs"}},"max_results":100}""".toByteArray()
 NativeEngine.openRawDexSet(bytes,arrayOf("a","b1","b2")).use { snapshot ->
  val result = UseGraphQueryExecution.execute(snapshot,query)
  check(result.queryId.startsWith("query:v16:") && result.requiredCapabilities and 16777216 != 0)
  check(result.rowCount()==4 && result.sourceCount()==3 && !result.profile.scopeComplete)
  val actual = mutableSetOf<Pair<Long,Long>>()
  repeat(result.rowCount()) { i ->
   val row=result.row(i);check(row.linkCount()==1)
   val link=row.link(0);check(link.key==6L && link.left.relation==8L && link.left.sourceIndex==0L && link.right.relation==0L)
   check(row.value.kind==1 && row.value.use.targetDomain==2L && row.value.use.targetIndex==1L)
   actual.add(link.left.dexPc to link.right.sourceIndex)
  }
  check(actual==setOf(0L to 1L,0L to 2L,3L to 1L,3L to 2L))
  try {snapshot.queryGraph(query);error("metadata graph accepted use profile")} catch(e: NativeEngine.NativeFailure){check(e.status==3)}
  val noCap = query.toString(Charsets.UTF_8).replace("\"required_capabilities\":[\"use_target_symbol\"],","").toByteArray()
  try {UseGraphQueryExecution.execute(snapshot,noCap);error("missing capability accepted")} catch(e: NativeEngine.NativeFailure){check(e.status==3)}
 }
 println("target symbol Kotlin/JNI source set PASS")
}
