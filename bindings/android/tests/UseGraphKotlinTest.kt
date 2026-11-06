package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path
fun main(args: Array<String>) {
 val dex = Files.readAllBytes(Path.of(args[0]))
 val query = """{"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"required_capabilities":["use_streaming"]}""".toByteArray()
 NativeEngine.openRawDex(dex,"fixture").use { snapshot ->
  val result = UseGraphQueryExecution.execute(snapshot, query)
  check(result.queryId.startsWith("query:v9:") && result.rowCount() == 2)
  check(result.row(1).value.use.dexPc == 3L && result.row(1).value.use.targetIndex == 4L)
  check(result.source(0).sourceSha256 == "04656bbfe03c8b04e6f77d29b8cae8e7e06f18a038f85300658f8c691435648b")
 }
 println("Kotlin v9 use graph bridge PASS")
}
