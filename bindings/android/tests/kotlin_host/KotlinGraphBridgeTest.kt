package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path

fun main(args: Array<String>) {
    val dex=Files.readAllBytes(Path.of(args[0]))
    val scan="""{"schema_version":1,"relation":{"op":"scan","relation":"method_defs"}}""".toByteArray()
    val join="""{"schema_version":1,"relation":{"op":"join","on":"local_owner","left":{"op":"scan","relation":"method_defs"},"right":{"op":"scan","relation":"class_defs"}}}""".toByteArray()
    val saved=NativeEngine.openRawDex(dex,"one").use { s ->
        GraphQueryExecution.execute(s,scan).also { check(it.rowCount()==1 && it.coverage==1 && it.queryId.startsWith("query:v3:")) }
    }
    check(saved.row(0).entity.name=="abstractMethod")
    NativeEngine.openRawDexSet(arrayOf(dex,dex),arrayOf("one","two")).use { s ->
        val result=GraphQueryExecution.execute(s,join)
        check(result.rowCount()==2 && result.row(1).bindingCount()==2 && result.row(1).link(0).rightSource==1L)
        check(result.source(0).archiveEntryName==null && result.source(0).archiveEntryIndex==0xffffffffL)
    }
    println("PASS Kotlin graph JSON single and multi-source")
}
