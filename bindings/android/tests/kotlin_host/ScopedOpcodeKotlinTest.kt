package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path
fun main(args:Array<String>){
 val dex=Files.readAllBytes(Path.of(args[0]));val q="""{"schema_version":1,"relation":"method_defs","where":{"name":"uses","opcodes":{"mode":"contains","values":[26,-1,96],"negative_wildcards":true}},"intent":"unique","scope":{"slots":["two"]},"required_capabilities":["opcode_sequence"]}""".toByteArray()
 NativeEngine.openRawDexSet(arrayOf(dex,dex),arrayOf("one","two")).use { set -> val r=ScopedOpcodeQuery.execute(set,q);check(r.query.candidateCount()==1&&r.query.candidate(0).sourceIndex==1&&r.scope.sourceIndex(0)==1&&!r.scope.sourceScopeAuthenticated) }
 println("PASS Kotlin scoped opcode source selection")
}
