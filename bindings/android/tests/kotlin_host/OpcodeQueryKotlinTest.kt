package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path
fun main(args:Array<String>) {
 val dex=Files.readAllBytes(Path.of(args[0]))
 val q="""{"schema_version":1,"relation":"method_defs","where":{"name":"uses","opcodes":{"mode":"contains","values":[26,-1,96],"negative_wildcards":true}},"required_capabilities":["opcode_sequence"]}""".toByteArray(Charsets.UTF_8)
 NativeEngine.openRawDex(dex,"kotlin").use { check(OpcodeQuery.execute(it,q).candidateCount()==1) }
 println("PASS OpcodeQuery Kotlin-to-Java JNI")
}
