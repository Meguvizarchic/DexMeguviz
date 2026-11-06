package io.github.jichuo1.dexmeguviz
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
fun main(args:Array<String>) {
 val dex=Files.readAllBytes(Path.of(args[0]))
 NativeEngine.openRawDex(dex,"stream").use { s ->
  val out=ByteArrayOutputStream();check(DexStreamExport.writeTo(s,out,dex.size.toLong(),43)==dex.size.toLong());check(out.toByteArray().contentEquals(dex))
 }
 NativeEngine.openRawDexSet(arrayOf(dex,dex),arrayOf("a","b")).use { s ->
  val a=ByteArrayOutputStream();val b=ByteArrayOutputStream();val counts=DexStreamExport.writeAll(s,arrayOf(a,b),dex.size.toLong(),dex.size.toLong()*2,47)
  check(counts.contentEquals(longArrayOf(dex.size.toLong(),dex.size.toLong()))&&a.toByteArray().contentEquals(dex)&&b.toByteArray().contentEquals(dex))
 }
 println("PASS Kotlin bounded stream export")
}
