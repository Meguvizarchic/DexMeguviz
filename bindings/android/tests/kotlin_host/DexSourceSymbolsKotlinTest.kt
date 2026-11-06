package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path
fun main(args:Array<String>){
 val data=Files.readAllBytes(Path.of(args[0]));val mixed=Files.readAllBytes(Path.of(args[1]));val limits=Annotations.Limits(256,1000000,100000,0)
 NativeEngine.openRawDex(data,"single").use { s ->
  val item=Annotations.collect(s,Annotations.Target.classType(2),limits).item(0)
  check(DexSourceExportExecution.stringAt(s,item.element(0).nameIndex,100)==item.element(0).name)
  check(DexSourceExportExecution.typeAt(s,item.typeIndex,100)==item.descriptor)
 }
 NativeEngine.openRawDexSet(arrayOf(data,data),arrayOf("one","two")).use { s ->
  val item=Annotations.collect(s,1,Annotations.Target.classType(2),limits).item(0)
  check(DexSourceExportExecution.stringAt(s,1,item.element(0).nameIndex,100)==item.element(0).name)
  check(DexSourceExportExecution.typeAt(s,1,item.typeIndex,100)==item.descriptor)
 }
 var copied=""
 NativeEngine.openRawDex(mixed,"unicode").use { s -> copied=DexSourceExportExecution.stringAt(s,7,6) }
 check(copied.toCharArray().contentEquals(charArrayOf(0xd800.toChar(),'x',0xdc00.toChar(),0.toChar(),0xd83d.toChar(),0xde00.toChar())))
 println("PASS Kotlin source-local symbols and preserved UTF16")
}
