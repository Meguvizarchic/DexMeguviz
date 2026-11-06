package io.github.jichuo1.dexmeguviz
import java.nio.file.Files
import java.nio.file.Path
fun main(args:Array<String>) {
 val dex=Files.readAllBytes(Path.of(args[0]))
 NativeEngine.openRawDex(dex,"member").use { s ->
  val f=DexSourceExportExecution.fieldRefAt(s,0); val m=DexSourceExportExecution.methodRefAt(s,2)
  check(DexSourceExportExecution.typeAt(s,f[0],100)=="Lfixture/Annotated;")
  check(DexSourceExportExecution.stringAt(s,f[1],100)=="value")
  check(DexSourceExportExecution.prototypeAt(s,m[2],100)=="(Ljava/lang/String;)V")
 }
 println("PASS Kotlin source member and prototype interfaces")
}
