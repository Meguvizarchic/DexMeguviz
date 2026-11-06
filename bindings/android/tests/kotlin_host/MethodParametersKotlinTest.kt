package io.github.jichuo1.dexmeguviz

import java.nio.file.Files
import java.nio.file.Path

fun main(args:Array<String>){
    val dex=Files.readAllBytes(Path.of(args[0]))
    NativeEngine.openRawDex(dex,"named").use { snapshot ->
        val result=MethodParametersExecution.execute(snapshot,2,MethodParametersLimits(maxParameters=4))
        check(result.debugState==MethodParametersResult.DEBUG_PRESENT&&result.parameterCount()==2)
        check(result.parameter(0).name=="\u96ea"&&result.parameter(1).typeDescriptor=="J")
    }
    try{MethodParametersLimits(maxParameters=0);error("invalid limits accepted")}catch(_:IllegalArgumentException){}
    println("PASS Kotlin method parameters typed facade")
}
