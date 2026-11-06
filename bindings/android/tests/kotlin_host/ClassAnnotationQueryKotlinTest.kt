package io.github.jichuo1.dexmeguviz

import java.nio.file.Files
import java.nio.file.Path

fun main(args: Array<String>) {
    check(args.size == 1)
    val dex = Files.readAllBytes(Path.of(args[0]))
    val query = """{"schema_version":1,"relation":"class_defs","required_capabilities":["class_annotation_static"],"where":{"annotation":{"type":"Lfixture/Complex;","visibility":1,"element":{"name":"n","int":-7}}}}""".toByteArray(Charsets.UTF_8)
    NativeEngine.openRawDex(dex, "kotlin").use { snapshot ->
        val result = ClassAnnotationQuery.execute(snapshot, query)
        check(result.queryId.startsWith("query:v24:") && result.executionStatus == 0 && result.coverage == 1)
        check(result.candidateCount() == 1 && result.unknownRows == 0L)
        check(result.candidate(0).typeDescriptor == "Lfixture/Annotated;")
    }
    println("PASS v24 class annotation Kotlin-to-Java JNI")
}
