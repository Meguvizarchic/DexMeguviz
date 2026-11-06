package io.github.jichuo1.dexmeguviz

import java.nio.file.Files
import java.nio.file.Path

fun main(args: Array<String>) {
    val dex = Files.readAllBytes(Path.of(args[0]))
    val one = MethodPredicate.text(MethodTextField.NAME, TextOperation.EXACT, "locate")
    val none = MethodPredicate.text(MethodTextField.NAME, TextOperation.EXACT, "absent")
    val all = MethodPredicate.text(MethodTextField.NAME, TextOperation.CONTAINS, "")
    val cases = listOf(
        "enumerate" to MethodQuery(all),
        "unique-one" to MethodQuery(one, QueryIntent.UNIQUE),
        "unique-none" to MethodQuery(none, QueryIntent.UNIQUE),
        "unique-two" to MethodQuery(all, QueryIntent.UNIQUE),
        "exists-one" to MethodQuery(one, QueryIntent.EXISTS),
        "exists-none" to MethodQuery(none, QueryIntent.EXISTS)
    )
    NativeEngine.openRawDex(dex, "one").use { snapshot ->
        val sha = snapshot.info().sourceSha256
        for ((name, query) in cases) {
            val result = QueryExecution.execute(snapshot, query)
            println("CASE\t$name\t${result.queryId}\t$sha\t${result.executionStatus}\t${result.coverage}\t${result.decision}\t${result.reason}\t${result.candidateCount()}\t${result.visitedMethods}\t${result.totalMethods}\t${query.toQueryIrJson()}")
            repeat(result.candidateCount()) { i ->
                val row = result.candidate(i)
                check(listOf(row.owner, row.name, row.prototype).all { it != null && it.all { c -> c.code in 32..126 && c != '\t' } })
                println("ROW\t$name\t${row.methodIndex}\t${row.accessFlags}\t${row.declarationOffset}\t${row.codeOffset}\t${row.owner}\t${row.name}\t${row.prototype}")
            }
        }
    }
}
