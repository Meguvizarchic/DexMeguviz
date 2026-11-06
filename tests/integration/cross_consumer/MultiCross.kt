package io.github.jichuo1.dexmeguviz

import java.nio.file.Files
import java.nio.file.Path

fun main(args: Array<String>) {
    val first = Files.readAllBytes(Path.of(args[0]))
    val other = Files.readAllBytes(Path.of(args[1]))
    val all = MethodPredicate.text(MethodTextField.NAME, TextOperation.CONTAINS, "")
    val locate = MethodPredicate.text(MethodTextField.NAME, TextOperation.EXACT, "locate")
    val uses = MethodPredicate.text(MethodTextField.NAME, TextOperation.EXACT, "uses")
    val absent = MethodPredicate.text(MethodTextField.NAME, TextOperation.EXACT, "absent")
    val cases = listOf("enumerate" to MethodQuery(all), "unique-locate" to MethodQuery(locate, QueryIntent.UNIQUE),
        "unique-uses" to MethodQuery(uses, QueryIntent.UNIQUE), "unique-absent" to MethodQuery(absent, QueryIntent.UNIQUE),
        "exists-locate" to MethodQuery(locate, QueryIntent.EXISTS), "exists-uses" to MethodQuery(uses, QueryIntent.EXISTS),
        "exists-absent" to MethodQuery(absent, QueryIntent.EXISTS))
    for ((dataset, second) in listOf("repeated" to first, "distinct" to other)) {
        NativeEngine.openRawDexSet(arrayOf(first,second),arrayOf("base","split")).use { snapshot ->
            val info=snapshot.info();check(info.sourceCount()==2&&!info.sourceScopeComplete)
            repeat(info.sourceCount()) { i -> val s=info.source(i)
                println("SOURCE\t$dataset\t${info.snapshotId}\t${s.sourceIndex}\t${s.inputIndex}\t${s.slot}\t${s.sourceSha256}\t${s.contentId}\t${s.occurrenceId}\t${s.logicalDexId}")
            }
            for ((name,query) in cases) {
                val result=QueryExecution.execute(snapshot,query)
                println("CASE\t$dataset\t$name\t${result.queryId}\t${result.snapshotId}\t${result.executionStatus}\t${result.coverage}\t${result.decision}\t${result.reason}\t${result.candidateCount()}\t${result.visitedMethods}\t${result.totalMethods}\t${query.toQueryIrJson()}")
                repeat(result.candidateCount()) { i -> val r=result.candidate(i)
                    check(listOf(r.owner,r.name,r.prototype,r.sourceSlot,r.occurrenceId).all { it!=null && it.all { c -> c.code in 32..126 && c!='\t' } })
                    println("ROW\t$dataset\t$name\t${r.sourceIndex}\t${r.inputIndex}\t${r.methodIndex}\t${r.accessFlags}\t${r.declarationOffset}\t${r.codeOffset}\t${r.owner}\t${r.name}\t${r.prototype}\t${r.sourceSlot}\t${r.occurrenceId}")
                }
            }
        }
    }
}
