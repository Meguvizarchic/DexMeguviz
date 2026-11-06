package io.github.jichuo1.dexmeguviz

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

fun main(args: Array<String>) {
    check(args.size == 1)
    val fixture = Path.of(args[0])
    val dex = Files.readAllBytes(fixture.resolve("raw-a.dex"))
    val apk = Files.readAllBytes(fixture.resolve("reverse-stored.apk"))
    val resources = Files.readAllBytes(fixture.resolve("resource-only.apk"))
    val predicate = MethodPredicate.text(MethodTextField.NAME, TextOperation.EXACT, "locate")
    val enumerate = MethodQuery(predicate, QueryIntent.ENUMERATE, 4096, 100000000L)
    val unique = MethodQuery(predicate, QueryIntent.UNIQUE, 4096, 100000000L)
    val exists = MethodQuery(predicate, QueryIntent.EXISTS, 4096, 100000000L)
    val copied: NativeEngine.QueryResult
    val info: NativeEngine.SourceSetInfo
    NativeEngine.openSources(arrayOf(dex, apk, resources, dex), arrayOf("raw", "base", "resource", "split"),
        intArrayOf(NativeEngine.SOURCE_RAW_DEX, NativeEngine.SOURCE_APK, NativeEngine.SOURCE_APK, NativeEngine.SOURCE_RAW_DEX),
        booleanArrayOf(false, false, true, false)).use { set ->
        info = set.info()
        check(!info.sourceScopeComplete && info.inputCount() == 4 && info.sourceCount() == 5)
        check(info.input(1).sourceCount == 3 && info.input(2).sourceCount == 0 && info.input(2).allowNoDex)
        val names = arrayOf("classes.dex", "classes2.dex", "classes10.dex")
        val indexes = intArrayOf(3, 2, 0)
        names.indices.forEach { i ->
            val source = info.source(i + 1)
            check(source.sourceIndex == i + 1 && source.inputIndex == 1 && source.slot == "base")
            check(source.archiveEntryName == names[i] && source.archiveEntryIndex == indexes[i])
        }
        check(info.source(4).sourceIndex == 4 && info.source(4).inputIndex == 3 && info.source(4).slot == "split")
        copied = QueryExecution.execute(set, enumerate)
        val direct = set.queryMethods(enumerate.toQueryIrJson().toByteArray(StandardCharsets.UTF_8))
        check(copied.executionStatus == 0 && copied.coverage == 1 && copied.candidateCount() == 5)
        check(copied.queryId == direct.queryId && copied.snapshotId == direct.snapshotId && copied.snapshotId == info.snapshotId)
        for (i in 0 until copied.candidateCount()) {
            val row = copied.candidate(i)
            val origin = info.source(i)
            check(row.name == "locate" && row.sourceIndex == origin.sourceIndex && row.inputIndex == origin.inputIndex)
            check(row.sourceSlot == origin.slot && row.occurrenceId == origin.occurrenceId)
        }
        val ambiguous = QueryExecution.execute(set, unique)
        check(ambiguous.executionStatus == 0 && ambiguous.coverage == 1 && ambiguous.decision == 2 && ambiguous.reason == 2)
    }
    check(copied.candidate(4).sourceSlot == "split" && info.source(3).archiveEntryName == "classes10.dex")
    NativeEngine.openSources(arrayOf(resources), arrayOf("resource"), intArrayOf(NativeEngine.SOURCE_APK),
        booleanArrayOf(true)).use { empty ->
        val metadata = empty.info()
        check(metadata.inputCount() == 1 && metadata.sourceCount() == 0 && metadata.input(0).sourceCount == 0)
        check(!metadata.sourceScopeComplete)
        val result = QueryExecution.execute(empty, exists)
        check(result.executionStatus == 0 && result.coverage == 1 && result.candidateCount() == 0 && result.decision == 1)
    }
    println("PASS final AAR Kotlin APK sources, candidate origins, ambiguous unique and empty incomplete scope")
}
