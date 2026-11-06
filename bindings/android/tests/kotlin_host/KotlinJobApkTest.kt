package io.github.jichuo1.dexmeguviz

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

private fun drain(job: NativeEngine.Job, snapshot: String, query: String): List<NativeEngine.MethodCandidate> {
    val copied = ArrayList<NativeEngine.MethodCandidate>()
    repeat(100) {
        val poll = job.next(1000)
        when (poll.kind) {
            1 -> check(poll.batch == null)
            2 -> { check(poll.batch == null); return copied }
            0 -> {
                val batch = checkNotNull(poll.batch)
                check(batch.executionStatus == 0 && batch.coverage == 1 && batch.decision == 0)
                check(batch.snapshotId == snapshot && batch.queryId == query)
                for (i in 0 until batch.candidateCount()) copied.add(batch.candidate(i))
            }
            else -> error("unexpected JobPoll kind ${poll.kind}")
        }
    }
    error("Job did not reach EOS")
}

private fun terminal(job: NativeEngine.Job): NativeEngine.JobStatus {
    repeat(20) { val status = job.waitFor(1000); if (status.terminal) return status }
    error("Job did not reach terminal state")
}

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
    val set = NativeEngine.openSources(arrayOf(dex, apk, resources, dex),
        arrayOf("raw", "base", "resource", "split"),
        intArrayOf(NativeEngine.SOURCE_RAW_DEX, NativeEngine.SOURCE_APK, NativeEngine.SOURCE_APK, NativeEngine.SOURCE_RAW_DEX),
        booleanArrayOf(false, false, true, false))
    val info = set.info()
    check(!info.sourceScopeComplete && info.inputCount() == 4 && info.sourceCount() == 5)
    check(info.input(1).sourceCount == 3 && info.input(2).sourceCount == 0)
    val enumerateBytes = enumerate.toQueryIrJson().toByteArray(StandardCharsets.UTF_8)
    val uniqueBytes = unique.toQueryIrJson().toByteArray(StandardCharsets.UTF_8)
    val direct = set.queryMethods(enumerateBytes)
    val uniqueDirect = set.queryMethods(uniqueBytes)
    check(direct.executionStatus == 0 && direct.coverage == 1 && direct.candidateCount() == 5)
    val enumerateJob = set.startMethodJob(enumerateBytes, 1, 1, 0)
    val uniqueJob = set.startMethodJob(uniqueBytes, 1, 1, 0)
    set.close()
    val copied: List<NativeEngine.MethodCandidate>
    enumerateJob.use { job ->
        copied = drain(job, info.snapshotId, direct.queryId)
        val status = terminal(job)
        check(status.executionStatus == 0 && status.coverage == 1 && status.decision == 0)
        check(status.candidateCount == 5 && status.queryId == direct.queryId && status.snapshotId == info.snapshotId)
        check(copied.size == 5)
        copied.forEachIndexed { index, row ->
            val origin = info.source(index)
            check(row.name == "locate" && row.sourceIndex == origin.sourceIndex && row.inputIndex == origin.inputIndex)
            check(row.sourceSlot == origin.slot && row.occurrenceId == origin.occurrenceId)
        }
    }
    uniqueJob.use { job ->
        val rows = drain(job, info.snapshotId, uniqueDirect.queryId)
        val status = terminal(job)
        check(status.executionStatus == 0 && status.coverage == 1 && status.decision == 2 && status.reason == 2)
        check(rows.size == 2 && status.candidateCount == 2)
        check(rows.map { it.occurrenceId }.toSet().size == 2)
        rows.forEach { row ->
            val origin = info.source(row.sourceIndex)
            check(row.name == "locate" && row.inputIndex == origin.inputIndex && row.occurrenceId == origin.occurrenceId)
        }
    }
    check(copied[4].sourceSlot == "split" && info.source(3).archiveEntryName == "classes10.dex")
    NativeEngine.openSources(arrayOf(resources), arrayOf("resource"), intArrayOf(NativeEngine.SOURCE_APK),
        booleanArrayOf(true)).use { empty ->
        val metadata = empty.info()
        check(metadata.inputCount() == 1 && metadata.sourceCount() == 0 && !metadata.sourceScopeComplete)
        val bytes = exists.toQueryIrJson().toByteArray(StandardCharsets.UTF_8)
        val synchronous = empty.queryMethods(bytes)
        empty.startMethodJob(bytes, 1, 1, 0).use { job ->
            val rows = drain(job, metadata.snapshotId, synchronous.queryId)
            val status = terminal(job)
            check(rows.isEmpty() && status.executionStatus == 0 && status.coverage == 1)
            check(status.decision == 1 && status.reason == 5 && status.candidateCount == 0)
        }
    }
    println("PASS Kotlin method query, mixed APK/raw Job batches, EOS, terminal status and origins")
}
