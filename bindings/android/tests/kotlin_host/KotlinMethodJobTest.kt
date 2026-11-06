package io.github.jichuo1.dexmeguviz

import java.nio.file.Files
import java.nio.file.Path

private fun equal(a: NativeEngine.MethodCandidate, b: NativeEngine.MethodCandidate) {
    check(a.methodIndex == b.methodIndex && a.accessFlags == b.accessFlags &&
          a.declarationOffset == b.declarationOffset && a.codeOffset == b.codeOffset &&
          a.owner == b.owner && a.name == b.name && a.prototype == b.prototype &&
          a.sourceIndex == b.sourceIndex && a.inputIndex == b.inputIndex &&
          a.sourceSlot == b.sourceSlot && a.occurrenceId == b.occurrenceId)
}

private fun drain(job: NativeEngine.Job): List<NativeEngine.MethodCandidate> {
    val rows = mutableListOf<NativeEngine.MethodCandidate>()
    repeat(1000) {
        val poll = job.next(1000)
        when (poll.kind) {
            0 -> {
                check(poll.batch != null && poll.batch.coverage == 1 && poll.batch.decision == 0)
                repeat(poll.batch.candidateCount()) { rows.add(poll.batch.candidate(it)) }
            }
            1 -> check(poll.batch == null)
            2 -> { check(poll.batch == null); return rows }
            else -> error("unknown poll kind")
        }
    }
    error("job did not complete")
}

fun main(args: Array<String>) {
    val bytes = Files.readAllBytes(Path.of(args[0]))
    val q03 = Files.readAllBytes(Path.of(args[1]))
    val all = MethodQuery(MethodPredicate.constant(true))
    NativeEngine.openRawDex(bytes, "one").use { snapshot ->
        val expected = QueryExecution.execute(snapshot, all)
        QueryExecution.startMethodJob(snapshot, all, 1, 1, 0).use { job ->
            val rows = drain(job); val status = job.waitFor(10000)
            check(status.terminal && status.executionStatus == expected.executionStatus &&
                  status.coverage == expected.coverage && status.candidateCount == expected.candidateCount())
            check(status.queryId == expected.queryId && status.snapshotId == expected.snapshotId)
            check(rows.size == expected.candidateCount())
            rows.forEachIndexed { i, row -> equal(row, expected.candidate(i)) }
        }
        try { QueryExecution.startMethodJob(snapshot, all, 0, 1, 0); error("bad batch accepted") }
        catch (_: IllegalArgumentException) { }

    }
    NativeEngine.openRawDexSet(arrayOf(bytes, bytes), arrayOf("base", "split")).use { snapshot ->
        val limited = MethodQuery(MethodPredicate.constant(true), QueryIntent.ENUMERATE, 1)
        QueryExecution.startMethodJob(snapshot, limited, 1, 1, 0).use { job ->
            val rows = drain(job); val status = job.waitFor(10000)
            check(status.terminal && status.executionStatus == 4 && status.coverage == 1 &&
                  status.reason == 4 && rows.size == status.candidateCount && rows.size <= 1) { "limited terminal=${status.terminal}, exec=${status.executionStatus}, coverage=${status.coverage}, reason=${status.reason}, observed=${rows.size}, candidates=${status.candidateCount}" }
        }
        val expected = QueryExecution.execute(snapshot, all)
        QueryExecution.startMethodJob(snapshot, all, 2, 1, 0).use { job ->
            val rows = drain(job); val status = job.waitFor(10000)
            check(status.terminal && status.executionStatus == 0 && status.coverage == 1)
            check(rows.size == expected.candidateCount() && status.candidateCount == rows.size)
            rows.forEachIndexed { i, row -> equal(row, expected.candidate(i)) }
        }
    }
    NativeEngine.openRawDex(q03, "facts").use { snapshot ->
        val q = MethodQuery(MethodPredicate.usesString(TextOperation.EXACT, "code-use-q03"))
        val expected = QueryExecution.execute(snapshot, q)
        QueryExecution.startMethodJob(snapshot, q, 1, 1, 0).use { job ->
            val rows = drain(job); val status = job.waitFor(10000)
            check(status.terminal && status.executionStatus == 0 && expected.candidateCount() > 0 && rows.size == expected.candidateCount() && status.candidateCount == rows.size)
            rows.forEachIndexed { i, row -> equal(row, expected.candidate(i)) }
        }
    }
    val released = NativeEngine.openRawDex(bytes, "released")
    val retainedJob = QueryExecution.startMethodJob(released, all, 1, 1, 0)
    released.close()
    retainedJob.use { job ->
        val rows = drain(job); val status = job.waitFor(10000)
        check(status.terminal && status.executionStatus == 0 && rows.size == status.candidateCount && rows.isNotEmpty())
        check(rows.first().name.isNotEmpty())
    }
    val closed = NativeEngine.openRawDex(bytes, "closed")
    closed.close()
    try { QueryExecution.startMethodJob(closed, all, 1, 1, 0); error("closed snapshot accepted") }
    catch (_: IllegalStateException) { }
    println("PASS Kotlin method Job single/multi-source and terminal status")
}





