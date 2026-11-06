package io.github.jichuo1.dexmeguviz

import java.nio.file.Files
import java.nio.file.Path

fun main(args: Array<String>) {
    val bytes = Files.readAllBytes(Path.of(args[0]))
    NativeEngine.openRawDex(bytes, "single").use { snapshot ->
        val query = EntityQuery(EntityRelation.FIELD_DEFS)
        val expected = QueryExecution.execute(snapshot, query)
        QueryExecution.startEntityJob(snapshot, query, 1, 1, 0).use { job ->
            val rows = mutableListOf<NativeEngine.EntityCandidate>()
            while (true) {
                val poll = job.next(10000)
                if (poll.kind == 2) break
                check(poll.kind == 0 && poll.batch.coverage == 1 && poll.batch.decision == 0)
                repeat(poll.batch.candidateCount()) { rows.add(poll.batch.candidate(it)) }
            }
            val state = job.waitFor(10000)
            check(state.terminal && state.executionStatus == 0 && state.coverage == 1)
            check(rows.size == expected.candidateCount() && state.candidateCount == rows.size)
            for (i in rows.indices) check(rows[i].recordOffset == expected.candidate(i).recordOffset)
        }
    }
    NativeEngine.openRawDexSet(arrayOf(bytes, bytes), arrayOf("a", "b")).use { snapshot ->
        QueryExecution.startEntityJob(snapshot, EntityQuery(EntityRelation.CLASS_DEFS), 2, 1, 0).use { job ->
            var count = 0
            while (true) {
                val poll = job.next(10000)
                if (poll.kind == 2) break
                check(poll.kind == 0)
                count += poll.batch.candidateCount()
            }
            check(job.waitFor(10000).executionStatus == 0 && count == 10)
        }
    }
    println("PASS Kotlin single and multi-source entity job")
}
