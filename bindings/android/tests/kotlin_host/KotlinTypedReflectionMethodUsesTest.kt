package io.github.jichuo1.dexmeguviz

import java.nio.file.Files
import java.nio.file.Path

private fun rejects(block: () -> Unit) {
    try { block(); error("invalid query accepted") } catch (_: IllegalArgumentException) { }
}

fun main(args: Array<String>) {
    val dex = Files.readAllBytes(Path.of(args[0]))
    val flag = ReflectionMethodPredicate.reflectionFlags(RawFlagOperation.CONTAINS, ReflectionFlags(8))
    val name = ReflectionMethodPredicate.metadata(MethodPredicate.text(MethodTextField.NAME, TextOperation.EXACT, "uses"))
    val string = ReflectionMethodPredicate.stringsAll(StaticTextMatch(TextOperation.EXACT, "used-string"))
    val invoke = ReflectionMethodPredicate.invokesAll(InvokeTarget(name = StaticTextMatch(TextOperation.EXACT, "sink"), minParameters = 0, maxParameters = 0))
    val field = ReflectionMethodPredicate.fieldsAll(FieldTarget(name = StaticTextMatch(TextOperation.EXACT, "counter"), access = FieldUseAccess.READ))
    val body = ReflectionMethodPredicate.all(name, flag, string, invoke, field)
    val query = ReflectionMethodUsesQuery(body)
    val manual = """{"schema_version":1,"relation":"method_defs","where":{"all":[{"name":"uses"},{"flags":{"domain":"reflection","mode":"contains","value":8}},{"using_strings":{"all":[{"op":"exact","value":"used-string"}]}},{"invokes":{"all":[{"name":"sink","param_count":0,"reference_kind":"method_like"}]}},{"field_access":{"all":[{"name":"counter","access":"read"}]}}]},"intent":"enumerate","max_results":4096,"max_work":100000000,"required_capabilities":["reflection_flags_static","reflection_method_uses"]}"""
    NativeEngine.openRawDexSet(arrayOf(dex, dex), arrayOf("one", "two")).use { snapshot ->
        val actual = TypedReflectionMethodUsesExecution.execute(snapshot, query)
        val expected = ReflectionMethodUsesExecution.execute(snapshot, manual.toByteArray(Charsets.UTF_8))
        check(actual.queryId == expected.queryId && actual.candidateCount() == 2 &&
            actual.coverage == expected.coverage && actual.unknownRows == expected.unknownRows)
        check(actual.candidate(0).sourceIndex != actual.candidate(1).sourceIndex)
        var eos = false
        TypedReflectionMethodUsesExecution.startJob(snapshot, query, 1, 1, 0).use { job ->
            var count = 0
            while (true) {
                val poll = job.next(10000)
                if (poll.kind == 2) { eos = true; break }
                check(poll.kind == 0); count += poll.batch.candidateCount()
            }
            val status = job.waitFor(10000)
            check(eos && status.terminal && status.executionStatus == 0 && status.candidateCount == count && count == 2)
        }
        println("CASE\tall\t${actual.queryId}\t${actual.candidateCount()}\t${actual.unknownRows}\t${query.toQueryIrJson()}")
        val missing = ReflectionMethodPredicate.stringsAny(StaticTextMatch(TextOperation.EXACT, "not-in-pool"))
        val q = ReflectionMethodUsesQuery(ReflectionMethodPredicate.all(name, flag, missing), QueryIntent.EXISTS)
        val noMatch = TypedReflectionMethodUsesExecution.execute(snapshot, q)
        check(noMatch.candidateCount() == 0)
        println("CASE\tmissing\t${noMatch.queryId}\t${noMatch.candidateCount()}\t${noMatch.unknownRows}\t${q.toQueryIrJson()}")
        val ci = ReflectionMethodPredicate.stringsAny(StaticTextMatch(TextOperation.EXACT, "absent"),
            StaticTextMatch(TextOperation.EXACT, "USED-STRING", true))
        val invAny = ReflectionMethodPredicate.invokesAny(InvokeTarget(name = StaticTextMatch(TextOperation.EXACT, "absent")),
            InvokeTarget(name = StaticTextMatch(TextOperation.EXACT, "sink")))
        val fieldsAny = ReflectionMethodPredicate.fieldsAny(FieldTarget(name = StaticTextMatch(TextOperation.EXACT, "absent")),
            FieldTarget(name = StaticTextMatch(TextOperation.EXACT, "counter")))
        val anyQuery = ReflectionMethodUsesQuery(ReflectionMethodPredicate.all(name, flag, ci, invAny, fieldsAny))
        val anyResult = TypedReflectionMethodUsesExecution.execute(snapshot, anyQuery)
        check(anyResult.candidateCount() == 2)
        println("CASE\tany-ci\t${anyResult.queryId}\t${anyResult.candidateCount()}\t${anyResult.unknownRows}\t${anyQuery.toQueryIrJson()}")
        val callSite = ReflectionMethodPredicate.invokesAll(InvokeTarget(referenceKind = InvokeReferenceKind.CALL_SITE))
        val callQuery = ReflectionMethodUsesQuery(ReflectionMethodPredicate.all(name, flag, callSite))
        val callResult = TypedReflectionMethodUsesExecution.execute(snapshot, callQuery)
        check(callResult.candidateCount() == 0)
        println("CASE\tcall-site\t${callResult.queryId}\t${callResult.candidateCount()}\t${callResult.unknownRows}\t${callQuery.toQueryIrJson()}")
        val owner = ReflectionMethodPredicate.reflectionOwnerFlags(RawFlagOperation.CONTAINS, ReflectionFlags(1))
        val ownerQuery = ReflectionMethodUsesQuery(ReflectionMethodPredicate.all(name, owner, string))
        val ownerResult = TypedReflectionMethodUsesExecution.execute(snapshot, ownerQuery)
        println("CASE\towner-flags\t${ownerResult.queryId}\t${ownerResult.candidateCount()}\t${ownerResult.unknownRows}\t${ownerQuery.toQueryIrJson()}")
    }
    val unknownDex = Files.readAllBytes(Path.of(args[1]))
    val unknownQuery = ReflectionMethodUsesQuery(ReflectionMethodPredicate.all(name, flag, string), QueryIntent.UNIQUE)
    NativeEngine.openRawDexSet(arrayOf(unknownDex, unknownDex), arrayOf("one", "two")).use { snapshot ->
        val result = TypedReflectionMethodUsesExecution.execute(snapshot, unknownQuery)
        check(result.candidateCount() == 0 && result.unknownRows == 2L && result.coverage == 1)
        println("CASE\tunknown\t${result.queryId}\t${result.candidateCount()}\t${result.unknownRows}\t${unknownQuery.toQueryIrJson()}")
        val anyQuery = ReflectionMethodUsesQuery(ReflectionMethodPredicate.all(name, ReflectionMethodPredicate.any(flag, string)))
        val anyResult = TypedReflectionMethodUsesExecution.execute(snapshot, anyQuery)
        check(anyResult.candidateCount() == 2 && anyResult.unknownRows == 0L)
        println("CASE\tunknown-any\t${anyResult.queryId}\t${anyResult.candidateCount()}\t${anyResult.unknownRows}\t${anyQuery.toQueryIrJson()}")
        val notQuery = ReflectionMethodUsesQuery(ReflectionMethodPredicate.all(name, ReflectionMethodPredicate.not(flag), string))
        val notResult = TypedReflectionMethodUsesExecution.execute(snapshot, notQuery)
        check(notResult.candidateCount() == 0 && notResult.unknownRows == 2L)
        println("CASE\tunknown-not\t${notResult.queryId}\t${notResult.candidateCount()}\t${notResult.unknownRows}\t${notQuery.toQueryIrJson()}")
    }
    val weird = ReflectionMethodPredicate.stringsAll(StaticTextMatch(TextOperation.EXACT, "nul\u0000\ud800"))
    val escaped = ReflectionMethodUsesQuery(ReflectionMethodPredicate.all(flag, weird)).toQueryIrJson()
    check(escaped.all { it.code < 128 } && !escaped.contains('\u0000'))
    rejects { ReflectionMethodUsesQuery(flag) }
    rejects { ReflectionMethodUsesQuery(string) }
    rejects { ReflectionMethodPredicate.stringsAll() }
    rejects { InvokeTarget(minParameters = 1) }
    rejects { InvokeTarget(name = StaticTextMatch(TextOperation.EXACT, "x"), referenceKind = InvokeReferenceKind.CALL_SITE) }
    rejects { ReflectionMethodUsesQuery(body, maxResults = 4097) }
    rejects { ReflectionMethodUsesQuery(body, maxWork = 100000001) }
    println("PASS typed v15 JNI sync, Job, CLI cases and boundaries")
}
