package io.github.jichuo1.dexmeguviz

private fun expectFailure(block: () -> Unit) {
    try { block(); error("expected failure") } catch (_: IllegalArgumentException) {}
}
fun main() {
    val p = MethodPredicate
    val lone = String(charArrayOf('A', '\u0000', '\ud800', 'X', '\udfff'))
    val q = MethodQuery(p.text(MethodTextField.NAME, TextOperation.EXACT, lone), QueryIntent.UNIQUE)
    check(q.toQueryIrJson().contains("\"u16\":[65,0,55296,88,57343]"))
    val digits = String(charArrayOf('\u0009', '\u000a', '\u0063', '\u0064', '\u03e7', '\u03e8', '\u270f', '\u2710', '\uffff'))
    check(MethodQuery(p.text(MethodTextField.NAME, TextOperation.EXACT, digits)).toQueryIrJson()
        .contains("\"u16\":[9,10,99,100,999,1000,9999,10000,65535]"))
    check(MethodQuery(p.all()).toQueryIrJson().contains("\"all\":[]"))
    check(MethodQuery(p.any()).toQueryIrJson().contains("\"any\":[]"))
    check(MethodQuery(p.flags(RawFlagOperation.CONTAINS, RawDexFlags(0xffffffffL))).toQueryIrJson().contains("4294967295"))
    expectFailure { RawDexFlags(-1) }; expectFailure { RawDexFlags(0x100000000L) }
    expectFailure { MethodQuery(p.constant(true), maxResults = 0) }
    expectFailure { MethodQuery(p.constant(true), maxResults = 100001) }
    expectFailure { MethodQuery(p.constant(true), maxWork = 0) }
    val longText = MethodQuery(p.text(MethodTextField.NAME, TextOperation.EXACT, "x".repeat(33000))).toQueryIrJson()
    check(longText.contains("\"value\":\""))
    check(longText.length < 65536)
    val longBackspace = MethodQuery(p.text(MethodTextField.NAME, TextOperation.EXACT, "\b".repeat(16400))).toQueryIrJson()
    check(longBackspace.contains("\"value\":\"\\b\\b") && longBackspace.length < 65536)
    expectFailure { p.text(MethodTextField.NAME, TextOperation.EXACT, "x".repeat(100000)) }
    val longPredicate = p.text(MethodTextField.NAME, TextOperation.EXACT, "x".repeat(16000))
    val combined = MethodQuery(p.all(longPredicate, longPredicate)).toQueryIrJson()
    check(combined.length < 65536 && combined.contains("\"value\":\""))
    expectFailure { p.any(*Array(40000) { p.constant(true) }) }
    expectFailure {
        var nested = longPredicate
        repeat(3000) { nested = p.not(nested) }
    }
    var boundaryCovered = false
    for (limit in listOf(1, 10, 100, 1000, 10000, 100000)) {
        val one = MethodQuery(p.text(MethodTextField.NAME, TextOperation.EXACT, "\uffff"), maxResults = limit, maxWork = 1).toQueryIrJson()
        val fixed = one.length - 5 // encoded UTF-16 unit 65535 occupies five bytes
        val needed = 65536 - fixed + 1
        if (needed % 6 != 0) continue // n units occupy 6*n-1 bytes including separators
        val count = needed / 6
        val exact = MethodQuery(p.text(MethodTextField.NAME, TextOperation.EXACT, "\uffff".repeat(count)), maxResults = limit, maxWork = 1)
        check(exact.toQueryIrJson().length == 65536)
        expectFailure { MethodQuery(p.text(MethodTextField.NAME, TextOperation.EXACT, "\uffff".repeat(count + 1)), maxResults = limit, maxWork = 1).toQueryIrJson() }
        boundaryCovered = true
        break
    }
    check(boundaryCovered)
    var depth = p.constant(true)
    repeat(31) { depth = p.not(depth) }
    check(MethodQuery(depth).toQueryIrJson().length < 65536)
    expectFailure { p.not(depth) }
    var arrayDepth = p.constant(true)
    repeat(15) { arrayDepth = p.all(arrayDepth) }
    check(MethodQuery(arrayDepth).toQueryIrJson().length < 65536)
    expectFailure { p.all(arrayDepth) }
    var textDepth = p.text(MethodTextField.NAME, TextOperation.EXACT, "x")
    repeat(29) { textDepth = p.not(textDepth) }
    check(MethodQuery(textDepth).toQueryIrJson().contains("\"value\":\"x\""))
    expectFailure { p.not(textDepth) }
    val rawNull = MethodQuery(p.text(MethodTextField.NAME, TextOperation.EXACT, "\u0000".repeat(11000))).toQueryIrJson()
    check(rawNull.contains("\"u16\":["))
    val nullPart = p.text(MethodTextField.NAME, TextOperation.EXACT, "\u0000".repeat(6000))
    val mixed = MethodQuery(p.all(nullPart, nullPart, nullPart)).toQueryIrJson()
    check(mixed.length < 65536 && mixed.split("\"value\":").size - 1 == 1)
    val forced = p.textValue(MethodTextField.NAME, TextOperation.EXACT, "\u0000".repeat(6000))
    val explicitMixed = MethodQuery(p.all(forced, nullPart, nullPart)).toQueryIrJson()
    check(explicitMixed.length < 65536 && explicitMixed.split("\"value\":").size - 1 == 1)
    check(!QueryExecution.supported)
    try { QueryExecution.execute(q) } catch (_: UnsupportedOperationException) { /* expected */ }
    val incomplete = QuerySummary(ExecutionStatus.COMPLETE, Coverage.PARTIAL, Decision.UNDETERMINED, DecisionReason.SOURCE_SCOPE_INCOMPLETE, 0)
    check(incomplete.decision == Decision.UNDETERMINED && incomplete.coverage == Coverage.PARTIAL)
    val cases = listOf(
        "exact" to MethodQuery(p.text(MethodTextField.NAME, TextOperation.EXACT, "locate"), QueryIntent.UNIQUE),
        "fold" to MethodQuery(p.text(MethodTextField.NAME, TextOperation.EXACT, "LOCATE", true), QueryIntent.UNIQUE),
        "empty" to MethodQuery(p.text(MethodTextField.NAME, TextOperation.CONTAINS, ""), QueryIntent.ENUMERATE),
        "flags" to MethodQuery(p.flags(RawFlagOperation.CONTAINS, RawDexFlags(0x100)), QueryIntent.ENUMERATE),
        "unicode" to q,
        "and-not" to MethodQuery(p.all(p.text(MethodTextField.NAME, TextOperation.PREFIX, "lo"), p.not(p.flags(RawFlagOperation.ANY, RawDexFlags(8)))), QueryIntent.ENUMERATE)
    )
    for ((name, query) in cases) println("$name\t${query.toQueryIrJson()}")
    System.err.println("PASS Kotlin query and value types (no JNI execution)")
}
