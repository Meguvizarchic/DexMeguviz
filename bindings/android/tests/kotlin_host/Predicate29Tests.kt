package io.github.jichuo1.dexmeguviz

private fun expectFailure(block: () -> Unit) {
    try { block(); error("expected IllegalArgumentException") } catch (_: IllegalArgumentException) {}
}

fun main() {
    val p = MethodPredicate
    expectFailure { p.parameterCount(-1) }
    expectFailure { p.parameterCount(0x100000000L) }
    expectFailure { p.parameterCount(2, 1) }
    expectFailure { p.parameterCount(0, 0x100000000L) }
    expectFailure { p.parameter(-1, TextOperation.EXACT, "I") }
    expectFailure { p.parameter(0x100000000L, TextOperation.EXACT, "I") }
    val escaped = String(charArrayOf('\u0000', '\ud800', '"', '\\', '\udfff'))
    val paramUnicode = MethodQuery(p.parameter(1, TextOperation.PREFIX, escaped, true)).toQueryIrJson()
    check(paramUnicode.contains("\"u16\":[0,55296,34,92,57343]"))
    val paramLong = MethodQuery(p.parameter(0, TextOperation.EXACT, "x".repeat(18000))).toQueryIrJson()
    check(paramLong.contains("\"value\":\""))
    val useLong = MethodQuery(p.usesString(TextOperation.EXACT, "x".repeat(18000))).toQueryIrJson()
    check(useLong.contains("\"value\":\""))
    var deepParam = p.parameter(0, TextOperation.EXACT, "x")
    repeat(28) { deepParam = p.not(deepParam) }
    check(MethodQuery(deepParam).toQueryIrJson().contains("\"value\":\"x\""))
    expectFailure { p.not(deepParam) }
    var deepUse = p.usesString(TextOperation.EXACT, "x")
    repeat(27) { deepUse = p.not(deepUse) }
    check(MethodQuery(deepUse).toQueryIrJson().contains("\"value\":\"x\""))
    expectFailure { p.not(deepUse) }

    val cases = listOf(
        "count-exact" to p.parameterCount(1),
        "count-range" to p.parameterCount(1, 3),
        "param-exact" to p.parameter(0, TextOperation.EXACT, "I"),
        "param-absent" to p.parameter(1, TextOperation.EXACT, "I"),
        "param-unicode" to p.parameter(1, TextOperation.PREFIX, escaped, true),
        "owner-flags" to p.ownerFlags(RawFlagOperation.CONTAINS, RawDexFlags(1)),
        "owner-exact" to p.ownerFlags(RawFlagOperation.EXACT, RawDexFlags(0xffffffffL)),
        "normal" to p.normalMethod(),
        "constructor" to p.constructor(),
        "clinit" to p.classInitializer(),
        "body-use" to p.usesString(TextOperation.EXACT, "code-use-q03"),
        "pool-only" to p.usesString(TextOperation.EXACT, "annotation-only-q03"),
        "use-fold" to p.usesString(TextOperation.PREFIX, "CODE-USE", true),
        "combined" to p.all(p.parameterCount(1), p.parameter(0, TextOperation.EXACT, "I"), p.normalMethod())
    )
    for ((name, predicate) in cases) println("$name\t${MethodQuery(predicate).toQueryIrJson()}")
    System.err.println("PASS method parameters, owner flags, kind and string-use bounds")
}
