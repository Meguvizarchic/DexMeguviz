package io.github.jichuo1.dexmeguviz

fun main() {
    val p = MethodPredicate
    fun text(value: String) = p.text(MethodTextField.NAME, TextOperation.EXACT, value)
    val longUnicode = "x".repeat(16400) + String(charArrayOf('\u0000', '"', '\\', '\ud800', 'Q', '\udfff', '\ud83d', '\ude00', '\u007f'))
    val oldComparable = MethodQuery(text("x".repeat(10000)))
    val longAscii = MethodQuery(text("x".repeat(20000)))
    val longBackspace = MethodQuery(text("\b".repeat(16400)))
    val longEscaped = MethodQuery(text(longUnicode))
    val nested = MethodQuery(p.all(text("x".repeat(9000)), text("x".repeat(9000))))
    val nullBoundary = MethodQuery(text("\u0000".repeat(16373)))
    val nullOver = MethodQuery(text("\u0000".repeat(16374)))
    val nullPart = text("\u0000".repeat(6000))
    val mixed = MethodQuery(p.all(nullPart, nullPart, nullPart))
    val explicit = MethodQuery(p.all(p.textValue(MethodTextField.NAME, TextOperation.EXACT, "\u0000".repeat(6000)), nullPart, nullPart))
    val fixed = text("\u0000".repeat(15000))
    val expensive = text("\u0000".repeat(1000))
    val cheaper = text("\u0080".repeat(3000))
    val padding = p.textValue(MethodTextField.NAME, TextOperation.EXACT, "z".repeat(13500))
    val greedyIncomplete = MethodQuery(p.all(fixed, expensive, cheaper, padding))
    val greedyExplicit = MethodQuery(p.all(fixed, expensive,
        p.textValue(MethodTextField.NAME, TextOperation.EXACT, "\u0080".repeat(3000)), padding))
    // The original fragment fits 64 KiB, but the enclosing query does not.
    // Switching only the ASCII item saves bytes; switching all items does not.
    val outerPredicate = p.all(text("\uffff".repeat(10404)), text("x".repeat(400)), text("\u0000".repeat(600)))
    val outerMixed = MethodQuery(outerPredicate)
    val outerMixedWide = MethodQuery(outerPredicate, maxWork = Long.MAX_VALUE)
    val outerExplicit = MethodQuery(p.all(text("\uffff".repeat(10404)),
        p.textValue(MethodTextField.NAME, TextOperation.EXACT, "x".repeat(400)), text("\u0000".repeat(600))))
    var deep = p.constant(true)
    repeat(31) { deep = p.not(deep) }
    var deepText = text("x")
    repeat(29) { deepText = p.not(deepText) }
    val cases = listOf("old-comparable" to oldComparable, "long-ascii" to longAscii,
        "long-backspace" to longBackspace, "long-escaped" to longEscaped, "combined" to nested,
        "depth-limit" to MethodQuery(deep), "text-depth-fallback" to MethodQuery(deepText),
        "null-node-boundary" to nullBoundary, "null-node-over" to nullOver,
        "mixed-auto" to mixed, "mixed-explicit" to explicit,
        "greedy-incomplete" to greedyIncomplete, "greedy-explicit" to greedyExplicit,
        "outer-mixed" to outerMixed, "outer-mixed-wide" to outerMixedWide, "outer-explicit" to outerExplicit)
    for ((name, query) in cases) println("$name\t${query.toQueryIrJson()}")
}
