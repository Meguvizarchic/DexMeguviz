package io.github.jichuo1.dexmeguviz

fun main() {
    val p = MethodPredicate
    fun text(s: String) = p.text(MethodTextField.NAME, TextOperation.EXACT, s)
    fun value(s: String) = p.textValue(MethodTextField.NAME, TextOperation.EXACT, s)

    // The mixed candidate is shorter but deeper than the all-value candidate.
    // The latter is needed after wrapping until the u16 child is too deep.
    var deep = p.all(text("x".repeat(200)), text("\u0000".repeat(1000)))
    repeat(27) { deep = p.not(deep) }
    val deepJson = MethodQuery(deep).toQueryIrJson()
    check(deepJson.split("\"value\":").size - 1 == 2)
    check(!deepJson.contains("\"u16\":"))

    val longHigh = "\uffff".repeat(10404)
    val shortAscii = "x".repeat(400)
    val nulls = "\u0000".repeat(600)
    val nested = MethodQuery(p.not(p.all(text(longHigh), text(shortAscii), text(nulls)))).toQueryIrJson()
    val nestedExplicit = MethodQuery(p.not(p.all(text(longHigh), value(shortAscii), text(nulls)))).toQueryIrJson()
    check(nested == nestedExplicit)
    val nestedComposite = MethodQuery(p.all(p.all(text(longHigh), text(shortAscii), text(nulls)))).toQueryIrJson()
    val nestedCompositeExplicit = MethodQuery(p.all(p.all(text(longHigh), value(shortAscii), text(nulls)))).toQueryIrJson()
    check(nestedComposite == nestedCompositeExplicit)

    val unusual = "x".repeat(397) + String(charArrayOf('\ud800', 'Q', '\udfff'))
    val surrogate = MethodQuery(p.all(text(longHigh), text(unusual), text(nulls))).toQueryIrJson()
    val surrogateExplicit = MethodQuery(p.all(text(longHigh), value(unusual), text(nulls))).toQueryIrJson()
    check(surrogate == surrogateExplicit)
    check(surrogate.contains("\\ud800Q\\udfff"))
    check(surrogate.split("\"value\":").size - 1 == 1)
    println("incomparable\t$deepJson")
    println("nested\t$nested")
    println("nested-composite\t$nestedComposite")
    println("surrogate\t$surrogate")
}
