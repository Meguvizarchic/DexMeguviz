package io.github.jichuo1.dexmeguviz

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption

private fun expectInvalid(block: () -> Unit) {
    try { block(); error("expected IllegalArgumentException") } catch (_: IllegalArgumentException) { }
}
fun main(args: Array<String>) {
    check(args.size == 4)
    val bytes = Array(3) { Files.readAllBytes(Path.of(args[it])) }
    val output = Path.of(args[3])
    val cases = listOf(
        "forward" to UseTargetSymbolQuery(UseSymbolTarget.METHOD_DEFINITION, maxResults = 100),
        "filtered" to UseTargetSymbolQuery(UseSymbolTarget.METHOD_DEFINITION,
            useWhere = UseEventPredicate.all(UseEventPredicate.number(UseEventNumberField.PC, 3),
                UseEventPredicate.text(UseEventTextField.CALLER_NAME, TextOperation.EXACT, "a"),
                UseEventPredicate.targetDomain(UseEventTargetDomain.METHOD_REFERENCE)),
            targetWhere = EntityPredicate.text(EntityTextField.NAME, TextOperation.EXACT, "b"), maxResults = 100),
        "reverse_semi" to UseTargetSymbolQuery(UseSymbolTarget.METHOD_DEFINITION,
            direction = UseSymbolDirection.TARGET_FIRST, join = UseSymbolJoin.SEMI_JOIN, maxResults = 100),
        "field" to UseTargetSymbolQuery(UseSymbolTarget.FIELD_REFERENCE, maxResults = 100),
        "string" to UseTargetSymbolQuery(UseSymbolTarget.STRING_VALUE, maxResults = 100),
        "missing" to UseTargetSymbolQuery(UseSymbolTarget.METHOD_DEFINITION,
            useWhere = UseEventPredicate.text(UseEventTextField.CALLER_NAME, TextOperation.EXACT, "a\u0000\ud800"),
            intent = QueryIntent.EXISTS, maxResults = 100)
    )
    expectInvalid { UseTargetSymbolQuery(UseSymbolTarget.FIELD_REFERENCE,
        useWhere = UseEventPredicate.targetDomain(UseEventTargetDomain.METHOD_REFERENCE)) }
    expectInvalid { UseTargetSymbolQuery(UseSymbolTarget.STRING_VALUE,
        targetWhere = EntityPredicate.text(EntityTextField.OWNER, TextOperation.EXACT, "x")) }
    expectInvalid { UseEventPredicate.number(UseEventNumberField.PC, 8, 7) }
    expectInvalid { UseEventPredicate.number(UseEventNumberField.OPCODE, 0x100000000L) }
    expectInvalid { UseTargetSymbolQuery(UseSymbolTarget.METHOD_REFERENCE, maxResults = 0) }
    val longText = "a".repeat(20000)
    val longQuery = UseTargetSymbolQuery(UseSymbolTarget.METHOD_DEFINITION,
        targetWhere = EntityPredicate.text(EntityTextField.NAME, TextOperation.EXACT, longText)).toQueryIrJson()
    check(longQuery.length <= 65536 && longQuery.contains("\"value\""))
    NativeEngine.openRawDexSet(bytes, arrayOf("a", "b1", "b2")).use { snapshot ->
        for ((label, query) in cases) {
            val json = query.toQueryIrJson()
            check(json.all { it.code < 128 } && json.contains("\"use_target_symbol\""))
            Files.writeString(output.resolve("$label.query.json"), json, StandardOpenOption.CREATE_NEW)
            val result = TypedUseTargetSymbolExecution.execute(snapshot, query)
            check(result.queryId.startsWith("query:v16:") && result.requiredCapabilities and 16777216 != 0)
            check(!result.profile.scopeComplete)
            val expected = when (label) { "forward" -> 4; "filtered" -> 2; "reverse_semi" -> 2; else -> 0 }
            check(result.rowCount() == expected) { "$label rows ${result.rowCount()} != $expected" }
            println("CASE $label ${result.queryId} ${result.rowCount()}")
        }
    }
    println("PASS typed v16 Kotlin source set")
}
