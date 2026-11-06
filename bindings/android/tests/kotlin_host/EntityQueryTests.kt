package io.github.jichuo1.dexmeguviz

import java.nio.file.Files
import java.nio.file.Path

private fun invalid(block: () -> Unit) {
    try { block(); error("expected invalid entity query") } catch (_: IllegalArgumentException) {}
}
private fun unsupported(block: () -> Unit) {
    try { block(); error("expected unsupported entity JNI") }
    catch (e: NativeEngine.NativeFailure) { check(e.status == 3) }
}

fun main(args: Array<String>) {
    check(args.size == 1)
    val p = EntityPredicate
    for (relation in EntityRelation.values()) println("all-${relation.name}\t${EntityQuery(relation).toQueryIrJson()}")
    val entries = listOf(
        "class" to EntityQuery(EntityRelation.CLASS_DEFS, p.text(EntityTextField.DESCRIPTOR, TextOperation.EXACT, "Lcatalog/Child;")),
        "field" to EntityQuery(EntityRelation.FIELD_DEFS, p.all(p.text(EntityTextField.TYPE, TextOperation.EXACT, "J"), p.flags(RawFlagOperation.CONTAINS, RawDexFlags(8)))),
        "external-field" to EntityQuery(EntityRelation.FIELD_REFS, p.hasLocalDefinition(false)),
        "unknown-flags" to EntityQuery(EntityRelation.FIELD_REFS, p.flags(RawFlagOperation.CONTAINS, RawDexFlags(0))),
        "owner-flags" to EntityQuery(EntityRelation.FIELD_REFS, p.ownerFlags(RawFlagOperation.CONTAINS, RawDexFlags(1))),
        "method-ref" to EntityQuery(EntityRelation.METHOD_REFS, p.text(EntityTextField.NAME, TextOperation.EXACT, "abstractMethod")),
        "external-type" to EntityQuery(EntityRelation.TYPE_REFS, p.textValue(EntityTextField.DESCRIPTOR, TextOperation.EXACT, "Lexternal/External;")),
        "string" to EntityQuery(EntityRelation.STRING_VALUES, p.text(EntityTextField.VALUE, TextOperation.EXACT, "shared")),
        "method-kind" to EntityQuery(EntityRelation.METHOD_DEFS, p.normalMethod()),
        "not-unknown" to EntityQuery(EntityRelation.FIELD_REFS, p.not(p.flags(RawFlagOperation.CONTAINS, RawDexFlags(0)))),
        "class-owner" to EntityQuery(EntityRelation.CLASS_DEFS, p.text(EntityTextField.SUPERCLASS, TextOperation.EXACT, "Lcatalog/Base;")),
        "absent-utf16" to EntityQuery(EntityRelation.STRING_VALUES, p.text(EntityTextField.VALUE, TextOperation.EXACT, String(charArrayOf('\u0000','\ud800','"','\\','\udfff')))),
        "absent-utf16-value" to EntityQuery(EntityRelation.STRING_VALUES, p.textValue(EntityTextField.VALUE, TextOperation.EXACT, String(charArrayOf('\u0000','\ud800','"','\\','\udfff')))),
        "method-param" to EntityQuery(EntityRelation.METHOD_REFS, p.parameterCount(0)),
        "method-param-range" to EntityQuery(EntityRelation.METHOD_REFS, p.parameterCount(0, 0)),
        "method-param-absent" to EntityQuery(EntityRelation.METHOD_REFS, p.parameter(0, TextOperation.EXACT, "I"))
    )
    for ((name, query) in entries) println("$name\t${query.toQueryIrJson()}")
    invalid { EntityQuery(EntityRelation.CLASS_DEFS, p.text(EntityTextField.NAME, TextOperation.EXACT, "x")) }
    invalid { EntityQuery(EntityRelation.STRING_VALUES, p.flags(RawFlagOperation.CONTAINS, RawDexFlags(0))) }
    invalid { EntityQuery(EntityRelation.METHOD_REFS, p.any(p.constant(true), p.text(EntityTextField.TYPE, TextOperation.EXACT, "I"))) }
    invalid { EntityQuery(EntityRelation.CLASS_DEFS, p.not(p.ownerFlags(RawFlagOperation.ANY, RawDexFlags(1)))) }
    invalid { EntityQuery(EntityRelation.TYPE_REFS, p.parameterCount(0)) }
    invalid { EntityQuery(EntityRelation.FIELD_REFS, p.parameterCount(-1)) }
    invalid { EntityQuery(EntityRelation.FIELD_REFS, p.constant(true), maxResults = 0) }
    val long = EntityQuery(EntityRelation.STRING_VALUES, p.text(EntityTextField.VALUE, TextOperation.EXACT, "x".repeat(18000))).toQueryIrJson()
    check(long.contains("\"value\":\""))
    val bytes = Files.readAllBytes(Path.of(args[0]))
    NativeEngine.openRawDex(bytes, "one").use { snapshot ->
        unsupported { snapshot.queryMethods(EntityQuery(EntityRelation.FIELD_REFS).toQueryIrJson().toByteArray(Charsets.UTF_8)) }
        // A method_defs JSON document that remains in the old v1 profile can execute.
        check(snapshot.queryMethods(EntityQuery(EntityRelation.METHOD_DEFS).toQueryIrJson().toByteArray(Charsets.UTF_8)).executionStatus == 0)
        // The same root can require entity-v2 when it asks for entity-only metadata.
        unsupported { snapshot.queryMethods(EntityQuery(EntityRelation.METHOD_DEFS, p.hasLocalDefinition(true)).toQueryIrJson().toByteArray(Charsets.UTF_8)) }
        check(QueryExecution.execute(snapshot, MethodQuery(MethodPredicate.constant(true))).executionStatus == 0)
    }
    NativeEngine.openRawDexSet(arrayOf(bytes), arrayOf("one")).use { snapshot ->
        unsupported { snapshot.queryMethods(EntityQuery(EntityRelation.CLASS_DEFS).toQueryIrJson().toByteArray(Charsets.UTF_8)) }
    }
    System.err.println("PASS entity roots, applicability, UTF-16 bounds and unsupported JNI")
}
