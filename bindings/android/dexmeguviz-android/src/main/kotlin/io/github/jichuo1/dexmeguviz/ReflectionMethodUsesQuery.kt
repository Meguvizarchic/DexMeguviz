package io.github.jichuo1.dexmeguviz

/** A bounded UTF-16 text matcher; the core defines the comparison semantics. */
public class StaticTextMatch(
    public val operation: TextOperation,
    public val value: String,
    public val asciiCaseInsensitive: Boolean = false
) {
    internal fun json(): String {
        val wrapper = MethodPredicate.text(MethodTextField.NAME, operation, value, asciiCaseInsensitive).jsonWithin(65536)
        val prefix = "{\"name\":"
        check(wrapper.startsWith(prefix) && wrapper.endsWith('}'))
        return wrapper.substring(prefix.length, wrapper.length - 1)
    }
}

public enum class InvokeReferenceKind(internal val wire: String) {
    METHOD_LIKE("method_like"), METHOD("method"), METHOD_AND_PROTO("method_and_proto"), CALL_SITE("call_site")
}

public enum class FieldUseAccess(internal val wire: String) { ANY("any"), READ("read"), WRITE("write") }

/** Static reference constraints; a call-site does not expose a bootstrap method symbol. */
public class InvokeTarget(
    public val owner: StaticTextMatch? = null,
    public val name: StaticTextMatch? = null,
    public val prototype: StaticTextMatch? = null,
    public val returnType: StaticTextMatch? = null,
    public val minParameters: Long? = null,
    public val maxParameters: Long? = null,
    public val referenceKind: InvokeReferenceKind = InvokeReferenceKind.METHOD_LIKE
) {
    init {
        require((minParameters == null && maxParameters == null) ||
            (minParameters != null && maxParameters != null && minParameters in 0L..0xffffffffL && maxParameters in minParameters..0xffffffffL)) { "invalid parameter range" }
        require(referenceKind != InvokeReferenceKind.CALL_SITE ||
            (owner == null && name == null && prototype == null && returnType == null && minParameters == null)) { "call-site symbols are unsupported" }
    }
    internal fun json(): String {
        val entries = ArrayList<String>()
        owner?.let { entries.add("\"owner\":" + it.json()) }
        name?.let { entries.add("\"name\":" + it.json()) }
        prototype?.let { entries.add("\"prototype\":" + it.json()) }
        returnType?.let { entries.add("\"return_type\":" + it.json()) }
        if (minParameters != null) entries.add("\"param_count\":{\"min\":$minParameters,\"max\":$maxParameters}")
        entries.add("\"reference_kind\":\"${referenceKind.wire}\"")
        return boundedJoin("{", "}", entries)
    }
}

public class FieldTarget(
    public val owner: StaticTextMatch? = null,
    public val name: StaticTextMatch? = null,
    public val type: StaticTextMatch? = null,
    public val access: FieldUseAccess = FieldUseAccess.ANY
) {
    internal fun json(): String {
        val entries = ArrayList<String>()
        owner?.let { entries.add("\"owner\":" + it.json()) }
        name?.let { entries.add("\"name\":" + it.json()) }
        type?.let { entries.add("\"type\":" + it.json()) }
        entries.add("\"access\":\"${access.wire}\"")
        return boundedJoin("{", "}", entries)
    }
}

private fun boundedJoin(prefix: String, suffix: String, items: List<String>): String {
    var length = prefix.length.toLong() + suffix.length + maxOf(items.size - 1, 0)
    for (item in items) length += item.length
    require(length <= 65536) { "QueryIR JSON exceeds 64 KiB" }
    return prefix + items.joinToString(",") + suffix
}

/** A v15 predicate; Unknown and short-circuit semantics remain native decisions. */
public class ReflectionMethodPredicate private constructor(
    internal val json: String, internal val hasReflection: Boolean, internal val hasUses: Boolean
) {
    public companion object {
        public fun metadata(value: MethodPredicate): ReflectionMethodPredicate =
            ReflectionMethodPredicate(value.jsonWithin(65536), false, false)
        public fun reflectionFlags(operation: RawFlagOperation, value: ReflectionFlags): ReflectionMethodPredicate =
            reflection(operation, value, false)
        public fun reflectionOwnerFlags(operation: RawFlagOperation, value: ReflectionFlags): ReflectionMethodPredicate =
            reflection(operation, value, true)
        private fun reflection(operation: RawFlagOperation, value: ReflectionFlags, owner: Boolean): ReflectionMethodPredicate {
            val field = if (owner) "owner_flags" else "flags"
            return ReflectionMethodPredicate("{\"$field\":{\"domain\":\"reflection\",\"mode\":\"${operation.wire.removePrefix("flags_")}\",\"value\":${value.bits}}}", true, false)
        }
        public fun stringsAll(vararg values: StaticTextMatch): ReflectionMethodPredicate =
            quantified("using_strings", "all", checkedMap(values) { it.json() })
        public fun stringsAny(vararg values: StaticTextMatch): ReflectionMethodPredicate =
            quantified("using_strings", "any", checkedMap(values) { it.json() })
        public fun invokesAll(vararg targets: InvokeTarget): ReflectionMethodPredicate =
            quantified("invokes", "all", checkedMap(targets) { it.json() })
        public fun invokesAny(vararg targets: InvokeTarget): ReflectionMethodPredicate =
            quantified("invokes", "any", checkedMap(targets) { it.json() })
        public fun fieldsAll(vararg targets: FieldTarget): ReflectionMethodPredicate =
            quantified("field_access", "all", checkedMap(targets) { it.json() })
        public fun fieldsAny(vararg targets: FieldTarget): ReflectionMethodPredicate =
            quantified("field_access", "any", checkedMap(targets) { it.json() })
        private fun <T> checkedMap(values: Array<out T>, render: (T) -> String): List<String> {
            require(values.isNotEmpty() && values.size <= 128) { "use matcher needs 1..128 items" }
            val result = ArrayList<String>(values.size)
            var length = 0L
            for (value in values) {
                val text = render(value)
                length += text.length
                require(length <= 65536) { "QueryIR JSON exceeds 64 KiB" }
                result.add(text)
            }
            return result
        }
        private fun quantified(field: String, operator: String, values: List<String>): ReflectionMethodPredicate {
            require(values.isNotEmpty() && values.size <= 128) { "use matcher needs 1..128 items" }
            return ReflectionMethodPredicate(boundedJoin("{\"$field\":{\"$operator\":[", "]}}", values), false, true)
        }
        public fun not(value: ReflectionMethodPredicate): ReflectionMethodPredicate =
            ReflectionMethodPredicate(boundedJoin("{\"not\":", "}", listOf(value.json)), value.hasReflection, value.hasUses)
        public fun all(vararg values: ReflectionMethodPredicate): ReflectionMethodPredicate = combine("all", values)
        public fun any(vararg values: ReflectionMethodPredicate): ReflectionMethodPredicate = combine("any", values)
        private fun combine(operator: String, values: Array<out ReflectionMethodPredicate>): ReflectionMethodPredicate {
            require(values.size <= 128) { "too many predicate branches" }
            return ReflectionMethodPredicate(boundedJoin("{\"$operator\":[", "]}", values.map { it.json }),
                values.any { it.hasReflection }, values.any { it.hasUses })
        }
    }
}

/** Typed direct method query; native compilation still checks JSON nodes and depth. */
public class ReflectionMethodUsesQuery(
    public val where: ReflectionMethodPredicate,
    public val intent: QueryIntent = QueryIntent.ENUMERATE,
    public val maxResults: Int = 4096,
    public val maxWork: Long = 100000000L
) {
    init {
        require(where.hasReflection && where.hasUses) { "v15 requires reflection flags and a use matcher" }
        require(maxResults in 1..4096 && maxWork in 1L..100000000L) { "JNI query limit exceeded" }
    }
    public fun toQueryIrJson(): String = boundedJoin(
        "{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":", "}",
        listOf(where.json, "\"intent\":\"${intent.wire}\"", "\"max_results\":$maxResults", "\"max_work\":$maxWork",
            "\"required_capabilities\":[\"reflection_flags_static\",\"reflection_method_uses\"]"))
}

/** Executes the typed v15 query through its dedicated bounded JNI entry points. */
public object TypedReflectionMethodUsesExecution {
    public fun execute(snapshot: NativeEngine.Snapshot, query: ReflectionMethodUsesQuery): NativeEngine.EntityResult =
        ReflectionMethodUsesExecution.execute(snapshot, query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun execute(snapshot: NativeEngine.SourceSetSnapshot, query: ReflectionMethodUsesQuery): NativeEngine.EntityResult =
        ReflectionMethodUsesExecution.execute(snapshot, query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun startJob(snapshot: NativeEngine.Snapshot, query: ReflectionMethodUsesQuery, batchSize: Int, maxQueuedBatches: Int, deadlineAfterMs: Long): NativeEngine.EntityJob =
        ReflectionMethodUsesExecution.startJob(snapshot, query.toQueryIrJson().toByteArray(Charsets.UTF_8), batchSize, maxQueuedBatches, deadlineAfterMs)
    public fun startJob(snapshot: NativeEngine.SourceSetSnapshot, query: ReflectionMethodUsesQuery, batchSize: Int, maxQueuedBatches: Int, deadlineAfterMs: Long): NativeEngine.EntityJob =
        ReflectionMethodUsesExecution.startJob(snapshot, query.toQueryIrJson().toByteArray(Charsets.UTF_8), batchSize, maxQueuedBatches, deadlineAfterMs)
}
