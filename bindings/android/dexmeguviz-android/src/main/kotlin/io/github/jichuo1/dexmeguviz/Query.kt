package io.github.jichuo1.dexmeguviz

/** Limited method_defs QueryIR v1 writer. It does not run a query or create a QueryID. */
public enum class TextOperation(internal val wire: String) {
    EXACT("exact"), CONTAINS("contains"), PREFIX("prefix")
}

public enum class MethodTextField(internal val wire: String) {
    NAME("name"), OWNER("owner"), PROTOTYPE("prototype"), RETURN_TYPE("return_type")
}

public enum class RawFlagOperation(internal val wire: String) {
    CONTAINS("flags_contains"), EXACT("flags_exact"), ANY("flags_any")
}

public enum class QueryIntent(internal val wire: String) {
    ENUMERATE("enumerate"), EXISTS("exists"), UNIQUE("unique")
}

/** DEX access_flags are raw uint32 bits, not Java reflection modifiers. */
public class RawDexFlags(public val bits: Long) {
    init { require(bits in 0L..0xffffffffL) { "raw DEX flags must fit uint32" } }
}

/** A predicate constructed only from the subset understood by this writer. */
public class MethodPredicate private constructor(internal val json: String) {
    private var jsonNodes: Long = 1
    private var jsonDepth: Int = 0
    private var alternativeJson: String? = null
    private var alternativeNodes: Long = 1
    private var alternativeDepth: Int = 0

    internal fun jsonWithin(maxBytes: Int): String {
        val alternate = alternativeJson
        if (json.length <= maxBytes && (jsonNodes <= 16378 || alternate == null || alternate.length > maxBytes || alternativeNodes > 16378)) return json
        if (alternate != null && alternate.length <= maxBytes) return alternate
        require(json.length <= maxBytes) { "Selected QueryIR encoding exceeds 64 KiB; try textValue for an explicit mixed form" }
        return json
    }

    public companion object {
        // Every fragment is ASCII, so its UTF-16 length equals its UTF-8 byte length.
        private const val MAX_QUERY_JSON_BYTES = 65536
        // Root object and its five non-predicate values occupy six JSON nodes.
        private const val MAX_PREDICATE_NODES = 16378L
        // The predicate is the root object's child, at JSON depth one.
        private const val MAX_PREDICATE_DEPTH = 31
        private const val HEX = "0123456789abcdef"
        private fun make(primary: String?, nodes: Long, depth: Int,
                         alternate: String?, alternateNodes: Long, alternateDepth: Int): MethodPredicate {
            val first = primary != null && depth <= MAX_PREDICATE_DEPTH
            val second = alternate != null && alternateDepth <= MAX_PREDICATE_DEPTH
            require(first || second) { "Selected QueryIR encoding exceeds size or nesting limit; try textValue for an explicit mixed form" }
            val useAlternate = second && (!first || (nodes > MAX_PREDICATE_NODES && alternateNodes <= MAX_PREDICATE_NODES))
            val result = MethodPredicate(if (useAlternate) alternate!! else primary!!)
            result.jsonNodes = if (useAlternate) alternateNodes else nodes
            result.jsonDepth = if (useAlternate) alternateDepth else depth
            if (!useAlternate && second && alternate != primary) {
                result.alternativeJson = alternate
                result.alternativeNodes = alternateNodes
                result.alternativeDepth = alternateDepth
            }
            return result
        }

        private fun escapedSize(code: Int): Int = when {
            code in 0x20..0x7f && code != 0x22 && code != 0x5c -> 1
            code == 0x22 || code == 0x5c || code == 8 || code == 9 || code == 10 || code == 12 || code == 13 -> 2
            else -> 6
        }

        private fun appendEscaped(out: StringBuilder, code: Int) {
            when {
                code in 0x20..0x7f && code != 0x22 && code != 0x5c -> out.append(code.toChar())
                code == 0x22 || code == 0x5c -> out.append('\\').append(code.toChar())
                code == 8 -> out.append("\\b")
                code == 9 -> out.append("\\t")
                code == 10 -> out.append("\\n")
                code == 12 -> out.append("\\f")
                code == 13 -> out.append("\\r")
                else -> {
                    out.append("\\u")
                    out.append(HEX[(code ushr 12) and 15]).append(HEX[(code ushr 8) and 15])
                    out.append(HEX[(code ushr 4) and 15]).append(HEX[code and 15])
                }
            }
        }

        /** Text preserves UTF-16 code units, including NUL and unpaired surrogates. */
        public fun text(field: MethodTextField, operation: TextOperation, value: String,
                        asciiCaseInsensitive: Boolean = false): MethodPredicate =
            textWithEncoding(field, operation, value, asciiCaseInsensitive, false)

        /** Force JSON string encoding when callers need to choose a mixed representation. */
        public fun textValue(field: MethodTextField, operation: TextOperation, value: String,
                             asciiCaseInsensitive: Boolean = false): MethodPredicate =
            textWithEncoding(field, operation, value, asciiCaseInsensitive, true)

        private fun textWithEncoding(field: MethodTextField, operation: TextOperation, value: String,
                                     asciiCaseInsensitive: Boolean, forceValue: Boolean): MethodPredicate =
            textWithEncodingWire(field.wire, operation, value, asciiCaseInsensitive, forceValue)

        // Shared by the entity writer. A closed enum also constrains the JVM-visible internal method.
        internal fun entityText(field: EntityTextField, operation: TextOperation, value: String,
                                asciiCaseInsensitive: Boolean, forceValue: Boolean): MethodPredicate =
            textWithEncodingWire(field.wire, operation, value, asciiCaseInsensitive, forceValue)

        internal fun localDefinition(value: Boolean): MethodPredicate =
            make("{\"has_local_definition\":$value}", 2, 1, null, 0, 0)

        private fun textWithEncodingWire(wire: String, operation: TextOperation, value: String,
                                         asciiCaseInsensitive: Boolean, forceValue: Boolean): MethodPredicate {
            val arrayPrefix = "{\"$wire\":{\"op\":\"${operation.wire}\",\"u16\":["
            val arraySuffix = "],\"ascii_case_insensitive\":$asciiCaseInsensitive}}"
            val textPrefix = "{\"$wire\":{\"op\":\"${operation.wire}\",\"value\":\""
            val textSuffix = "\",\"ascii_case_insensitive\":$asciiCaseInsensitive}}"
            // Each code unit needs at least one output byte in either encoding.
            require(value.length <= MAX_QUERY_JSON_BYTES) { "QueryIR JSON exceeds 64 KiB" }
            var arrayLength = arrayPrefix.length + arraySuffix.length
            var textLength = textPrefix.length + textSuffix.length
            value.forEachIndexed { i, unit ->
                val code = unit.code
                val digits = when {
                    code < 10 -> 1
                    code < 100 -> 2
                    code < 1000 -> 3
                    code < 10000 -> 4
                    else -> 5
                }
                if (arrayLength <= MAX_QUERY_JSON_BYTES) arrayLength += digits + if (i == 0) 0 else 1
                if (textLength <= MAX_QUERY_JSON_BYTES) textLength += escapedSize(code)
            }
            val array = if (arrayLength <= MAX_QUERY_JSON_BYTES) {
                val out = StringBuilder(arrayLength).append(arrayPrefix)
                value.forEachIndexed { i, unit -> if (i != 0) out.append(','); out.append(unit.code) }
                out.append(arraySuffix).toString()
            } else null
            val text = if (textLength <= MAX_QUERY_JSON_BYTES) {
                val out = StringBuilder(textLength).append(textPrefix)
                value.forEach { appendEscaped(out, it.code) }
                out.append(textSuffix).toString()
            } else null
            if (forceValue) return make(text, 5, 2, null, 0, 0)
            return make(array, 5L + value.length, if (value.isEmpty()) 2 else 3, text, 5, 2)
        }

        public fun flags(operation: RawFlagOperation, value: RawDexFlags): MethodPredicate =
            make("{\"${operation.wire}\":${value.bits}}", 2, 1, null, 0, 0)

        /** Match the declaration owner's raw DEX access_flags, not Java modifiers. */
        public fun ownerFlags(operation: RawFlagOperation, value: RawDexFlags): MethodPredicate =
            make("{\"owner_flags\":{\"mode\":\"${operation.wire.removePrefix("flags_")}\",\"value\":${value.bits},\"domain\":\"dex\"}}", 5, 2, null, 0, 0)

        /** Exact or inclusive parameter-count bounds, in the native uint32 domain. */
        public fun parameterCount(exact: Long): MethodPredicate {
            require(exact in 0L..0xffffffffL) { "parameter count must fit uint32" }
            return make("{\"param_count\":$exact}", 2, 1, null, 0, 0)
        }
        public fun parameterCount(minimum: Long, maximum: Long): MethodPredicate {
            require(minimum in 0L..0xffffffffL && maximum in minimum..0xffffffffL) { "invalid parameter count range" }
            return make("{\"param_count\":{\"min\":$minimum,\"max\":$maximum}}", 4, 2, null, 0, 0)
        }

        /** Match a single positional parameter; an out-of-range index does not match. */
        public fun parameter(index: Long, operation: TextOperation, value: String,
                             asciiCaseInsensitive: Boolean = false): MethodPredicate {
            require(index in 0L..0xffffffffL) { "parameter index must fit uint32" }
            return reframeText(operation, value, asciiCaseInsensitive,
                "{\"parameter\":{\"index\":$index,\"type\":", "}}", 2, 1)
        }

        /** Match a const-string use in the method body, not mere string-pool presence. */
        public fun usesString(operation: TextOperation, value: String,
                              asciiCaseInsensitive: Boolean = false): MethodPredicate =
            reframeText(operation, value, asciiCaseInsensitive,
                "{\"using_strings\":{\"all\":[", "]}}", 2, 2)

        /** Kinds describe DEX declarations, not runtime reflection bindings. */
        public fun constructor(): MethodPredicate = make("{\"kind\":\"constructor\"}", 2, 1, null, 0, 0)
        public fun classInitializer(): MethodPredicate = make("{\"kind\":\"clinit\"}", 2, 1, null, 0, 0)
        public fun normalMethod(): MethodPredicate = make("{\"kind\":\"normal\"}", 2, 1, null, 0, 0)

        // Reuse the existing bounded UTF-16 encoder and carry both candidates
        // through the enclosing JSON shape without changing their wire values.
        private fun reframeText(operation: TextOperation, value: String, asciiCaseInsensitive: Boolean,
                                prefix: String, suffix: String, extraNodes: Long, extraDepth: Int): MethodPredicate {
            val base = textWithEncoding(MethodTextField.NAME, operation, value, asciiCaseInsensitive, false)
            val oldPrefix = "{\"name\":"
            fun wrap(text: String): String? {
                check(text.startsWith(oldPrefix) && text.endsWith('}'))
                val length = prefix.length.toLong() + text.length - oldPrefix.length - 1 + suffix.length
                if (length > MAX_QUERY_JSON_BYTES) return null
                return StringBuilder(length.toInt()).append(prefix)
                    .append(text, oldPrefix.length, text.length - 1).append(suffix).toString()
            }
            val primary = if (base.jsonDepth + extraDepth <= MAX_PREDICATE_DEPTH) wrap(base.json) else null
            val other = base.alternativeJson
            val alternate = if (other != null && base.alternativeDepth + extraDepth <= MAX_PREDICATE_DEPTH) wrap(other) else null
            return make(primary, base.jsonNodes + extraNodes, base.jsonDepth + extraDepth,
                alternate, base.alternativeNodes + extraNodes, base.alternativeDepth + extraDepth)
        }

        /** Empty all is true; empty any is false, as defined by QueryIR v1. */
        public fun all(vararg items: MethodPredicate): MethodPredicate = composite("all", items)
        public fun any(vararg items: MethodPredicate): MethodPredicate = composite("any", items)
        public fun not(item: MethodPredicate): MethodPredicate {
            val prefix = "{\"not\":"
            fun wrap(text: String): String? {
                val length = prefix.length.toLong() + text.length + 1
                if (length > MAX_QUERY_JSON_BYTES) return null
                return StringBuilder(length.toInt()).append(prefix).append(text).append('}').toString()
            }
            val primary = if (item.jsonDepth < MAX_PREDICATE_DEPTH) wrap(item.json) else null
            val alternate = item.alternativeJson
            val alternative = if (alternate != null && item.alternativeDepth < MAX_PREDICATE_DEPTH) wrap(alternate) else null
            return make(primary, item.jsonNodes + 1, item.jsonDepth + 1,
                        alternative, item.alternativeNodes + 1, item.alternativeDepth + 1)
        }
        public fun constant(value: Boolean): MethodPredicate = make(value.toString(), 1, 0, null, 0, 0)

        private fun composite(kind: String, items: Array<out MethodPredicate>): MethodPredicate {
            val prefix = "{\"$kind\":["
            val suffix = "]}"
            val overhead = prefix.length + suffix.length
            // Every nonempty fragment has at least one byte and each separator has two.
            require(items.size <= (MAX_QUERY_JSON_BYTES - overhead + 2) / 3) { "QueryIR JSON exceeds 64 KiB" }
            var primaryLength = overhead.toLong()
            var alternativeLength = overhead.toLong()
            var primaryNodes = 2L
            var alternativeNodes = 2L
            var primaryDepth = 1
            var alternativeDepth = 1
            items.forEachIndexed { i, item ->
                val separator = if (i == 0) 0 else 2
                primaryLength += separator + item.json.length
                primaryNodes += item.jsonNodes
                primaryDepth = maxOf(primaryDepth, 2 + item.jsonDepth)
                alternativeLength += separator + (item.alternativeJson ?: item.json).length
                alternativeNodes += if (item.alternativeJson == null) item.jsonNodes else item.alternativeNodes
                alternativeDepth = maxOf(alternativeDepth, 2 + if (item.alternativeJson == null) item.jsonDepth else item.alternativeDepth)
            }
            fun render(alternative: Boolean, length: Long): String? {
                if (length > MAX_QUERY_JSON_BYTES) return null
                val out = StringBuilder(length.toInt()).append(prefix)
                items.forEachIndexed { i, item ->
                    if (i != 0) out.append(", ")
                    out.append(if (alternative) item.alternativeJson ?: item.json else item.json)
                }
                return out.append(suffix).toString()
            }
            val primary = if (primaryDepth <= MAX_PREDICATE_DEPTH) render(false, primaryLength) else null
            var alternative = if (alternativeDepth <= MAX_PREDICATE_DEPTH) render(true, alternativeLength) else null
            // Retain a byte-saving mixture even when the primary fragment fits:
            // the enclosing query may have less room than the fragment limit.
            // Each chosen child is no larger and uses no more JSON nodes.
            fun savesBytes(item: MethodPredicate): Boolean {
                val other = item.alternativeJson ?: return false
                return item.alternativeDepth + 2 <= MAX_PREDICATE_DEPTH &&
                    item.alternativeNodes <= item.jsonNodes && other.length < item.json.length
            }
            var savingLength = overhead.toLong()
            var savingNodes = 2L
            var savingDepth = 1
            var hasSavings = false
            items.forEachIndexed { i, item ->
                val useOther = savesBytes(item)
                hasSavings = hasSavings || useOther
                savingLength += (if (i == 0) 0 else 2) + (if (useOther) item.alternativeJson!! else item.json).length
                savingNodes += if (useOther) item.alternativeNodes else item.jsonNodes
                savingDepth = maxOf(savingDepth, 2 + if (useOther) item.alternativeDepth else item.jsonDepth)
            }
            // Keep the existing alternative unless this candidate dominates it.
            // Incomparable mixtures remain available through explicit textValue.
            if (hasSavings && savingLength <= MAX_QUERY_JSON_BYTES && savingDepth <= MAX_PREDICATE_DEPTH &&
                (alternative == null || (savingLength <= alternative.length && savingNodes <= alternativeNodes && savingDepth <= alternativeDepth))) {
                val out = StringBuilder(savingLength.toInt()).append(prefix)
                items.forEachIndexed { i, item ->
                    if (i != 0) out.append(", ")
                    out.append(if (savesBytes(item)) item.alternativeJson!! else item.json)
                }
                alternative = out.append(suffix).toString()
                alternativeNodes = savingNodes
                alternativeDepth = savingDepth
            }
            if (primary == null || primaryNodes > MAX_PREDICATE_NODES) {
                // Bounded linear fallback: first resolve depth and byte-saving
                // switches, then select remaining node-saving switches in order.
                // It does not claim an exhaustive search of every possible mix.
                val selected = BooleanArray(items.size)
                var mixedLength = primaryLength
                var mixedNodes = primaryNodes
                var possible = true
                fun choose(i: Int) {
                    val item = items[i]
                    val other = item.alternativeJson!!
                    selected[i] = true
                    mixedLength += other.length.toLong() - item.json.length
                    mixedNodes += item.alternativeNodes - item.jsonNodes
                }
                for (i in items.indices) {
                    val item = items[i]
                    if (item.jsonDepth + 2 <= MAX_PREDICATE_DEPTH) continue
                    if (item.alternativeJson == null || item.alternativeDepth + 2 > MAX_PREDICATE_DEPTH) {
                        possible = false; break
                    }
                    choose(i)
                }
                if (possible) for (i in items.indices) {
                    val item = items[i]; val other = item.alternativeJson
                    if (!selected[i] && other != null && item.alternativeNodes <= item.jsonNodes &&
                        item.alternativeDepth + 2 <= MAX_PREDICATE_DEPTH && other.length <= item.json.length) choose(i)
                }
                if (possible && mixedLength <= MAX_QUERY_JSON_BYTES && mixedNodes > MAX_PREDICATE_NODES) {
                    for (i in items.indices) {
                        if (mixedNodes <= MAX_PREDICATE_NODES) break
                        val item = items[i]; val other = item.alternativeJson
                        if (!selected[i] && other != null && item.alternativeNodes < item.jsonNodes &&
                            item.alternativeDepth + 2 <= MAX_PREDICATE_DEPTH &&
                            mixedLength + other.length - item.json.length <= MAX_QUERY_JSON_BYTES) choose(i)
                    }
                }
                if (possible && mixedLength <= MAX_QUERY_JSON_BYTES && mixedNodes <= MAX_PREDICATE_NODES) {
                    var mixedDepth = 1
                    val out = StringBuilder(mixedLength.toInt()).append(prefix)
                    items.forEachIndexed { i, item ->
                        if (i != 0) out.append(", ")
                        out.append(if (selected[i]) item.alternativeJson!! else item.json)
                        mixedDepth = maxOf(mixedDepth, 2 + if (selected[i]) item.alternativeDepth else item.jsonDepth)
                    }
                    return make(out.append(suffix).toString(), mixedNodes, mixedDepth,
                                alternative, alternativeNodes, alternativeDepth)
                }
            }
            return make(primary, primaryNodes, primaryDepth, alternative, alternativeNodes, alternativeDepth)
        }
    }
}

/** The core validates additional complexity limits when it compiles this JSON. */
public class MethodQuery(
    public val where: MethodPredicate,
    public val intent: QueryIntent = QueryIntent.ENUMERATE,
    public val maxResults: Int = 4096,
    public val maxWork: Long = 100000000L
) {
    init {
        require(maxResults in 1..100000) { "maxResults must be in 1..100000" }
        require(maxWork > 0) { "maxWork must be positive" }
    }

    /** ASCII-only JSON; Kotlin does not derive or promise the native canonical ID. */
    public fun toQueryIrJson(): String {
        val prefix = "{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":"
        val suffix = ",\"intent\":\"${intent.wire}\",\"max_results\":$maxResults,\"max_work\":$maxWork}"
        val capacity = 65536 - prefix.length - suffix.length
        val predicate = where.jsonWithin(capacity)
        val length = prefix.length + predicate.length + suffix.length
        return StringBuilder(length).append(prefix).append(predicate).append(suffix).toString()
    }
}

/** Limited method-v1 and direct-entity bridges require an explicit snapshot. */
public object QueryExecution {
    /** The legacy snapshot-free entry point remains unsupported. */
    public val supported: Boolean get() = false
    public fun execute(query: MethodQuery): Nothing {
        throw UnsupportedOperationException("snapshot-free Kotlin query execution is not supported")
    }
    /** Returns copied candidates and native status; no independent witness is included. */
    public fun execute(snapshot: NativeEngine.Snapshot, query: MethodQuery): NativeEngine.QueryResult {
        return snapshot.queryMethods(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    }
    /** Uses the ordered, explicitly incomplete raw-DEX set and preserves row origins. */
    public fun execute(snapshot: NativeEngine.SourceSetSnapshot, query: MethodQuery): NativeEngine.QueryResult {
        return snapshot.queryMethods(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    }

    /** Executes a direct entity metadata query and returns copied source-local rows. */
    public fun execute(snapshot: NativeEngine.Snapshot, query: EntityQuery): NativeEngine.EntityResult {
        return snapshot.queryEntities(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    }
    public fun execute(snapshot: NativeEngine.SourceSetSnapshot, query: EntityQuery): NativeEngine.EntityResult {
        return snapshot.queryEntities(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    }

    /** Starts a bounded provisional method batch stream; drain it before checking the terminal status. */
    public fun startMethodJob(snapshot: NativeEngine.Snapshot, query: MethodQuery, batchSize: Int,
                              maxQueuedBatches: Int, deadlineAfterMs: Long): NativeEngine.Job =
        snapshot.startMethodJob(query.toQueryIrJson().toByteArray(Charsets.UTF_8), batchSize, maxQueuedBatches, deadlineAfterMs)

    public fun startMethodJob(snapshot: NativeEngine.SourceSetSnapshot, query: MethodQuery, batchSize: Int,
                              maxQueuedBatches: Int, deadlineAfterMs: Long): NativeEngine.Job =
        snapshot.startMethodJob(query.toQueryIrJson().toByteArray(Charsets.UTF_8), batchSize, maxQueuedBatches, deadlineAfterMs)

    /** Starts a bounded provisional entity batch stream; drain it before checking the terminal status. */
    public fun startEntityJob(snapshot: NativeEngine.Snapshot, query: EntityQuery, batchSize: Int,
                              maxQueuedBatches: Int, deadlineAfterMs: Long): NativeEngine.EntityJob =
        snapshot.startEntityJob(query.toQueryIrJson().toByteArray(Charsets.UTF_8), batchSize, maxQueuedBatches, deadlineAfterMs)

    public fun startEntityJob(snapshot: NativeEngine.SourceSetSnapshot, query: EntityQuery, batchSize: Int,
                              maxQueuedBatches: Int, deadlineAfterMs: Long): NativeEngine.EntityJob =
        snapshot.startEntityJob(query.toQueryIrJson().toByteArray(Charsets.UTF_8), batchSize, maxQueuedBatches, deadlineAfterMs)

}

