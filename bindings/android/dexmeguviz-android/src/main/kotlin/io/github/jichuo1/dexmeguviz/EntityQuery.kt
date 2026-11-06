package io.github.jichuo1.dexmeguviz

/** Static DEX directory roots; indices and identities remain source-local. */
public enum class EntityRelation(internal val wire: String, internal val mask: Int) {
    METHOD_DEFS("method_defs", 1), CLASS_DEFS("class_defs", 2), FIELD_DEFS("field_defs", 4),
    METHOD_REFS("method_refs", 8), FIELD_REFS("field_refs", 16), TYPE_REFS("type_refs", 32),
    STRING_VALUES("string_values", 64)
}

/** Supported text fields and their applicable roots, checked even inside boolean branches. */
public enum class EntityTextField(internal val wire: String, internal val mask: Int) {
    NAME("name", 29), OWNER("owner", 29), PROTOTYPE("prototype", 9), RETURN_TYPE("return_type", 9),
    DESCRIPTOR("descriptor", 34), TYPE("type", 20), VALUE("value", 64),
    SUPERCLASS("superclass", 63), DIRECT_INTERFACE("direct_interface", 63)
}

/** A static predicate; absent local definitions retain the core's Unknown semantics. */
public class EntityPredicate private constructor(internal val body: MethodPredicate, internal val roots: Int) {
    public companion object {
        public fun text(field: EntityTextField, operation: TextOperation, value: String,
                        asciiCaseInsensitive: Boolean = false): EntityPredicate =
            EntityPredicate(MethodPredicate.entityText(field, operation, value, asciiCaseInsensitive, false), field.mask)

        /** Explicit JSON string form for caller-selected long/mixed UTF-16 predicates. */
        public fun textValue(field: EntityTextField, operation: TextOperation, value: String,
                             asciiCaseInsensitive: Boolean = false): EntityPredicate =
            EntityPredicate(MethodPredicate.entityText(field, operation, value, asciiCaseInsensitive, true), field.mask)

        public fun flags(operation: RawFlagOperation, value: RawDexFlags): EntityPredicate =
            EntityPredicate(MethodPredicate.flags(operation, value), 63)
        public fun ownerFlags(operation: RawFlagOperation, value: RawDexFlags): EntityPredicate =
            EntityPredicate(MethodPredicate.ownerFlags(operation, value), 29)
        public fun hasLocalDefinition(value: Boolean): EntityPredicate =
            EntityPredicate(MethodPredicate.localDefinition(value), 63)
        public fun parameterCount(exact: Long): EntityPredicate = EntityPredicate(MethodPredicate.parameterCount(exact), 9)
        public fun parameterCount(minimum: Long, maximum: Long): EntityPredicate =
            EntityPredicate(MethodPredicate.parameterCount(minimum, maximum), 9)
        public fun parameter(index: Long, operation: TextOperation, value: String,
                             asciiCaseInsensitive: Boolean = false): EntityPredicate =
            EntityPredicate(MethodPredicate.parameter(index, operation, value, asciiCaseInsensitive), 9)
        public fun constructor(): EntityPredicate = EntityPredicate(MethodPredicate.constructor(), 9)
        public fun classInitializer(): EntityPredicate = EntityPredicate(MethodPredicate.classInitializer(), 9)
        public fun normalMethod(): EntityPredicate = EntityPredicate(MethodPredicate.normalMethod(), 9)
        public fun constant(value: Boolean): EntityPredicate = EntityPredicate(MethodPredicate.constant(value), 127)
        public fun not(item: EntityPredicate): EntityPredicate = EntityPredicate(MethodPredicate.not(item.body), item.roots)

        public fun all(vararg items: EntityPredicate): EntityPredicate = combine(true, items)
        public fun any(vararg items: EntityPredicate): EntityPredicate = combine(false, items)

        private fun combine(all: Boolean, items: Array<out EntityPredicate>): EntityPredicate {
            // The shared writer also enforces fragment byte, depth and node limits.
            require(items.size <= 21846) { "QueryIR JSON exceeds 64 KiB" }
            var roots = 127
            val bodies = Array(items.size) { i -> roots = roots and items[i].roots; items[i].body }
            val body = if (all) MethodPredicate.all(*bodies) else MethodPredicate.any(*bodies)
            return EntityPredicate(body, roots)
        }
    }
}

/** Limited direct-entity JSON writer; native compilation remains authoritative. */
public class EntityQuery(
    public val relation: EntityRelation,
    public val where: EntityPredicate = EntityPredicate.constant(true),
    public val intent: QueryIntent = QueryIntent.ENUMERATE,
    public val maxResults: Int = 4096,
    public val maxWork: Long = 100000000L
) {
    init {
        require((where.roots and relation.mask) != 0) { "predicate does not apply to entity relation" }
        require(maxResults in 1..100000) { "maxResults must be in 1..100000" }
        require(maxWork > 0) { "maxWork must be positive" }
    }

    /** Output is ASCII JSON; QueryID and coverage are determined by the core. */
    public fun toQueryIrJson(): String {
        val prefix = "{\"schema_version\":1,\"relation\":\"${relation.wire}\",\"where\":"
        val suffix = ",\"intent\":\"${intent.wire}\",\"max_results\":$maxResults,\"max_work\":$maxWork}"
        val predicate = where.body.jsonWithin(65536 - prefix.length - suffix.length)
        return StringBuilder(prefix.length + predicate.length + suffix.length)
            .append(prefix).append(predicate).append(suffix).toString()
    }
}
