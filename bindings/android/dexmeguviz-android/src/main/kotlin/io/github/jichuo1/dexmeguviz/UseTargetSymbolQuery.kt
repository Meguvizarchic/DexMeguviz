package io.github.jichuo1.dexmeguviz

/** A static target relation and its corresponding use-event relation. */
public enum class UseSymbolTarget(internal val useWire: String, internal val family: Int, internal val entity: EntityRelation) {
    METHOD_DEFINITION("invoke_sites", 1, EntityRelation.METHOD_DEFS),
    METHOD_REFERENCE("invoke_sites", 1, EntityRelation.METHOD_REFS),
    FIELD_DEFINITION("field_uses", 2, EntityRelation.FIELD_DEFS),
    FIELD_REFERENCE("field_uses", 2, EntityRelation.FIELD_REFS),
    STRING_VALUE("string_uses", 4, EntityRelation.STRING_VALUES)
}
public enum class UseSymbolDirection { USE_FIRST, TARGET_FIRST }
public enum class UseSymbolJoin { JOIN, SEMI_JOIN }
public enum class UseEventTextField(internal val wire: String) { CALLER_NAME("caller_name"), CALLER_OWNER("caller_owner") }
public enum class UseEventNumberField(internal val wire: String) { PC("pc"), OPCODE("opcode"), TARGET_INDEX("target_index") }
public enum class UseEventTargetDomain(internal val wire: String, internal val family: Int) {
    METHOD_REFERENCE("method_ref", 1), METHOD_AND_PROTO("method_and_proto", 1), CALL_SITE("call_site", 1),
    FIELD_REFERENCE("field_ref", 2), STRING_VALUE("string_value", 4)
}

/** Immutable predicate for use events. Text is encoded as UTF-16 code units. */
public class UseEventPredicate private constructor(internal val json: String, internal val families: Int) {
    public companion object {
        public fun constant(value: Boolean): UseEventPredicate = UseEventPredicate(value.toString(), 7)
        public fun text(field: UseEventTextField, operation: TextOperation, value: String,
                        asciiCaseInsensitive: Boolean = false): UseEventPredicate {
            val original = MethodPredicate.text(MethodTextField.NAME, operation, value, asciiCaseInsensitive).jsonWithin(65536)
            val prefix = "{\"name\":"
            check(original.startsWith(prefix))
            val json = "{\"${field.wire}\":" + original.substring(prefix.length)
            require(json.length <= 65536) { "QueryIR JSON exceeds 64 KiB" }
            return UseEventPredicate(json, 7)
        }
        public fun number(field: UseEventNumberField, value: Long): UseEventPredicate = number(field, value, value)
        public fun number(field: UseEventNumberField, minimum: Long, maximum: Long): UseEventPredicate {
            require(minimum in 0L..0xffffffffL && maximum in minimum..0xffffffffL) { "invalid uint32 range" }
            val value = if (minimum == maximum) minimum.toString() else "{\"min\":$minimum,\"max\":$maximum}"
            return UseEventPredicate("{\"${field.wire}\":$value}", 7)
        }
        public fun targetDomain(domain: UseEventTargetDomain): UseEventPredicate =
            UseEventPredicate("{\"target_domain\":\"${domain.wire}\"}", domain.family)
        public fun not(item: UseEventPredicate): UseEventPredicate {
            require(item.json.length <= 65528) { "QueryIR JSON exceeds 64 KiB" }
            return UseEventPredicate("{\"not\":${item.json}}", item.families)
        }
        public fun all(vararg items: UseEventPredicate): UseEventPredicate = combine("all", items)
        public fun any(vararg items: UseEventPredicate): UseEventPredicate = combine("any", items)
        private fun combine(op: String, items: Array<out UseEventPredicate>): UseEventPredicate {
            require(items.size <= 21846) { "QueryIR JSON exceeds 64 KiB" }
            var length = op.length.toLong() + 7L + maxOf(items.size - 1, 0)
            var families = 7
            for (item in items) { length += item.json.length; families = families and item.families }
            require(length <= 65536) { "QueryIR JSON exceeds 64 KiB" }
            return UseEventPredicate("{\"$op\":[" + items.joinToString(",") { it.json } + "]}", families)
        }
    }
}

/** One v16 Join/SemiJoin of use events and their static target symbols. */
public class UseTargetSymbolQuery(
    public val target: UseSymbolTarget,
    public val useWhere: UseEventPredicate = UseEventPredicate.constant(true),
    public val targetWhere: EntityPredicate = EntityPredicate.constant(true),
    public val direction: UseSymbolDirection = UseSymbolDirection.USE_FIRST,
    public val join: UseSymbolJoin = UseSymbolJoin.JOIN,
    public val intent: QueryIntent = QueryIntent.ENUMERATE,
    public val maxResults: Int = 4096,
    public val maxWork: Long = 100000000L
) {
    init {
        require((useWhere.families and target.family) != 0) { "use predicate does not apply to target family" }
        require((targetWhere.roots and target.entity.mask) != 0) { "entity predicate does not apply to target relation" }
        require(maxResults in 1..100000 && maxWork > 0) { "invalid query bounds" }
    }
    /** ASCII JSON; IDs, capability checks and result completeness belong to native core. */
    public fun toQueryIrJson(): String {
        val uses = "{\"op\":\"scan\",\"relation\":\"${target.useWire}\",\"where\":${useWhere.json}}"
        val entityPrefix = "{\"op\":\"scan\",\"relation\":\"${target.entity.wire}\",\"where\":"
        val op = if (join == UseSymbolJoin.JOIN) "join" else "semi_join"
        fun render(entity: String): String {
            val left = if (direction == UseSymbolDirection.USE_FIRST) uses else entity
            val right = if (direction == UseSymbolDirection.USE_FIRST) entity else uses
            return "{\"schema_version\":1,\"required_capabilities\":[\"use_target_symbol\"],\"relation\":{\"op\":\"$op\",\"on\":\"target_symbol\",\"left\":$left,\"right\":$right},\"intent\":\"${intent.wire}\",\"max_results\":$maxResults,\"max_work\":$maxWork}"
        }
        val overhead = render(entityPrefix + "}").length
        require(overhead <= 65536) { "QueryIR JSON exceeds 64 KiB" }
        val predicate = targetWhere.body.jsonWithin(65536 - overhead)
        val result = render(entityPrefix + predicate + "}")
        require(result.length <= 65536) { "QueryIR JSON exceeds 64 KiB" }
        return result
    }
}

/** Synchronous use-graph entry point; Android source scope stays incomplete. */
public object TypedUseTargetSymbolExecution {
    public fun execute(snapshot: NativeEngine.Snapshot, query: UseTargetSymbolQuery): UseGraphResult =
        UseGraphQueryExecution.execute(snapshot, query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun execute(snapshot: NativeEngine.SourceSetSnapshot, query: UseTargetSymbolQuery): UseGraphResult =
        UseGraphQueryExecution.execute(snapshot, query.toQueryIrJson().toByteArray(Charsets.UTF_8))
}
