package io.github.jichuo1.dexmeguviz

/** target_ref compares an event with a reference in the same source occurrence. */
public enum class UseReferenceTarget(internal val useWire: String, internal val family: Int, internal val entity: EntityRelation) {
    METHOD_REFERENCE("invoke_sites", 1, EntityRelation.METHOD_REFS),
    FIELD_REFERENCE("field_uses", 2, EntityRelation.FIELD_REFS),
    STRING_VALUE("string_uses", 4, EntityRelation.STRING_VALUES)
}

/** One v4 local target-reference Join/SemiJoin; it does not resolve runtime targets. */
public class UseTargetReferenceQuery(
    public val target: UseReferenceTarget,
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
    /** ASCII QueryIR; native core decides identity, coverage and results. */
    public fun toQueryIrJson(): String {
        val uses = "{\"op\":\"scan\",\"relation\":\"${target.useWire}\",\"where\":${useWhere.json}}"
        val entityPrefix = "{\"op\":\"scan\",\"relation\":\"${target.entity.wire}\",\"where\":"
        val op = if (join == UseSymbolJoin.JOIN) "join" else "semi_join"
        fun render(entity: String): String {
            val left = if (direction == UseSymbolDirection.USE_FIRST) uses else entity
            val right = if (direction == UseSymbolDirection.USE_FIRST) entity else uses
            return "{\"schema_version\":1,\"relation\":{\"op\":\"$op\",\"on\":\"target_ref\",\"left\":$left,\"right\":$right},\"intent\":\"${intent.wire}\",\"max_results\":$maxResults,\"max_work\":$maxWork}"
        }
        val overhead = render(entityPrefix + "}").length
        require(overhead <= 65536) { "QueryIR JSON exceeds 64 KiB" }
        val predicate = targetWhere.body.jsonWithin(65536 - overhead)
        val result = render(entityPrefix + predicate + "}")
        require(result.length <= 65536) { "QueryIR JSON exceeds 64 KiB" }
        return result
    }
}

/** Existing synchronous v4 bridge; source completeness is not inferred. */
public object TypedUseTargetReferenceExecution {
    public fun execute(snapshot: NativeEngine.Snapshot, query: UseTargetReferenceQuery): UseGraphResult =
        UseGraphQueryExecution.execute(snapshot, query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun execute(snapshot: NativeEngine.SourceSetSnapshot, query: UseTargetReferenceQuery): UseGraphResult =
        UseGraphQueryExecution.execute(snapshot, query.toQueryIrJson().toByteArray(Charsets.UTF_8))
}
