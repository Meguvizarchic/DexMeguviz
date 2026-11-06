package io.github.jichuo1.dexmeguviz

/** Tuple/entity identity applies only to the selected static snapshot. */
public enum class GraphIdentity(internal val wire: String) { ENTITY("entity"), TUPLE("tuple") }
public enum class GraphSetSemantics(internal val wire: String) { BAG("bag"), SET("set") }
public enum class GraphJoinKey(internal val wire: String) {
    SAME_ENTITY("same_entity"), LOCAL_DEFINITION("local_definition"), LOCAL_OWNER("local_owner"), SYMBOL("symbol")
}
public enum class GraphRolePolicy(internal val wire: String) { SHARED("shared"), DISTINCT("distinct") }

/** Bits in the limited static reflection model, not raw DEX access_flags. */
public class ReflectionFlags(public val bits: Long) {
    init { require(bits in 0L..0xffffffffL) { "reflection flags must fit uint32" } }
}

/** Bounded ASCII QueryIR fragment; native compilation remains authoritative. */
public class GraphPredicate private constructor(
    internal val json: String, internal val roots: Int, internal val reflection: Boolean
) {
    public companion object {
        public fun from(predicate: EntityPredicate): GraphPredicate =
            GraphPredicate(predicate.body.jsonWithin(65536), predicate.roots, false)
        public fun constant(value: Boolean): GraphPredicate = from(EntityPredicate.constant(value))
        public fun reflectionFlags(operation: RawFlagOperation, value: ReflectionFlags): GraphPredicate =
            reflection(operation, value, false)
        public fun reflectionOwnerFlags(operation: RawFlagOperation, value: ReflectionFlags): GraphPredicate =
            reflection(operation, value, true)
        private fun reflection(operation: RawFlagOperation, value: ReflectionFlags, owner: Boolean): GraphPredicate {
            val field = if (owner) "owner_flags" else "flags"
            val mode = operation.wire.removePrefix("flags_")
            return GraphPredicate("{\"$field\":{\"domain\":\"reflection\",\"mode\":\"$mode\",\"value\":${value.bits}}}",
                                  if (owner) 29 else 63, true)
        }
        public fun not(item: GraphPredicate): GraphPredicate {
            val body = "{\"not\":${item.json}}"
            require(body.length <= 65536) { "QueryIR JSON exceeds 64 KiB" }
            return GraphPredicate(body, item.roots, item.reflection)
        }
        public fun all(vararg items: GraphPredicate): GraphPredicate = combine("all", items)
        public fun any(vararg items: GraphPredicate): GraphPredicate = combine("any", items)
        private fun combine(op: String, items: Array<out GraphPredicate>): GraphPredicate {
            require(items.size <= 21846) { "QueryIR JSON exceeds 64 KiB" }
            var length = op.length.toLong() + 7L + maxOf(items.size - 1, 0)
            var roots = 127
            var reflection = false
            for (item in items) { length += item.json.length; roots = roots and item.roots; reflection = reflection || item.reflection }
            require(length <= 65536) { "QueryIR JSON exceeds 64 KiB" }
            return GraphPredicate("{\"$op\":[" + items.joinToString(",") { it.json } + "]}", roots, reflection)
        }
    }
}

/** Immutable typed expression for the metadata relations supported by the core. */
public class GraphExpression private constructor(
    public val relation: EntityRelation,
    internal val json: String,
    internal val nodeCount: Int,
    internal val depth: Int,
    internal val reflection: Boolean,
    internal val expandCount: Int
) {
    public companion object {
        private fun checked(relation: EntityRelation, json: String, children: List<GraphExpression>, reflection: Boolean, ownExpansion: Int = 0): GraphExpression {
            var nodes = 1L
            var depth = 1
            for (child in children) { nodes += child.nodeCount; depth = maxOf(depth, child.depth + 1) }
            require(nodes <= 128 && depth <= 32 && json.length <= 65536) { "graph exceeds node, depth or JSON limit" }
            val expansions = ownExpansion + children.sumOf { it.expandCount }
            val usesReflection = reflection || children.any { it.reflection }
            require(expansions <= 1 && (expansions == 0 || !usesReflection)) { "multiple expansions and reflection combinations are not supported" }
            return GraphExpression(relation, json, nodes.toInt(), depth, usesReflection, expansions)
        }
        private fun list(items: List<GraphExpression>): String {
            var length = 2L + maxOf(items.size - 1, 0)
            for (item in items) length += item.json.length
            require(length <= 65536) { "graph exceeds JSON limit" }
            return "[" + items.joinToString(",") { it.json } + "]"
        }
        private fun requireLabel(value: String) {
            require(value.length in 1..64 && value.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '_' || it == '.' || it == '-' }) { "invalid graph label" }
        }
        /** A single bounded expansion may be composed with ordinary entity operators. */
        public fun expand(query: ExpandQuery): GraphExpression =
            checked(EntityRelation.METHOD_DEFS, query.relationJson(), listOf(query.input), false, 1)
        public fun scan(relation: EntityRelation, where: GraphPredicate = GraphPredicate.constant(true)): GraphExpression {
            require((where.roots and relation.mask) != 0) { "predicate does not apply to relation" }
            return checked(relation, "{\"op\":\"scan\",\"relation\":\"${relation.wire}\",\"where\":${where.json}}", emptyList(), where.reflection)
        }
        public fun filter(input: GraphExpression, where: GraphPredicate): GraphExpression {
            require((where.roots and input.relation.mask) != 0) { "predicate does not apply to relation" }
            return checked(input.relation, "{\"op\":\"filter\",\"input\":${input.json},\"where\":${where.json}}", listOf(input), where.reflection)
        }
        public fun label(input: GraphExpression, label: String): GraphExpression {
            requireLabel(label)
            return checked(input.relation, "{\"op\":\"label\",\"input\":${input.json},\"label\":\"$label\"}", listOf(input), false)
        }
        public fun union(semantics: GraphSetSemantics, identity: GraphIdentity, vararg inputs: GraphExpression): GraphExpression {
            require(inputs.isNotEmpty() && inputs.size <= 128 && inputs.all { it.relation == inputs[0].relation }) { "union requires same-relation inputs" }
            val children = inputs.toList()
            return checked(inputs[0].relation, "{\"op\":\"union\",\"semantics\":\"${semantics.wire}\",\"identity\":\"${identity.wire}\",\"inputs\":${list(children)}}", children, false)
        }
        public fun distinct(input: GraphExpression, identity: GraphIdentity = GraphIdentity.TUPLE): GraphExpression =
            checked(input.relation, "{\"op\":\"distinct\",\"identity\":\"${identity.wire}\",\"input\":${input.json}}", listOf(input), false)
        private fun family(relation: EntityRelation): Int = when (relation) {
            EntityRelation.METHOD_DEFS, EntityRelation.METHOD_REFS -> 1
            EntityRelation.FIELD_DEFS, EntityRelation.FIELD_REFS -> 2
            EntityRelation.CLASS_DEFS, EntityRelation.TYPE_REFS -> 3
            EntityRelation.STRING_VALUES -> 4
        }
        private fun validateJoin(left: EntityRelation, right: EntityRelation, key: GraphJoinKey) {
            val supported = when (key) {
                GraphJoinKey.SAME_ENTITY -> left == right
                GraphJoinKey.LOCAL_DEFINITION -> family(left) == family(right) && family(left) != 4 && left != right
                GraphJoinKey.LOCAL_OWNER -> (family(left) == 1 || family(left) == 2) && right == EntityRelation.CLASS_DEFS
                GraphJoinKey.SYMBOL -> family(left) == family(right)
            }
            require(supported) { "join key does not apply to relations" }
        }
        public fun join(left: GraphExpression, right: GraphExpression, key: GraphJoinKey): GraphExpression = joined(left, right, key, false)
        public fun semiJoin(left: GraphExpression, right: GraphExpression, key: GraphJoinKey): GraphExpression = joined(left, right, key, true)
        private fun joined(left: GraphExpression, right: GraphExpression, key: GraphJoinKey, semi: Boolean): GraphExpression {
            validateJoin(left.relation, right.relation, key)
            val op = if (semi) "semi_join" else "join"
            return checked(left.relation, "{\"op\":\"$op\",\"on\":\"${key.wire}\",\"left\":${left.json},\"right\":${right.json}}", listOf(left, right), false)
        }
        public fun groupByOwner(inputs: List<GraphExpression>, minimum: Long = 1, maximum: Long = 0xffffffffL,
                                requiredRoles: List<String> = emptyList(), rolePolicy: GraphRolePolicy = GraphRolePolicy.SHARED): GraphExpression {
            require(inputs.size <= 128 && requiredRoles.size <= 128) { "excessive group inputs or roles" }
            val children = inputs.toList(); val roleNames = requiredRoles.toList()
            require(children.size <= 128 && roleNames.size <= 128) { "excessive group inputs or roles" }
            require(children.isNotEmpty() && children.all { it.relation == EntityRelation.METHOD_DEFS || it.relation == EntityRelation.FIELD_DEFS }) { "group requires member definitions" }
            require(minimum in 0..0xffffffffL && maximum in minimum..0xffffffffL) { "invalid group bounds" }
            require(roleNames.toSet().size == roleNames.size) { "duplicate roles" }
            roleNames.forEach { requireLabel(it) }
            val roles = roleNames.joinToString(",", "[", "]") { "\"$it\"" }
            return checked(EntityRelation.CLASS_DEFS, "{\"op\":\"group_by_owner\",\"inputs\":${list(children)},\"min\":$minimum,\"max\":$maximum,\"required_roles\":$roles,\"role_policy\":\"${rolePolicy.wire}\"}", children, false)
        }
    }
}

/** JSON writer for typed metadata graphs; graph identifiers are assigned by the core. */
public class GraphQuery(public val relation: GraphExpression, public val intent: QueryIntent = QueryIntent.ENUMERATE,
                        public val maxResults: Int = 4096, public val maxWork: Long = 100000000L) {
    init { require(maxResults in 1..100000 && maxWork > 0) { "invalid query bounds" }; require(relation.expandCount == 0) { "use ExpandGraphQuery for expanded graphs" } }
    public fun toQueryIrJson(): String {
        val capabilities = if (relation.reflection) ",\"required_capabilities\":[\"reflection_flags_static\",\"reflection_relational\"]" else ""
        val json = "{\"schema_version\":1,\"relation\":${relation.json},\"intent\":\"${intent.wire}\",\"max_results\":$maxResults,\"max_work\":$maxWork$capabilities}"
        require(json.length <= 65536) { "QueryIR JSON exceeds 64 KiB" }
        return json
    }
}

/** Snapshot-bound entry points retain the existing incomplete-source and Job semantics. */
public object TypedGraphQueryExecution {
    public fun execute(snapshot: NativeEngine.Snapshot, query: GraphQuery): GraphResult =
        GraphQueryExecution.execute(snapshot, query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun execute(snapshot: NativeEngine.SourceSetSnapshot, query: GraphQuery): GraphResult =
        GraphQueryExecution.execute(snapshot, query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun startJob(snapshot: NativeEngine.Snapshot, query: GraphQuery, batchSize: Int, maxQueuedBatches: Int, deadlineAfterMs: Long): NativeEngine.GraphJob =
        GraphQueryExecution.startGraphJob(snapshot, query.toQueryIrJson().toByteArray(Charsets.UTF_8), batchSize, maxQueuedBatches, deadlineAfterMs)
    public fun startJob(snapshot: NativeEngine.SourceSetSnapshot, query: GraphQuery, batchSize: Int, maxQueuedBatches: Int, deadlineAfterMs: Long): NativeEngine.GraphJob =
        GraphQueryExecution.startGraphJob(snapshot, query.toQueryIrJson().toByteArray(Charsets.UTF_8), batchSize, maxQueuedBatches, deadlineAfterMs)
}



