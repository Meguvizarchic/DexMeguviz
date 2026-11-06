package io.github.jichuo1.dexmeguviz

/** Relative to the field reference owner, never relative to the caller or runtime loader. */
public enum class FieldDeclarationScope(internal val wire: String) {
    DECLARED("declared"), INHERITED("inherited"), ANY("any")
}

/** A static field-use lookup inside an explicitly selected set of source slots.
 * The constructor permits up to 100000 results and any positive Long maxWork;
 * the JNI execution entry currently limits these to 4096 and 100000000. A
 * constructed query exceeding either limit fails with BudgetExceeded when run.
 */
public class FieldDeclarationQuery(
    slots: List<String>,
    public val declarationScope: FieldDeclarationScope,
    public val access: FieldUseAccess = FieldUseAccess.ANY,
    public val owner: StaticTextMatch? = null,
    public val name: StaticTextMatch? = null,
    public val type: StaticTextMatch? = null,
    public val flagsContains: Long = 0,
    public val intent: QueryIntent = QueryIntent.ENUMERATE,
    public val maxResults: Int = 4096,
    public val maxWork: Long = 100000000L,
    public val maxIntermediateRows: Int = 100000
) {
    private val scopeJson: String
    init {
        val copied = slots.toList()
        require(copied.isNotEmpty() && copied.size <= 8 && copied.distinct().size == copied.size) { "invalid or duplicate slots" }
        require(copied.all { it.length in 1..128 && it.all { ch -> ch.code in 0x21..0x7e } }) { "invalid slot" }
        require(flagsContains in 0L..0xffffffffL && maxResults in 1..100000 && maxWork > 0 && maxIntermediateRows in 1..1000000) { "invalid query bounds" }
        val buffer = StringBuilder("[")
        for (i in copied.indices) {
            if (i != 0) buffer.append(',')
            buffer.append('"')
            for (ch in copied[i]) { if (ch == '\\' || ch == '"') buffer.append('\\'); buffer.append(ch) }
            buffer.append('"')
        }
        scopeJson = buffer.append(']').toString()
    }
    private fun fieldWhereJson(): String {
        val parts = ArrayList<String>()
        parts.add("\"scope\":\"${declarationScope.wire}\"")
        owner?.let { parts.add("\"owner\":" + it.json()) }
        name?.let { parts.add("\"name\":" + it.json()) }
        type?.let { parts.add("\"type\":" + it.json()) }
        if (flagsContains != 0L) parts.add("\"flags_contains\":$flagsContains")
        val field = "{\"target_field_declaration\":{" + parts.joinToString(",") + "}}"
        val accessPredicate = when (access) {
            FieldUseAccess.ANY -> "true"
            FieldUseAccess.READ -> "{\"any\":[{\"opcode\":{\"min\":82,\"max\":88}},{\"opcode\":{\"min\":96,\"max\":102}}]}"
            FieldUseAccess.WRITE -> "{\"any\":[{\"opcode\":{\"min\":89,\"max\":95}},{\"opcode\":{\"min\":103,\"max\":109}}]}"
        }
        return "{\"all\":[$field,$accessPredicate]}"
    }
    /** Query identity, scoped Unknown and evidence remain native decisions. */
    public fun toQueryIrJson(): String {
        val where=fieldWhereJson()
        val json = "{\"schema_version\":1,\"required_capabilities\":[\"field_declaration_static\"],\"scope\":{\"slots\":$scopeJson},\"relation\":{\"op\":\"scan\",\"relation\":\"field_uses\",\"where\":$where},\"intent\":\"${intent.wire}\",\"max_results\":$maxResults,\"max_work\":$maxWork,\"max_intermediate_rows\":$maxIntermediateRows}"
        require(json.length <= 65536) { "QueryIR JSON exceeds 64 KiB" }
        return json
    }
    internal fun toCallerQueryIrJson(caller: EntityPredicate, join: UseSymbolJoin): String {
        require((caller.roots and EntityRelation.METHOD_DEFS.mask)!=0) { "caller predicate does not apply to method definitions" }
        val fieldWhere=fieldWhereJson()
        val op=if(join==UseSymbolJoin.JOIN) "join" else "semi_join"
        val prefix="{\"schema_version\":1,\"required_capabilities\":[\"field_declaration_static\"],\"scope\":{\"slots\":$scopeJson},\"relation\":{\"op\":\"$op\",\"on\":\"caller\",\"left\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":"
        val suffix="},\"right\":{\"op\":\"scan\",\"relation\":\"field_uses\",\"where\":$fieldWhere}},\"intent\":\"${intent.wire}\",\"max_results\":$maxResults,\"max_work\":$maxWork,\"max_intermediate_rows\":$maxIntermediateRows}"
        require(prefix.length.toLong()+suffix.length<=65536L) { "QueryIR JSON exceeds 64 KiB" }
        val callerWhere=caller.body.jsonWithin(65536-prefix.length-suffix.length)
        return prefix+callerWhere+suffix
    }
}

/** The source scope is a caller-selected static universe; no runtime binding is inferred. */
public object FieldDeclarationQueryExecution {
    public fun execute(snapshot: NativeEngine.Snapshot, query: FieldDeclarationQuery): UseGraphResult =
        snapshot.queryFieldDeclarationGraph(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun execute(snapshot: NativeEngine.SourceSetSnapshot, query: FieldDeclarationQuery): UseGraphResult =
        snapshot.queryFieldDeclarationGraph(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
}

/** A caller-to-field-use Join or SemiJoin in the same explicit static source scope.
 * The declaration scope remains relative to field_ref.owner, never caller owner.
 * Execution uses the same JNI 4096-result and 100000000-work limits as v19.
 * Only method metadata predicates are accepted; NOT remains Unsupported.
 */
public class FieldDeclarationCallerQuery(
    public val field: FieldDeclarationQuery,
    public val caller: EntityPredicate = EntityPredicate.constant(true),
    public val join: UseSymbolJoin = UseSymbolJoin.JOIN
) {
    public fun toQueryIrJson(): String = field.toCallerQueryIrJson(caller,join)
}

/** Synchronous typed access; C Job retains provisional-batch semantics. */
public object TypedFieldDeclarationCallerExecution {
    public fun execute(snapshot: NativeEngine.Snapshot, query: FieldDeclarationCallerQuery): UseGraphResult =
        snapshot.queryFieldDeclarationGraph(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun execute(snapshot: NativeEngine.SourceSetSnapshot, query: FieldDeclarationCallerQuery): UseGraphResult =
        snapshot.queryFieldDeclarationGraph(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
}
