package io.github.jichuo1.dexmeguviz

/** A v4 invoke scan in an explicitly declared static input-slot scope. */
public class ScopedInvokeSiteQuery(
    slots: List<String>,
    public val where: UseEventPredicate = UseEventPredicate.constant(true),
    public val intent: QueryIntent = QueryIntent.ENUMERATE,
    public val maxResults: Int = 4096,
    public val maxWork: Long = 100000000L
) {
    private val scopeJson: String
    init {
        val copied = slots.toList()
        require(copied.size <= 8 && copied.distinct().size == copied.size) { "invalid or duplicate slots" }
        require(copied.all { it.length in 1..128 && it.all { ch -> ch.code in 0x21..0x7e } }) { "invalid slot" }
        require((where.families and 1) != 0) { "predicate does not apply to invoke sites" }
        require(maxResults in 1..100000 && maxWork > 0) { "invalid query bounds" }
        val buffer = StringBuilder("[")
        for (i in copied.indices) {
            if (i != 0) buffer.append(',')
            buffer.append('"')
            for (ch in copied[i]) {
                if (ch == '\\' || ch == '"') buffer.append('\\')
                buffer.append(ch)
            }
            buffer.append('"')
        }
        scopeJson = buffer.append(']').toString()
    }
    /** ASCII QueryIR; an empty slot list declares an empty static scope. */
    public fun toQueryIrJson(): String {
        val json = "{\"schema_version\":1,\"scope\":{\"slots\":$scopeJson},\"relation\":{\"op\":\"scan\",\"relation\":\"invoke_sites\",\"where\":${where.json}},\"intent\":\"${intent.wire}\",\"max_results\":$maxResults,\"max_work\":$maxWork}"
        require(json.length <= 65536) { "QueryIR JSON exceeds 64 KiB" }
        return json
    }
}

/** Explicit opt-in; native core reports only the caller-declared static scope. */
public object ScopedUseGraphExecution {
    public fun execute(snapshot: NativeEngine.Snapshot, queryJson: ByteArray): UseGraphResult =
        snapshot.queryUseGraphScopedV4(queryJson)
    public fun execute(snapshot: NativeEngine.SourceSetSnapshot, queryJson: ByteArray): UseGraphResult =
        snapshot.queryUseGraphScopedV4(queryJson)
    public fun execute(snapshot: NativeEngine.Snapshot, query: ScopedInvokeSiteQuery): UseGraphResult =
        snapshot.queryUseGraphScopedV4(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun execute(snapshot: NativeEngine.SourceSetSnapshot, query: ScopedInvokeSiteQuery): UseGraphResult =
        snapshot.queryUseGraphScopedV4(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
}
