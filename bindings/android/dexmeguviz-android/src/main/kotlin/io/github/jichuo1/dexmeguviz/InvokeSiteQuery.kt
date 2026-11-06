package io.github.jichuo1.dexmeguviz

/** One v4 static invoke-site scan; no runtime target resolution is implied. */
public class InvokeSiteQuery(
    public val where: UseEventPredicate = UseEventPredicate.constant(true),
    public val intent: QueryIntent = QueryIntent.ENUMERATE,
    public val maxResults: Int = 4096,
    public val maxWork: Long = 100000000L
) {
    init {
        require((where.families and 1) != 0) { "predicate does not apply to invoke sites" }
        require(maxResults in 1..100000 && maxWork > 0) { "invalid query bounds" }
    }
    /** ASCII QueryIR; the native core decides result and source coverage. */
    public fun toQueryIrJson(): String {
        val json = "{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"invoke_sites\",\"where\":${where.json}},\"intent\":\"${intent.wire}\",\"max_results\":$maxResults,\"max_work\":$maxWork}"
        require(json.length <= 65536) { "QueryIR JSON exceeds 64 KiB" }
        return json
    }
}

/** Existing synchronous v4 bridge; source completeness is not inferred. */
public object TypedInvokeSiteExecution {
    public fun execute(snapshot: NativeEngine.Snapshot, query: InvokeSiteQuery): UseGraphResult =
        UseGraphQueryExecution.execute(snapshot, query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun execute(snapshot: NativeEngine.SourceSetSnapshot, query: InvokeSiteQuery): UseGraphResult =
        UseGraphQueryExecution.execute(snapshot, query.toQueryIrJson().toByteArray(Charsets.UTF_8))
}
