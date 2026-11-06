package io.github.jichuo1.dexmeguviz

/** Opt-in structural caller-class observations on an existing v19 caller graph.
 * A classification is relative to the caller declaration occurrence and does
 * not authenticate ClassLoader selection, visibility, or runtime access.
 * JNI keeps the v19 limits of 4096 results and 100000000 work units.
 */
public class CallerFieldRelationQuery(public val callerGraph: FieldDeclarationCallerQuery) {
    public fun toQueryIrJson(): String {
        val json=callerGraph.toQueryIrJson()
        val prefix="{\"schema_version\":1,\"required_capabilities\":[\"field_declaration_static\"]"
        val replacement="{\"schema_version\":1,\"required_capabilities\":[\"field_declaration_static\",\"caller_field_relation_observation\"]"
        check(json.startsWith(prefix)) { "unexpected caller graph serialization" }
        val result=replacement+json.substring(prefix.length)
        require(result.length<=65536) { "QueryIR JSON exceeds 64 KiB" }
        return result
    }
}

/** Synchronous-only opt-in; this observation capability rejects Job admission. */
public object CallerFieldRelationExecution {
    public fun execute(snapshot: NativeEngine.Snapshot, query: CallerFieldRelationQuery): CallerFieldRelationResult =
        snapshot.queryCallerFieldRelationGraph(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun execute(snapshot: NativeEngine.SourceSetSnapshot, query: CallerFieldRelationQuery): CallerFieldRelationResult =
        snapshot.queryCallerFieldRelationGraph(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
}
