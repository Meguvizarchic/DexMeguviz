package io.github.jichuo1.dexmeguviz

/** Explicit annotation-aware static reflection graph; no runtime binding is implied. */
public class ClassAnnotationGraphQuery(
    public val relation: GraphExpression,
    public val intent: QueryIntent = QueryIntent.ENUMERATE,
    public val maxResults: Int = 4096,
    public val maxWork: Long = 100000000L,
    slots: List<String>? = null
) {
    private val scopeJson: String?
    init {
        require(relation.reflection) { "a static reflection predicate is required" }
        require(maxResults in 1..4096 && maxWork in 1L..100000000L) { "JNI query limit exceeded" }
        val captured=slots?.toList()
        if(captured!=null){
            require(captured.size<=8 && captured.distinct().size==captured.size) { "invalid or duplicate slots" }
            require(captured.all { it.length in 1..128 && it.all { ch -> ch.code in 0x21..0x7e } }) { "invalid slot" }
        }
        scopeJson=captured?.joinToString(",","[","]") { slot ->
            "\""+slot.replace("\\","\\\\").replace("\"","\\\"")+"\""
        }
    }
    public fun toQueryIrJson(): String {
        val scope=if(scopeJson==null)"" else ",\"scope\":{\"slots\":$scopeJson}"
        val json="{\"schema_version\":1,\"relation\":${relation.json},\"intent\":\"${intent.wire}\",\"max_results\":$maxResults,\"max_work\":$maxWork,\"required_capabilities\":[\"reflection_flags_static\",\"reflection_relational\",\"reflection_class_annotations_static\"]$scope}"
        require(json.length<=65536) { "QueryIR JSON exceeds 64 KiB" }
        return json
    }
}

/** Synchronous v20 graph; scope completeness is limited to caller-selected static inputs. */
public object ClassAnnotationGraphExecution {
    public fun execute(snapshot: NativeEngine.Snapshot, query: ClassAnnotationGraphQuery): GraphResult =
        snapshot.queryClassAnnotationGraph(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun execute(snapshot: NativeEngine.SourceSetSnapshot, query: ClassAnnotationGraphQuery): GraphResult =
        snapshot.queryClassAnnotationGraph(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
}
