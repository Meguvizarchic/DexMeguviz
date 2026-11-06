package io.github.jichuo1.dexmeguviz

public enum class ExpandDirection(internal val wire:String){OUTGOING("outgoing"),INCOMING("incoming")}
public enum class ExpandOutput(internal val wire:String){PATHS("paths"),ENDPOINTS("endpoints")}
/** Static method-ref expansion; neither dispatch nor a runtime loader claim. */
public class ExpandQuery(
    public val input:GraphExpression,
    public val maxDepth:Int,
    public val minDepth:Int=1,
    public val direction:ExpandDirection=ExpandDirection.OUTGOING,
    public val output:ExpandOutput=ExpandOutput.PATHS,
    public val intent:QueryIntent=QueryIntent.ENUMERATE,
    public val maxResults:Int=4096,
    public val maxWork:Long=100000000,
    public val maxVisited:Long=100000,
    public val maxEdges:Long=100000,
    public val maxPaths:Long=100000,
    slots:List<String>?=null,
    public val walkWhere:MethodPredicate?=null,
    public val emitWhere:MethodPredicate?=null
){
    private val scope:String?
    init{
        require(input.relation==EntityRelation.METHOD_DEFS&&!input.reflection&&input.expandCount==0){"expand input must be an ordinary method graph"}
        require(input.nodeCount<128&&input.depth<32){"expand graph exceeds node/depth limit"}
        require(maxDepth>=0&&minDepth in 0..maxDepth){"invalid expansion depth"}
        require(maxResults in 1..4096&&maxWork in 1L..100000000L){"JNI query limit"}
        require(maxVisited in 1L..100000000L&&maxEdges in 1L..100000000L&&maxPaths in 1L..100000000L){"invalid expansion budget"}
        val copy=slots?.toList();require(copy==null||copy.size<=8&&copy.distinct().size==copy.size&&copy.all{it.length in 1..128&&it.all{c->c.code in 0x21..0x7e}}){"invalid source slots"}
        scope=copy?.joinToString(",","[","]"){"\""+it.replace("\\","\\\\").replace("\"","\\\"")+"\""}
    }
    internal fun relationJson():String{
        val scopePart=scope?.let{",\"scope\":{\"slots\":$it}"}?:""
        val walk=walkWhere?.let{",\"walk_where\":"+it.jsonWithin(65536)}?:""
        val emit=emitWhere?.let{",\"emit_where\":"+it.jsonWithin(65536)}?:""
        val text="{\"op\":\"bounded_expand\",\"input\":${input.json},\"direction\":\"${direction.wire}\",\"output\":\"${output.wire}\",\"min_depth\":$minDepth,\"max_depth\":$maxDepth,\"max_visited\":$maxVisited,\"max_edges\":$maxEdges,\"max_paths\":$maxPaths$scopePart$walk$emit}"
        require(text.length<=65536){"QueryIR JSON exceeds 64 KiB"};return text
    }
    public fun toQueryIrJson():String=ExpandGraphQuery(GraphExpression.expand(this),intent,maxResults,maxWork).toQueryIrJson()

}
/** Typed outer entity operators preserve each expansion's paths and frontiers. */
public class ExpandGraphQuery(public val relation:GraphExpression,
    public val intent:QueryIntent=QueryIntent.ENUMERATE,
    public val maxResults:Int=4096,public val maxWork:Long=100000000L){
    init{
        require(relation.expandCount==1&&!relation.reflection){"exactly one ordinary expansion is required"}
        require(maxResults in 1..4096&&maxWork in 1L..100000000L){"JNI query limit"}
    }
    public fun toQueryIrJson():String{
        val text="{\"schema_version\":1,\"required_capabilities\":[\"bounded_expand\"],\"relation\":${relation.json},\"intent\":\"${intent.wire}\",\"max_results\":$maxResults,\"max_work\":$maxWork}"
        require(text.length<=65536){"QueryIR JSON exceeds 64 KiB"};return text
    }
}
public object ExpandExecution{
    public fun execute(snapshot:NativeEngine.Snapshot,query:ExpandGraphQuery):ExpandResult=snapshot.queryExpand(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun execute(snapshot:NativeEngine.SourceSetSnapshot,query:ExpandGraphQuery):ExpandResult=snapshot.queryExpand(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun startJob(snapshot:NativeEngine.Snapshot,query:ExpandGraphQuery,batchSize:Int,maxQueuedBatches:Int,deadlineAfterMs:Long):NativeEngine.ExpandJob=snapshot.startExpandJob(query.toQueryIrJson().toByteArray(Charsets.UTF_8),batchSize,maxQueuedBatches,deadlineAfterMs)
    public fun startJob(snapshot:NativeEngine.SourceSetSnapshot,query:ExpandGraphQuery,batchSize:Int,maxQueuedBatches:Int,deadlineAfterMs:Long):NativeEngine.ExpandJob=snapshot.startExpandJob(query.toQueryIrJson().toByteArray(Charsets.UTF_8),batchSize,maxQueuedBatches,deadlineAfterMs)

    public fun execute(snapshot:NativeEngine.Snapshot,query:ExpandQuery):ExpandResult=snapshot.queryExpand(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun execute(snapshot:NativeEngine.SourceSetSnapshot,query:ExpandQuery):ExpandResult=snapshot.queryExpand(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun startJob(snapshot:NativeEngine.Snapshot,query:ExpandQuery,batchSize:Int,maxQueuedBatches:Int,deadlineAfterMs:Long):NativeEngine.ExpandJob=snapshot.startExpandJob(query.toQueryIrJson().toByteArray(Charsets.UTF_8),batchSize,maxQueuedBatches,deadlineAfterMs)
    public fun startJob(snapshot:NativeEngine.SourceSetSnapshot,query:ExpandQuery,batchSize:Int,maxQueuedBatches:Int,deadlineAfterMs:Long):NativeEngine.ExpandJob=snapshot.startExpandJob(query.toQueryIrJson().toByteArray(Charsets.UTF_8),batchSize,maxQueuedBatches,deadlineAfterMs)
}
