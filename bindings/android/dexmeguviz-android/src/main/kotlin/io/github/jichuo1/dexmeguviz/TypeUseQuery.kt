package io.github.jichuo1.dexmeguviz

/** Raw DEX opcode: this records an instruction, not a runtime type or allocation. */
public enum class TypeUseOpcode(public val code: Int) {
    CONST_CLASS(0x1c), CHECK_CAST(0x1f), INSTANCE_OF(0x20), NEW_INSTANCE(0x22),
    NEW_ARRAY(0x23), FILLED_NEW_ARRAY(0x24), FILLED_NEW_ARRAY_RANGE(0x25)
}
public enum class TypeUseJoinTarget { TYPE_REFERENCE, CALLER_METHOD }
public enum class TypeUseJoinDirection { USE_FIRST, TARGET_FIRST }
public enum class TypeUseJoinKind { JOIN, SEMI_JOIN }

/** Source-local instruction predicate; no implicit class or loader resolution. */
public class TypeUsePredicate private constructor(internal val json:String) {
    public companion object {
        public fun constant(value:Boolean):TypeUsePredicate=TypeUsePredicate(value.toString())
        public fun opcode(value:TypeUseOpcode):TypeUsePredicate=TypeUsePredicate("{\"opcode\":${value.code}}")
        public fun pc(minimum:Long,maximum:Long=minimum):TypeUsePredicate=number("pc",minimum,maximum)
        public fun targetIndex(minimum:Long,maximum:Long=minimum):TypeUsePredicate=number("target_index",minimum,maximum)
        private fun number(field:String,minimum:Long,maximum:Long):TypeUsePredicate{
            require(minimum in 0L..0xffffffffL&&maximum in minimum..0xffffffffL){"invalid uint32 range"}
            return TypeUsePredicate("{\"$field\":"+(if(minimum==maximum)minimum.toString() else "{\"min\":$minimum,\"max\":$maximum}")+"}")
        }
        public fun targetDescriptor(operation:TextOperation,value:String,asciiCaseInsensitive:Boolean=false):TypeUsePredicate = text("target_descriptor",operation,value,asciiCaseInsensitive)
        public fun callerName(operation:TextOperation,value:String,asciiCaseInsensitive:Boolean=false):TypeUsePredicate = text("caller_name",operation,value,asciiCaseInsensitive)
        public fun callerOwner(operation:TextOperation,value:String,asciiCaseInsensitive:Boolean=false):TypeUsePredicate = text("caller_owner",operation,value,asciiCaseInsensitive)
        private fun text(field:String,operation:TextOperation,value:String,fold:Boolean):TypeUsePredicate{
            val original=MethodPredicate.text(MethodTextField.NAME,operation,value,fold).jsonWithin(65536)
            check(original.startsWith("{\"name\":"));val json="{\"$field\":"+original.substring(8)
            require(json.length<=65536){"query too large"};return TypeUsePredicate(json)
        }
        public fun not(item:TypeUsePredicate):TypeUsePredicate=wrap("{\"not\":${item.json}}")
        public fun all(vararg items:TypeUsePredicate):TypeUsePredicate=combine("all",items)
        public fun any(vararg items:TypeUsePredicate):TypeUsePredicate=combine("any",items)
        private fun combine(op:String,items:Array<out TypeUsePredicate>):TypeUsePredicate {
            var n=op.length.toLong()+7+maxOf(items.size-1,0);for(item in items)n+=item.json.length
            require(n<=65536){"query too large"};return TypeUsePredicate("{\"$op\":["+items.joinToString(","){it.json}+"]}")
        }
        private fun wrap(json:String):TypeUsePredicate{require(json.length<=65536){"query too large"};return TypeUsePredicate(json)}
    }
}

/** Bounded scan or same-occurrence caller/type-reference Join or SemiJoin. */
public class TypeUseQuery(
    public val where:TypeUsePredicate=TypeUsePredicate.constant(true),
    public val joinTarget:TypeUseJoinTarget?=null,
    public val targetWhere:EntityPredicate?=null,
    public val direction:TypeUseJoinDirection=TypeUseJoinDirection.USE_FIRST,
    public val joinKind:TypeUseJoinKind=TypeUseJoinKind.JOIN,
    public val intent:QueryIntent=QueryIntent.ENUMERATE,
    public val maxResults:Int=4096,
    public val maxWork:Long=100000000L,
    slots:List<String>?=null
){
    private val scopeJson:String?
    init{
        require(maxResults in 1..4096&&maxWork in 1L..100000000L){"JNI query limit exceeded"}
        require((joinTarget==null)==(targetWhere==null)){"join target and predicate must be supplied together"}
        if(joinTarget!=null){val mask=if(joinTarget==TypeUseJoinTarget.TYPE_REFERENCE)EntityRelation.TYPE_REFS.mask else EntityRelation.METHOD_DEFS.mask;require((targetWhere!!.roots and mask)!=0){"target predicate relation mismatch"}}
        val captured=slots?.toList();if(captured!=null){require(captured.size<=8&&captured.distinct().size==captured.size){"invalid slots"};require(captured.all{it.length in 1..128&&it.all{c->c.code in 0x21..0x7e}}){"invalid slot"}}
        scopeJson=captured?.joinToString(",","[","]"){"\""+it.replace("\\","\\\\").replace("\"","\\\"")+"\""}
    }
    public fun toQueryIrJson():String {
        val use="{\"op\":\"scan\",\"relation\":\"type_uses\",\"where\":${where.json}}"
        val relation=if(joinTarget==null)use else {
            val target=if(joinTarget==TypeUseJoinTarget.TYPE_REFERENCE)"type_refs" else "method_defs"
            val key=if(joinTarget==TypeUseJoinTarget.TYPE_REFERENCE)"target_ref" else "caller"
            val entity="{\"op\":\"scan\",\"relation\":\"$target\",\"where\":"+targetWhere!!.body.jsonWithin(65536)+"}"
            val left=if(direction==TypeUseJoinDirection.USE_FIRST)use else entity;val right=if(direction==TypeUseJoinDirection.USE_FIRST)entity else use
            "{\"op\":\"${if(joinKind==TypeUseJoinKind.JOIN)"join" else "semi_join"}\",\"on\":\"$key\",\"left\":$left,\"right\":$right}"
        }
        val scope=if(scopeJson==null)"" else ",\"scope\":{\"slots\":$scopeJson}"
        val result="{\"schema_version\":1,\"required_capabilities\":[\"type_uses\"],\"relation\":$relation,\"intent\":\"${intent.wire}\",\"max_results\":$maxResults,\"max_work\":$maxWork$scope}"
        require(result.length<=65536){"QueryIR JSON exceeds 64 KiB"};return result
    }
}
public object TypeUseExecution {
    public fun execute(snapshot:NativeEngine.Snapshot,query:TypeUseQuery):UseGraphResult=snapshot.queryTypeUseGraph(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun execute(snapshot:NativeEngine.SourceSetSnapshot,query:TypeUseQuery):UseGraphResult=snapshot.queryTypeUseGraph(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun startJob(snapshot:NativeEngine.Snapshot,query:TypeUseQuery,batchSize:Int,maxQueuedBatches:Int,deadlineAfterMs:Long):NativeEngine.UseGraphJob=snapshot.startTypeUseGraphJob(query.toQueryIrJson().toByteArray(Charsets.UTF_8),batchSize,maxQueuedBatches,deadlineAfterMs)
    public fun startJob(snapshot:NativeEngine.SourceSetSnapshot,query:TypeUseQuery,batchSize:Int,maxQueuedBatches:Int,deadlineAfterMs:Long):NativeEngine.UseGraphJob=snapshot.startTypeUseGraphJob(query.toQueryIrJson().toByteArray(Charsets.UTF_8),batchSize,maxQueuedBatches,deadlineAfterMs)
}
