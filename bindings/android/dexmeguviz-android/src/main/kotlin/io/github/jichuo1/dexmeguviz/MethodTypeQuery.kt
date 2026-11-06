package io.github.jichuo1.dexmeguviz

/** Static type reference and optional DEX opcode, not a runtime type binding. */
public class MethodTypeTarget(public val descriptor:StaticTextMatch,public val opcode:TypeUseOpcode?=null){
    internal fun json():String = "{\"descriptor\":"+descriptor.json()+(opcode?.let{",\"opcode\":${it.code}"}?:"")+"}"
}
private fun methodTypeJoin(prefix:String,suffix:String,parts:List<String>):String{
    var size=prefix.length.toLong()+suffix.length+maxOf(parts.size-1,0);for(p in parts)size+=p.length
    require(size<=65536){"QueryIR JSON exceeds 64 KiB"};return prefix+parts.joinToString(",")+suffix
}
/** Predicates compose static events within one method, with no control-flow claim. */
public class MethodTypePredicate private constructor(internal val json:String,internal val hasTypes:Boolean){
    public companion object{
        public fun metadata(value:MethodPredicate):MethodTypePredicate=MethodTypePredicate(value.jsonWithin(65536),false)
        public fun typesAll(vararg values:MethodTypeTarget):MethodTypePredicate=quantified("using_types","all",checkedMap(values,true){it.json()},true)
        public fun typesAny(vararg values:MethodTypeTarget):MethodTypePredicate=quantified("using_types","any",checkedMap(values,true){it.json()},true)
        public fun stringsAll(vararg values:StaticTextMatch):MethodTypePredicate=quantified("using_strings","all",checkedMap(values){it.json()},false)
        public fun stringsAny(vararg values:StaticTextMatch):MethodTypePredicate=quantified("using_strings","any",checkedMap(values){it.json()},false)
        public fun invokesAll(vararg values:InvokeTarget):MethodTypePredicate=quantified("invokes","all",checkedMap(values){it.json()},false)
        public fun invokesAny(vararg values:InvokeTarget):MethodTypePredicate=quantified("invokes","any",checkedMap(values){it.json()},false)
        public fun fieldsAll(vararg values:FieldTarget):MethodTypePredicate=quantified("field_access","all",checkedMap(values){it.json()},false)
        public fun fieldsAny(vararg values:FieldTarget):MethodTypePredicate=quantified("field_access","any",checkedMap(values){it.json()},false)
        private fun <T> checkedMap(values:Array<out T>,allowEmpty:Boolean=false,render:(T)->String):List<String>{
            require((allowEmpty||values.isNotEmpty())&&values.size<=128){"matcher needs 1..128 items"};val result=ArrayList<String>(values.size);var size=0L
            for(value in values){val text=render(value);size+=text.length;require(size<=65536){"QueryIR JSON exceeds 64 KiB"};result.add(text)};return result
        }
        private fun quantified(field:String,op:String,items:List<String>,types:Boolean):MethodTypePredicate{require((types||items.isNotEmpty())&&items.size<=128){"matcher needs 1..128 items"};return MethodTypePredicate(methodTypeJoin("{\"$field\":{\"$op\":[","]}}",items),types)}
        public fun not(value:MethodTypePredicate):MethodTypePredicate=MethodTypePredicate(methodTypeJoin("{\"not\":","}",listOf(value.json)),value.hasTypes)
        public fun all(vararg values:MethodTypePredicate):MethodTypePredicate=combine("all",values)
        public fun any(vararg values:MethodTypePredicate):MethodTypePredicate=combine("any",values)
        private fun combine(op:String,values:Array<out MethodTypePredicate>):MethodTypePredicate{require(values.size<=128){"too many predicates"};return MethodTypePredicate(methodTypeJoin("{\"$op\":[","]}",values.map{it.json}),values.any{it.hasTypes})}
    }
}
public class MethodTypeQuery(public val where:MethodTypePredicate,public val intent:QueryIntent=QueryIntent.ENUMERATE,public val maxResults:Int=4096,public val maxWork:Long=100000000L,slots:List<String>?=null){
    private val scopeJson:String?
    init{require(where.hasTypes){"type predicate required"};require(maxResults in 1..4096&&maxWork in 1L..100000000L){"JNI query limit exceeded"};val captured=slots?.toList();if(captured!=null){require(captured.size<=8&&captured.distinct().size==captured.size){"invalid slots"};require(captured.all{it.length in 1..128&&it.all{c->c.code in 0x21..0x7e}}){"invalid slot"}};scopeJson=captured?.joinToString(",","[","]"){"\""+it.replace("\\","\\\\").replace("\"","\\\"")+"\""}}
    public fun toQueryIrJson():String{val scope=scopeJson?.let{",\"scope\":{\"slots\":$it}"}?:"";val json="{\"schema_version\":1,\"required_capabilities\":[\"type_uses\"],\"relation\":\"method_defs\",\"where\":${where.json},\"intent\":\"${intent.wire}\",\"max_results\":$maxResults,\"max_work\":$maxWork$scope}";require(json.length<=65536){"QueryIR JSON exceeds 64 KiB"};return json}
}
public object MethodTypeExecution{
    public fun execute(snapshot:NativeEngine.Snapshot,query:MethodTypeQuery):MethodTypeResult=snapshot.queryMethodType(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun execute(snapshot:NativeEngine.SourceSetSnapshot,query:MethodTypeQuery):MethodTypeResult=snapshot.queryMethodType(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun startJob(snapshot:NativeEngine.Snapshot,query:MethodTypeQuery,batchSize:Int,maxQueuedBatches:Int,deadlineAfterMs:Long):NativeEngine.MethodTypeJob=snapshot.startMethodTypeJob(query.toQueryIrJson().toByteArray(Charsets.UTF_8),batchSize,maxQueuedBatches,deadlineAfterMs)
    public fun startJob(snapshot:NativeEngine.SourceSetSnapshot,query:MethodTypeQuery,batchSize:Int,maxQueuedBatches:Int,deadlineAfterMs:Long):NativeEngine.MethodTypeJob=snapshot.startMethodTypeJob(query.toQueryIrJson().toByteArray(Charsets.UTF_8),batchSize,maxQueuedBatches,deadlineAfterMs)
}
