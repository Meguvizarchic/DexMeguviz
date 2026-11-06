package io.github.jichuo1.dexmeguviz

/** Explicit bounded QueryIR for standalone v6/v7/v8/v11; native compilation is authoritative.
 * Use JSON u16 arrays/escapes for UTF-16 values. This entry never performs runtime binding. */
public class AdvancedQuery(private val json:String) {
    init { require(json.length in 1..65536 && json.all { it.code <= 0x7f }) { "Advanced QueryIR must be bounded ASCII JSON" } }
    public fun toQueryIrJson():String=json
}
public object AdvancedExecution {
    public fun execute(snapshot:NativeEngine.Snapshot,query:AdvancedQuery):AdvancedResult=snapshot.queryAdvanced(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun execute(snapshot:NativeEngine.SourceSetSnapshot,query:AdvancedQuery):AdvancedResult=snapshot.queryAdvanced(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun startJob(snapshot:NativeEngine.Snapshot,query:AdvancedQuery,batchSize:Int,maxQueuedBatches:Int,deadlineAfterMs:Long):NativeEngine.AdvancedJob=snapshot.startAdvancedJob(query.toQueryIrJson().toByteArray(Charsets.UTF_8),batchSize,maxQueuedBatches,deadlineAfterMs)
    public fun startJob(snapshot:NativeEngine.SourceSetSnapshot,query:AdvancedQuery,batchSize:Int,maxQueuedBatches:Int,deadlineAfterMs:Long):NativeEngine.AdvancedJob=snapshot.startAdvancedJob(query.toQueryIrJson().toByteArray(Charsets.UTF_8),batchSize,maxQueuedBatches,deadlineAfterMs)
}

/** Explicit v6 static inheritance and use graph; native profile admission is authoritative. */
public object InheritedUseGraphExecution {
    public fun execute(snapshot:NativeEngine.Snapshot,query:AdvancedQuery):UseGraphResult=snapshot.queryInheritedUseGraph(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun execute(snapshot:NativeEngine.SourceSetSnapshot,query:AdvancedQuery):UseGraphResult=snapshot.queryInheritedUseGraph(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun startJob(snapshot:NativeEngine.Snapshot,query:AdvancedQuery,batchSize:Int,maxQueuedBatches:Int,deadlineAfterMs:Long):NativeEngine.UseGraphJob=snapshot.startInheritedUseGraphJob(query.toQueryIrJson().toByteArray(Charsets.UTF_8),batchSize,maxQueuedBatches,deadlineAfterMs)
    public fun startJob(snapshot:NativeEngine.SourceSetSnapshot,query:AdvancedQuery,batchSize:Int,maxQueuedBatches:Int,deadlineAfterMs:Long):NativeEngine.UseGraphJob=snapshot.startInheritedUseGraphJob(query.toQueryIrJson().toByteArray(Charsets.UTF_8),batchSize,maxQueuedBatches,deadlineAfterMs)
}

/** Explicit v8/v11 static interface inheritance and use graph. */
public object InterfaceUseGraphExecution {
    public fun execute(snapshot:NativeEngine.Snapshot,query:AdvancedQuery):UseGraphResult=snapshot.queryInterfaceUseGraph(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun execute(snapshot:NativeEngine.SourceSetSnapshot,query:AdvancedQuery):UseGraphResult=snapshot.queryInterfaceUseGraph(query.toQueryIrJson().toByteArray(Charsets.UTF_8))
    public fun startJob(snapshot:NativeEngine.Snapshot,query:AdvancedQuery,batchSize:Int,maxQueuedBatches:Int,deadlineAfterMs:Long):NativeEngine.UseGraphJob=snapshot.startInterfaceUseGraphJob(query.toQueryIrJson().toByteArray(Charsets.UTF_8),batchSize,maxQueuedBatches,deadlineAfterMs)
    public fun startJob(snapshot:NativeEngine.SourceSetSnapshot,query:AdvancedQuery,batchSize:Int,maxQueuedBatches:Int,deadlineAfterMs:Long):NativeEngine.UseGraphJob=snapshot.startInterfaceUseGraphJob(query.toQueryIrJson().toByteArray(Charsets.UTF_8),batchSize,maxQueuedBatches,deadlineAfterMs)
}
