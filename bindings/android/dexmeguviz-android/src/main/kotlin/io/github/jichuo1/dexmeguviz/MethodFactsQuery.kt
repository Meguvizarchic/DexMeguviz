package io.github.jichuo1.dexmeguviz

import java.util.Collections

/** Explicit categories and bounds for one selected, local static DEX method. */
public class MethodFactsRequest(categories:Set<MethodFactsResult.Category>,public val maxRecords:Int,
    public val maxWork:Long,public val deadlineAfterMs:Long=0) {
    public val categories:Set<MethodFactsResult.Category> = Collections.unmodifiableSet(LinkedHashSet(categories))
    internal val mask:Int
    init {
        require(this.categories.isNotEmpty()) { "at least one method fact category is required" }
        require(maxRecords in 1..100000 && maxWork in 1..100000000L && deadlineAfterMs in 0..86400000L) { "invalid method fact bounds" }
        mask=this.categories.fold(0){value,category->value or category.mask}
    }
}
/** Synchronous; callers should schedule work away from their UI thread. */
public object MethodFactsExecution {
    public fun inspect(snapshot:NativeEngine.Snapshot,methodRef:Long,request:MethodFactsRequest):MethodFactsResult =
        snapshot.inspectMethodFacts(methodRef,request.mask,request.maxRecords,request.maxWork,request.deadlineAfterMs)
    public fun inspect(snapshot:NativeEngine.SourceSetSnapshot,sourceIndex:Int,methodRef:Long,request:MethodFactsRequest):MethodFactsResult =
        snapshot.inspectMethodFacts(sourceIndex,methodRef,request.mask,request.maxRecords,request.maxWork,request.deadlineAfterMs)
}
