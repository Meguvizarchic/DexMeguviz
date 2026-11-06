package io.github.jichuo1.dexmeguviz

/** Executes bounded v4/v9/v16/v18 static use-event graph JSON; no runtime binding is inferred. */
public object UseGraphQueryExecution {
    public fun startJob(snapshot: NativeEngine.Snapshot, queryJson: ByteArray, batchSize: Int, maxQueuedBatches: Int, deadlineAfterMs: Long): NativeEngine.UseGraphJob = snapshot.startUseGraphJob(queryJson, batchSize, maxQueuedBatches, deadlineAfterMs)
    public fun startJob(snapshot: NativeEngine.SourceSetSnapshot, queryJson: ByteArray, batchSize: Int, maxQueuedBatches: Int, deadlineAfterMs: Long): NativeEngine.UseGraphJob = snapshot.startUseGraphJob(queryJson, batchSize, maxQueuedBatches, deadlineAfterMs)
    public fun execute(snapshot: NativeEngine.Snapshot, queryJson: ByteArray): UseGraphResult = snapshot.queryUseGraph(queryJson)
    public fun execute(snapshot: NativeEngine.SourceSetSnapshot, queryJson: ByteArray): UseGraphResult = snapshot.queryUseGraph(queryJson)
}

