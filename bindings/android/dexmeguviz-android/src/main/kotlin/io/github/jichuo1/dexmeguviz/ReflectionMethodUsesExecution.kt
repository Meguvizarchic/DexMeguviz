package io.github.jichuo1.dexmeguviz

/** Executes bounded v15 static reflection and method-body JSON; no runtime binding is inferred. */
public object ReflectionMethodUsesExecution {
    public fun execute(snapshot: NativeEngine.Snapshot, queryJson: ByteArray): NativeEngine.EntityResult =
        snapshot.queryReflectionMethodUses(queryJson)
    public fun execute(snapshot: NativeEngine.SourceSetSnapshot, queryJson: ByteArray): NativeEngine.EntityResult =
        snapshot.queryReflectionMethodUses(queryJson)
    public fun startJob(snapshot: NativeEngine.Snapshot, queryJson: ByteArray, batchSize: Int, maxQueuedBatches: Int, deadlineAfterMs: Long): NativeEngine.EntityJob =
        snapshot.startReflectionMethodUsesJob(queryJson, batchSize, maxQueuedBatches, deadlineAfterMs)
    public fun startJob(snapshot: NativeEngine.SourceSetSnapshot, queryJson: ByteArray, batchSize: Int, maxQueuedBatches: Int, deadlineAfterMs: Long): NativeEngine.EntityJob =
        snapshot.startReflectionMethodUsesJob(queryJson, batchSize, maxQueuedBatches, deadlineAfterMs)
}
