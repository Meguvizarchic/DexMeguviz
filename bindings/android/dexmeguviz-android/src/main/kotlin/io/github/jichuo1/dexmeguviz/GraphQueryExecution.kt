package io.github.jichuo1.dexmeguviz

/** Executes bounded v3/v14 metadata graph JSON; see TypedGraphQueryExecution for typed construction. */
public object GraphQueryExecution {
    public fun execute(snapshot: NativeEngine.Snapshot, queryJson: ByteArray): GraphResult = snapshot.queryGraph(queryJson)
    public fun execute(snapshot: NativeEngine.SourceSetSnapshot, queryJson: ByteArray): GraphResult = snapshot.queryGraph(queryJson)
    /** Provisional graph batches; drain to EOS and check the terminal status. */
    public fun startGraphJob(snapshot: NativeEngine.Snapshot, queryJson: ByteArray, batchSize: Int,
                             maxQueuedBatches: Int, deadlineAfterMs: Long): NativeEngine.GraphJob =
        snapshot.startGraphJob(queryJson, batchSize, maxQueuedBatches, deadlineAfterMs)
    public fun startGraphJob(snapshot: NativeEngine.SourceSetSnapshot, queryJson: ByteArray, batchSize: Int,
                             maxQueuedBatches: Int, deadlineAfterMs: Long): NativeEngine.GraphJob =
        snapshot.startGraphJob(queryJson, batchSize, maxQueuedBatches, deadlineAfterMs)
}


