package io.github.jichuo1.dexmeguviz;

/** Explicit v23 static instruction-sequence query; no loader authentication. */
public final class OpcodeQuery {
    private OpcodeQuery() {}
    private static native NativeEngine.QueryResult nativeExecute(Object snapshot,boolean sourceSet,byte[] queryJson);
    public static NativeEngine.QueryResult execute(NativeEngine.Snapshot snapshot,byte[] queryJson) {
        if(snapshot==null||queryJson==null)throw new NullPointerException("snapshot and queryJson are required");
        synchronized(snapshot){return nativeExecute(snapshot,false,queryJson);}
    }
    public static NativeEngine.QueryResult execute(NativeEngine.SourceSetSnapshot snapshot,byte[] queryJson) {
        if(snapshot==null||queryJson==null)throw new NullPointerException("snapshot and queryJson are required");
        synchronized(snapshot){return nativeExecute(snapshot,true,queryJson);}
    }
    /** Starts provisional batches; consume to EOS and inspect the terminal status. */
    public static NativeEngine.Job startJob(NativeEngine.Snapshot snapshot,byte[] queryJson,int batchSize,int maxQueuedBatches,long deadlineAfterMs) {
        if(snapshot==null)throw new NullPointerException("snapshot is required");
        return snapshot.startOpcodeJob(queryJson,batchSize,maxQueuedBatches,deadlineAfterMs);
    }
    /** Starts provisional batches over the explicitly supplied source occurrences. */
    public static NativeEngine.Job startJob(NativeEngine.SourceSetSnapshot snapshot,byte[] queryJson,int batchSize,int maxQueuedBatches,long deadlineAfterMs) {
        if(snapshot==null)throw new NullPointerException("snapshot is required");
        return snapshot.startOpcodeJob(queryJson,batchSize,maxQueuedBatches,deadlineAfterMs);
    }
}
