package io.github.jichuo1.dexmeguviz;

/** Explicit non-scoped v25 static class annotation query, without loader authentication. */
public final class ClassAnnotationStringQuery {
    private ClassAnnotationStringQuery() {}
    private static native NativeEngine.EntityResult nativeExecute(Object snapshot,boolean sourceSet,byte[] queryJson);
    public static NativeEngine.EntityResult execute(NativeEngine.Snapshot snapshot,byte[] queryJson) {
        if(snapshot==null||queryJson==null)throw new NullPointerException("snapshot and queryJson are required");
        synchronized(snapshot){return nativeExecute(snapshot,false,queryJson);}
    }
    public static NativeEngine.EntityResult execute(NativeEngine.SourceSetSnapshot snapshot,byte[] queryJson) {
        if(snapshot==null||queryJson==null)throw new NullPointerException("snapshot and queryJson are required");
        synchronized(snapshot){return nativeExecute(snapshot,true,queryJson);}
    }
    /** Starts provisional batches; consume to EOS and inspect terminal status. */
    public static NativeEngine.EntityJob startJob(NativeEngine.Snapshot snapshot,byte[] queryJson,int batchSize,int maxQueuedBatches,long deadlineAfterMs) {
        if(snapshot==null)throw new NullPointerException("snapshot is required");
        return snapshot.startClassAnnotationStringJob(queryJson,batchSize,maxQueuedBatches,deadlineAfterMs);
    }
    /** Starts provisional batches over the explicit source occurrences. */
    public static NativeEngine.EntityJob startJob(NativeEngine.SourceSetSnapshot snapshot,byte[] queryJson,int batchSize,int maxQueuedBatches,long deadlineAfterMs) {
        if(snapshot==null)throw new NullPointerException("snapshot is required");
        return snapshot.startClassAnnotationStringJob(queryJson,batchSize,maxQueuedBatches,deadlineAfterMs);
    }
}
