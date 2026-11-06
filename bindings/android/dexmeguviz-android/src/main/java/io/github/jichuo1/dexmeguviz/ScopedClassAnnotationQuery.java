package io.github.jichuo1.dexmeguviz;

/** Explicit static input-slot scope; does not authenticate loader origin. */
public final class ScopedClassAnnotationQuery {
    private ScopedClassAnnotationQuery() {}
    /** Selected occurrences are static inputs, not necessarily visited or loaded. */
    public static final class Scope {
        private final String[] inputSlots;
        private final int[] sourceIndices;
        public final String provenance="CALLER_DECLARED_INPUT_SLOTS";
        public final boolean snapshotScopeComplete=false,sourceScopeAuthenticated=false;
        private Scope(String[] inputSlots,int[] sourceIndices){this.inputSlots=inputSlots.clone();this.sourceIndices=sourceIndices.clone();}
        public int inputSlotCount(){return inputSlots.length;}
        public String inputSlot(int index){return inputSlots[index];}
        public int sourceCount(){return sourceIndices.length;}
        public int sourceIndex(int index){return sourceIndices[index];}
    }
    /** Coverage and decisions apply only to the caller-selected static inputs. */
    public static final class Result {
        public final NativeEngine.EntityResult query;
        public final Scope scope;
        private Result(NativeEngine.EntityResult query,String[] slots,int[] sources){
            if(query==null)throw new IllegalArgumentException("query result required");
            this.query=query;this.scope=new Scope(slots,sources);
        }
    }
    /** Source list is caller-declared and copied; successful terminal status verifies the actual source list. */
    public static final class Job implements AutoCloseable {
        private final NativeEngine.EntityJob delegate;
        public final Scope scope;
        private Job(NativeEngine.EntityJob delegate,String[] slots,int[] sources){
            if(delegate==null)throw new IllegalArgumentException("job is required");
            this.delegate=delegate;this.scope=new Scope(slots,sources);
        }
        public NativeEngine.EntityJobPoll next(int timeoutMs){return delegate.next(timeoutMs);}
        public NativeEngine.EntityJobStatus status(){return delegate.status();}
        public NativeEngine.EntityJobStatus waitFor(int timeoutMs){return delegate.waitFor(timeoutMs);}
        public void cancel(){delegate.cancel();}
        @Override public void close(){delegate.close();}
    }
    public static Job start(NativeEngine.Snapshot snapshot,byte[] queryJson,int batchSize,int maxQueuedBatches,long deadlineAfterMs){return start0(snapshot,false,queryJson,batchSize,maxQueuedBatches,deadlineAfterMs);}
    public static Job start(NativeEngine.SourceSetSnapshot snapshot,byte[] queryJson,int batchSize,int maxQueuedBatches,long deadlineAfterMs){return start0(snapshot,true,queryJson,batchSize,maxQueuedBatches,deadlineAfterMs);}
    private static Job start0(Object snapshot,boolean sourceSet,byte[] queryJson,int batchSize,int maxQueuedBatches,long deadlineAfterMs){
        if(snapshot==null||queryJson==null)throw new NullPointerException("snapshot and queryJson are required");
        synchronized(snapshot){return nativeStart(snapshot,sourceSet,queryJson,batchSize,maxQueuedBatches,deadlineAfterMs);}
    }
    private static native Job nativeStart(Object snapshot,boolean sourceSet,byte[] queryJson,int batchSize,int maxQueuedBatches,long deadlineAfterMs);
    public static Result execute(NativeEngine.Snapshot snapshot,byte[] queryJson){return execute0(snapshot,false,queryJson);}
    public static Result execute(NativeEngine.SourceSetSnapshot snapshot,byte[] queryJson){return execute0(snapshot,true,queryJson);}
    private static Result execute0(Object snapshot,boolean sourceSet,byte[] queryJson){
        if(snapshot==null||queryJson==null)throw new NullPointerException("snapshot and queryJson are required");
        synchronized(snapshot){return nativeExecute(snapshot,sourceSet,queryJson);}
    }
    private static native Result nativeExecute(Object snapshot,boolean sourceSet,byte[] queryJson);
}
