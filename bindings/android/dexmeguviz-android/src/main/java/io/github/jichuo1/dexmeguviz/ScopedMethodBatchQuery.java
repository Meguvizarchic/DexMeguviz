package io.github.jichuo1.dexmeguviz;

/** Synchronous bounded multi-method query over caller-declared static input slots. */
public final class ScopedMethodBatchQuery {
    private ScopedMethodBatchQuery() {}
    /** Selected sources describe static inputs, not loader authentication or visited rows. */
    public static final class Scope {
        private final String[] inputSlots;
        private final int[] sourceIndices;
        public final String provenance="CALLER_DECLARED_INPUT_SLOTS";
        public final boolean snapshotScopeComplete=false,sourceScopeAuthenticated=false;
        private Scope(String[] slots,int[] sources){inputSlots=slots.clone();sourceIndices=sources.clone();}
        public int inputSlotCount(){return inputSlots.length;}
        public String inputSlot(int index){return inputSlots[index];}
        public int sourceCount(){return sourceIndices.length;}
        public int sourceIndex(int index){return sourceIndices[index];}
    }
    /** Ordered immutable results, cache profile and caller-declared scope. */
    public static final class Result {
        private final NativeEngine.QueryResult[] values;
        public final MethodBatchQuery.Profile profile;
        public final Scope scope;
        private Result(NativeEngine.QueryResult[] values,MethodBatchQuery.Profile profile,String[] slots,int[] sources){
            if(values==null||profile==null)throw new IllegalArgumentException("results and profile required");
            this.values=values.clone();this.profile=profile;this.scope=new Scope(slots,sources);
        }
        public int size(){return values.length;}
        public NativeEngine.QueryResult get(int index){return values[index];}
    }
    /** All rules and bytes must remain unchanged until this synchronous call returns. */
    public static Result execute(NativeEngine.Snapshot snapshot,byte[][] rules,long cacheBytes,long maxCacheWork){return execute0(snapshot,false,rules,cacheBytes,maxCacheWork);}
    public static Result execute(NativeEngine.SourceSetSnapshot snapshot,byte[][] rules,long cacheBytes,long maxCacheWork){return execute0(snapshot,true,rules,cacheBytes,maxCacheWork);}
    private static Result execute0(Object snapshot,boolean sourceSet,byte[][] rules,long cacheBytes,long maxCacheWork){
        if(snapshot==null||rules==null)throw new NullPointerException("snapshot and rules are required");
        synchronized(snapshot){return nativeExecute(snapshot,sourceSet,rules,cacheBytes,maxCacheWork);}
    }
    private static native Result nativeExecute(Object snapshot,boolean sourceSet,byte[][] rules,long cacheBytes,long maxCacheWork);
}
