package io.github.jichuo1.dexmeguviz;

/** Explicit input-slot subset for a synchronous direct opcode query; not loader authentication. */
public final class ScopedOpcodeQuery {
    private ScopedOpcodeQuery(){}
    /** Selected source occurrences are static inputs, not necessarily visited or loaded. */
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
    /** Query coverage and decisions apply only to the caller-selected input slots. */
    public static final class Result {
        public final NativeEngine.QueryResult query;
        public final Scope scope;
        private Result(NativeEngine.QueryResult query,String[] slots,int[] sources){
            if(query==null)throw new IllegalArgumentException("query result required");
            this.query=query;this.scope=new Scope(slots,sources);
        }
    }
    public static Result execute(NativeEngine.Snapshot snapshot,byte[] queryJson){return execute0(snapshot,false,queryJson);}
    public static Result execute(NativeEngine.SourceSetSnapshot snapshot,byte[] queryJson){return execute0(snapshot,true,queryJson);}
    private static Result execute0(Object snapshot,boolean sourceSet,byte[] queryJson){
        if(snapshot==null||queryJson==null)throw new NullPointerException("snapshot and queryJson are required");
        synchronized(snapshot){return nativeExecute(snapshot,sourceSet,queryJson);}
    }
    private static native Result nativeExecute(Object snapshot,boolean sourceSet,byte[] queryJson);
}
