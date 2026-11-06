package io.github.jichuo1.dexmeguviz;

/** Synchronous bounded multi-method query; caller must run outside the UI thread. */
public final class MethodBatchQuery {
    private MethodBatchQuery() {}
    /** The rules and their bytes must not be changed until this call returns. */
    public static Result execute(NativeEngine.Snapshot snapshot,byte[][] rules,long cacheBytes,long maxCacheWork) {
        return execute0(snapshot,false,rules,cacheBytes,maxCacheWork);
    }
    public static Result execute(NativeEngine.SourceSetSnapshot snapshot,byte[][] rules,long cacheBytes,long maxCacheWork) {
        return execute0(snapshot,true,rules,cacheBytes,maxCacheWork);
    }
    private static Result execute0(Object snapshot,boolean sourceSet,byte[][] rules,long cacheBytes,long maxCacheWork) {
        if(snapshot==null||rules==null)throw new NullPointerException("snapshot and rules are required");
        synchronized(snapshot){return nativeExecute(snapshot,sourceSet,rules,cacheBytes,maxCacheWork);}
    }
    private static native Result nativeExecute(Object snapshot,boolean sourceSet,byte[][] rules,long cacheBytes,long maxCacheWork);
    /** Immutable ordered query results. Inspect each result's status, coverage and decision. */
    public static final class Result {
        private final NativeEngine.QueryResult[] values;
        public final Profile profile;
        private Result(NativeEngine.QueryResult[] values,Profile profile){this.values=values.clone();this.profile=profile;}
        public int size(){return values.length;}
        public NativeEngine.QueryResult get(int index){return values[index];}
    }
    /** Cache counters describe only the core's admitted cache paths, not all physical decoding. */
    public static final class Profile {
        public final long physicalCollects,cacheHits,cacheBuilds,traceOverflows,cacheRejections,replayFailures,cacheWorkCharged;
        public final boolean arenaBudgetUnavailable;
        private Profile(long a,long b,long c,long d,long e,long f,long g,boolean h){physicalCollects=a;cacheHits=b;cacheBuilds=c;traceOverflows=d;cacheRejections=e;replayFailures=f;cacheWorkCharged=g;arenaBudgetUnavailable=h;}
    }
    /** An attributed native failure; index -1 denotes no attributable rule. */
    public static final class Failure extends RuntimeException {
        public final int status,failureIndex;
        public final long errorOffset;
        private Failure(int status,int failureIndex,long errorOffset,String message){super(message);this.status=status;this.failureIndex=failureIndex;this.errorOffset=errorOffset;}
    }
}
