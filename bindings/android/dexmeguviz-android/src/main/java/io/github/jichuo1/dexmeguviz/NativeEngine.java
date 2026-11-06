package io.github.jichuo1.dexmeguviz;

/** ABI probes and a bounded, copied raw-DEX snapshot. */
public final class NativeEngine {
    static {
        System.loadLibrary("dexmeguviz");
    }

    private NativeEngine() {}

    public static native int abiVersion();
    public static native String capabilities();

    /**
     * Opens a copied raw DEX. The slot is nonempty printable ASCII, at most 128
     * characters; callers must not mutate {@code bytes} until this call returns.
     * APKs and split discovery are not supported by this entry point.
     *
     * <p>The result must be closed. This single input is explicitly marked as an
     * incomplete source scope; it does not describe an entire app or loader.
     * Source preparation is synchronous and is not cancellable; the source
     * limit is 16 MiB.</p>
     */
    public static Snapshot openRawDex(byte[] bytes, String slot) {
        if (bytes == null || slot == null) throw new NullPointerException("bytes and slot are required");
        long token = 0;
        try {
            token = nativeOpenRawDex(bytes, slot);
            return new Snapshot(token);
        } catch (Throwable failure) {
            if (token != 0) {
                try { nativeClose(token); } catch (Throwable closeFailure) { failure.addSuppressed(closeFailure); }
            }
            throw failure;
        }
    }

    /**
     * Opens an owned raw DEX snapshot using caller-selected source and core
     * memory limits in bytes. The Java array and VM memory are not included
     * in the core limit. Callers must keep the array unchanged until return.
     * Like {@link #openRawDex(byte[], String)}, this is synchronous,
     * non-cancellable and reports an incomplete source scope.
     */
    public static Snapshot openRawDexWithLimits(byte[] bytes, String slot, long maxSourceBytes, long maxOwnedBytes) {
        if (bytes == null || slot == null) throw new NullPointerException("bytes and slot are required");
        if (maxSourceBytes <= 0 || maxSourceBytes > Integer.MAX_VALUE || maxOwnedBytes <= 0)
            throw new IllegalArgumentException("invalid source or owned memory limit");
        long token = 0;
        try {
            token = nativeOpenRawDexWithLimits(bytes, slot, maxSourceBytes, maxOwnedBytes);
            return new Snapshot(token);
        } catch (Throwable failure) {
            if (token != 0) try { nativeClose(token); } catch (Throwable closeFailure) { failure.addSuppressed(closeFailure); }
            throw failure;
        }
    }

    private static native long nativeOpenRawDex(byte[] bytes, String slot);
    private static native long nativeOpenRawDexWithLimits(byte[] bytes, String slot, long maxSourceBytes, long maxOwnedBytes);
    private static native long nativeCreateMethodStream(byte[][] queries, long maxSourceBytes, long maxOwnedBytes);
    private static native long nativeOpenMethodStreamDex(long session, byte[] bytes, String slot);
    private static native QueryResult nativeMethodStreamQuery(long session, long snapshot, int queryIndex);
    private static native MethodBatchQuery.Result nativeMethodStreamQueryBatch(long session, long snapshot, int[] queryIndices, long cacheBytes, long maxCacheWork);
    private static native void nativeCloseMethodStream(long session);
    private static native SnapshotInfo nativeSnapshotInfo(long token);
    private static native void nativeClose(long token);
    private static native QueryResult nativeQueryMethods(long token, byte[] queryJson);
    private static native long nativeOpenRawDexSet(byte[][] bytes, String[] slots);
    private static native long nativeOpenSources(byte[][] bytes, String[] slots, int[] formats, boolean[] allowNoDex);
    private static native long nativeOpenApkPaths(byte[][] paths, String[] slots, boolean[] allowNoDex, String[] expectedSha256, long[] limits);
    private static native long nativeOpenApkFdSources(int[] fds, long[] offsets, long[] lengths, String[] slots, boolean[] allowNoDex, String[] expectedSha256, long[] limits, Object[] keepAlive);
    private static native SourceSetInfo nativeSourceSetInfo(long token);
    private static native QueryResult nativeQuerySourceSetMethods(long token, byte[] queryJson);
    private static native EntityResult nativeQueryEntities(long token, byte[] queryJson, boolean sourceSet);
    private static native EntityResult nativeQueryReflectionMethodUses(long token, byte[] queryJson, boolean sourceSet);
    private static native byte[] nativeQueryGraph(long token, byte[] queryJson, boolean sourceSet);
    private static native byte[] nativeQueryClassAnnotationGraph(long token, byte[] queryJson, boolean sourceSet);
    private static native byte[] nativeQueryUseGraph(long token, byte[] queryJson, boolean sourceSet);
    private static native byte[] nativeQueryTypeUseGraph(long token, byte[] queryJson, boolean sourceSet);
    private static native byte[] nativeQueryInheritedUseGraph(long token, byte[] queryJson, boolean sourceSet);
    private static native byte[] nativeQueryInterfaceUseGraph(long token, byte[] queryJson, boolean sourceSet);
    private static native byte[] nativeInspectMethodCalls(long token,int sourceIndex,long methodRef,boolean sourceSet,int maxRecords,long maxWork,long deadlineAfterMs);
    private static native byte[] nativeInspectMethodParameters(long token,int sourceIndex,long methodRef,boolean sourceSet,int maxParameters,int maxTextUnits,long maxWork,long deadlineAfterMs);
    private static native byte[] nativeInspectMethodFacts(long token,int sourceIndex,long methodRef,boolean sourceSet,int requestedMask,int maxRecords,long maxWork,long deadlineAfterMs);
    private static native byte[] nativeQueryAdvanced(long token,byte[] queryJson,boolean sourceSet);
    private static native long nativeStartAdvancedJob(long token,byte[] queryJson,boolean sourceSet,int batchSize,int maxQueuedBatches,long deadlineAfterMs);
    private static native AdvancedJobPoll nativeAdvancedJobNext(long token,int timeoutMs);
    private static native byte[] nativeQueryMethodType(long token, byte[] queryJson, boolean sourceSet);
    private static native byte[] nativeExpandJobStatus(long token,int timeoutMs);
    private static native byte[] nativeQueryExpand(long token, byte[] queryJson, boolean sourceSet);
    private static native long nativeStartMethodTypeJob(long token, byte[] queryJson, boolean sourceSet, int batchSize, int maxQueuedBatches, long deadlineAfterMs);
    private static native long nativeStartExpandJob(long token, byte[] queryJson, boolean sourceSet, int batchSize, int maxQueuedBatches, long deadlineAfterMs);
    private static native MethodTypeJobPoll nativeMethodTypeJobNext(long token, int timeoutMs);
    private static native ExpandJobPoll nativeExpandJobNext(long token, int timeoutMs);
    private static native byte[] nativeQueryUseGraphScopedV4(long token, byte[] queryJson, boolean sourceSet);
    private static native byte[] nativeQueryFieldDeclarationGraph(long token, byte[] queryJson, boolean sourceSet);
    private static native byte[][] nativeQueryCallerFieldRelationGraph(long token, byte[] queryJson, boolean sourceSet);
    private static native long nativeStartMethodJob(long token, byte[] queryJson, boolean sourceSet,
                                                    int batchSize, int maxQueuedBatches, long deadlineAfterMs);
    private static native long nativeStartOpcodeJob(long token, byte[] queryJson, boolean sourceSet,
                                                    int batchSize, int maxQueuedBatches, long deadlineAfterMs);
    private static native long nativeStartClassAnnotationStringJob(long token, byte[] queryJson, boolean sourceSet,
                                                    int batchSize, int maxQueuedBatches, long deadlineAfterMs);
    private static native long nativeStartClassAnnotationJob(long token, byte[] queryJson, boolean sourceSet,
                                                    int batchSize, int maxQueuedBatches, long deadlineAfterMs);
    private static native long nativeStartEntityJob(long token, byte[] queryJson, boolean sourceSet,
                                                    int batchSize, int maxQueuedBatches, long deadlineAfterMs);
    private static native long nativeStartReflectionMethodUsesJob(long token, byte[] queryJson, boolean sourceSet,
                                                    int batchSize, int maxQueuedBatches, long deadlineAfterMs);
    private static native EntityJobPoll nativeEntityJobNext(long token, int timeoutMs);
    private static native long nativeStartGraphJob(long token, byte[] queryJson, boolean sourceSet,
                                                   int batchSize, int maxQueuedBatches, long deadlineAfterMs);
    private static native GraphJobPoll nativeGraphJobNext(long token, int timeoutMs);
    private static native long nativeStartUseGraphJob(long token, byte[] queryJson, boolean sourceSet, int batchSize, int maxQueuedBatches, long deadlineAfterMs);
    private static native long nativeStartTypeUseGraphJob(long token, byte[] queryJson, boolean sourceSet, int batchSize, int maxQueuedBatches, long deadlineAfterMs);
    private static native long nativeStartInheritedUseGraphJob(long token, byte[] queryJson, boolean sourceSet, int batchSize, int maxQueuedBatches, long deadlineAfterMs);
    private static native long nativeStartInterfaceUseGraphJob(long token, byte[] queryJson, boolean sourceSet, int batchSize, int maxQueuedBatches, long deadlineAfterMs);
    private static native UseGraphJobPoll nativeUseGraphJobNext(long token, int timeoutMs);
    private static native UseGraphJobStatus nativeUseGraphJobStatus(long token, int timeoutMs);
    private static native JobPoll nativeJobNext(long token, int timeoutMs);
    private static native JobStatus nativeJobStatus(long token, int timeoutMs);
    private static native void nativeJobCancel(long token);
    private static native void nativeJobClose(long token);

    private static Job startMethodJob(long token, byte[] json, boolean sourceSet,
                                      int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
        if (json == null) throw new NullPointerException("queryJson is required");
        long job = 0;
        try {
            job = nativeStartMethodJob(token, json, sourceSet, batchSize, maxQueuedBatches, deadlineAfterMs);
            return new Job(job);
        } catch (Throwable failure) {
            if (job != 0) try { nativeJobClose(job); } catch (Throwable closeFailure) { failure.addSuppressed(closeFailure); }
            throw failure;
        }
    }

    private static Job startOpcodeJob(long token, byte[] json, boolean sourceSet,
                                      int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
        if (json == null) throw new NullPointerException("queryJson is required");
        long job = 0;
        try {
            job = nativeStartOpcodeJob(token, json, sourceSet, batchSize, maxQueuedBatches, deadlineAfterMs);
            return new Job(job);
        } catch (Throwable failure) {
            if (job != 0) try { nativeJobClose(job); } catch (Throwable closeFailure) { failure.addSuppressed(closeFailure); }
            throw failure;
        }
    }

    private static EntityJob startClassAnnotationStringJob(long token, byte[] json, boolean sourceSet,
                                             int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
        if (json == null) throw new NullPointerException("queryJson is required");
        long job = 0;
        try {
            job = nativeStartClassAnnotationStringJob(token, json, sourceSet, batchSize, maxQueuedBatches, deadlineAfterMs);
            return new EntityJob(job);
        } catch (Throwable failure) {
            if (job != 0) try { nativeJobClose(job); } catch (Throwable closeFailure) { failure.addSuppressed(closeFailure); }
            throw failure;
        }
    }

    private static EntityJob startClassAnnotationJob(long token, byte[] json, boolean sourceSet,
                                             int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
        if (json == null) throw new NullPointerException("queryJson is required");
        long job = 0;
        try {
            job = nativeStartClassAnnotationJob(token, json, sourceSet, batchSize, maxQueuedBatches, deadlineAfterMs);
            return new EntityJob(job);
        } catch (Throwable failure) {
            if (job != 0) try { nativeJobClose(job); } catch (Throwable closeFailure) { failure.addSuppressed(closeFailure); }
            throw failure;
        }
    }

    private static EntityJob startEntityJob(long token, byte[] json, boolean sourceSet,
                                             int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
        if (json == null) throw new NullPointerException("queryJson is required");
        long job = 0;
        try {
            job = nativeStartEntityJob(token, json, sourceSet, batchSize, maxQueuedBatches, deadlineAfterMs);
            return new EntityJob(job);
        } catch (Throwable failure) {
            if (job != 0) try { nativeJobClose(job); } catch (Throwable closeFailure) { failure.addSuppressed(closeFailure); }
            throw failure;
        }
    }

    private static EntityJob startReflectionMethodUsesJob(long token, byte[] json, boolean sourceSet,
                                             int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
        if (json == null) throw new NullPointerException("queryJson is required");
        long job = 0;
        try {
            job = nativeStartReflectionMethodUsesJob(token, json, sourceSet, batchSize, maxQueuedBatches, deadlineAfterMs);
            return new EntityJob(job);
        } catch (Throwable failure) {
            if (job != 0) try { nativeJobClose(job); } catch (Throwable closeFailure) { failure.addSuppressed(closeFailure); }
            throw failure;
        }
    }

    private static GraphJob startGraphJob(long token, byte[] json, boolean sourceSet,
                                          int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
        if (json == null) throw new NullPointerException("queryJson is required");
        long job = 0;
        try {
            job = nativeStartGraphJob(token, json, sourceSet, batchSize, maxQueuedBatches, deadlineAfterMs);
            return new GraphJob(job);
        } catch (Throwable failure) {
            if (job != 0) try { nativeJobClose(job); } catch (Throwable closeFailure) { failure.addSuppressed(closeFailure); }
            throw failure;
        }
    }

    private static UseGraphJob startUseGraphJob(long token, byte[] json, boolean sourceSet, int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
        if (json == null) throw new NullPointerException("queryJson is required");
        long job=0;
        try { job=nativeStartUseGraphJob(token,json,sourceSet,batchSize,maxQueuedBatches,deadlineAfterMs); return new UseGraphJob(job); }
        catch(Throwable failure) { if(job!=0)try{nativeJobClose(job);}catch(Throwable closeFailure){failure.addSuppressed(closeFailure);} throw failure; }
    }

    private static UseGraphJob startInterfaceUseGraphJob(long token,byte[] json,boolean sourceSet,int batchSize,int maxQueuedBatches,long deadlineAfterMs){
        if(json==null)throw new NullPointerException("queryJson is required");long job=0;
        try{job=nativeStartInterfaceUseGraphJob(token,json,sourceSet,batchSize,maxQueuedBatches,deadlineAfterMs);return new UseGraphJob(job);}
        catch(Throwable failure){if(job!=0)try{nativeJobClose(job);}catch(Throwable closeFailure){failure.addSuppressed(closeFailure);}throw failure;}
    }

    private static UseGraphJob startInheritedUseGraphJob(long token,byte[] json,boolean sourceSet,int batchSize,int maxQueuedBatches,long deadlineAfterMs){
        if(json==null)throw new NullPointerException("queryJson is required");long job=0;
        try{job=nativeStartInheritedUseGraphJob(token,json,sourceSet,batchSize,maxQueuedBatches,deadlineAfterMs);return new UseGraphJob(job);}
        catch(Throwable failure){if(job!=0)try{nativeJobClose(job);}catch(Throwable closeFailure){failure.addSuppressed(closeFailure);}throw failure;}
    }

    private static UseGraphJob startTypeUseGraphJob(long token,byte[] json,boolean sourceSet,int batchSize,int maxQueuedBatches,long deadlineAfterMs){
        if(json==null)throw new NullPointerException("queryJson is required");long job=0;
        try{job=nativeStartTypeUseGraphJob(token,json,sourceSet,batchSize,maxQueuedBatches,deadlineAfterMs);return new UseGraphJob(job);}
        catch(Throwable failure){if(job!=0)try{nativeJobClose(job);}catch(Throwable closeFailure){failure.addSuppressed(closeFailure);}throw failure;}
    }

    private static MethodTypeJob startMethodTypeJob(long token,byte[] json,boolean sourceSet,int batchSize,int maxQueuedBatches,long deadlineAfterMs){
        if(json==null)throw new NullPointerException("queryJson is required");long job=0;
        try{job=nativeStartMethodTypeJob(token,json,sourceSet,batchSize,maxQueuedBatches,deadlineAfterMs);return new MethodTypeJob(job);}
        catch(Throwable failure){if(job!=0)try{nativeJobClose(job);}catch(Throwable closeFailure){failure.addSuppressed(closeFailure);}throw failure;}
    }
    private static AdvancedJob startAdvancedJob(long token,byte[] json,boolean sourceSet,int batchSize,int maxQueuedBatches,long deadlineAfterMs){
        if(json==null)throw new NullPointerException("queryJson is required");long job=0;
        try{job=nativeStartAdvancedJob(token,json,sourceSet,batchSize,maxQueuedBatches,deadlineAfterMs);return new AdvancedJob(job);}
        catch(Throwable failure){if(job!=0)try{nativeJobClose(job);}catch(Throwable closeFailure){failure.addSuppressed(closeFailure);}throw failure;}
    }    private static ExpandJob startExpandJob(long token,byte[] json,boolean sourceSet,int batchSize,int maxQueuedBatches,long deadlineAfterMs){
        if(json==null)throw new NullPointerException("queryJson is required");long job=0;
        try{job=nativeStartExpandJob(token,json,sourceSet,batchSize,maxQueuedBatches,deadlineAfterMs);return new ExpandJob(job);}
        catch(Throwable failure){if(job!=0)try{nativeJobClose(job);}catch(Throwable closeFailure){failure.addSuppressed(closeFailure);}throw failure;}
    }

    /**
     * Opens 1–8 ordered raw DEX inputs, at most 16 MiB in total. Slots must be
     * unique printable non-space ASCII, 1–128 characters. Callers must not
     * mutate either array or any source bytes until this call returns. Scope is
     * always incomplete; APKs and automatic source discovery are unsupported.
     */
    public static SourceSetSnapshot openRawDexSet(byte[][] bytes, String[] slots) {
        if (bytes == null || slots == null) throw new NullPointerException("bytes and slots are required");
        long token = 0;
        try { token = nativeOpenRawDexSet(bytes, slots); return new SourceSetSnapshot(token); }
        catch (Throwable failure) {
            if (token != 0) try { nativeClose(token); } catch (Throwable closeFailure) { failure.addSuppressed(closeFailure); }
            throw failure;
        }
    }

    public static final int SOURCE_RAW_DEX = 1;
    public static final int SOURCE_APK = 2;

    /**
     * Opens 1–8 explicitly typed ordered inputs, with at most 16 MiB of input
     * and 16 MiB of expanded DEX bytes and at most 64 resulting DEX sources.
     * A resource-only APK requires allowNoDex=true; raw DEX does not permit it.
     * Arrays, slots and source bytes must remain unchanged until return. No
     * APK, split or class-loader discovery is performed and scope is incomplete.
     */
    public static SourceSetSnapshot openSources(byte[][] bytes, String[] slots, int[] formats, boolean[] allowNoDex) {
        if (bytes == null || slots == null || formats == null || allowNoDex == null)
            throw new NullPointerException("bytes, slots, formats and allowNoDex are required");
        long token = 0;
        try { token = nativeOpenSources(bytes, slots, formats, allowNoDex); return new SourceSetSnapshot(token); }
        catch (Throwable failure) {
            if (token != 0) try { nativeClose(token); } catch (Throwable closeFailure) { failure.addSuppressed(closeFailure); }
            throw failure;
        }
    }

    /**
     * Opens 1–8 borrowed regular-file APK ranges under explicit core limits.
     * Caller retains and must keep every descriptor and array stable until return.
     * Native duplicates descriptors and copies data synchronously; this call is not cancellable.
     * The returned static source scope remains incomplete and does not authenticate runtime origin.
     */
    public static SourceSetSnapshot openApkFdSources(int[] fds,long[] offsets,long[] lengths,String[] slots,
            boolean[] allowNoDex,String[] expectedSha256,ApkFdLimits limits) {
        return openApkFdSourcesRetained(fds,offsets,lengths,slots,allowNoDex,expectedSha256,limits,null);
    }
    // JNI parameter remains a strong local reference for the full synchronous call.
    static SourceSetSnapshot openApkFdSourcesRetained(int[] fds,long[] offsets,long[] lengths,String[] slots,
            boolean[] allowNoDex,String[] expectedSha256,ApkFdLimits limits,Object[] keepAlive) {
        if(fds==null||offsets==null||lengths==null||slots==null||allowNoDex==null||limits==null)
            throw new NullPointerException("fd sources and limits are required");
        int count=fds.length;if(count<1||count>8||offsets.length!=count||lengths.length!=count||slots.length!=count||allowNoDex.length!=count||
                (expectedSha256!=null&&expectedSha256.length!=count)||(keepAlive!=null&&keepAlive.length!=count))throw new IllegalArgumentException("invalid fd source count");
        int[] capturedFds=fds.clone();long[] capturedOffsets=offsets.clone(),capturedLengths=lengths.clone();
        String[] capturedSlots=slots.clone(),capturedExpected=expectedSha256==null?null:expectedSha256.clone();
        boolean[] capturedAllow=allowNoDex.clone();
        ApkFdInputs.validate(capturedFds,capturedOffsets,capturedLengths,capturedSlots,capturedAllow,capturedExpected,limits);long token=0;
        try {token=nativeOpenApkFdSources(capturedFds,capturedOffsets,capturedLengths,capturedSlots,capturedAllow,capturedExpected,limits.nativeValues(),keepAlive);return new SourceSetSnapshot(token);}
        catch(Throwable failure){if(token!=0)try{nativeClose(token);}catch(Throwable closeFailure){failure.addSuppressed(closeFailure);}throw failure;}
    }

    // Only AndroidApkSources supplies strictly encoded paths. Native revalidates all inputs.
    static SourceSetSnapshot openApkPaths(byte[][] paths,String[] slots,boolean[] allowNoDex,String[] expectedSha256,ApkFdLimits limits) {
        if(paths==null||slots==null||allowNoDex==null||limits==null)throw new NullPointerException("paths and limits are required");
        int count=paths.length;if(count<1||count>8||slots.length!=count||allowNoDex.length!=count||
                (expectedSha256!=null&&expectedSha256.length!=count))throw new IllegalArgumentException("invalid path source count");
        byte[][] captured=new byte[count][];for(int i=0;i<count;i++){
            if(paths[i]==null||paths[i].length<1||paths[i].length>32767)throw new IllegalArgumentException("invalid path bytes");
            captured[i]=paths[i].clone();
        }
        String[] keys=slots.clone(),expected=expectedSha256==null?null:expectedSha256.clone();boolean[] allow=allowNoDex.clone();
        ApkFdInputs.validate(new int[captured.length],new long[captured.length],new long[captured.length],keys,allow,expected,limits);
        long token=0;try{token=nativeOpenApkPaths(captured,keys,allow,expected,limits.nativeValues());return new SourceSetSnapshot(token);}
        catch(Throwable failure){if(token!=0)try{nativeClose(token);}catch(Throwable closeFailure){if(closeFailure!=failure)failure.addSuppressed(closeFailure);}throw failure;}
    }

    /** Single-threaded per handle by synchronization; arrays must remain unchanged during open. */
    public static final class SourceSetSnapshot implements AutoCloseable {
        private long token;
        private SourceSetSnapshot(long token) { if (token == 0) throw new IllegalStateException("native snapshot token is zero"); this.token=token; }
        public synchronized SourceSetInfo info() { if(token==0)throw new IllegalStateException("snapshot is closed"); return nativeSourceSetInfo(token); }
        public synchronized QueryResult queryMethods(byte[] queryJson) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            if(queryJson==null)throw new NullPointerException("queryJson is required");
            return nativeQuerySourceSetMethods(token,queryJson);
        }
        /** Returns static facts co-occurring in the same method. */
        public synchronized MethodTypeResult queryMethodType(byte[] json){if(token==0)throw new IllegalStateException("snapshot is closed");if(json==null)throw new NullPointerException("queryJson is required");return MethodTypeResult.decode(nativeQueryMethodType(token,json,true));}
        /** Static prototype parameters and optional DEX debug names from this source occurrence. */
        public synchronized MethodParametersResult inspectMethodParameters(int sourceIndex,long methodRef){return inspectMethodParameters(sourceIndex,methodRef,4096,1048576,100000000L,0L);}
        public synchronized MethodParametersResult inspectMethodParameters(int sourceIndex,long methodRef,int maxParameters,int maxTextUnits,long maxWork,long deadlineAfterMs){if(token==0)throw new IllegalStateException("snapshot is closed");return MethodParametersResult.decode(nativeInspectMethodParameters(token,sourceIndex,methodRef,true,maxParameters,maxTextUnits,maxWork,deadlineAfterMs));}
        public synchronized MethodCallsResult inspectMethodCalls(int sourceIndex,long methodRef){return inspectMethodCalls(sourceIndex,methodRef,4096,100000000L,0L);}
        public synchronized MethodCallsResult inspectMethodCalls(int sourceIndex,long methodRef,int maxRecords,long maxWork,long deadlineAfterMs){if(token==0)throw new IllegalStateException("snapshot is closed");return MethodCallsResult.decode(nativeInspectMethodCalls(token,sourceIndex,methodRef,true,maxRecords,maxWork,deadlineAfterMs));}
        /** Complete checked facts for one selected local method; source identity is not runtime binding. */
        public synchronized MethodFactsResult inspectMethodFacts(int sourceIndex,long methodRef,int requestedMask,int maxRecords,long maxWork,long deadlineAfterMs){if(token==0)throw new IllegalStateException("snapshot is closed");return MethodFactsResult.decode(nativeInspectMethodFacts(token,sourceIndex,methodRef,true,requestedMask,maxRecords,maxWork,deadlineAfterMs));}
        public synchronized AdvancedResult queryAdvanced(byte[] json){if(token==0)throw new IllegalStateException("snapshot is closed");if(json==null)throw new NullPointerException("queryJson is required");return AdvancedResult.decode(nativeQueryAdvanced(token,json,true));}
        public synchronized ExpandResult queryExpand(byte[] json){if(token==0)throw new IllegalStateException("snapshot is closed");if(json==null)throw new NullPointerException("queryJson is required");return ExpandResult.decode(nativeQueryExpand(token,json,true));}
        public synchronized MethodTypeJob startMethodTypeJob(byte[] json,int batchSize,int maxQueuedBatches,long deadlineAfterMs){if(token==0)throw new IllegalStateException("snapshot is closed");return NativeEngine.startMethodTypeJob(token,json,true,batchSize,maxQueuedBatches,deadlineAfterMs);}
        public synchronized AdvancedJob startAdvancedJob(byte[] json,int batchSize,int maxQueuedBatches,long deadlineAfterMs){if(token==0)throw new IllegalStateException("snapshot is closed");return NativeEngine.startAdvancedJob(token,json,true,batchSize,maxQueuedBatches,deadlineAfterMs);}
        public synchronized ExpandJob startExpandJob(byte[] json,int batchSize,int maxQueuedBatches,long deadlineAfterMs){if(token==0)throw new IllegalStateException("snapshot is closed");return NativeEngine.startExpandJob(token,json,true,batchSize,maxQueuedBatches,deadlineAfterMs);}
        /** Explicit v21 type-use graph; returned descriptors are static source-local facts. */
        /** Explicit v8/v11 static interface inheritance with use graph evidence. */
        public synchronized UseGraphResult queryInterfaceUseGraph(byte[] queryJson){
            if(token==0)throw new IllegalStateException("snapshot is closed");if(queryJson==null)throw new NullPointerException("queryJson is required");
            return UseGraphResult.decode(nativeQueryInterfaceUseGraph(token,queryJson,true));
        }
        public synchronized UseGraphJob startInterfaceUseGraphJob(byte[] queryJson,int batchSize,int maxQueuedBatches,long deadlineAfterMs){
            if(token==0)throw new IllegalStateException("snapshot is closed");return NativeEngine.startInterfaceUseGraphJob(token,queryJson,true,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        /** Explicit v6 static inheritance and use graph; scope is a caller declaration. */
        public synchronized UseGraphResult queryInheritedUseGraph(byte[] queryJson){
            if(token==0)throw new IllegalStateException("snapshot is closed");if(queryJson==null)throw new NullPointerException("queryJson is required");
            return UseGraphResult.decode(nativeQueryInheritedUseGraph(token,queryJson,true));
        }
        public synchronized UseGraphJob startInheritedUseGraphJob(byte[] queryJson,int batchSize,int maxQueuedBatches,long deadlineAfterMs){
            if(token==0)throw new IllegalStateException("snapshot is closed");return NativeEngine.startInheritedUseGraphJob(token,queryJson,true,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        public synchronized UseGraphResult queryTypeUseGraph(byte[] queryJson){
            if(token==0)throw new IllegalStateException("snapshot is closed");if(queryJson==null)throw new NullPointerException("queryJson is required");
            return UseGraphResult.decode(nativeQueryTypeUseGraph(token,queryJson,true));
        }
        public synchronized UseGraphJob startTypeUseGraphJob(byte[] queryJson,int batchSize,int maxQueuedBatches,long deadlineAfterMs){
            if(token==0)throw new IllegalStateException("snapshot is closed");return NativeEngine.startTypeUseGraphJob(token,queryJson,true,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        /** Executes a bounded v4/v9/v16/v18 use-event graph and copies its tagged evidence. */
        public synchronized UseGraphResult queryUseGraph(byte[] queryJson) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            if(queryJson==null)throw new NullPointerException("queryJson is required");
            return UseGraphResult.decode(nativeQueryUseGraph(token,queryJson,true));
        }
        /** Explicit v4 top-level slot scope; completeness is the caller's static declaration. */
        public synchronized UseGraphResult queryUseGraphScopedV4(byte[] queryJson) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            if(queryJson==null)throw new NullPointerException("queryJson is required");
            return UseGraphResult.decode(nativeQueryUseGraphScopedV4(token,queryJson,true));
        }
        /** Scoped static field declaration candidates relative to the field reference owner. */
        public synchronized UseGraphResult queryFieldDeclarationGraph(byte[] queryJson) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            if(queryJson==null)throw new NullPointerException("queryJson is required");
            return UseGraphResult.decode(nativeQueryFieldDeclarationGraph(token,queryJson,true));
        }
        /** Static caller-to-field-class observation; does not authenticate loader or access. */
        public synchronized CallerFieldRelationResult queryCallerFieldRelationGraph(byte[] queryJson) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            if(queryJson==null)throw new NullPointerException("queryJson is required");
            return CallerFieldRelationResult.decode(nativeQueryCallerFieldRelationGraph(token,queryJson,true));
        }
        /** Starts a provisional unscoped v4/v9 use-event graph job. */
        public synchronized UseGraphJob startUseGraphJob(byte[] queryJson, int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            return NativeEngine.startUseGraphJob(token,queryJson,true,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        /** Executes a v3 metadata graph and copies bindings, links and witnesses. */
        public synchronized GraphResult queryGraph(byte[] queryJson) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            if(queryJson==null)throw new NullPointerException("queryJson is required");
            return GraphResult.decode(nativeQueryGraph(token,queryJson,true));
        }
        /** Explicit static annotation-aware reflection graph; not runtime binding. */
        public synchronized GraphResult queryClassAnnotationGraph(byte[] queryJson) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            if(queryJson==null)throw new NullPointerException("queryJson is required");
            return GraphResult.decode(nativeQueryClassAnnotationGraph(token,queryJson,true));
        }
        /** Starts a provisional stream of v3 metadata graph batches. */
        public synchronized GraphJob startGraphJob(byte[] queryJson, int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            return NativeEngine.startGraphJob(token,queryJson,true,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        /** Executes a direct metadata entity query; results are copied and contain no witnesses. */
        public synchronized EntityResult queryEntities(byte[] queryJson) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            if(queryJson==null)throw new NullPointerException("queryJson is required");
            return nativeQueryEntities(token,queryJson,true);
        }
        /** Executes an explicitly declared v15 method query over this incomplete source set. */
        public synchronized EntityResult queryReflectionMethodUses(byte[] queryJson) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            if(queryJson==null)throw new NullPointerException("queryJson is required");
            return nativeQueryReflectionMethodUses(token,queryJson,true);
        }
        /** Starts provisional v15 entity batches; consume to EOS before checking status. */
        public synchronized EntityJob startReflectionMethodUsesJob(byte[] queryJson, int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            return NativeEngine.startReflectionMethodUsesJob(token,queryJson,true,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        /** Starts provisional batches for an explicitly declared, non-scoped v24 class annotation query. */
        public synchronized EntityJob startClassAnnotationJob(byte[] queryJson, int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            return NativeEngine.startClassAnnotationJob(token,queryJson,true,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        /** Starts provisional batches for an explicitly declared, non-scoped v25 class annotation string query. */
        public synchronized EntityJob startClassAnnotationStringJob(byte[] queryJson, int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            return NativeEngine.startClassAnnotationStringJob(token,queryJson,true,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        /** Starts a provisional stream of direct metadata entity batches. */
        public synchronized EntityJob startEntityJob(byte[] queryJson, int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            return NativeEngine.startEntityJob(token,queryJson,true,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        /** Starts provisional batches for an explicitly declared, non-scoped v23 opcode query. */
        public synchronized Job startOpcodeJob(byte[] queryJson, int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            return NativeEngine.startOpcodeJob(token,queryJson,true,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        /** Starts a provisional batch stream for a direct method-v1 query. */
        public synchronized Job startMethodJob(byte[] queryJson, int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            return NativeEngine.startMethodJob(token,queryJson,true,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        @Override public synchronized void close() { if(token!=0){nativeClose(token);token=0;} }
    }

    /** Ordered copied source identities. This list does not describe an entire loader. */
    public static final class SourceSetInfo {
        public final String snapshotId;
        public final boolean sourceScopeComplete;
        private final RawDexSourceInfo[] sources;
        private final InputInfo[] inputs;
        private SourceSetInfo(String snapshotId,boolean sourceScopeComplete,RawDexSourceInfo[] sources) {
            this(snapshotId,sourceScopeComplete,sources,new InputInfo[0]);
        }
        private SourceSetInfo(String snapshotId,boolean sourceScopeComplete,RawDexSourceInfo[] sources,InputInfo[] inputs) {
            this.snapshotId=snapshotId;this.sourceScopeComplete=sourceScopeComplete;this.sources=sources;this.inputs=inputs;
        }
        public int sourceCount(){return sources.length;}
        public RawDexSourceInfo source(int index){return sources[index];}
        public int inputCount(){return inputs.length;}
        public InputInfo input(int index){return inputs[index];}
    }
    /** A copied input identity, including resource-only APK inputs with zero DEX sources. */
    public static final class InputInfo {
        public final int inputIndex,format,sourceCount;
        /** containerMetadataChecked is false for raw DEX; it is not a signature check. */
        public final boolean allowNoDex,containerMetadataChecked;
        public final long inputBytes;
        public final String slot,sourceSha256,contentId;
        private InputInfo(int inputIndex,int format,int sourceCount,boolean allowNoDex,boolean containerMetadataChecked,
                          long inputBytes,String slot,String sourceSha256,String contentId) {
            this.inputIndex=inputIndex;this.format=format;this.sourceCount=sourceCount;this.allowNoDex=allowNoDex;
            this.containerMetadataChecked=containerMetadataChecked;this.inputBytes=inputBytes;this.slot=slot;
            this.sourceSha256=sourceSha256;this.contentId=contentId;
        }
    }
    public static final class RawDexSourceInfo {
        public final int sourceIndex,inputIndex;
        public final long sourceBytes;
        public final String slot,sourceSha256,contentId,occurrenceId,logicalDexId;
        /** Null and -1 for raw inputs; ZIP entry name and central directory index for APK DEX. */
        public final String archiveEntryName;
        public final int archiveEntryIndex;
        private RawDexSourceInfo(int sourceIndex,int inputIndex,long sourceBytes,String slot,String sourceSha256,
                                 String contentId,String occurrenceId,String logicalDexId){
            this(sourceIndex,inputIndex,sourceBytes,slot,sourceSha256,contentId,occurrenceId,logicalDexId,null,-1);
        }
        private RawDexSourceInfo(int sourceIndex,int inputIndex,long sourceBytes,String slot,String sourceSha256,
                                 String contentId,String occurrenceId,String logicalDexId,String archiveEntryName,int archiveEntryIndex){
            this.sourceIndex=sourceIndex;this.inputIndex=inputIndex;this.sourceBytes=sourceBytes;this.slot=slot;
            this.sourceSha256=sourceSha256;this.contentId=contentId;this.occurrenceId=occurrenceId;this.logicalDexId=logicalDexId;
            this.archiveEntryName=archiveEntryName;this.archiveEntryIndex=archiveEntryIndex;
        }
    }

    /**
     * Compiles method-v1 queries once and opens raw DEX snapshots on the same
     * engine. Close each snapshot as soon as its result is consumed to keep
     * input memory bounded; sources are not collected into one full snapshot.
     * Limits apply to this session's core allocations, not Java or VM memory.
     * Source scope remains incomplete. Calls are synchronous and not cancellable.
     */
    public static MethodStream openMethodStream(byte[][] queries,long maxSourceBytes,long maxOwnedBytes) {
        if(queries==null)throw new NullPointerException("queries are required");
        if(maxSourceBytes<=0||maxSourceBytes>Integer.MAX_VALUE||maxOwnedBytes<=0)throw new IllegalArgumentException("invalid source or owned memory limit");
        long token=0;
        try {token=nativeCreateMethodStream(queries,maxSourceBytes,maxOwnedBytes);return new MethodStream(token);}
        catch(Throwable failure){if(token!=0)try{nativeCloseMethodStream(token);}catch(Throwable closeFailure){failure.addSuppressed(closeFailure);}throw failure;}
    }
    public static final class MethodStream implements AutoCloseable {
        private long token;
        private MethodStream(long token){if(token==0)throw new IllegalStateException("native stream token is zero");this.token=token;}
        public synchronized Snapshot openRawDex(byte[] bytes,String slot){
            if(token==0)throw new IllegalStateException("stream is closed");
            if(bytes==null||slot==null)throw new NullPointerException("bytes and slot are required");
            long snapshot=0;
            try{snapshot=nativeOpenMethodStreamDex(token,bytes,slot);return new Snapshot(snapshot);}
            catch(Throwable failure){if(snapshot!=0)try{nativeClose(snapshot);}catch(Throwable closeFailure){failure.addSuppressed(closeFailure);}throw failure;}
        }
        public synchronized QueryResult queryMethods(Snapshot snapshot,int queryIndex){
            if(token==0)throw new IllegalStateException("stream is closed");
            if(snapshot==null)throw new NullPointerException("snapshot is required");
            synchronized(snapshot){if(snapshot.token==0)throw new IllegalStateException("snapshot is closed");return nativeMethodStreamQuery(token,snapshot.token,queryIndex);}
        }
        /**
         * Runs selected precompiled plans in index order. Eligible method enumerations
         * share the source traversal; admitted batch shapes that cannot share it
         * fall back to the existing per-rule executor. Plans outside the existing
         * MethodBatchQuery capability, demand or projection subset are rejected.
         * The index array must not change until the call returns.
         * Execution is atomic: MethodBatchQuery.Failure.failureIndex identifies the
         * position in queryIndices, or -1 when no individual plan is attributable.
         * Inspect each returned result's status and coverage.
         */
        public synchronized MethodBatchQuery.Result queryMethodsBatch(Snapshot snapshot,int[] queryIndices,long cacheBytes,long maxCacheWork){
            if(token==0)throw new IllegalStateException("stream is closed");
            if(snapshot==null||queryIndices==null)throw new NullPointerException("snapshot and queryIndices are required");
            synchronized(snapshot){if(snapshot.token==0)throw new IllegalStateException("snapshot is closed");return nativeMethodStreamQueryBatch(token,snapshot.token,queryIndices,cacheBytes,maxCacheWork);}
        }
        @Override public synchronized void close(){if(token!=0){long old=token;token=0;nativeCloseMethodStream(old);}}
    }

    /** A closeable source handle; close and info are serialized per instance. */
    public static final class Snapshot implements AutoCloseable {
        private long token;
        private Snapshot(long token) {
            if (token == 0) throw new IllegalStateException("native snapshot token is zero");
            this.token = token;
        }
        public synchronized SnapshotInfo info() {
            if (token == 0) throw new IllegalStateException("snapshot is closed");
            return nativeSnapshotInfo(token);
        }
        /**
         * Executes direct method-v1 JSON synchronously; callers must not mutate the
         * input until this call returns. Explicit scopes, other profiles and queries
         * above the bridge limits are rejected. Rows are candidates without witnesses;
         * decisions are native results, not independently verified proofs.
         */
        public synchronized QueryResult queryMethods(byte[] queryJson) {
            if (token == 0) throw new IllegalStateException("snapshot is closed");
            if (queryJson == null) throw new NullPointerException("queryJson is required");
            return nativeQueryMethods(token, queryJson);
        }
        /** Explicit v21 type-use graph; returned descriptors are static source-local facts. */
        /** Returns static facts co-occurring in the same method. */
        public synchronized MethodTypeResult queryMethodType(byte[] json){if(token==0)throw new IllegalStateException("snapshot is closed");if(json==null)throw new NullPointerException("queryJson is required");return MethodTypeResult.decode(nativeQueryMethodType(token,json,false));}
        /** Static prototype parameters and optional DEX debug names, not runtime reflection. */
        public synchronized MethodParametersResult inspectMethodParameters(long methodRef){return inspectMethodParameters(methodRef,4096,1048576,100000000L,0L);}
        public synchronized MethodParametersResult inspectMethodParameters(long methodRef,int maxParameters,int maxTextUnits,long maxWork,long deadlineAfterMs){if(token==0)throw new IllegalStateException("snapshot is closed");return MethodParametersResult.decode(nativeInspectMethodParameters(token,0,methodRef,false,maxParameters,maxTextUnits,maxWork,deadlineAfterMs));}
        public synchronized MethodCallsResult inspectMethodCalls(long methodRef){return inspectMethodCalls(methodRef,4096,100000000L,0L);}
        public synchronized MethodCallsResult inspectMethodCalls(long methodRef,int maxRecords,long maxWork,long deadlineAfterMs){if(token==0)throw new IllegalStateException("snapshot is closed");return MethodCallsResult.decode(nativeInspectMethodCalls(token,0,methodRef,false,maxRecords,maxWork,deadlineAfterMs));}
        /** Complete checked facts for one selected local method; source identity is not runtime binding. */
        public synchronized MethodFactsResult inspectMethodFacts(long methodRef,int requestedMask,int maxRecords,long maxWork,long deadlineAfterMs){if(token==0)throw new IllegalStateException("snapshot is closed");return MethodFactsResult.decode(nativeInspectMethodFacts(token,0,methodRef,false,requestedMask,maxRecords,maxWork,deadlineAfterMs));}
        public synchronized AdvancedResult queryAdvanced(byte[] json){if(token==0)throw new IllegalStateException("snapshot is closed");if(json==null)throw new NullPointerException("queryJson is required");return AdvancedResult.decode(nativeQueryAdvanced(token,json,false));}
        public synchronized ExpandResult queryExpand(byte[] json){if(token==0)throw new IllegalStateException("snapshot is closed");if(json==null)throw new NullPointerException("queryJson is required");return ExpandResult.decode(nativeQueryExpand(token,json,false));}
        public synchronized MethodTypeJob startMethodTypeJob(byte[] json,int batchSize,int maxQueuedBatches,long deadlineAfterMs){if(token==0)throw new IllegalStateException("snapshot is closed");return NativeEngine.startMethodTypeJob(token,json,false,batchSize,maxQueuedBatches,deadlineAfterMs);}
        public synchronized AdvancedJob startAdvancedJob(byte[] json,int batchSize,int maxQueuedBatches,long deadlineAfterMs){if(token==0)throw new IllegalStateException("snapshot is closed");return NativeEngine.startAdvancedJob(token,json,false,batchSize,maxQueuedBatches,deadlineAfterMs);}
        public synchronized ExpandJob startExpandJob(byte[] json,int batchSize,int maxQueuedBatches,long deadlineAfterMs){if(token==0)throw new IllegalStateException("snapshot is closed");return NativeEngine.startExpandJob(token,json,false,batchSize,maxQueuedBatches,deadlineAfterMs);}
        /** Explicit v8/v11 static interface inheritance with use graph evidence. */
        public synchronized UseGraphResult queryInterfaceUseGraph(byte[] queryJson){
            if(token==0)throw new IllegalStateException("snapshot is closed");if(queryJson==null)throw new NullPointerException("queryJson is required");
            return UseGraphResult.decode(nativeQueryInterfaceUseGraph(token,queryJson,false));
        }
        public synchronized UseGraphJob startInterfaceUseGraphJob(byte[] queryJson,int batchSize,int maxQueuedBatches,long deadlineAfterMs){
            if(token==0)throw new IllegalStateException("snapshot is closed");return NativeEngine.startInterfaceUseGraphJob(token,queryJson,false,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        /** Explicit v6 static inheritance and use graph; scope is a caller declaration. */
        public synchronized UseGraphResult queryInheritedUseGraph(byte[] queryJson){
            if(token==0)throw new IllegalStateException("snapshot is closed");if(queryJson==null)throw new NullPointerException("queryJson is required");
            return UseGraphResult.decode(nativeQueryInheritedUseGraph(token,queryJson,false));
        }
        public synchronized UseGraphJob startInheritedUseGraphJob(byte[] queryJson,int batchSize,int maxQueuedBatches,long deadlineAfterMs){
            if(token==0)throw new IllegalStateException("snapshot is closed");return NativeEngine.startInheritedUseGraphJob(token,queryJson,false,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        public synchronized UseGraphResult queryTypeUseGraph(byte[] queryJson){
            if(token==0)throw new IllegalStateException("snapshot is closed");if(queryJson==null)throw new NullPointerException("queryJson is required");
            return UseGraphResult.decode(nativeQueryTypeUseGraph(token,queryJson,false));
        }
        public synchronized UseGraphJob startTypeUseGraphJob(byte[] queryJson,int batchSize,int maxQueuedBatches,long deadlineAfterMs){
            if(token==0)throw new IllegalStateException("snapshot is closed");return NativeEngine.startTypeUseGraphJob(token,queryJson,false,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        /** Executes a bounded v4/v9/v16/v18 use-event graph and copies its tagged evidence. */
        public synchronized UseGraphResult queryUseGraph(byte[] queryJson) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            if(queryJson==null)throw new NullPointerException("queryJson is required");
            return UseGraphResult.decode(nativeQueryUseGraph(token,queryJson,false));
        }
        /** Explicit v4 top-level slot scope; completeness is the caller's static declaration. */
        public synchronized UseGraphResult queryUseGraphScopedV4(byte[] queryJson) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            if(queryJson==null)throw new NullPointerException("queryJson is required");
            return UseGraphResult.decode(nativeQueryUseGraphScopedV4(token,queryJson,false));
        }
        /** Scoped static field declaration candidates relative to the field reference owner. */
        public synchronized UseGraphResult queryFieldDeclarationGraph(byte[] queryJson) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            if(queryJson==null)throw new NullPointerException("queryJson is required");
            return UseGraphResult.decode(nativeQueryFieldDeclarationGraph(token,queryJson,false));
        }
        /** Static caller-to-field-class observation; does not authenticate loader or access. */
        public synchronized CallerFieldRelationResult queryCallerFieldRelationGraph(byte[] queryJson) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            if(queryJson==null)throw new NullPointerException("queryJson is required");
            return CallerFieldRelationResult.decode(nativeQueryCallerFieldRelationGraph(token,queryJson,false));
        }
        /** Starts a provisional unscoped v4/v9 use-event graph job. */
        public synchronized UseGraphJob startUseGraphJob(byte[] queryJson, int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            return NativeEngine.startUseGraphJob(token,queryJson,false,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        /** Executes a v3 metadata graph and copies bindings, links and witnesses. */
        public synchronized GraphResult queryGraph(byte[] queryJson) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            if(queryJson==null)throw new NullPointerException("queryJson is required");
            return GraphResult.decode(nativeQueryGraph(token,queryJson,false));
        }
        /** Explicit static annotation-aware reflection graph; not runtime binding. */
        public synchronized GraphResult queryClassAnnotationGraph(byte[] queryJson) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            if(queryJson==null)throw new NullPointerException("queryJson is required");
            return GraphResult.decode(nativeQueryClassAnnotationGraph(token,queryJson,false));
        }
        /** Starts a provisional stream of v3 metadata graph batches. */
        public synchronized GraphJob startGraphJob(byte[] queryJson, int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            return NativeEngine.startGraphJob(token,queryJson,false,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        /** Executes a direct metadata entity query; results are copied and contain no witnesses. */
        public synchronized EntityResult queryEntities(byte[] queryJson) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            if(queryJson==null)throw new NullPointerException("queryJson is required");
            return nativeQueryEntities(token,queryJson,false);
        }
        /** Executes an explicitly declared v15 method query over this incomplete snapshot. */
        public synchronized EntityResult queryReflectionMethodUses(byte[] queryJson) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            if(queryJson==null)throw new NullPointerException("queryJson is required");
            return nativeQueryReflectionMethodUses(token,queryJson,false);
        }
        /** Starts provisional v15 entity batches; consume to EOS before checking status. */
        public synchronized EntityJob startReflectionMethodUsesJob(byte[] queryJson, int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            return NativeEngine.startReflectionMethodUsesJob(token,queryJson,false,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        /** Starts provisional batches for an explicitly declared, non-scoped v24 class annotation query. */
        public synchronized EntityJob startClassAnnotationJob(byte[] queryJson, int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            return NativeEngine.startClassAnnotationJob(token,queryJson,false,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        /** Starts provisional batches for an explicitly declared, non-scoped v25 class annotation string query. */
        public synchronized EntityJob startClassAnnotationStringJob(byte[] queryJson, int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            return NativeEngine.startClassAnnotationStringJob(token,queryJson,false,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        /** Starts a provisional stream of direct metadata entity batches. */
        public synchronized EntityJob startEntityJob(byte[] queryJson, int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            return NativeEngine.startEntityJob(token,queryJson,false,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        /** Starts provisional batches for an explicitly declared, non-scoped v23 opcode query. */
        public synchronized Job startOpcodeJob(byte[] queryJson, int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            return NativeEngine.startOpcodeJob(token,queryJson,false,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        /** Starts a provisional batch stream for a direct method-v1 query. */
        public synchronized Job startMethodJob(byte[] queryJson, int batchSize, int maxQueuedBatches, long deadlineAfterMs) {
            if(token==0)throw new IllegalStateException("snapshot is closed");
            return NativeEngine.startMethodJob(token,queryJson,false,batchSize,maxQueuedBatches,deadlineAfterMs);
        }
        @Override public synchronized void close() {
            if (token == 0) return;
            nativeClose(token);
            token = 0;
        }
    }

    /**
     * One consumer may call next at a time. cancel and close can run concurrently
     * with next or wait. An in-flight call may finish after close; after an
     * exception while reading a batch, discard the stream and close the job.
     */
    public static final class Job implements AutoCloseable {
        private long token;
        private Job(long token) { if(token==0)throw new IllegalStateException("native job token is zero");this.token=token; }
        private synchronized long liveToken() { if(token==0)throw new IllegalStateException("job is closed");return token; }
        public JobPoll next(int timeoutMs) { return nativeJobNext(liveToken(),timeoutMs); }
        public JobStatus status() { return nativeJobStatus(liveToken(),-1); }
        public JobStatus waitFor(int timeoutMs) {
            if(timeoutMs<0)throw new IllegalArgumentException("invalid wait timeout");
            return nativeJobStatus(liveToken(),timeoutMs);
        }
        public void cancel() { nativeJobCancel(liveToken()); }
        @Override public void close() {
            long previous;
            synchronized(this) { previous=token;token=0; }
            if(previous!=0)nativeJobClose(previous);
        }
    }
    /** kind: 0 batch, 1 wait timed out, 2 end of stream. End is not success. */
    public static final class JobPoll {
        public final int kind;
        public final QueryResult batch;
        private JobPoll(int kind,QueryResult batch) {this.kind=kind;this.batch=batch;}
    }
    /** Final fields are authoritative only when terminal is true. */
    public static final class JobStatus {
        public final int lifecycle,executionStatus,coverage,decision,reason,candidateCount,visitedMethods,totalMethods;
        public final boolean terminal;
        public final long unknownRows,errorOffset;
        public final String queryId,snapshotId,errorMessage;
        private JobStatus(int lifecycle,boolean terminal,int executionStatus,int coverage,int decision,int reason,
                          int candidateCount,int visitedMethods,int totalMethods,long unknownRows,long errorOffset,
                          String queryId,String snapshotId,String errorMessage) {
            this.lifecycle=lifecycle;this.terminal=terminal;this.executionStatus=executionStatus;this.coverage=coverage;
            this.decision=decision;this.reason=reason;this.candidateCount=candidateCount;this.visitedMethods=visitedMethods;
            this.totalMethods=totalMethods;this.unknownRows=unknownRows;this.errorOffset=errorOffset;
            this.queryId=queryId;this.snapshotId=snapshotId;this.errorMessage=errorMessage;
        }
    }

    public static final class MethodTypeJob implements AutoCloseable {
        private long token;
        private MethodTypeJob(long token){if(token==0)throw new IllegalStateException("native job token is zero");this.token=token;}
        private synchronized long liveToken(){if(token==0)throw new IllegalStateException("job is closed");return token;}
        public MethodTypeJobPoll next(int timeoutMs){return nativeMethodTypeJobNext(liveToken(),timeoutMs);}
        public JobStatus status(){return nativeJobStatus(liveToken(),-1);}
        public JobStatus waitFor(int timeoutMs){if(timeoutMs<0)throw new IllegalArgumentException("invalid wait timeout");return nativeJobStatus(liveToken(),timeoutMs);}
        public void cancel(){nativeJobCancel(liveToken());}
        @Override public void close(){long previous;synchronized(this){previous=token;token=0;}if(previous!=0)nativeJobClose(previous);}
    }
    public static final class MethodTypeJobPoll {
        public final int kind; public final MethodTypeResult batch;
        private MethodTypeJobPoll(int kind,MethodTypeResult batch){this.kind=kind;this.batch=batch;}
    }
    public static final class AdvancedJob implements AutoCloseable {
        private long token;
        private AdvancedJob(long token){if(token==0)throw new IllegalStateException("native job token is zero");this.token=token;}
        private synchronized long liveToken(){if(token==0)throw new IllegalStateException("job is closed");return token;}
        public AdvancedJobPoll next(int timeoutMs){return nativeAdvancedJobNext(liveToken(),timeoutMs);}
        public JobStatus status(){return nativeJobStatus(liveToken(),-1);}
        public JobStatus waitFor(int timeoutMs){if(timeoutMs<0)throw new IllegalArgumentException("invalid wait timeout");return nativeJobStatus(liveToken(),timeoutMs);}
        public void cancel(){nativeJobCancel(liveToken());}
        @Override public void close(){long previous;synchronized(this){previous=token;token=0;}if(previous!=0)nativeJobClose(previous);}
    }
    public static final class AdvancedJobPoll {
        public final int kind; public final AdvancedResult batch;
        private AdvancedJobPoll(int kind,AdvancedResult batch){this.kind=kind;this.batch=batch;}
    }
    public static final class ExpandJob implements AutoCloseable {
        private long token;
        private ExpandJob(long token){if(token==0)throw new IllegalStateException("native job token is zero");this.token=token;}
        private synchronized long liveToken(){if(token==0)throw new IllegalStateException("job is closed");return token;}
        public ExpandJobPoll next(int timeoutMs){return nativeExpandJobNext(liveToken(),timeoutMs);}
        public ExpandResult status(){return ExpandResult.decode(nativeExpandJobStatus(liveToken(),-1));}
        public ExpandResult waitFor(int timeoutMs){if(timeoutMs<0)throw new IllegalArgumentException("invalid wait timeout");return ExpandResult.decode(nativeExpandJobStatus(liveToken(),timeoutMs));}
        public void cancel(){nativeJobCancel(liveToken());}
        @Override public void close(){long previous;synchronized(this){previous=token;token=0;}if(previous!=0)nativeJobClose(previous);}
    }
    public static final class ExpandJobPoll {
        public final int kind; public final ExpandResult batch;
        private ExpandJobPoll(int kind,ExpandResult batch){this.kind=kind;this.batch=batch;}
    }

    /** One consumer at a time; cancel and close can run concurrently with next and wait. */
    public static final class EntityJob implements AutoCloseable {
        private long token;
        private EntityJob(long token) { if(token==0)throw new IllegalStateException("native job token is zero");this.token=token; }
        private synchronized long liveToken() { if(token==0)throw new IllegalStateException("job is closed");return token; }
        public EntityJobPoll next(int timeoutMs) { return nativeEntityJobNext(liveToken(),timeoutMs); }
        public EntityJobStatus status() { return new EntityJobStatus(nativeJobStatus(liveToken(),-1)); }
        public EntityJobStatus waitFor(int timeoutMs) {
            if(timeoutMs<0)throw new IllegalArgumentException("invalid wait timeout");
            return new EntityJobStatus(nativeJobStatus(liveToken(),timeoutMs));
        }
        public void cancel() { nativeJobCancel(liveToken()); }
        @Override public void close() { long previous; synchronized(this){previous=token;token=0;} if(previous!=0)nativeJobClose(previous); }
    }
    /** kind 0 batch, 1 timeout, 2 end of stream; end is not success. */
    public static final class EntityJobPoll {
        public final int kind;
        public final EntityResult batch;
        private EntityJobPoll(int kind,EntityResult batch){this.kind=kind;this.batch=batch;}
    }
    /** Final fields are authoritative only when terminal is true. */
    public static final class EntityJobStatus {
        public final int lifecycle,executionStatus,coverage,decision,reason,candidateCount,visitedRows,totalRows;
        public final boolean terminal;
        public final long unknownRows,errorOffset;
        public final String queryId,snapshotId,errorMessage;
        private EntityJobStatus(JobStatus s) {
            lifecycle=s.lifecycle;terminal=s.terminal;executionStatus=s.executionStatus;coverage=s.coverage;
            decision=s.decision;reason=s.reason;candidateCount=s.candidateCount;visitedRows=s.visitedMethods;totalRows=s.totalMethods;
            unknownRows=s.unknownRows;errorOffset=s.errorOffset;queryId=s.queryId;snapshotId=s.snapshotId;errorMessage=s.errorMessage;
        }
    }

    /** One consumer at a time; cancel and close can run concurrently with next and wait. */
    public static final class GraphJob implements AutoCloseable {
        private long token;
        private GraphJob(long token) { if(token==0)throw new IllegalStateException("native job token is zero");this.token=token; }
        private synchronized long liveToken() { if(token==0)throw new IllegalStateException("job is closed");return token; }
        public GraphJobPoll next(int timeoutMs) { return nativeGraphJobNext(liveToken(),timeoutMs); }
        public GraphJobStatus status() { return new GraphJobStatus(nativeJobStatus(liveToken(),-1)); }
        public GraphJobStatus waitFor(int timeoutMs) {
            if(timeoutMs<0)throw new IllegalArgumentException("invalid wait timeout");
            return new GraphJobStatus(nativeJobStatus(liveToken(),timeoutMs));
        }
        public void cancel() { nativeJobCancel(liveToken()); }
        @Override public void close() { long previous; synchronized(this){previous=token;token=0;} if(previous!=0)nativeJobClose(previous); }
    }
    /** kind 0 batch, 1 timeout, 2 end of stream; end is not success. */
    public static final class GraphJobPoll {
        public final int kind;
        public final GraphResult batch;
        private GraphJobPoll(int kind,GraphResult batch){this.kind=kind;this.batch=batch;}
    }
    /** Final fields are authoritative only when terminal is true. */
    public static final class GraphJobStatus {
        public final int lifecycle,executionStatus,coverage,decision,reason,candidateCount,visitedRows,totalRows;
        public final boolean terminal;
        public final long unknownRows,errorOffset;
        public final String queryId,snapshotId,errorMessage;
        private GraphJobStatus(JobStatus s) {
            lifecycle=s.lifecycle;terminal=s.terminal;executionStatus=s.executionStatus;coverage=s.coverage;
            decision=s.decision;reason=s.reason;candidateCount=s.candidateCount;visitedRows=s.visitedMethods;totalRows=s.totalMethods;
            unknownRows=s.unknownRows;errorOffset=s.errorOffset;queryId=s.queryId;snapshotId=s.snapshotId;errorMessage=s.errorMessage;
        }
    }

    /** One consumer; cancellation and close may run during next/wait. */
    public static final class UseGraphJob implements AutoCloseable {
        private long token;
        private UseGraphJob(long token){if(token==0)throw new IllegalStateException("native job token is zero");this.token=token;}
        private synchronized long liveToken(){if(token==0)throw new IllegalStateException("job is closed");return token;}
        public UseGraphJobPoll next(int timeoutMs){return nativeUseGraphJobNext(liveToken(),timeoutMs);}
        public UseGraphJobStatus status(){return nativeUseGraphJobStatus(liveToken(),-1);}
        public UseGraphJobStatus waitFor(int timeoutMs){if(timeoutMs<0)throw new IllegalArgumentException("invalid wait timeout");return nativeUseGraphJobStatus(liveToken(),timeoutMs);}
        public void cancel(){nativeJobCancel(liveToken());}
        @Override public void close(){long previous;synchronized(this){previous=token;token=0;}if(previous!=0)nativeJobClose(previous);}
    }
    /** kind 0 = provisional batch, 1 = timeout, 2 = EOS (not success). */
    public static final class UseGraphJobPoll {
        public final int kind; public final UseGraphResult batch;
        private UseGraphJobPoll(int kind,UseGraphResult batch){this.kind=kind;this.batch=batch;}
    }
    /** Terminal fields are authoritative only when terminal is true. */
    public static final class UseGraphJobStatus {
        public final int lifecycle,executionStatus,coverage,decision,reason,candidateCount;
        public final boolean terminal;
        public final long entityVisited,entityTotal,methodVisited,methodTotal,eventsCollected,unknownRows,errorOffset;
        public final String queryId,snapshotId,errorMessage;
        private UseGraphJobStatus(long[] x,String queryId,String snapshotId,String errorMessage){
            if(x==null||x.length!=14)throw new IllegalStateException("invalid use job status");
            lifecycle=(int)x[0];terminal=x[1]!=0;executionStatus=(int)x[2];coverage=(int)x[3];decision=(int)x[4];reason=(int)x[5];candidateCount=(int)x[6];
            entityVisited=x[7];entityTotal=x[8];methodVisited=x[9];methodTotal=x[10];eventsCollected=x[11];unknownRows=x[12];errorOffset=x[13];
            this.queryId=queryId;this.snapshotId=snapshotId;this.errorMessage=errorMessage;
        }
    }

    /** One source-local static entity. Nullable attributes are not known local definitions. */
    public static final class EntityCandidate {
        public final int relation,sourceIndex,inputIndex;
        public final long localIndex,referenceIndex,recordOffset;
        public final Long definitionOffset,accessFlags,codeOffset;
        public final String owner,name,prototype,typeDescriptor,stringValue,sourceSlot,occurrenceId;
        private EntityCandidate(int relation,int sourceIndex,int inputIndex,long localIndex,long referenceIndex,long recordOffset,
                                boolean definitionKnown,long definitionOffset,boolean flagsKnown,long accessFlags,
                                boolean codeKnown,long codeOffset,String owner,String name,String prototype,
                                String typeDescriptor,String stringValue,String sourceSlot,String occurrenceId) {
            this.relation=relation;this.sourceIndex=sourceIndex;this.inputIndex=inputIndex;
            this.localIndex=localIndex;this.referenceIndex=referenceIndex;this.recordOffset=recordOffset;
            this.definitionOffset=definitionKnown?Long.valueOf(definitionOffset):null;
            this.accessFlags=flagsKnown?Long.valueOf(accessFlags):null;
            this.codeOffset=codeKnown?Long.valueOf(codeOffset):null;
            this.owner=owner;this.name=name;this.prototype=prototype;this.typeDescriptor=typeDescriptor;
            this.stringValue=stringValue;this.sourceSlot=sourceSlot;this.occurrenceId=occurrenceId;
        }
    }

    /** Copied static entity rows and independent native completion/decision fields. */
    public static final class EntityResult {
        public final int relation,executionStatus,coverage,decision,reason,visitedRows,totalRows,projectionMask;
        public final long unknownRows;
        public final String queryId,snapshotId;
        private final EntityCandidate[] candidates;
        private EntityResult(int relation,int executionStatus,int coverage,int decision,int reason,int visitedRows,int totalRows,
                             int projectionMask,long unknownRows,String queryId,String snapshotId,EntityCandidate[] candidates) {
            this.relation=relation;this.executionStatus=executionStatus;this.coverage=coverage;this.decision=decision;
            this.reason=reason;this.visitedRows=visitedRows;this.totalRows=totalRows;this.projectionMask=projectionMask;
            this.unknownRows=unknownRows;this.queryId=queryId;this.snapshotId=snapshotId;this.candidates=candidates;
        }
        public int candidateCount(){return candidates.length;}
        public EntityCandidate candidate(int index){return candidates[index];}
    }

    /** Copied method candidate; absent projections are null, not empty strings. */
    public static final class MethodCandidate {
        public final long methodIndex, accessFlags, declarationOffset, codeOffset;
        public final String owner, name, prototype;
        /** Single-source legacy results use index 0 and leave slot/occurrence null. */
        public final int sourceIndex,inputIndex;
        public final String sourceSlot,occurrenceId;
        private MethodCandidate(long methodIndex, long accessFlags, long declarationOffset, long codeOffset,
                                String owner, String name, String prototype) {
            this(methodIndex,accessFlags,declarationOffset,codeOffset,owner,name,prototype,0,0,null,null);
        }
        private MethodCandidate(long methodIndex,long accessFlags,long declarationOffset,long codeOffset,
                                String owner,String name,String prototype,int sourceIndex,int inputIndex,String sourceSlot,String occurrenceId) {
            this.methodIndex=methodIndex;this.accessFlags=accessFlags;this.declarationOffset=declarationOffset;
            this.codeOffset=codeOffset;this.owner=owner;this.name=name;this.prototype=prototype;
            this.sourceIndex=sourceIndex;this.inputIndex=inputIndex;this.sourceSlot=sourceSlot;this.occurrenceId=occurrenceId;
        }
    }

    /** C status, coverage and decision remain separate; no witnesses are included. */
    public static final class QueryResult {
        public final int executionStatus, coverage, decision, reason, visitedMethods, totalMethods, projectionMask;
        public final long unknownRows;
        public final String queryId, snapshotId;
        private final MethodCandidate[] candidates;
        private QueryResult(int executionStatus,int coverage,int decision,int reason,int visitedMethods,int totalMethods,
                            int projectionMask,long unknownRows,String queryId,String snapshotId,MethodCandidate[] candidates) {
            this.executionStatus=executionStatus;this.coverage=coverage;this.decision=decision;this.reason=reason;
            this.visitedMethods=visitedMethods;this.totalMethods=totalMethods;this.projectionMask=projectionMask;
            this.unknownRows=unknownRows;this.queryId=queryId;this.snapshotId=snapshotId;this.candidates=candidates;
        }
        public int candidateCount() { return candidates.length; }
        public MethodCandidate candidate(int index) { return candidates[index]; }
    }

    /** Copied metadata values; no native pointer or borrowed text is exposed. */
    public static final class SnapshotInfo {
        public final int dexVersion, stringCount, typeCount, classCount, methodRefCount, methodDefCount;
        public final long sourceBytes;
        public final boolean sourceScopeComplete;
        public final String sourceSha256, snapshotId;
        private SnapshotInfo(int dexVersion, int stringCount, int typeCount, int classCount,
                             int methodRefCount, int methodDefCount, long sourceBytes,
                             boolean sourceScopeComplete, String sourceSha256, String snapshotId) {
            this.dexVersion = dexVersion; this.stringCount = stringCount; this.typeCount = typeCount;
            this.classCount = classCount; this.methodRefCount = methodRefCount; this.methodDefCount = methodDefCount;
            this.sourceBytes = sourceBytes; this.sourceScopeComplete = sourceScopeComplete;
            this.sourceSha256 = sourceSha256; this.snapshotId = snapshotId;
        }
    }

    /** C status and bounded source offset; diagnostics are not a runtime-binding claim. */
    public static final class NativeFailure extends RuntimeException {
        public final int status;
        public final long offset;
        private NativeFailure(int status, long offset, String message) {
            super(message); this.status = status; this.offset = offset;
        }
    }
}


