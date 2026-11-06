package io.github.jichuo1.dexmeguviz;

import io.github.jichuo1.dexmeguviz.MethodBatchQuery;
import io.github.jichuo1.dexmeguviz.NativeEngine;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentLinkedQueue;

/** Experimental, source-ordered static queries over an explicitly trusted immutable APK. */
public final class ParallelDexQuery {
    private ParallelDexQuery() {}
    private static String nativeSlotPrefix(String sourceSlot){
        final MessageDigest digest;
        try{digest=MessageDigest.getInstance("SHA-256");}catch(NoSuchAlgorithmException e){throw new IllegalStateException("SHA-256 unavailable",e);}
        // Hash UTF-16 code units directly so isolated surrogates do not collapse through replacement encoding.
        digest.update((byte)'D');digest.update((byte)'M');digest.update((byte)'G');digest.update((byte)1);
        for(int i=0;i<sourceSlot.length();i++){char unit=sourceSlot.charAt(i);digest.update((byte)(unit>>>8));digest.update((byte)unit);}
        final char[] hex="0123456789abcdef".toCharArray();byte[] value=digest.digest();char[] out=new char[65];out[0]='s';
        for(int i=0;i<value.length;i++){int b=value[i]&255;out[1+2*i]=hex[b>>>4];out[2+2*i]=hex[b&15];}
        return new String(out);
    }
    public enum Kind { METHOD, REFLECTION_METHOD_USES }
    public static final class Rule {
        private final Kind kind;
        private final byte[] json;
        private Rule(Kind kind,byte[] json){this.kind=Objects.requireNonNull(kind);this.json=Objects.requireNonNull(json).clone();}
        public static Rule method(byte[] json){return new Rule(Kind.METHOD,json);}
        public static Rule reflectionMethodUses(byte[] json){return new Rule(Kind.REFLECTION_METHOD_USES,json);}
        public Kind kind(){return kind;}
    }
    /** One copied result in the same order as the input rules. */
    public static final class RuleResult {
        public final Kind kind;
        private final NativeEngine.QueryResult method;
        private final NativeEngine.EntityResult reflection;
        private RuleResult(NativeEngine.QueryResult value){kind=Kind.METHOD;method=value;reflection=null;}
        private RuleResult(NativeEngine.EntityResult value){kind=Kind.REFLECTION_METHOD_USES;method=null;reflection=value;}
        public NativeEngine.QueryResult method(){if(method==null)throw new IllegalStateException("not a method rule");return method;}
        public NativeEngine.EntityResult reflection(){if(reflection==null)throw new IllegalStateException("not a reflection rule");return reflection;}
    }
    /** Called concurrently while the source Snapshot is open. Must not retain it or publish partial results. */
    @FunctionalInterface public interface SourceMapper<T> {
        T map(TrustedApkDexSource.Entry entry,NativeEngine.Snapshot snapshot,List<RuleResult> results)throws Exception;
    }
    /**
     * Explicit trusted-source path; reads and checks selected DEX entries, not all ZIP entries.
     * A nonempty caller-selected sourceSlot identifies this APK; native slots derive from a SHA-256
     * of its UTF-16 code units plus the central index, while results preserve the original slot.
     * map handles one APK; mapAll preserves supplied base/split order and permits resource-only inputs.
     * Each worker owns one Engine and its plans: core memory may reach workers*ownedBytesPerWorker,
     * plus Java/VM/ZIP memory. Fusion evaluates method rules before reflection rules, so failures
     * can surface in a different order. Each DEX Snapshot has incomplete source scope. Caller aggregates
     * coverage and binds runtime members separately. JNI work is synchronous and not cancellable.
     * Up to 16 workers may be selected; concurrent streams in this process share the existing 16-session
     * limit and can fail rather than wait. The mapper must be thread-safe, avoid observable partial
     * publication and not retain Snapshot. Fusion can fall back to per-rule calls when a plan is
     * unsupported by the batch bridge; other failures propagate without retry.
     */
    public static <T> TrustedApkDexSource.Result<T> map(
        File apk,String sourceSlot,TrustedApkDexSource.Policy sourcePolicy,TrustedApkDexSource.Limits limits,List<Rule> rules,
        long ownedBytesPerWorker,
        boolean fuseMethods,long cacheBytes,long cacheWork,SourceMapper<T> mapper)throws Exception {
        Objects.requireNonNull(limits);
        TrustedApkDexSource.SourceSetLimits setLimits=new TrustedApkDexSource.SourceSetLimits(limits,1,limits.maxSources,limits.maxArchiveBytes,limits.maxTotalDexBytes);
        return mapAll(Collections.singletonList(new TrustedApkDexSource.Input(apk,sourceSlot,limits.allowNoDex)),sourcePolicy,setLimits,rules,ownedBytesPerWorker,fuseMethods,cacheBytes,cacheWork,mapper).inputs.get(0);
    }
    /** Scan ordered base/split inputs with a single bounded worker pool. */
    public static <T> TrustedApkDexSource.SourceSetResult<T> mapAll(
        List<TrustedApkDexSource.Input> inputs,TrustedApkDexSource.Policy sourcePolicy,TrustedApkDexSource.SourceSetLimits setLimits,List<Rule> rules,
        long ownedBytesPerWorker,boolean fuseMethods,long cacheBytes,long cacheWork,SourceMapper<T> mapper)throws Exception {
        Objects.requireNonNull(inputs);Objects.requireNonNull(rules);Objects.requireNonNull(mapper);Objects.requireNonNull(setLimits);
        List<TrustedApkDexSource.Input> sources=new ArrayList<>(inputs);
        Map<String,String> nativeSlots=new HashMap<>();HashSet<String> prefixes=new HashSet<>();
        for(TrustedApkDexSource.Input source:sources){
            if(source==null || source.slot==null || source.slot.isEmpty()||source.slot.length()>4096||source.slot.indexOf('\0')>=0)
                throw new IllegalArgumentException("invalid source slot");
            String prefix=nativeSlotPrefix(source.slot);
            if(nativeSlots.put(source.slot,prefix)!=null||!prefixes.add(prefix))throw new IllegalArgumentException("duplicate or colliding source slot");
        }
        TrustedApkDexSource.Limits limits=setLimits.perInput;
        if(rules.isEmpty()||rules.size()>64||limits.workers>16||ownedBytesPerWorker<1)
            throw new IllegalArgumentException("invalid query or worker limits");
        List<Rule> ordered=Collections.unmodifiableList(new ArrayList<>(rules));List<byte[]> methodList=new ArrayList<>();int[] methodIndex=new int[ordered.size()];
        for(int i=0;i<ordered.size();i++){
            Rule rule=Objects.requireNonNull(ordered.get(i));
            if(rule.kind==Kind.METHOD){methodIndex[i]=methodList.size();methodList.add(rule.json.clone());}else methodIndex[i]=-1;
        }
        byte[][] methods=methodList.toArray(new byte[0][]);ConcurrentLinkedQueue<NativeEngine.MethodStream> sessions=new ConcurrentLinkedQueue<>();
        ThreadLocal<NativeEngine.MethodStream> local=new ThreadLocal<NativeEngine.MethodStream>() {
            @Override protected NativeEngine.MethodStream initialValue(){
                NativeEngine.MethodStream stream=NativeEngine.openMethodStream(methods,limits.maxDexBytes,ownedBytesPerWorker);
                try{sessions.add(stream);return stream;}
                catch(RuntimeException|Error failure){try{stream.close();}catch(RuntimeException|Error closeFailure){failure.addSuppressed(closeFailure);}throw failure;}
            }
        };
        Throwable primary=null;
        try {
            return TrustedApkDexSource.mapAll(sources,sourcePolicy,setLimits,(entry,bytes)->{
                NativeEngine.MethodStream stream=methods.length==0?null:local.get();
                String dexSlot=nativeSlots.get(entry.inputSlot)+":"+entry.centralIndex;
                try(NativeEngine.Snapshot snapshot=stream==null?NativeEngine.openRawDexWithLimits(bytes,dexSlot,limits.maxDexBytes,ownedBytesPerWorker):stream.openRawDex(bytes,dexSlot)){
                    NativeEngine.QueryResult[] methodResults=new NativeEngine.QueryResult[methods.length];
                    if(fuseMethods){
                        for(int first=0;first<methods.length;first+=32){
                            int n=Math.min(32,methods.length-first);int[] indices=new int[n];for(int j=0;j<n;j++)indices[j]=first+j;
                            try {
                                MethodBatchQuery.Result batch=stream.queryMethodsBatch(snapshot,indices,cacheBytes,cacheWork);
                                if(batch.size()!=n)throw new IllegalStateException("unexpected batch size");
                                for(int j=0;j<n;j++)methodResults[first+j]=batch.get(j);
                            } catch(MethodBatchQuery.Failure failure) {
                                if(failure.status!=3 || failure.failureIndex<0)throw failure;
                                for(int j=0;j<n;j++)methodResults[first+j]=stream.queryMethods(snapshot,indices[j]);
                            }
                        }
                    }
                    List<RuleResult> values=new ArrayList<>(ordered.size());
                    for(int i=0;i<ordered.size();i++){
                        Rule rule=ordered.get(i);int index=methodIndex[i];
                        if(index>=0)values.add(new RuleResult(fuseMethods?methodResults[index]:stream.queryMethods(snapshot,index)));
                        else values.add(new RuleResult(snapshot.queryReflectionMethodUses(rule.json)));
                    }
                    return mapper.map(entry,snapshot,Collections.unmodifiableList(values));
                }
            });
        } catch(Exception|Error failure){primary=failure;throw failure;}
        finally {
            Throwable closeFailure=null;
            for(NativeEngine.MethodStream session:sessions)try{session.close();}catch(RuntimeException|Error failure){
                if(closeFailure==null)closeFailure=failure;else closeFailure.addSuppressed(failure);
            }
            if(closeFailure!=null){
                if(primary!=null)primary.addSuppressed(closeFailure);
                else if(closeFailure instanceof RuntimeException)throw (RuntimeException)closeFailure;
                else throw (Error)closeFailure;
            }
        }
    }
}
