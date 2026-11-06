package io.github.jichuo1.dexmeguviz;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Experimental selected-only fast DEX queries. This is not a verifier or the
 * ordinary Snapshot API. The caller must supply immutable, structurally valid
 * DEX with correctly sorted ID tables and must know the complete source set.
 * Coverage is always partial; empty results do not independently prove absence.
 * QueryIR max_work is not applied by this API; Limits supplies distinct bounds.
 * Limits are not Engine memory accounting or a process-wide memory limit.
 */
public final class FastDexQuery {
    static { System.loadLibrary("dexmeguviz"); }
    private FastDexQuery() {}
    private static native long nativeCompile(byte[][] json, boolean[] captureCalls);
    private static native byte[] nativeScan(long token,byte[] dex,long maxDexBytes,int maxRows,int maxCalls,long maxTextUnits,int maxCodeUnits,int maxInstructions,int maxWireBytes);
    private static native void nativeClose(long token);
    private static native byte[] nativeScanArchives(long token,String[] paths,String[] slots,boolean[] allowNoDex,long[] sourceLimits,long[] queryLimits,boolean digestMatches,int maxWireBytes);

    public static final class Failure extends RuntimeException {
        public final int status,ruleIndex; public final long errorOffset;
        private Failure(int status,int ruleIndex,long errorOffset,String message){super(message);this.status=status;this.ruleIndex=ruleIndex;this.errorOffset=errorOffset;}
    }
    /** Explicit limits for each DEX scan; they do not bound total process memory. */
    public static final class Limits {
        public final long maxDexBytes,maxTextUnits;
        public final int maxRows,maxCalls,maxCodeUnits,maxInstructions,maxWireBytes;
        public Limits(long maxDexBytes,int maxRows,int maxCalls,long maxTextUnits,int maxCodeUnits,int maxInstructions,int maxWireBytes){
            if(maxDexBytes<1||maxDexBytes>Integer.MAX_VALUE||maxRows<1||maxRows>65536||maxCalls<0||maxCalls>100000||
               maxTextUnits<1||maxTextUnits>1048576||maxCodeUnits<1||maxCodeUnits>1048576||
               maxInstructions<1||maxInstructions>1048576||maxWireBytes<1||maxWireBytes>8*1024*1024)
                throw new IllegalArgumentException("invalid selected-only limits");
            this.maxDexBytes=maxDexBytes;this.maxRows=maxRows;this.maxCalls=maxCalls;this.maxTextUnits=maxTextUnits;
            this.maxCodeUnits=maxCodeUnits;this.maxInstructions=maxInstructions;this.maxWireBytes=maxWireBytes;
        }
    }
    /** Caller confirms validity/sortedness and immutability; this is not authentication. */
    public enum InputAssumption { CALLER_ASSERTS_VALID_SORTED_DEX }
    /** Compile one to sixteen QueryIR rules; inputs must not change during this call. */
    public static Plans compile(byte[][] json,boolean[] captureCalls) {
        if(json==null||captureCalls==null)throw new NullPointerException("queries and call flags are required");
        long token=0;try{token=nativeCompile(json,captureCalls);return new Plans(token);}
        catch(Throwable failure){if(token!=0)try{nativeClose(token);}catch(Throwable closeFailure){failure.addSuppressed(closeFailure);}throw failure;}
    }
    /** Owns immutable native plans. Close after use. Methods on one instance serialize. */
    public static final class Plans implements AutoCloseable {
        private long token;
        private Plans(long token){if(token==0)throw new IllegalStateException("zero plan token");this.token=token;}
        /** Source bytes must remain unchanged until this synchronous call returns. */
        public synchronized Result scan(byte[] dex,InputAssumption assumption,Limits limits){
            if(token==0)throw new IllegalStateException("plans closed");
            if(dex==null||assumption==null||limits==null)throw new NullPointerException("dex, assumption and limits required");
            if(assumption!=InputAssumption.CALLER_ASSERTS_VALID_SORTED_DEX)throw new IllegalArgumentException("input assumption required");
            return decode(nativeScan(token,dex,limits.maxDexBytes,limits.maxRows,limits.maxCalls,limits.maxTextUnits,limits.maxCodeUnits,limits.maxInstructions,limits.maxWireBytes));
        }
        synchronized byte[] scanArchives(String[] paths,String[] slots,boolean[] allowNoDex,long[] sourceLimits,long[] queryLimits,boolean digestMatches,int maxWireBytes){
            if(token==0)throw new IllegalStateException("plans closed");
            return nativeScanArchives(token,paths,slots,allowNoDex,sourceLimits,queryLimits,digestMatches,maxWireBytes);
        }
        @Override public synchronized void close(){if(token!=0){long old=token;token=0;nativeClose(old);}}
    }
    public static final class Call {
        public final long pc,targetRef,extraProto,opcode,referenceKind;
        public final String owner,name,prototype,extraPrototype;
        private Call(long a,long b,long c,long d,long e,String f,String g,String h,String x){pc=a;targetRef=b;extraProto=c;opcode=d;referenceKind=e;owner=e==1?null:f;name=e==1?null:g;prototype=e==1?null:h;extraPrototype=e==2?x:null;}
    }
    public static final class Method {
        public final long methodRef,accessFlags,declarationOffset,codeOffset;
        public final String owner,name,prototype;
        public final List<Call> calls;
        private Method(long a,long b,long c,long d,String e,String f,String g,List<Call> h){methodRef=a;accessFlags=b;declarationOffset=c;codeOffset=d;owner=e;name=f;prototype=g;calls=Collections.unmodifiableList(h);}
    }
    public static final class DexClass {
        public final long localIndex,typeIndex,definitionOffset,accessFlags;public final String descriptor;
        private DexClass(long a,long b,long c,long d,String e){localIndex=a;typeIndex=b;definitionOffset=c;accessFlags=d;descriptor=e;}
    }
    public static final class RuleResult {
        /** 0 = method_defs, 1 = class_defs. */
        public final int relation,executionStatus,unknownRows;public final boolean resultLimit,callerAssertedExhaustive;
        public final long selectedMethodsVisited,selectedBodiesDecoded,classDefsVisited;
        public final String queryId;public final List<Method> methods;public final List<DexClass> classes;
        private RuleResult(int relation,int status,int unknown,boolean limit,boolean asserted,long visited,long decoded,long classVisited,String id,List<Method> methods,List<DexClass> classes){this.relation=relation;executionStatus=status;unknownRows=unknown;resultLimit=limit;callerAssertedExhaustive=asserted;selectedMethodsVisited=visited;selectedBodiesDecoded=decoded;classDefsVisited=classVisited;queryId=id;this.methods=Collections.unmodifiableList(methods);this.classes=Collections.unmodifiableList(classes);}
        /** Always partial, including when callerAssertedExhaustive is true. */
        public int coverage(){return 1;}
    }
    public static final class Result {
        public final List<RuleResult> rules;
        private Result(List<RuleResult> r){rules=Collections.unmodifiableList(r);}
    }
    private static long u32(ByteBuffer b){return Integer.toUnsignedLong(b.getInt());}
    private static int count(ByteBuffer b,int max){long n=u32(b);if(n>max)throw new IllegalArgumentException("invalid fast query wire count");return (int)n;}
    private static String text(ByteBuffer b){int n=count(b,1048576);if((long)n*2>b.remaining())throw new IllegalArgumentException("truncated fast query text");char[] c=new char[n];for(int i=0;i<n;i++)c[i]=b.getChar();return new String(c);}
    private static String ascii(ByteBuffer b){int n=count(b,1024);if(n>b.remaining())throw new IllegalArgumentException("truncated fast query id");byte[] a=new byte[n];b.get(a);return new String(a,StandardCharsets.US_ASCII);}
    static Result decode(byte[] wire){
        if(wire==null)throw new IllegalArgumentException("null fast query wire");ByteBuffer b=ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN);
        if(b.remaining()<8||b.getInt()!=0x31514644)throw new IllegalArgumentException("invalid fast query wire");int count=count(b,16);List<RuleResult> rules=new ArrayList<>(count);
        for(int i=0;i<count;i++){
            int relation=(int)u32(b),status=(int)u32(b),unknown=(int)u32(b);boolean limited=u32(b)!=0,asserted=u32(b)!=0;long visited=b.getLong(),decoded=b.getLong(),classVisited=b.getLong();String id=ascii(b);int rows=count(b,65536);List<Method> methods=new ArrayList<>(relation==0?rows:0);List<DexClass> classes=new ArrayList<>(relation==1?rows:0);
            if(relation==1){for(int j=0;j<rows;j++)classes.add(new DexClass(u32(b),u32(b),u32(b),u32(b),text(b)));rules.add(new RuleResult(relation,status,unknown,limited,asserted,visited,decoded,classVisited,id,methods,classes));continue;}
            if(relation!=0)throw new IllegalArgumentException("unknown fast query relation");
            for(int j=0;j<rows;j++){
                long ref=u32(b),flags=u32(b),decl=u32(b),code=u32(b);String owner=text(b),name=text(b),proto=text(b);int calls=count(b,100000);List<Call> list=new ArrayList<>(calls);
                for(int k=0;k<calls;k++)list.add(new Call(u32(b),u32(b),u32(b),u32(b),u32(b),text(b),text(b),text(b),text(b)));
                methods.add(new Method(ref,flags,decl,code,owner,name,proto,list));
            }
            rules.add(new RuleResult(relation,status,unknown,limited,asserted,visited,decoded,classVisited,id,methods,classes));
        }
        if(b.hasRemaining())throw new IllegalArgumentException("trailing fast query wire");return new Result(rules);
    }
}
