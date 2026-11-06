package io.github.jichuo1.dexmeguviz;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;

/** Isolated, experimental native APK input bridge. Not a DEX verifier or stable API. */
public final class NativeApkFastQuery {
    private NativeApkFastQuery() {}
    public enum Policy { TRUSTED_IMMUTABLE_APK }

    /** A source slot is an opaque Java UTF-16 value and must be unique in one call. */
    public static final class Input {
        public final File apk;
        public final String slot;
        public final boolean allowNoDex;
        public Input(File apk,String slot,boolean allowNoDex) {
            this.apk=Objects.requireNonNull(apk,"apk");
            this.slot=Objects.requireNonNull(slot,"slot");
            this.allowNoDex=allowNoDex;
        }
    }

    /** Bounded source processing, not a bound on JVM/native/total peak memory. */
    public static final class SourceLimits {
        public final int workers,maxInputs,maxSourcesPerInput,maxSources,maxEntries;
        public final long maxArchivePerInput,maxArchiveTotal,maxDexPerInput,maxDexTotal,maxOneDex;
        public final long maxInflight,maxZipMetadata,maxRowsAggregate;
        public SourceLimits(int workers,int maxInputs,int maxSourcesPerInput,int maxSources,int maxEntries,
                            long maxArchivePerInput,long maxArchiveTotal,long maxDexPerInput,long maxDexTotal,
                            long maxOneDex,long maxInflight,long maxZipMetadata,long maxRowsAggregate) {
            if(workers<1||workers>32||maxInputs<1||maxInputs>1024||maxSourcesPerInput<1||maxSources<0||maxEntries<1||
               maxArchivePerInput<1||maxArchiveTotal<1||maxDexPerInput<1||maxDexTotal<0||maxOneDex<1||
               maxInflight<1||maxZipMetadata<1||maxRowsAggregate<1)
                throw new IllegalArgumentException("invalid source limits");
            this.workers=workers;this.maxInputs=maxInputs;this.maxSourcesPerInput=maxSourcesPerInput;
            this.maxSources=maxSources;this.maxEntries=maxEntries;this.maxArchivePerInput=maxArchivePerInput;
            this.maxArchiveTotal=maxArchiveTotal;this.maxDexPerInput=maxDexPerInput;this.maxDexTotal=maxDexTotal;
            this.maxOneDex=maxOneDex;this.maxInflight=maxInflight;this.maxZipMetadata=maxZipMetadata;
            this.maxRowsAggregate=maxRowsAggregate;
        }
        private long[] nativeLimits() {
            return new long[]{workers,maxInputs,maxSourcesPerInput,maxSources,maxEntries,maxArchivePerInput,maxArchiveTotal,
                    maxDexPerInput,maxDexTotal,maxOneDex,maxInflight,maxZipMetadata,maxRowsAggregate};
        }
    }

    public static final class InputSummary {
        public final String slot;
        public final int sourceCount;
        public final long archiveBytes,dexBytes,compressedBytes;
        private InputSummary(String slot,int count,long archive,long dex,long compressed) {
            this.slot=slot;sourceCount=count;archiveBytes=archive;dexBytes=dex;compressedBytes=compressed;
        }
    }

    /** The fast result retains every lane's status; the optional SHA applies only to sources with output. */
    public static final class SourceResult {
        public final String slot,matchedSha256;
        public final int inputIndex,centralIndex,ordinal;
        public final long size,compressedSize,crc;
        public final FastDexQuery.Result result;
        private SourceResult(String slot,int inputIndex,int centralIndex,int ordinal,long size,long compressedSize,long crc,
                             String sha,FastDexQuery.Result result) {
            this.slot=slot;this.inputIndex=inputIndex;this.centralIndex=centralIndex;this.ordinal=ordinal;
            this.size=size;this.compressedSize=compressedSize;this.crc=crc;matchedSha256=sha;this.result=result;
        }
    }
    public static final class Result {
        public final List<InputSummary> inputs;
        public final List<SourceResult> ordered;
        private Result(List<InputSummary> inputs,List<SourceResult> ordered) {
            this.inputs=Collections.unmodifiableList(inputs);this.ordered=Collections.unmodifiableList(ordered);
        }
    }

    /**
     * The caller must guarantee APK immutability throughout the synchronous call and DEX validity/sortedness.
     * The plan must have been compiled successfully and remains open until this call returns. All rule status,
     * unknown-row and limit fields must be checked before consuming candidates. Coverage remains partial.
     * An empty result is not proof of absence. The limits do not bound total process memory.
     */
    public static Result queryAll(List<Input> inputs,Policy policy,FastDexQuery.InputAssumption assumption,
                                  SourceLimits sourceLimits,FastDexQuery.Limits queryLimits,FastDexQuery.Plans plans,
                                  boolean digestMatches,int maxWireBytes) throws java.io.IOException {
        Objects.requireNonNull(inputs,"inputs");Objects.requireNonNull(sourceLimits,"sourceLimits");
        Objects.requireNonNull(queryLimits,"queryLimits");Objects.requireNonNull(plans,"plans");
        if(policy!=Policy.TRUSTED_IMMUTABLE_APK||assumption!=FastDexQuery.InputAssumption.CALLER_ASSERTS_VALID_SORTED_DEX)
            throw new IllegalArgumentException("explicit trusted input assumptions are required");
        if(inputs.isEmpty()||inputs.size()>sourceLimits.maxInputs||maxWireBytes<1||maxWireBytes>64*1024*1024)
            throw new IllegalArgumentException("invalid input count or wire limit");
        List<Input> snapshot=new ArrayList<>(inputs);
        String[] paths=new String[snapshot.size()],slots=new String[snapshot.size()];boolean[] allow=new boolean[snapshot.size()];
        HashSet<String> seen=new HashSet<>();
        for(int i=0;i<snapshot.size();i++) {
            Input x=Objects.requireNonNull(snapshot.get(i),"input");String slot=x.slot;
            if(slot.isEmpty()||slot.length()>4096||slot.indexOf('\0')>=0||!seen.add(slot))
                throw new IllegalArgumentException("invalid or duplicate input slot");
            paths[i]=x.apk.getAbsolutePath();slots[i]=slot;allow[i]=x.allowNoDex;
        }
        long[] q={queryLimits.maxDexBytes,queryLimits.maxRows,queryLimits.maxCalls,queryLimits.maxTextUnits,
                queryLimits.maxCodeUnits,queryLimits.maxInstructions,queryLimits.maxWireBytes};
        byte[] wire=plans.scanArchives(paths,slots,allow,sourceLimits.nativeLimits(),q,digestMatches,maxWireBytes);
        return decode(wire,slots,sourceLimits,maxWireBytes);
    }

    private static int count(ByteBuffer b,int max) {
        long n=Integer.toUnsignedLong(b.getInt());
        if(n>max)throw new IllegalArgumentException("invalid archive wire count");return (int)n;
    }
    private static long u64(ByteBuffer b) {
        long n=b.getLong();if(n<0)throw new IllegalArgumentException("archive wire value overflow");return n;
    }
    private static String hash(ByteBuffer b) {
        int n=count(b,64);if(n!=0&&n!=64||n>b.remaining())throw new IllegalArgumentException("invalid matched source SHA");
        byte[] bytes=new byte[n];b.get(bytes);
        for(byte x:bytes)if(!(x>='0'&&x<='9')&&!(x>='a'&&x<='f'))throw new IllegalArgumentException("invalid SHA encoding");
        return n==0?null:new String(bytes,StandardCharsets.US_ASCII);
    }
    private static Result decode(byte[] wire,String[] slots,SourceLimits limits,int maxWireBytes) {
        if(wire==null||wire.length>maxWireBytes)throw new IllegalArgumentException("invalid archive wire");
        ByteBuffer b=ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN);
        try {
            if(b.getInt()!=0x31415044)throw new IllegalArgumentException("invalid archive wire magic");
            int n=count(b,limits.maxInputs);if(n!=slots.length)throw new IllegalArgumentException("input count mismatch");
            List<InputSummary> summaries=new ArrayList<>(n);long expected=0;
            for(int i=0;i<n;i++) {
                int sources=count(b,limits.maxSourcesPerInput);expected+=sources;
                if(expected>limits.maxSources)throw new IllegalArgumentException("source count exceeds limit");
                summaries.add(new InputSummary(slots[i],sources,u64(b),u64(b),u64(b)));
            }
            int count=count(b,limits.maxSources);if(expected!=count)throw new IllegalArgumentException("source count mismatch");
            List<SourceResult> output=new ArrayList<>(count);int[] seenCounts=new int[n];int previousInput=-1,previousOrdinal=0;
            for(int i=0;i<count;i++) {
                int input=count(b,n-1),central=count(b,Integer.MAX_VALUE),ordinal=count(b,Integer.MAX_VALUE);
                if(ordinal<1||input<previousInput||(input==previousInput&&ordinal<=previousOrdinal))
                    throw new IllegalArgumentException("invalid source order");
                previousInput=input;previousOrdinal=ordinal;seenCounts[input]++;
                long size=u64(b),compressed=u64(b),crc=Integer.toUnsignedLong(b.getInt());String sha=hash(b);
                int length=count(b,maxWireBytes);if(length>b.remaining())throw new IllegalArgumentException("truncated source wire");
                byte[] sub=new byte[length];b.get(sub);
                output.add(new SourceResult(slots[input],input,central,ordinal,size,compressed,crc,sha,FastDexQuery.decode(sub)));
            }
            for(int i=0;i<n;i++)if(seenCounts[i]!=summaries.get(i).sourceCount)throw new IllegalArgumentException("per-input source count mismatch");
            if(b.hasRemaining())throw new IllegalArgumentException("trailing archive wire");
            return new Result(summaries,output);
        } catch(java.nio.BufferUnderflowException e) {throw new IllegalArgumentException("truncated archive wire",e);}
    }
}
