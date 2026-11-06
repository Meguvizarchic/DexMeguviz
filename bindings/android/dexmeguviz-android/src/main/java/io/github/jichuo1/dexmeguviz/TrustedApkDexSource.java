package io.github.jichuo1.dexmeguviz;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Explicit trusted immutable APK prototype; the caller guarantees source immutability. */
public final class TrustedApkDexSource {
    private TrustedApkDexSource() {}
    /** Caller explicitly trusts source immutability for this invocation. */
    public enum Policy { TRUSTED_IMMUTABLE_APK }
    /** Limits apply to archive bytes and selected DEX output, not the JVM heap or total RSS. */
    public static final class Limits {
        public final int workers,maxSources,maxDexBytes,maxZipEntries;
        public final long maxArchiveBytes,maxTotalDexBytes;
        public final boolean allowNoDex;
        public Limits(int workers,int maxSources,int maxDexBytes,int maxZipEntries,long maxArchiveBytes,long maxTotalDexBytes) {
            this(workers,maxSources,maxDexBytes,maxZipEntries,maxArchiveBytes,maxTotalDexBytes,false);
        }
        public Limits(int workers,int maxSources,int maxDexBytes,int maxZipEntries,long maxArchiveBytes,long maxTotalDexBytes,boolean allowNoDex) {
            if(workers<1 || workers>32 || maxSources<1 || maxDexBytes<1 || maxZipEntries<1 || maxArchiveBytes<1 || maxTotalDexBytes<1)
                throw new IllegalArgumentException("invalid source limits");
            this.workers=workers;this.maxSources=maxSources;this.maxDexBytes=maxDexBytes;this.maxZipEntries=maxZipEntries;
            this.maxArchiveBytes=maxArchiveBytes;this.maxTotalDexBytes=maxTotalDexBytes;this.allowNoDex=allowNoDex;
        }
    }
    /** One ordered APK input; allowNoDex permits zero canonical DEX entries only for this input. */
    public static final class Input {
        public final File apk;public final String slot;public final boolean allowNoDex;
        public Input(File apk,String slot,boolean allowNoDex){this.apk=apk;this.slot=slot;this.allowNoDex=allowNoDex;}
    }
    /** Per-input limits plus independent total limits for the complete ordered set. */
    public static final class SourceSetLimits {
        public final Limits perInput;public final int maxInputs,maxTotalSources;public final long maxTotalArchiveBytes,maxTotalDexBytes;
        public SourceSetLimits(Limits perInput,int maxInputs,int maxTotalSources,long maxTotalArchiveBytes,long maxTotalDexBytes){
            if(perInput==null || maxInputs<1 || maxTotalSources<0 || maxTotalArchiveBytes<1 || maxTotalDexBytes<0)
                throw new IllegalArgumentException("invalid source-set limits");
            this.perInput=perInput;this.maxInputs=maxInputs;this.maxTotalSources=maxTotalSources;
            this.maxTotalArchiveBytes=maxTotalArchiveBytes;this.maxTotalDexBytes=maxTotalDexBytes;
        }
    }

    /** The mapper must not publish externally visible partial results. */
    @FunctionalInterface public interface Mapper<T> { T apply(Entry entry, byte[] dex) throws Exception; }
    public static final class Entry {
        public final String inputSlot,name; public final int inputIndex,centralIndex,ordinal; public final long size,crc;
        Entry(String inputSlot,int inputIndex,String name,int centralIndex,int ordinal,long size,long crc){this.inputSlot=inputSlot;this.inputIndex=inputIndex;this.name=name;this.centralIndex=centralIndex;this.ordinal=ordinal;this.size=size;this.crc=crc;}
    }
    /** Each value remains attached to its own input slot and archive occurrence. */
    public static final class SourceResult<T> {
        public final Entry source;public final T value;
        SourceResult(Entry source,T value){this.source=source;this.value=value;}
    }
    public static final class Result<T> {
        public final String inputSlot;public final int inputIndex;public final long archiveBytes;public final boolean allowNoDex;
        public final List<SourceResult<T>> ordered;public final int sources;public final long dexBytes,compressedBytes;
        Result(String inputSlot,int inputIndex,long archiveBytes,boolean allowNoDex,List<SourceResult<T>> ordered,int sources,long dexBytes,long compressedBytes){this.inputSlot=inputSlot;this.inputIndex=inputIndex;this.archiveBytes=archiveBytes;this.allowNoDex=allowNoDex;this.ordered=Collections.unmodifiableList(new ArrayList<>(ordered));this.sources=sources;this.dexBytes=dexBytes;this.compressedBytes=compressedBytes;}
    }
    public static final class SourceSetResult<T> {
        public final List<Result<T>> inputs;public final List<SourceResult<T>> ordered;
        public final long archiveBytes,dexBytes,compressedBytes;public final int sources;
        SourceSetResult(List<Result<T>> inputs,List<SourceResult<T>> ordered,long archiveBytes,long dexBytes,long compressedBytes){
            this.inputs=Collections.unmodifiableList(new ArrayList<>(inputs));this.ordered=Collections.unmodifiableList(new ArrayList<>(ordered));
            this.archiveBytes=archiveBytes;this.dexBytes=dexBytes;this.compressedBytes=compressedBytes;this.sources=ordered.size();
        }
    }

    private static int ordinal(String name) throws IOException {
        if (name.equals("classes.dex")) return 1;
        if (!name.startsWith("classes") || !name.endsWith(".dex")) return 0;
        String number = name.substring(7, name.length() - 4);
        if (number.isEmpty()) return 0;
        for (int i=0; i<number.length(); i++) if (number.charAt(i)<'0' || number.charAt(i)>'9') return 0;
        if (number.charAt(0)=='0') throw new IOException("noncanonical DEX entry");
        long value=0;
        for (int i=0; i<number.length(); i++) {
            value=value*10 + number.charAt(i)-'0';
            if (value>Integer.MAX_VALUE) throw new IOException("DEX ordinal overflow");
        }
        if (value<2) throw new IOException("noncanonical DEX entry");
        return (int)value;
    }

    private static byte[] read(ZipFile zip, ZipEntry entry) throws IOException {
        int size=Math.toIntExact(entry.getSize()); byte[] bytes=new byte[size]; int at=0;
        CRC32 crc=new CRC32();
        try (InputStream in=zip.getInputStream(entry)) {
            while (at<size) {
                int n=in.read(bytes,at,Math.min(64*1024,size-at));if(n<=0)throw new EOFException("truncated DEX");
                crc.update(bytes,at,n);at+=n;
            }
            if (in.read()!=-1) throw new IOException("DEX size mismatch");
        }
        if (crc.getValue()!=entry.getCrc()) throw new IOException("DEX CRC mismatch");
        return bytes;
    }

    private static final class Task {
        final ZipFile zip;final ZipEntry entry;final Entry info;
        Task(ZipFile zip,ZipEntry entry,Entry info){this.zip=zip;this.entry=entry;this.info=info;}
    }
    private static final class Indexed<T> {
        final int index;final SourceResult<T> result;
        Indexed(int index,SourceResult<T> result){this.index=index;this.result=result;}
    }
    private static <T> Future<Indexed<T>> submit(ExecutorCompletionService<Indexed<T>> completion,Task task,int index,Mapper<T> mapper) {
        return completion.submit(()->new Indexed<>(index,new SourceResult<>(task.info,mapper.apply(task.info,read(task.zip,task.entry)))));
    }
    private static final class OpenInput {
        final Input input;final int index;final long size,modified;final String canonical;final ZipFile zip;
        final List<Task> tasks=new ArrayList<>();long dexBytes,compressedBytes;
        OpenInput(Input input,int index,long size,long modified,String canonical,ZipFile zip){this.input=input;this.index=index;this.size=size;this.modified=modified;this.canonical=canonical;this.zip=zip;}
    }
    private static final class OpenArchives implements AutoCloseable {
        final List<ZipFile> files=new ArrayList<>();
        @Override public void close() throws IOException {
            IOException failure=null;for(int i=files.size()-1;i>=0;i--)try{files.get(i).close();}catch(IOException e){if(failure==null)failure=e;else failure.addSuppressed(e);}
            if(failure!=null)throw failure;
        }
    }
    /** Single-APK convenience wrapper around the same ordered source-set implementation. */
    public static <T> Result<T> map(File apk,String inputSlot,Policy policy,Limits limits,Mapper<T> mapper) throws Exception {
        if(limits==null)throw new IllegalArgumentException("limits are required");
        SourceSetLimits setLimits=new SourceSetLimits(limits,1,limits.maxSources,limits.maxArchiveBytes,limits.maxTotalDexBytes);
        return mapAll(Collections.singletonList(new Input(apk,inputSlot,limits.allowNoDex)),policy,setLimits,mapper).inputs.get(0);
    }
    /**
     * Checks selected DEX lengths/CRC, not all ZIP local headers, signatures or other entries.
     * The caller guarantees that each file remains immutable throughout the synchronous call.
     * Results are staged and returned only when every selected DEX and input succeeds.
     * The mapper must not publish partial results; cancellation cannot forcibly stop JNI work.
     */
    public static <T> SourceSetResult<T> mapAll(List<Input> inputs,Policy policy,SourceSetLimits setLimits,Mapper<T> mapper) throws Exception {
        if(inputs==null || policy!=Policy.TRUSTED_IMMUTABLE_APK || setLimits==null || mapper==null)
            throw new IllegalArgumentException("invalid source-set request");
        List<Input> requested=new ArrayList<>(inputs);Limits limits=setLimits.perInput;
        if(requested.isEmpty() || requested.size()>setLimits.maxInputs)throw new IllegalArgumentException("invalid input count");
        HashSet<String> slots=new HashSet<>();
        for(Input input:requested)if(input==null || input.apk==null || input.slot==null || input.slot.isEmpty() || input.slot.length()>4096 ||
            input.slot.indexOf('\0')>=0 || !slots.add(input.slot))throw new IllegalArgumentException("invalid or duplicate input slot");
        try(OpenArchives open=new OpenArchives()) {
            List<OpenInput> prepared=new ArrayList<>();long archives=0,totalDex=0,totalCompressed=0;int sources=0;
            for(int inputIndex=0;inputIndex<requested.size();inputIndex++) {
                Input input=requested.get(inputIndex);File apk=input.apk;
                if(!apk.isFile())throw new IOException("not a regular file");
                long size=apk.length(),modified=apk.lastModified();String canonical=apk.getCanonicalPath();
                if(size<=0 || size>limits.maxArchiveBytes || size>setLimits.maxTotalArchiveBytes-archives)throw new IOException("APK size limit");
                archives+=size;ZipFile zip=new ZipFile(apk,Charset.forName("CP437"));open.files.add(zip);
                OpenInput current=new OpenInput(input,inputIndex,size,modified,canonical,zip);HashSet<String> names=new HashSet<>();int centralIndex=0;
                Enumeration<? extends ZipEntry> entries=zip.entries();
                while(entries.hasMoreElements()) {
                    if(centralIndex==limits.maxZipEntries)throw new IOException("ZIP entry limit");
                    ZipEntry z=entries.nextElement();int n=ordinal(z.getName());
                    if(n>0){
                        if(!names.add(z.getName()) || z.isDirectory() || z.getSize()<=0 || z.getSize()>limits.maxDexBytes || z.getCrc()<0 ||
                           z.getCompressedSize()<0 || z.getCompressedSize()>size || (z.getMethod()!=ZipEntry.STORED && z.getMethod()!=ZipEntry.DEFLATED) ||
                           current.tasks.size()>=limits.maxSources || sources>=setLimits.maxTotalSources ||
                           z.getSize()>limits.maxTotalDexBytes-current.dexBytes || z.getSize()>setLimits.maxTotalDexBytes-totalDex)
                            throw new IOException("invalid DEX entry or source-set limit");
                        current.dexBytes+=z.getSize();totalDex+=z.getSize();
                        if(z.getCompressedSize()>Long.MAX_VALUE-current.compressedBytes || z.getCompressedSize()>Long.MAX_VALUE-totalCompressed)
                            throw new IOException("compressed size overflow");
                        current.compressedBytes+=z.getCompressedSize();totalCompressed+=z.getCompressedSize();sources++;
                        Entry info=new Entry(input.slot,inputIndex,z.getName(),centralIndex,n,z.getSize(),z.getCrc());
                        current.tasks.add(new Task(zip,z,info));
                    }
                    centralIndex++;
                }
                if(current.tasks.isEmpty()&&!input.allowNoDex)throw new IOException("no DEX entries");
                Collections.sort(current.tasks,(a,b)->Integer.compare(a.info.ordinal,b.info.ordinal));prepared.add(current);
            }
            List<SourceResult<T>> output=new ArrayList<>(sources);
            if(sources>0){
                ExecutorService pool=Executors.newFixedThreadPool(limits.workers);
                ExecutorCompletionService<Indexed<T>> completion=new ExecutorCompletionService<>(pool);
                HashSet<Future<Indexed<T>>> pending=new HashSet<>();List<Task> tasks=new ArrayList<>(sources);
                for(OpenInput input:prepared)tasks.addAll(input.tasks);
                List<SourceResult<T>> staged=new ArrayList<>(Collections.nCopies(sources,null));
                try {
                    int next=0;
                    while(next<tasks.size() && pending.size()<limits.workers){
                        pending.add(submit(completion,tasks.get(next),next,mapper));next++;
                    }
                    while(!pending.isEmpty()){
                        Future<Indexed<T>> done=completion.take();pending.remove(done);
                        Indexed<T> value=waitFor(done);staged.set(value.index,value.result);
                        if(next<tasks.size()){pending.add(submit(completion,tasks.get(next),next,mapper));next++;}
                    }
                    output.addAll(staged);
                } finally {
                    for(Future<Indexed<T>> task:pending)task.cancel(true);pool.shutdownNow();
                    // A synchronous native query cannot be forcibly interrupted.
                    // Keep every ZIP open until all in-flight workers actually exit.
                    boolean interrupted=false;for(;;)try {if(pool.awaitTermination(1,TimeUnit.DAYS))break;}catch(InterruptedException e){interrupted=true;}
                    if(interrupted)Thread.currentThread().interrupt();
                }
            }
            for(OpenInput input:prepared){File apk=input.input.apk;if(input.size!=apk.length() || input.modified!=apk.lastModified() || !input.canonical.equals(apk.getCanonicalPath()))throw new IOException("APK changed");}
            List<Result<T>> grouped=new ArrayList<>();int position=0;
            for(OpenInput input:prepared){int end=position+input.tasks.size();grouped.add(new Result<>(input.input.slot,input.index,input.size,input.input.allowNoDex,
                output.subList(position,end),input.tasks.size(),input.dexBytes,input.compressedBytes));position=end;}
            return new SourceSetResult<>(grouped,output,archives,totalDex,totalCompressed);
        }
    }

    private static <T> T waitFor(Future<T> future) throws Exception {
        try { return future.get(); }
        catch (ExecutionException failure) {
            Throwable cause=failure.getCause(); if(cause instanceof Exception) throw (Exception)cause;
            if(cause instanceof Error) throw (Error)cause; throw new RuntimeException(cause);
        }
    }
}
