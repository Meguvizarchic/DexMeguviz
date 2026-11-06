package io.github.jichuo1.dexmeguviz;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/** Explicit opt-in, synchronous method-v1 cache for one opened snapshot.
 * The caller chooses an app-private directory and trusts all of its writers.
 * Cached facts do not authenticate installed files, the loader, or results. */
public final class PersistentCacheBridge implements AutoCloseable {
    /** Zero selects the native default for the corresponding bounded resource. */
    public static final class Limits {
        public final long maxFileBytes,maxDirectoryBytes;
        public final int maxDirectoryEntries,maxRecords;
        public Limits(long maxFileBytes,long maxDirectoryBytes,int maxDirectoryEntries,int maxRecords) {
            long file=maxFileBytes==0?64L<<20:maxFileBytes;
            long directory=maxDirectoryBytes==0?256L<<20:maxDirectoryBytes;
            int entries=maxDirectoryEntries==0?2048:maxDirectoryEntries;
            int records=maxRecords==0?1_048_576:maxRecords;
            if(file<1||file>(256L<<20)||directory<file||directory>(4L<<30)||entries<2||entries>65536||records<1||records>1_048_576)
                throw new IllegalArgumentException("invalid persistent cache limits");
            this.maxFileBytes=maxFileBytes;this.maxDirectoryBytes=maxDirectoryBytes;
            this.maxDirectoryEntries=maxDirectoryEntries;this.maxRecords=maxRecords;
        }
        public static Limits defaults(){return new Limits(0,0,0,0);}
    }
    private long token;
    // Native side owns a separate retained source reference for its lifetime.
    private final Object snapshot;
    private PersistentCacheBridge(long token,Object snapshot){if(token==0)throw new IllegalStateException("native cache token is zero");this.token=token;this.snapshot=snapshot;}

    public static PersistentCacheBridge open(NativeEngine.Snapshot snapshot,File directory,Limits limits){return open0(snapshot,directory,limits,false);}
    public static PersistentCacheBridge open(NativeEngine.SourceSetSnapshot snapshot,File directory,Limits limits){return open0(snapshot,directory,limits,true);}
    public static PersistentCacheBridge open(NativeEngine.Snapshot snapshot,File directory){return open(snapshot,directory,Limits.defaults());}
    public static PersistentCacheBridge open(NativeEngine.SourceSetSnapshot snapshot,File directory){return open(snapshot,directory,Limits.defaults());}
    private static PersistentCacheBridge open0(Object snapshot,File directory,Limits limits,boolean sourceSet){
        if(snapshot==null||directory==null||limits==null)throw new NullPointerException("snapshot, directory and limits are required");
        final String absolute=directory.getAbsolutePath();
        if(absolute.length()==0||absolute.length()>4096||absolute.indexOf('\0')>=0)throw new IllegalArgumentException("invalid cache directory path");
        final byte[] path;
        try {
            ByteBuffer encoded=StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(absolute));
            if(encoded.remaining()==0||encoded.remaining()>4096)throw new IllegalArgumentException("cache path exceeds UTF-8 limit");
            path=new byte[encoded.remaining()];encoded.get(path);
        } catch(CharacterCodingException failure){throw new IllegalArgumentException("cache path is not valid UTF-8",failure);}
        synchronized(snapshot){
            long nativeToken=0;
            try {
                nativeToken=nativeOpen(snapshot,sourceSet,path,limits.maxFileBytes,limits.maxDirectoryBytes,limits.maxDirectoryEntries,limits.maxRecords);
                return new PersistentCacheBridge(nativeToken,snapshot);
            } catch(Throwable failure){
                if(nativeToken!=0)try{nativeClose(nativeToken);}catch(Throwable closeFailure){failure.addSuppressed(closeFailure);}
                throw failure;
            }
        }
    }
    /** Same direct method-v1 scope and limits as the snapshot's queryMethods.
     * It is synchronous; do not mutate queryJson until the call returns. */
    public synchronized NativeEngine.QueryResult queryMethods(byte[] queryJson){
        if(token==0)throw new IllegalStateException("cache session is closed");
        if(queryJson==null)throw new NullPointerException("queryJson is required");
        return nativeQueryMethods(token,queryJson);
    }
    /** Cumulative per-session cache counters, copied in the documented order. */
    public synchronized long[] statistics(){if(token==0)throw new IllegalStateException("cache session is closed");return nativeStatistics(token);}
    @Override public synchronized void close(){if(token!=0){long previous=token;token=0;nativeClose(previous);}}
    private static native long nativeOpen(Object snapshot,boolean sourceSet,byte[] directory,long maxFileBytes,long maxDirectoryBytes,int maxDirectoryEntries,int maxRecords);
    private static native NativeEngine.QueryResult nativeQueryMethods(long token,byte[] queryJson);
    private static native long[] nativeStatistics(long token);
    private static native void nativeClose(long token);
}
