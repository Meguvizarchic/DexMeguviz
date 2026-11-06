package io.github.jichuo1.dexmeguviz;

import java.io.IOException;
import java.io.OutputStream;

/** Bounded synchronous export of static source bytes to caller-owned streams. */
public final class DexStreamExport {
    private static final int MAX_CHUNK = 1 << 20;
    private DexStreamExport() {}
    private static native int nativeRead(Object snapshot,boolean sourceSet,int sourceIndex,long offset,byte[] buffer,int requested,long maxSourceBytes);
    private static void limits(long maxSourceBytes,long maxTotalBytes,int chunkBytes) {
        if(maxSourceBytes<1||maxTotalBytes<1||chunkBytes<1||chunkBytes>MAX_CHUNK)throw new IllegalArgumentException("invalid export limits");
    }
    private static long singleSize(NativeEngine.Snapshot snapshot,long maxBytes) {
        if(snapshot==null)throw new NullPointerException("snapshot is required");
        long n=snapshot.info().sourceBytes;
        if(n<0||n>maxBytes)throw new IllegalArgumentException("source exceeds export limit");
        return n;
    }
    private static long[] sizes(NativeEngine.SourceSetSnapshot snapshot,int count,long maxSourceBytes,long maxTotalBytes) {
        if(snapshot==null)throw new NullPointerException("snapshot is required");
        NativeEngine.SourceSetInfo info=snapshot.info();
        if(count!=info.sourceCount())throw new IllegalArgumentException("stream count must match source count");
        long[] result=new long[count];long sum=0;
        for(int i=0;i<count;i++) {
            long n=info.source(i).sourceBytes;
            if(n<0||n>maxSourceBytes||n>maxTotalBytes-sum)throw new IllegalArgumentException("sources exceed export limit");
            sum+=n;result[i]=n;
        }
        return result;
    }
    private static long transfer(Object snapshot,boolean sourceSet,int index,long size,OutputStream sink,byte[] buffer,long maxSourceBytes)throws IOException {
        long offset=0;
        while(offset<size) {
            int requested=(int)Math.min((long)buffer.length,size-offset),count;
            synchronized(snapshot){count=nativeRead(snapshot,sourceSet,index,offset,buffer,requested,maxSourceBytes);}
            if(count<=0||count>requested)throw new IOException("source read returned an invalid length");
            // Never hold the snapshot monitor while invoking caller code.
            sink.write(buffer,0,count);offset+=count;
        }
        return offset;
    }
    /** Writes one static DEX; does not flush or close the caller-owned stream. */
    public static long writeTo(NativeEngine.Snapshot snapshot,OutputStream sink,long maxBytes,int chunkBytes)throws IOException {
        if(sink==null)throw new NullPointerException("stream is required");limits(maxBytes,maxBytes,chunkBytes);long n=singleSize(snapshot,maxBytes);
        return transfer(snapshot,false,0,n,sink,new byte[(int)Math.min((long)chunkBytes,Math.max(n,1))],maxBytes);
    }
    /** Writes one selected source occurrence; does not flush or close the stream. */
    public static long writeTo(NativeEngine.SourceSetSnapshot snapshot,int sourceIndex,OutputStream sink,long maxBytes,int chunkBytes)throws IOException {
        if(snapshot==null||sink==null)throw new NullPointerException("snapshot and stream are required");limits(maxBytes,maxBytes,chunkBytes);
        NativeEngine.SourceSetInfo info=snapshot.info();if(sourceIndex<0||sourceIndex>=info.sourceCount())throw new IllegalArgumentException("invalid source index");
        long n=info.source(sourceIndex).sourceBytes;if(n<0||n>maxBytes)throw new IllegalArgumentException("source exceeds export limit");
        return transfer(snapshot,true,sourceIndex,n,sink,new byte[(int)Math.min((long)chunkBytes,Math.max(n,1))],maxBytes);
    }
    /** Preflights all source lengths before writing any stream, in source occurrence order. */
    public static long[] writeAll(NativeEngine.SourceSetSnapshot snapshot,OutputStream[] streams,long maxSourceBytes,long maxTotalBytes,int chunkBytes)throws IOException {
        if(snapshot==null||streams==null)throw new NullPointerException("snapshot and streams are required");limits(maxSourceBytes,maxTotalBytes,chunkBytes);
        if(streams.length>1024)throw new IllegalArgumentException("too many streams");
        OutputStream[] sinks=streams.clone();
        for(int i=0;i<sinks.length;i++) {
            if(sinks[i]==null)throw new NullPointerException("stream is required");
            for(int j=0;j<i;j++)if(sinks[i]==sinks[j])throw new IllegalArgumentException("each source requires a distinct stream");
        }
        long[] lengths=sizes(snapshot,sinks.length,maxSourceBytes,maxTotalBytes),written=new long[lengths.length];
        if(lengths.length==0)return written;long largest=0;for(long n:lengths)largest=Math.max(largest,n);
        byte[] buffer=new byte[(int)Math.min((long)chunkBytes,Math.max(largest,1))];
        for(int i=0;i<lengths.length;i++)written[i]=transfer(snapshot,true,i,lengths[i],sinks[i],buffer,maxSourceBytes);
        return written;
    }
}
