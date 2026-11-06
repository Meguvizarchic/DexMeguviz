package io.github.jichuo1.dexmeguviz;

/** Copies one source-local static DEX; does not write files or authenticate loader scope. */
public final class DexSourceExport {
    private DexSourceExport(){}
    private static native byte[] nativeBytes(Object snapshot,boolean sourceSet,int sourceIndex,long maxBytes);
    private static native char[] nativeSymbol(Object snapshot,boolean sourceSet,int sourceIndex,int kind,long index,int maxUnits);
    private static native long[] nativeMemberIndices(Object snapshot,boolean sourceSet,int sourceIndex,int kind,long index);
    private static long[] member(Object snapshot,boolean sourceSet,int sourceIndex,int kind,long index){
        if(snapshot==null)throw new NullPointerException("snapshot is required");
        if(sourceIndex<0||index<0||index>0xffffffffL)throw new IllegalArgumentException("invalid member or source index");
        synchronized(snapshot){return nativeMemberIndices(snapshot,sourceSet,sourceIndex,kind,index);}
    }
    /** Each result is [owner type_id, name string_id, field type_id or method proto_id]. */
    public static long[] fieldRefAt(NativeEngine.Snapshot snapshot,long index){return member(snapshot,false,0,0,index);}
    public static long[] methodRefAt(NativeEngine.Snapshot snapshot,long index){return member(snapshot,false,0,1,index);}
    public static long[] fieldRefAt(NativeEngine.SourceSetSnapshot snapshot,int sourceIndex,long index){return member(snapshot,true,sourceIndex,0,index);}
    public static long[] methodRefAt(NativeEngine.SourceSetSnapshot snapshot,int sourceIndex,long index){return member(snapshot,true,sourceIndex,1,index);}
    private static String symbol(Object snapshot,boolean sourceSet,int sourceIndex,int kind,long index,int maxUnits){
        if(snapshot==null)throw new NullPointerException("snapshot is required");
        if(sourceIndex<0||index<0||index>0xffffffffL||maxUnits<1||maxUnits>1048576)throw new IllegalArgumentException("invalid symbol or limit");
        synchronized(snapshot){return new String(nativeSymbol(snapshot,sourceSet,sourceIndex,kind,index,maxUnits));}
    }
    public static String prototypeAt(NativeEngine.Snapshot snapshot,long index,int maxUnits){return symbol(snapshot,false,0,2,index,maxUnits);}
    public static String prototypeAt(NativeEngine.SourceSetSnapshot snapshot,int sourceIndex,long index,int maxUnits){return symbol(snapshot,true,sourceIndex,2,index,maxUnits);}
    public static String stringAt(NativeEngine.Snapshot snapshot,long index,int maxUnits){return symbol(snapshot,false,0,0,index,maxUnits);}
    public static String typeAt(NativeEngine.Snapshot snapshot,long index,int maxUnits){return symbol(snapshot,false,0,1,index,maxUnits);}
    public static String stringAt(NativeEngine.SourceSetSnapshot snapshot,int sourceIndex,long index,int maxUnits){return symbol(snapshot,true,sourceIndex,0,index,maxUnits);}
    public static String typeAt(NativeEngine.SourceSetSnapshot snapshot,int sourceIndex,long index,int maxUnits){return symbol(snapshot,true,sourceIndex,1,index,maxUnits);}
    private static byte[] copy0(Object snapshot,boolean sourceSet,int sourceIndex,long maxBytes){
        if(snapshot==null)throw new NullPointerException("snapshot is required");
        if(sourceIndex<0||maxBytes<1||maxBytes>Integer.MAX_VALUE)throw new IllegalArgumentException("invalid source or byte limit");
        synchronized(snapshot){return nativeBytes(snapshot,sourceSet,sourceIndex,maxBytes);}
    }
    public static byte[] copy(NativeEngine.Snapshot snapshot,long maxBytes){return copy0(snapshot,false,0,maxBytes);}
    public static byte[] copy(NativeEngine.SourceSetSnapshot snapshot,int sourceIndex,long maxBytes){return copy0(snapshot,true,sourceIndex,maxBytes);}
}
