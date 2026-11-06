package io.github.jichuo1.dexmeguviz;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/** Copied source-local encoded annotations. Not a runtime annotation or origin proof. */
public final class AnnotationResult {
    public final long sourceIndex,inputIndex,targetRef,parameterIndex,workUnits,archiveEntryIndex,sourceBytes;
    public final int targetKind;public final boolean crcVerified,headerConsistencyVerified,expectedDigestVerified;
    public final String snapshotId,slot,role,sourceSha256,contentId,occurrenceId,logicalDexId,archiveSha256,archiveEntryName;
    private final Item[] items;
    private AnnotationResult(Reader r){
        if(r.i()!=0x41474d44)throw new IllegalStateException("unknown annotation wire");sourceIndex=r.u();inputIndex=r.u();targetKind=r.i();targetRef=r.u();parameterIndex=r.u();int count=r.count(100000);workUnits=r.l();
        snapshotId=r.ascii();slot=r.ascii();role=r.ascii();sourceSha256=r.ascii();contentId=r.ascii();occurrenceId=r.ascii();logicalDexId=r.ascii();archiveSha256=r.ascii();archiveEntryName=r.ascii();archiveEntryIndex=r.u();sourceBytes=r.l();crcVerified=r.bool();headerConsistencyVerified=r.bool();expectedDigestVerified=r.bool();
        if(sourceIndex>=64||inputIndex>=8||targetKind<0||targetKind>3||(targetKind!=3&&parameterIndex!=0xffffffffL)||snapshotId==null||slot==null||role==null||sourceSha256==null||contentId==null||occurrenceId==null||logicalDexId==null)throw new IllegalStateException("invalid annotation identity");
        r.charge(count);items=new Item[count];for(int i=0;i<count;i++)items[i]=new Item(r);
        if(r.data.hasRemaining())throw new IllegalStateException("trailing annotation bytes");
    }
    static AnnotationResult decode(byte[] bytes){if(bytes==null)throw new NullPointerException("annotation bytes");try{return new AnnotationResult(new Reader(bytes));}catch(java.nio.BufferUnderflowException e){throw new IllegalStateException("truncated annotation wire",e);}}
    public int itemCount(){return items.length;}public Item item(int i){return items[i];}
    public static final class Item {
        public final long visibility,typeIndex,itemOffset,encodedOffset;public final String descriptor;private final byte[] encoded;private final Element[] elements;
        private Item(Reader r){visibility=r.u();typeIndex=r.u();int n=r.count(100000);itemOffset=r.u();encodedOffset=r.u();descriptor=r.text();encoded=r.blob();if(visibility>2||descriptor==null||descriptor.isEmpty()||encoded.length<2||encodedOffset!=itemOffset+1)throw new IllegalStateException("invalid annotation item");r.charge(n);elements=new Element[n];for(int i=0;i<n;i++)elements[i]=new Element(r,encodedOffset,encoded.length);}
        /** Complete encoded_annotation bytes, including nested values; never parsed as empty. */
        public byte[] encodedAnnotation(){return encoded.clone();}public int elementCount(){return elements.length;}public Element element(int i){return elements[i];}
    }
    public static final class Element {
        public final long nameIndex,valueKind,valueArg,valueOffset;public final String name;private final byte[] encoded;
        private Element(Reader r,long start,int length){nameIndex=r.u();valueKind=r.u();valueArg=r.u();valueOffset=r.u();name=r.text();encoded=r.blob();if(name==null||valueKind>31||valueArg>7||encoded.length<1||valueOffset<start||valueOffset-start>length||encoded.length>length-(valueOffset-start)||((encoded[0]&31)!=valueKind)||((encoded[0]&255)>>>5)!=valueArg)throw new IllegalStateException("invalid encoded annotation element");}
        /** DEX encoded_value bytes, including the tag and any complete nested payload. */
        public byte[] encodedValue(){return encoded.clone();}
        /** Encoded size, allowing a budget check before requesting a copy. */
        public int encodedValueLength(){return encoded.length;}
    }
    private static final class Reader {
        int records;void charge(int n){if(n>100000-records)throw new IllegalStateException("annotation record limit");records+=n;}
        final ByteBuffer data;Reader(byte[] b){if(b.length>8*1024*1024)throw new IllegalStateException("annotation wire limit");data=ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);}
        int i(){return data.getInt();}long u(){return Integer.toUnsignedLong(i());}long l(){long n=data.getLong();if(n<0)throw new IllegalStateException("counter overflow");return n;}
        boolean bool(){int n=i();if(n!=0&&n!=1)throw new IllegalStateException("boolean");return n!=0;}int count(int max){int n=i();if(n<0||n>max||n>data.remaining())throw new IllegalStateException("count");return n;}
        String ascii(){int n=i();if(n==-1)return null;if(n<0||n>1024||n>data.remaining())throw new IllegalStateException("identity");byte[] b=new byte[n];data.get(b);for(byte x:b)if(x<0)throw new IllegalStateException("identity");return new String(b,StandardCharsets.US_ASCII);}
        String text(){int n=i();if(n==-1)return null;if(n<0||n>1048576||n>data.remaining()/2)throw new IllegalStateException("text");char[] c=new char[n];for(int i=0;i<n;i++)c[i]=data.getChar();return new String(c);}
        byte[] blob(){int n=i();if(n<0||n>8*1024*1024||n>data.remaining())throw new IllegalStateException("encoded length");byte[] out=new byte[n];data.get(out);return out;}
    }
}
