package io.github.jichuo1.dexmeguviz;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/** Copied static prototype and optional DEX debug names. Not reflection,
 * runtime binding, source authentication or complete DEX verification. */
public final class MethodParametersResult {
    public static final int DEBUG_NO_DEFINITION=0,DEBUG_NO_BODY=1,DEBUG_NOT_PRESENT=2,DEBUG_PRESENT=3;
    public static final int NAME_UNKNOWN=0,NAME_NO_INDEX=1,NAME_PRESENT=2;
    public final long sourceIndex,inputIndex,methodRef,methodOrdinal,debugOffset,workUnits,archiveEntryIndex,sourceBytes;
    public final int debugState;
    public final boolean crcVerified,headerConsistencyVerified,expectedDigestVerified;
    public final String snapshotId,slot,role,sourceSha256,contentId,occurrenceId,logicalDexId,archiveSha256,archiveEntryName,returnType;
    private final Parameter[] parameters;
    private MethodParametersResult(Reader r){
        if(r.i()!=0x50474d44)throw new IllegalStateException("unknown method parameters wire");
        sourceIndex=r.u();inputIndex=r.u();methodRef=r.u();methodOrdinal=r.u();debugState=r.i();debugOffset=r.u();int count=r.count(65536);workUnits=r.l();
        snapshotId=r.ascii();slot=r.ascii();role=r.ascii();sourceSha256=r.ascii();contentId=r.ascii();occurrenceId=r.ascii();logicalDexId=r.ascii();archiveSha256=r.ascii();archiveEntryName=r.ascii();archiveEntryIndex=r.u();sourceBytes=r.l();crcVerified=r.bool();headerConsistencyVerified=r.bool();expectedDigestVerified=r.bool();returnType=r.text();
        if(sourceIndex>=64||inputIndex>=8||debugState<DEBUG_NO_DEFINITION||debugState>DEBUG_PRESENT||snapshotId==null||slot==null||role==null||sourceSha256==null||contentId==null||occurrenceId==null||logicalDexId==null||returnType==null||returnType.isEmpty()||workUnits==0||
           ((debugState==DEBUG_NO_DEFINITION)!=(methodOrdinal==0xffffffffL))||((debugState==DEBUG_PRESENT)!=(debugOffset!=0))||
           ((archiveEntryIndex==0xffffffffL)!=(archiveEntryName==null))||((archiveEntryIndex==0xffffffffL)!=(archiveSha256==null)))throw new IllegalStateException("invalid method parameter identity");
        parameters=new Parameter[count];for(int i=0;i<count;i++){parameters[i]=new Parameter(r,i,debugState);}
        if(r.data.hasRemaining())throw new IllegalStateException("trailing method parameters bytes");
    }
    static MethodParametersResult decode(byte[] bytes){if(bytes==null)throw new NullPointerException("method parameter bytes");try{return new MethodParametersResult(new Reader(bytes));}catch(java.nio.BufferUnderflowException e){throw new IllegalStateException("truncated method parameters wire",e);}}
    public int parameterCount(){return parameters.length;}
    public Parameter parameter(int index){return parameters[index];}
    /** Null name has two distinct states: unavailable or encoded NO_INDEX. */
    public static final class Parameter {
        public final long ordinal,typeIndex,nameStringIndex;
        public final int nameState;
        public final String typeDescriptor,name;
        private Parameter(Reader r,int expected,int debugState){
            ordinal=r.u();typeIndex=r.u();nameState=r.i();nameStringIndex=r.u();typeDescriptor=r.text();name=r.text();
            if(ordinal!=expected||typeDescriptor==null||typeDescriptor.isEmpty()||nameState<NAME_UNKNOWN||nameState>NAME_PRESENT||
               (debugState==DEBUG_PRESENT?nameState==NAME_UNKNOWN:nameState!=NAME_UNKNOWN)||
               ((nameState==NAME_PRESENT)!=(name!=null))||((nameState==NAME_PRESENT)==(nameStringIndex==0xffffffffL)))throw new IllegalStateException("invalid parameter record");
        }
    }
    private static final class Reader {
        final ByteBuffer data;
        Reader(byte[] b){if(b.length>8*1024*1024)throw new IllegalStateException("method parameters wire limit");data=ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);}
        int i(){return data.getInt();}long u(){return Integer.toUnsignedLong(i());}long l(){long n=data.getLong();if(n<0)throw new IllegalStateException("counter overflow");return n;}
        boolean bool(){int n=i();if(n!=0&&n!=1)throw new IllegalStateException("boolean");return n!=0;}
        int count(int max){int n=i();if(n<0||n>max||n>data.remaining()/16)throw new IllegalStateException("count");return n;}
        String ascii(){int n=i();if(n==-1)return null;if(n<0||n>1024||n>data.remaining())throw new IllegalStateException("identity");byte[] b=new byte[n];data.get(b);for(byte x:b)if(x<0)throw new IllegalStateException("identity");return new String(b,StandardCharsets.US_ASCII);}
        String text(){int n=i();if(n==-1)return null;if(n<0||n>1048576||n>data.remaining()/2)throw new IllegalStateException("text");char[] c=new char[n];for(int i=0;i<n;i++)c[i]=data.getChar();return new String(c);}
    }
}
