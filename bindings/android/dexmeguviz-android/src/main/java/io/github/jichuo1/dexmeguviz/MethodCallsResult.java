package io.github.jichuo1.dexmeguviz;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/** Complete copied calls from one checked local method. This is not a query
 * decision, runtime dispatch, origin authentication or whole-DEX verifier. */
public final class MethodCallsResult {
    public final long sourceIndex,inputIndex,methodOrdinal,methodRef,codeOffset,codeUnits,validationWork;
    public final long callerFlags,callerDeclarationOffset,archiveEntryIndex,sourceBytes;
    public final boolean hasBody,instructionChecked,crcVerified,headerConsistencyVerified,expectedDigestVerified;
    public final String snapshotId,slot,role,sourceSha256,contentId,occurrenceId,logicalDexId,archiveSha256,archiveEntryName;
    public final String callerOwner,callerName,callerPrototype;
    private final Row[] rows;
    private MethodCallsResult(Reader r){
        if(r.i()!=0x43474d44)throw new IllegalStateException("unknown method calls wire");
        sourceIndex=r.u();inputIndex=r.u();methodOrdinal=r.u();methodRef=r.u();codeOffset=r.u();hasBody=r.bool();instructionChecked=r.bool();codeUnits=r.u();int n=r.count(100000);validationWork=r.l();
        snapshotId=r.ascii();slot=r.ascii();role=r.ascii();sourceSha256=r.ascii();contentId=r.ascii();occurrenceId=r.ascii();logicalDexId=r.ascii();archiveSha256=r.ascii();archiveEntryName=r.ascii();archiveEntryIndex=r.u();sourceBytes=r.l();crcVerified=r.bool();headerConsistencyVerified=r.bool();expectedDigestVerified=r.bool();
        callerFlags=r.u();callerDeclarationOffset=r.u();callerOwner=r.text();callerName=r.text();callerPrototype=r.text();
        if(sourceIndex>=64||inputIndex>=8||snapshotId==null||sourceSha256==null||occurrenceId==null||logicalDexId==null||callerOwner==null||callerName==null||callerPrototype==null||hasBody!=(codeOffset!=0)||instructionChecked!=hasBody||(!hasBody&&(n!=0||codeUnits!=0||validationWork!=0)))throw new IllegalStateException("invalid method calls identity");
        rows=new Row[n];long previous=-1;for(int i=0;i<n;i++){rows[i]=new Row(r,codeUnits);if(rows[i].dexPc<=previous)throw new IllegalStateException("unordered method calls");previous=rows[i].dexPc;}
        if(r.data.hasRemaining())throw new IllegalStateException("trailing method calls bytes");
    }
    static MethodCallsResult decode(byte[] bytes){if(bytes==null)throw new NullPointerException("method calls bytes");try{return new MethodCallsResult(new Reader(bytes));}catch(java.nio.BufferUnderflowException e){throw new IllegalStateException("truncated method calls wire",e);}}
    public int rowCount(){return rows.length;}public Row row(int index){return rows[index];}
    public static final class Row {
        public final long dexPc,opcode,targetDomain,targetIndex,extraProto;
        public final String owner,name,prototype,extraPrototype;
        private Row(Reader r,long codeUnits){dexPc=r.u();opcode=r.u();targetDomain=r.u();targetIndex=r.u();extraProto=r.u();owner=r.text();name=r.text();prototype=r.text();extraPrototype=r.text();
            if(dexPc>=codeUnits)throw new IllegalStateException("call PC outside body");
            if(targetDomain==2){if(!((opcode>=0x6e&&opcode<=0x72)||(opcode>=0x74&&opcode<=0x78))||extraProto!=0xffffffffL||owner==null||name==null||prototype==null||extraPrototype!=null)throw new IllegalStateException("ordinary call");}
            else if(targetDomain==3){if((opcode!=0xfa&&opcode!=0xfb)||extraProto==0xffffffffL||owner==null||name==null||prototype==null||extraPrototype==null)throw new IllegalStateException("polymorphic call");}
            else if(targetDomain==4){if((opcode!=0xfc&&opcode!=0xfd)||extraProto!=0xffffffffL||owner!=null||name!=null||prototype!=null||extraPrototype!=null)throw new IllegalStateException("custom call");}
            else throw new IllegalStateException("unknown call domain");
        }
    }
    private static final class Reader {
        final ByteBuffer data;
        Reader(byte[] b){if(b.length>8*1024*1024)throw new IllegalStateException("method calls wire limit");data=ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);}
        int i(){return data.getInt();}long u(){return Integer.toUnsignedLong(i());}long l(){long n=data.getLong();if(n<0)throw new IllegalStateException("counter overflow");return n;}
        boolean bool(){int n=i();if(n!=0&&n!=1)throw new IllegalStateException("boolean");return n!=0;}
        int count(int max){int n=i();if(n<0||n>max||n>data.remaining())throw new IllegalStateException("count");return n;}
        String ascii(){int n=i();if(n==-1)return null;if(n<0||n>1024||n>data.remaining())throw new IllegalStateException("identity");byte[] b=new byte[n];data.get(b);for(byte x:b)if(x<0)throw new IllegalStateException("identity");return new String(b,StandardCharsets.US_ASCII);}
        String text(){int n=i();if(n==-1)return null;if(n<0||n>1048576||n>data.remaining()/2)throw new IllegalStateException("text");char[] c=new char[n];for(int i=0;i<n;i++)c[i]=data.getChar();return new String(c);}
    }
}
