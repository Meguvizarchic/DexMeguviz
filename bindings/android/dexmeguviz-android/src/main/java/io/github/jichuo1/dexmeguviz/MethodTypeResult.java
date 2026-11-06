package io.github.jichuo1.dexmeguviz;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/** Copied static same-method evidence; it does not imply execution on one path. */
public final class MethodTypeResult {
    public final int executionStatus, coverage, decision, reason, visitedMethods, totalMethods, sourceCount;
    public final long unknownRows;
    public final boolean scopeComplete;
    public final String queryId, snapshotId;
    private final Row[] rows;
    private MethodTypeResult(Reader r) {
        if(r.i()!=0x59474d44)throw new IllegalStateException("unknown method type wire");
        executionStatus=r.i();coverage=r.i();decision=r.i();reason=r.i();int count=r.count(4096);
        visitedMethods=r.i();totalMethods=r.i();unknownRows=r.l();scopeComplete=r.bool();sourceCount=r.count(64);
        queryId=r.ascii();snapshotId=r.ascii();if(queryId==null||!queryId.startsWith("query:v22:")||snapshotId==null)throw new IllegalStateException("invalid method type profile");
        rows=new Row[count];for(int i=0;i<count;i++)rows[i]=new Row(r,sourceCount);
        if(r.data.hasRemaining())throw new IllegalStateException("trailing method type data");
    }
    static MethodTypeResult decode(byte[] bytes){if(bytes==null)throw new NullPointerException("method type bytes");try{return new MethodTypeResult(new Reader(bytes));}catch(java.nio.BufferUnderflowException e){throw new IllegalStateException("truncated method type data",e);}}
    public int rowCount(){return rows.length;} public Row row(int index){return rows[index];}
    private static final class Reader {
        final ByteBuffer data;int witnessTotal;
        Reader(byte[] b){if(b.length>8*1024*1024)throw new IllegalStateException("wire limit");data=ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);}
        int i(){return data.getInt();}long u(){return Integer.toUnsignedLong(i());}long l(){long n=data.getLong();if(n<0)throw new IllegalStateException("counter overflow");return n;}
        boolean bool(){int n=i();if(n!=0&&n!=1)throw new IllegalStateException("boolean");return n!=0;}
        int count(int max){int n=i();if(n<0||n>max||n>data.remaining())throw new IllegalStateException("count");return n;}
        String ascii(){int n=i();if(n==-1)return null;if(n<0||n>1024||n>data.remaining())throw new IllegalStateException("identity");byte[] b=new byte[n];data.get(b);for(byte x:b)if(x<0)throw new IllegalStateException("identity");return new String(b,StandardCharsets.US_ASCII);}
        String text(){int n=i();if(n==-1)return null;if(n<0||n>1048576||n>data.remaining()/2)throw new IllegalStateException("text");char[] c=new char[n];for(int i=0;i<n;i++)c[i]=data.getChar();return new String(c);}
    }
    public static final class Row {
        public final long sourceIndex,inputIndex,methodOrdinal,methodRef,accessFlags,declarationOffset,codeOffset,stringCount,typeCount,methodRefCount,methodDefCount;
        public final String slot,sourceSha256,occurrenceId,owner,name,prototype;
        private final Witness[] witnesses;
        private Row(Reader r,int sourceCount){sourceIndex=r.u();inputIndex=r.u();methodOrdinal=r.u();methodRef=r.u();accessFlags=r.u();declarationOffset=r.u();codeOffset=r.u();stringCount=r.u();typeCount=r.u();methodRefCount=r.u();methodDefCount=r.u();
            if(sourceIndex>=sourceCount||methodOrdinal>=methodDefCount||methodRef>=methodRefCount)throw new IllegalStateException("invalid method identity");
            slot=r.ascii();sourceSha256=r.ascii();occurrenceId=r.ascii();owner=r.text();name=r.text();prototype=r.text();int n=r.count(100000);r.witnessTotal+=n;if(r.witnessTotal>100000)throw new IllegalStateException("witness limit");witnesses=new Witness[n];for(int i=0;i<n;i++)witnesses[i]=new Witness(r,typeCount);
        }
        public int witnessCount(){return witnesses.length;}public Witness witness(int index){return witnesses[index];}
    }
    public static final class Witness {
        public final long kind,nodeId,matched,dexPc,opcode,referenceIndex,referenceKind,extraProto,codeUnits;
        public final String targetDescriptor;
        private Witness(Reader r,long typeCount){kind=r.u();nodeId=r.u();matched=r.u();dexPc=r.u();opcode=r.u();referenceIndex=r.u();referenceKind=r.u();extraProto=r.u();codeUnits=r.u();targetDescriptor=r.text();
            if(matched>2)throw new IllegalStateException("truth");
            if(kind==15){if(targetDescriptor==null||targetDescriptor.isEmpty()||dexPc>=codeUnits||referenceIndex>=typeCount||!(opcode==0x1c||opcode==0x1f||opcode==0x20||opcode==0x22||opcode==0x23||opcode==0x24||opcode==0x25))throw new IllegalStateException("type witness");}
            else if(targetDescriptor!=null||kind<1||kind>7)throw new IllegalStateException("witness");
        }
    }
}
