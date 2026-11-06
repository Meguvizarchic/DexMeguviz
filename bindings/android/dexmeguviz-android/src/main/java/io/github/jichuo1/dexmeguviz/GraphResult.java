package io.github.jichuo1.dexmeguviz;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/** Copied v3/v14 metadata graph and its static evidence; it is not runtime binding proof. */
public final class GraphResult {
    public final int relation,executionStatus,coverage,decision,reason,visitedRows,totalRows;
    public final long unknownRows,maxWork;
    public final int nodeCount,requiredCapabilities,demandMask,projectionMask,intent,maxResults;
    public final boolean explicitScope;
    public final String queryId,snapshotId;
    public final Profile profile;
    public final int rootNode,uniqueIdentity,identityCount;
    private final Operator[] operators;
    private final Input[] inputs;
    private final Source[] sources;
    private final int[] scopeSources;
    private final Row[] rows;

    private GraphResult(Reader r) {
        int magic=r.i();boolean annotationWire=magic==0x35474d44;
        if(magic!=0x34474d44&&!annotationWire)throw new IllegalStateException("unknown graph wire version");
        relation=r.i(); executionStatus=r.i(); coverage=r.i(); decision=r.i(); reason=r.i(); visitedRows=r.i(); totalRows=r.i(); unknownRows=r.l();
        nodeCount=r.i();requiredCapabilities=r.i();demandMask=r.i();projectionMask=r.i();intent=r.i();maxResults=r.i();explicitScope=r.bool();maxWork=r.l();queryId=r.ascii();snapshotId=r.ascii();
        profile=new Profile(r);rootNode=r.i();uniqueIdentity=r.i();identityCount=r.i();operators=new Operator[r.count(128)];for(int i=0;i<operators.length;i++)operators[i]=new Operator(r);
        inputs=new Input[r.count(8)];for(int i=0;i<inputs.length;i++)inputs[i]=new Input(r);
        sources=new Source[r.count(64)];for(int i=0;i<sources.length;i++)sources[i]=new Source(r);
        scopeSources=new int[profile.scopeSourceCount];for(int i=0;i<scopeSources.length;i++){scopeSources[i]=r.i();if(scopeSources[i]<0||scopeSources[i]>=sources.length)throw new IllegalStateException("invalid graph scope source");}
        rows=new Row[r.count(4096)];for(int i=0;i<rows.length;i++)rows[i]=new Row(r,annotationWire,sources);
        if(r.data.hasRemaining())throw new IllegalStateException("trailing graph data");
    }
    static GraphResult decode(byte[] bytes){
        if(bytes==null)throw new NullPointerException("graph bytes");
        try{return new GraphResult(new Reader(bytes));}
        catch(java.nio.BufferUnderflowException | java.nio.BufferOverflowException e){throw new IllegalStateException("truncated graph data",e);}
    }
    public int rowCount(){return rows.length;} public Row row(int i){return rows[i];}
    public int inputCount(){return inputs.length;} public Input input(int i){return inputs[i];}
    public int sourceCount(){return sources.length;} public Source source(int i){return sources[i];}
    public int scopeSourceCount(){return scopeSources.length;} public int scopeSource(int i){return scopeSources[i];}
    public int operatorCount(){return operators.length;} public Operator operator(int i){return operators[i];}

    private static final class Reader {
        final ByteBuffer data;
        Reader(byte[] bytes){if(bytes.length>8*1024*1024)throw new IllegalStateException("graph exceeds wire limit");data=ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);}
        int i(){return data.getInt();} long u(){return Integer.toUnsignedLong(i());} long l(){long v=data.getLong();if(v<0)throw new IllegalStateException("unsigned graph counter overflow");return v;}
        boolean bool(){int v=i();if(v!=0&&v!=1)throw new IllegalStateException("invalid graph boolean");return v!=0;}
        int count(int max){int n=i();if(n<0||n>max||n>data.remaining())throw new IllegalStateException("invalid graph count");return n;}
        String ascii(){int n=i();if(n==-1)return null;if(n<0||n>1024||n>data.remaining())throw new IllegalStateException("invalid graph string");byte[] b=new byte[n];data.get(b);for(byte x:b)if(x<0)throw new IllegalStateException("non-ASCII graph identity");return new String(b,StandardCharsets.US_ASCII);}
        String text(){int n=i();if(n==-1)return null;if(n<0||n>1048576||n>data.remaining()/2)throw new IllegalStateException("invalid graph text");char[] c=new char[n];for(int i=0;i<n;i++)c[i]=data.getChar();return new String(c);}
        byte[] path(){int n=count(32);byte[] p=new byte[n];data.get(p);for(byte b:p)if(b!=0&&b!=1)throw new IllegalStateException("invalid graph path");return p;}
    }
    public static final class Profile {
        public final long workUnits,factRequests,methodsDecoded,codeUnits,stringPoolLookups,invokeSites,fieldUses,declaredFields,matchesSeen,sortComparisons;
        public final int scopeSourceCount; public final boolean scopeComplete,orderVerified;
        private Profile(Reader r){workUnits=r.l();factRequests=r.l();methodsDecoded=r.l();codeUnits=r.l();stringPoolLookups=r.l();invokeSites=r.l();fieldUses=r.l();declaredFields=r.l();matchesSeen=r.l();sortComparisons=r.l();scopeSourceCount=r.count(64);scopeComplete=r.bool();orderVerified=r.bool();}
    }
    public static final class Operator {
        public final int nodeId,op; public final long inputRows,outputRows,unknownRows,visitedRows,totalRows;public final boolean complete;
        private Operator(Reader r){nodeId=r.i();op=r.i();inputRows=r.l();outputRows=r.l();unknownRows=r.l();visitedRows=r.l();totalRows=r.l();complete=r.bool();}
    }
    public static final class Input {
        public final int inputIndex,format,sourceCount; public final boolean allowNoDex,expectedDigestVerified,containerMetadataChecked;
        public final String slot,role,sourceSha256,contentId; public final long inputBytes;
        private Input(Reader r){inputIndex=r.i();format=r.i();allowNoDex=r.bool();sourceCount=r.i();slot=r.ascii();role=r.ascii();sourceSha256=r.ascii();contentId=r.ascii();inputBytes=r.l();expectedDigestVerified=r.bool();containerMetadataChecked=r.bool();}
    }
    public static final class Source {
        public final int sourceIndex,inputIndex,dexVersion,stringCount,typeCount,classCount,methodRefCount,methodDefCount;public final String slot,role,sourceSha256,contentId,occurrenceId,logicalDexId,archiveSha256,archiveEntryName;
        /** Raw DEX has null archiveEntryName and archiveEntryIndex 0xffffffff (legacy int API uses -1). */
        public final long archiveEntryIndex,sourceBytes;public final boolean crcVerified,headerConsistencyVerified,expectedDigestVerified;
        private Source(Reader r){sourceIndex=r.i();inputIndex=r.i();slot=r.ascii();role=r.ascii();sourceSha256=r.ascii();contentId=r.ascii();occurrenceId=r.ascii();logicalDexId=r.ascii();archiveSha256=r.ascii();archiveEntryName=r.ascii();archiveEntryIndex=r.u();crcVerified=r.bool();headerConsistencyVerified=r.bool();expectedDigestVerified=r.bool();sourceBytes=r.l();dexVersion=r.i();stringCount=r.i();typeCount=r.i();classCount=r.i();methodRefCount=r.i();methodDefCount=r.i();}
    }
    public static final class Entity {
        public final int relation,sourceIndex;public final long localIndex,referenceIndex,recordOffset;
        public final Long definitionOffset,accessFlags,codeOffset;public final String owner,name,prototype,typeDescriptor,stringValue;
        private Entity(Reader r){relation=r.i();sourceIndex=r.i();localIndex=r.u();referenceIndex=r.u();recordOffset=r.u();boolean dk=r.bool();long d=r.u();boolean fk=r.bool();long f=r.u();boolean ck=r.bool();long c=r.u();definitionOffset=dk?Long.valueOf(d):null;accessFlags=fk?Long.valueOf(f):null;codeOffset=ck?Long.valueOf(c):null;owner=r.text();name=r.text();prototype=r.text();typeDescriptor=r.text();stringValue=r.text();}
    }
    public static final class Binding {
        /** operatorNode is 0xffffffff for a normal binding. */
        public final long operatorNode;public final String label;public final Entity entity;private final byte[] path;
        private Binding(Reader r){operatorNode=r.u();label=r.ascii();path=r.path();entity=new Entity(r);}
        public byte[] path(){return path.clone();}
    }
    public static final class Link {
        public final long nodeId,key,leftSource,leftRelation,leftLocal,rightSource,rightRelation,rightLocal;
        private Link(Reader r){nodeId=r.u();key=r.u();leftSource=r.u();leftRelation=r.u();leftLocal=r.u();rightSource=r.u();rightRelation=r.u();rightLocal=r.u();}
    }
    public static final class Witness {
        /** Native uint32 sentinels remain 0xffffffff; matched is the native three-value code. */
        public final long kind,nodeId,matched,dexPc,opcode,referenceIndex,referenceKind,extraProto,codeUnits,operatorNode,sourceIndex,relation,localIndex;
        /** Null for the original wire and for non-annotation witnesses. */
        public final ClassAnnotationFlags classAnnotationFlags;
        private Witness(Reader r,boolean annotationWire,Source[] sources){kind=r.u();nodeId=r.u();matched=r.u();dexPc=r.u();opcode=r.u();referenceIndex=r.u();referenceKind=r.u();extraProto=r.u();codeUnits=r.u();operatorNode=r.u();sourceIndex=r.u();relation=r.u();localIndex=r.u();
            boolean detail=annotationWire&&r.bool();if(annotationWire&&(detail!=(kind==14)))throw new IllegalStateException("invalid class annotation witness tag");
            if(detail){if(matched>2||sourceIndex>=sources.length||relation!=1||localIndex>=Integer.toUnsignedLong(sources[(int)sourceIndex].classCount))throw new IllegalStateException("invalid class annotation identity");classAnnotationFlags=new ClassAnnotationFlags(r);}
            else classAnnotationFlags=null;}
    }
    /** Source-local static observation; it is not runtime reflection or origin proof. */
    public static final class ClassAnnotationFlags {
        public final long sourceKind,directoryOffset,setOffset,itemOffset,valueOffset,rawFlags,encodedFlags,projectedFlags;
        private ClassAnnotationFlags(Reader r){sourceKind=r.u();directoryOffset=r.u();setOffset=r.u();itemOffset=r.u();valueOffset=r.u();rawFlags=r.u();encodedFlags=r.u();projectedFlags=r.u();
            if(sourceKind>3||(sourceKind==0&&(directoryOffset!=0||setOffset!=0||itemOffset!=0||valueOffset!=0))||
               (sourceKind==1&&(directoryOffset==0||setOffset!=0||itemOffset!=0||valueOffset!=0))||
               (sourceKind==2&&(directoryOffset==0||setOffset==0||itemOffset!=0||valueOffset!=0))||
               (sourceKind==3&&(directoryOffset==0||setOffset==0||itemOffset==0||valueOffset==0))||projectedFlags>0xffffL)
                throw new IllegalStateException("invalid class annotation flags detail");}
    }
    public static final class Row {
        public final Entity entity;private final Binding[] bindings,proofBindings;private final Link[] links;private final Witness[] witnesses;
        private Row(Reader r,boolean annotationWire,Source[] sources){entity=new Entity(r);bindings=new Binding[r.count(100000)];for(int i=0;i<bindings.length;i++)bindings[i]=new Binding(r);proofBindings=new Binding[r.count(100000)];for(int i=0;i<proofBindings.length;i++)proofBindings[i]=new Binding(r);links=new Link[r.count(100000)];for(int i=0;i<links.length;i++)links[i]=new Link(r);witnesses=new Witness[r.count(100000)];for(int i=0;i<witnesses.length;i++)witnesses[i]=new Witness(r,annotationWire,sources);}
        public int bindingCount(){return bindings.length;}public Binding binding(int i){return bindings[i];}
        public int proofBindingCount(){return proofBindings.length;}public Binding proofBinding(int i){return proofBindings[i];}
        public int linkCount(){return links.length;}public Link link(int i){return links[i];}
        public int witnessCount(){return witnesses.length;}public Witness witness(int i){return witnesses[i];}
    }
}



