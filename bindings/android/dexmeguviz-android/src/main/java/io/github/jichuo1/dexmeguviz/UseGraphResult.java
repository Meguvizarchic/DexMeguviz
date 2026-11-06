package io.github.jichuo1.dexmeguviz;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/** Copied v4/v6/v8/v9/v11/v16/v18 static use-event graph; not runtime binding evidence. */
public final class UseGraphResult {
    public final int relation,executionStatus,coverage,decision,reason,candidateCount;
    public final long entityVisited,entityTotal,methodVisited,methodTotal,eventsCollected,unknownRows,maxWork;
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

    private UseGraphResult(Reader r) {
        int version=r.i();boolean inheritedWire=version==0x56474d44, fieldWire=version==0x57474d44;boolean typeWire=version==0x58474d44,interfaceWire=version==0x59474d44;r.typeWire=typeWire;
        if(version!=0x55474d44&&!inheritedWire&&!fieldWire&&!typeWire&&!interfaceWire)throw new IllegalStateException("unknown use graph wire version");
        relation=r.i();executionStatus=r.i();coverage=r.i();decision=r.i();reason=r.i();candidateCount=r.i();
        entityVisited=r.l();entityTotal=r.l();methodVisited=r.l();methodTotal=r.l();eventsCollected=r.l();unknownRows=r.l();
        nodeCount=r.i();requiredCapabilities=r.i();demandMask=r.i();projectionMask=r.i();intent=r.i();maxResults=r.i();explicitScope=r.bool();maxWork=r.l();queryId=r.ascii();snapshotId=r.ascii();
        profile=new Profile(r);rootNode=r.i();uniqueIdentity=r.i();identityCount=r.i();operators=new Operator[r.count(128)];for(int i=0;i<operators.length;i++)operators[i]=new Operator(r);
        inputs=new Input[r.count(8)];for(int i=0;i<inputs.length;i++)inputs[i]=new Input(r);
        sources=new Source[r.count(64)];for(int i=0;i<sources.length;i++)sources[i]=new Source(r);
        scopeSources=new int[profile.scopeSourceCount];for(int i=0;i<scopeSources.length;i++){scopeSources[i]=r.i();if(scopeSources[i]<0||scopeSources[i]>=sources.length)throw new IllegalStateException("invalid use graph scope source");}
        boolean interfaceResolved=interfaceWire&&queryId!=null&&queryId.startsWith("query:v11:");
        if(interfaceWire&&(queryId==null||(!queryId.startsWith("query:v8:")&&!interfaceResolved)||
            (requiredCapabilities&(interfaceResolved?524288:65536))==0))throw new IllegalStateException("invalid interface use graph profile");
        rows=new Row[r.count(4096)];for(int i=0;i<rows.length;i++)rows[i]=new Row(r,inheritedWire,fieldWire,interfaceWire,interfaceResolved,sources.length);
        if(typeWire){if(queryId==null||!queryId.startsWith("query:v21:")||(requiredCapabilities&1073741824)==0)throw new IllegalStateException("invalid type graph profile");for(Row row:rows)validateTypeRow(row,sources);}
        if(candidateCount!=rows.length||r.data.hasRemaining())throw new IllegalStateException("invalid use graph result length");
    }
    static UseGraphResult decode(byte[] bytes){
        if(bytes==null)throw new NullPointerException("use graph bytes");
        try{return new UseGraphResult(new Reader(bytes));}
        catch(java.nio.BufferUnderflowException | java.nio.BufferOverflowException e){throw new IllegalStateException("truncated use graph data",e);}
    }
    public int rowCount(){return rows.length;} public Row row(int i){return rows[i];}
    public int inputCount(){return inputs.length;} public Input input(int i){return inputs[i];}
    public int sourceCount(){return sources.length;} public Source source(int i){return sources[i];}
    public int scopeSourceCount(){return scopeSources.length;} public int scopeSource(int i){return scopeSources[i];}
    public int operatorCount(){return operators.length;} public Operator operator(int i){return operators[i];}

    private static void validateTypeIdentity(Identity id,int count){if(id.relation>10||id.sourceIndex>=count||(id.relation<=6?id.dexPc!=0xffffffffL:id.dexPc==0xffffffffL))throw new IllegalStateException("invalid type graph identity");}
    private static void validateTypeValue(Value value,Source[] sources){
        if(value.kind==0){if(value.entity.sourceIndex<0||value.entity.sourceIndex>=sources.length||value.entity.relation>6)throw new IllegalStateException("invalid type graph entity");return;}
        Use u=value.use;if(u==null||u.relation!=10||u.sourceIndex>=sources.length||u.targetDomain!=5||u.extraProto!=0xffffffffL||u.dexPc==0xffffffffL||u.targetDescriptor==null||u.targetDescriptor.isEmpty())throw new IllegalStateException("invalid type-use value");
        Source source=sources[(int)u.sourceIndex];if(u.callerOrdinal>=Integer.toUnsignedLong(source.methodDefCount)||u.callerMethodRef>=Integer.toUnsignedLong(source.methodRefCount)||u.targetIndex>=Integer.toUnsignedLong(source.typeCount)||!(u.opcode==0x1c||u.opcode==0x1f||u.opcode==0x20||u.opcode==0x22||u.opcode==0x23||u.opcode==0x24||u.opcode==0x25))throw new IllegalStateException("invalid type-use target");
    }
    private static void validateTypeRow(Row row,Source[] sources){
        validateTypeValue(row.value,sources);for(Binding b:row.bindings)validateTypeValue(b.value,sources);for(Binding b:row.proofBindings)validateTypeValue(b.value,sources);
        for(Link l:row.links){validateTypeIdentity(l.left,sources.length);validateTypeIdentity(l.right,sources.length);}
        for(Witness w:row.witnesses){
            validateTypeIdentity(w.entity,sources.length);if(w.matched>2)throw new IllegalStateException("invalid type graph truth");
            if(w.kind==15){if(w.entity.relation!=10||w.entity.dexPc!=w.dexPc||w.dexPc>=w.codeUnits||w.referenceIndex>=Integer.toUnsignedLong(sources[(int)w.entity.sourceIndex].typeCount)||w.extraProto!=0xffffffffL||!(w.opcode==0x1c||w.opcode==0x1f||w.opcode==0x20||w.opcode==0x22||w.opcode==0x23||w.opcode==0x24||w.opcode==0x25))throw new IllegalStateException("invalid type-use witness");}
            else if(w.kind!=1)throw new IllegalStateException("unsupported type graph witness");
        }
    }

    private static final class Reader {
        final ByteBuffer data;boolean typeWire;
        Reader(byte[] bytes){if(bytes.length>8*1024*1024)throw new IllegalStateException("use graph exceeds wire limit");data=ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);}
        int i(){return data.getInt();} long u(){return Integer.toUnsignedLong(i());} long l(){long v=data.getLong();if(v<0)throw new IllegalStateException("unsigned use graph counter overflow");return v;}
        boolean bool(){int v=i();if(v!=0&&v!=1)throw new IllegalStateException("invalid use graph boolean");return v!=0;}
        int count(int max){int n=i();if(n<0||n>max||n>data.remaining())throw new IllegalStateException("invalid use graph count");return n;}
        String ascii(){int n=i();if(n==-1)return null;if(n<0||n>1024||n>data.remaining())throw new IllegalStateException("invalid use graph string");byte[] b=new byte[n];data.get(b);for(byte x:b)if(x<0)throw new IllegalStateException("non-ASCII use graph identity");return new String(b,StandardCharsets.US_ASCII);}
        String text(){int n=i();if(n==-1)return null;if(n<0||n>1048576||n>data.remaining()/2)throw new IllegalStateException("invalid use graph text");char[] c=new char[n];for(int i=0;i<n;i++)c[i]=data.getChar();return new String(c);}
        byte[] path(){int n=count(32);byte[] p=new byte[n];data.get(p);for(byte b:p)if(b!=0&&b!=1)throw new IllegalStateException("invalid use graph path");return p;}
    }
    public static final class Profile {
        public final long workUnits,factRequests,methodsDecoded,codeUnits,stringPoolLookups,invokeSites,fieldUses,declaredFields,matchesSeen,sortComparisons;
        public final int scopeSourceCount;public final boolean scopeComplete,orderVerified;
        private Profile(Reader r){workUnits=r.l();factRequests=r.l();methodsDecoded=r.l();codeUnits=r.l();stringPoolLookups=r.l();invokeSites=r.l();fieldUses=r.l();declaredFields=r.l();matchesSeen=r.l();sortComparisons=r.l();scopeSourceCount=r.count(64);scopeComplete=r.bool();orderVerified=r.bool();}
    }
    public static final class Operator {
        public final int nodeId,op,scanDomain;public final boolean complete;
        public final long inputRows,outputRows,unknownRows,visited,total,attemptedMethods,noBodyMethods,decodedMethods,eventsCollected,codeUnits;
        private Operator(Reader r){nodeId=r.i();op=r.i();scanDomain=r.i();complete=r.bool();inputRows=r.l();outputRows=r.l();unknownRows=r.l();visited=r.l();total=r.l();attemptedMethods=r.l();noBodyMethods=r.l();decodedMethods=r.l();eventsCollected=r.l();codeUnits=r.l();}
    }
    public static final class Input {
        public final int inputIndex,format,sourceCount;public final boolean allowNoDex,expectedDigestVerified,containerMetadataChecked;
        public final String slot,role,sourceSha256,contentId;public final long inputBytes;
        private Input(Reader r){inputIndex=r.i();format=r.i();allowNoDex=r.bool();sourceCount=r.i();slot=r.ascii();role=r.ascii();sourceSha256=r.ascii();contentId=r.ascii();inputBytes=r.l();expectedDigestVerified=r.bool();containerMetadataChecked=r.bool();}
    }
    public static final class Source {
        public final int sourceIndex,inputIndex,dexVersion,stringCount,typeCount,classCount,methodRefCount,methodDefCount;
        public final String slot,role,sourceSha256,contentId,occurrenceId,logicalDexId,archiveSha256,archiveEntryName;
        public final long archiveEntryIndex,sourceBytes;public final boolean crcVerified,headerConsistencyVerified,expectedDigestVerified;
        private Source(Reader r){sourceIndex=r.i();inputIndex=r.i();slot=r.ascii();role=r.ascii();sourceSha256=r.ascii();contentId=r.ascii();occurrenceId=r.ascii();logicalDexId=r.ascii();archiveSha256=r.ascii();archiveEntryName=r.ascii();archiveEntryIndex=r.u();crcVerified=r.bool();headerConsistencyVerified=r.bool();expectedDigestVerified=r.bool();sourceBytes=r.l();dexVersion=r.i();stringCount=r.i();typeCount=r.i();classCount=r.i();methodRefCount=r.i();methodDefCount=r.i();}
    }
    public static final class Entity {
        public final int relation,sourceIndex;public final long localIndex,referenceIndex,recordOffset;
        public final Long definitionOffset,accessFlags,codeOffset;public final String owner,name,prototype,typeDescriptor,stringValue;
        private Entity(Reader r){relation=r.i();sourceIndex=r.i();localIndex=r.u();referenceIndex=r.u();recordOffset=r.u();boolean dk=r.bool();long d=r.u();boolean fk=r.bool();long f=r.u();boolean ck=r.bool();long c=r.u();definitionOffset=dk?Long.valueOf(d):null;accessFlags=fk?Long.valueOf(f):null;codeOffset=ck?Long.valueOf(c):null;owner=r.text();name=r.text();prototype=r.text();typeDescriptor=r.text();stringValue=r.text();}
    }
    public static final class Use {
        /** uint32 sentinel values remain 0xffffffff. PC is a DEX code-unit offset. */
        public final long relation,sourceIndex,callerOrdinal,callerMethodRef,dexPc,opcode,codeOffset,targetDomain,targetIndex,extraProto;
        public final String owner,name,prototype,targetDescriptor;
        private Use(Reader r){relation=r.u();sourceIndex=r.u();callerOrdinal=r.u();callerMethodRef=r.u();dexPc=r.u();opcode=r.u();codeOffset=r.u();targetDomain=r.u();targetIndex=r.u();extraProto=r.u();owner=r.text();name=r.text();prototype=r.text();targetDescriptor=r.typeWire?r.text():null;}
    }
    public static final class Value {
        /** kind 0 is an entity, 1 is a use event; exactly one field is non-null. */
        public final int kind;public final Entity entity;public final Use use;
        private Value(Reader r){kind=r.i();if(kind==0){entity=new Entity(r);use=null;}else if(kind==1){entity=null;use=new Use(r);}else throw new IllegalStateException("unknown use graph value kind");}
    }
    public static final class Identity {
        public final long relation,sourceIndex,localIndex,dexPc;
        private Identity(Reader r){relation=r.u();sourceIndex=r.u();localIndex=r.u();dexPc=r.u();}
    }
    public static final class Binding {
        public final long operatorNode;public final String label;public final Value value;private final byte[] path;
        private Binding(Reader r){operatorNode=r.u();label=r.ascii();path=r.path();value=new Value(r);}
        public byte[] path(){return path.clone();}
    }
    public static final class Link {
        public final long nodeId,key;public final Identity left,right;
        private Link(Reader r){nodeId=r.u();key=r.u();left=new Identity(r);right=new Identity(r);}
    }
    public static final class Witness {
        public final long kind,nodeId,matched,dexPc,opcode,referenceIndex,referenceKind,extraProto,codeUnits,operatorNode;public final Identity entity;
        /** For inherited items, indices are local to the matching leaf; 0xffffffff means absent. */
        public final boolean inheritedDetailPresent;
        public final long inheritedItem,inheritedPath,inheritedAux,inheritedBranch,inheritedDetail;
        public final boolean fieldDeclarationDetailPresent;
        public final long fieldDeclarationItem,fieldDeclarationPath,fieldDeclarationEdge,fieldDeclarationInterfaceIndex,fieldDeclarationDetail;
        /** Interface evidence indices are local to the same predicate and branch. */
        public final boolean interfaceDetailPresent,interfaceResolved;
        public final long interfaceItem,interfaceBranch,interfaceNode,interfaceAux,interfaceDetail;
        private Witness(Reader r,boolean inheritedWire,boolean fieldWire,boolean interfaceWire,boolean resolvedProfile){kind=r.u();nodeId=r.u();matched=r.u();dexPc=r.u();opcode=r.u();referenceIndex=r.u();referenceKind=r.u();extraProto=r.u();codeUnits=r.u();operatorNode=r.u();entity=new Identity(r);
            inheritedDetailPresent=inheritedWire && r.bool();if(inheritedWire && inheritedDetailPresent!=(kind==8))throw new IllegalStateException("invalid inherited witness tag");
            if(inheritedDetailPresent){inheritedItem=r.u();inheritedPath=r.u();inheritedAux=r.u();inheritedBranch=r.u();inheritedDetail=r.u();if(inheritedItem>4)throw new IllegalStateException("invalid inherited witness kind");}
            else{inheritedItem=0xffffffffL;inheritedPath=0xffffffffL;inheritedAux=0xffffffffL;inheritedBranch=0xffffffffL;inheritedDetail=0xffffffffL;}
            fieldDeclarationDetailPresent=fieldWire && r.bool();if(fieldWire && fieldDeclarationDetailPresent!=(kind==12))throw new IllegalStateException("invalid field declaration witness tag");
            if(fieldDeclarationDetailPresent){fieldDeclarationItem=r.u();fieldDeclarationPath=r.u();fieldDeclarationEdge=r.u();fieldDeclarationInterfaceIndex=r.u();fieldDeclarationDetail=r.u();
                if(fieldDeclarationItem>1 || (fieldDeclarationItem==0 ? entity.relation!=1 : entity.relation!=2))throw new IllegalStateException("invalid field declaration witness");}
            else{fieldDeclarationItem=0xffffffffL;fieldDeclarationPath=0xffffffffL;fieldDeclarationEdge=0xffffffffL;fieldDeclarationInterfaceIndex=0xffffffffL;fieldDeclarationDetail=0xffffffffL;}
            int tag=interfaceWire?r.i():0;
            if(tag<0||tag>2||(interfaceWire&&((tag==0&&(kind==10||kind==11))||(tag==1&&(kind!=10||resolvedProfile))||(tag==2&&(kind!=11||!resolvedProfile)))))throw new IllegalStateException("invalid interface witness tag");
            interfaceDetailPresent=tag!=0;interfaceResolved=tag==2;
            if(interfaceDetailPresent){interfaceItem=r.u();interfaceBranch=r.u();interfaceNode=r.u();interfaceAux=r.u();interfaceDetail=r.u();if(interfaceItem>(interfaceResolved?6:5))throw new IllegalStateException("invalid interface item");}
            else{interfaceItem=0xffffffffL;interfaceBranch=0xffffffffL;interfaceNode=0xffffffffL;interfaceAux=0xffffffffL;interfaceDetail=0xffffffffL;}}


    }
    public static final class Row {
        public final Value value;private final Binding[] bindings,proofBindings;private final Link[] links;private final Witness[] witnesses;
        private Row(Reader r,boolean inheritedWire,boolean fieldWire,boolean interfaceWire,boolean resolvedProfile,int sourceCount){value=new Value(r);bindings=new Binding[r.count(100000)];for(int i=0;i<bindings.length;i++)bindings[i]=new Binding(r);proofBindings=new Binding[r.count(100000)];for(int i=0;i<proofBindings.length;i++)proofBindings[i]=new Binding(r);links=new Link[r.count(100000)];for(int i=0;i<links.length;i++)links[i]=new Link(r);witnesses=new Witness[r.count(100000)];for(int i=0;i<witnesses.length;i++)witnesses[i]=new Witness(r,inheritedWire,fieldWire,interfaceWire,resolvedProfile);
            if(fieldWire){
                for(Link link:links){validateIdentity(link.left,sourceCount);validateIdentity(link.right,sourceCount);
                    if(link.key!=4 || link.left.relation!=0 || link.right.relation!=9 || link.left.sourceIndex!=link.right.sourceIndex || link.left.localIndex!=link.right.localIndex)throw new IllegalStateException("invalid v19 caller link");}
                for(Witness witness:witnesses)validateIdentity(witness.entity,sourceCount);
                long path=0;boolean terminal=false;for(Witness w:witnesses)if(w.fieldDeclarationDetailPresent){
                if(terminal)throw new IllegalStateException("field declaration after terminal");
                if(w.fieldDeclarationItem==0){if(w.fieldDeclarationPath!=path || w.fieldDeclarationEdge>2 || (path==0)!=(w.fieldDeclarationEdge==0) ||
                    ((w.fieldDeclarationEdge==1)!=(w.fieldDeclarationInterfaceIndex!=0xffffffffL)))throw new IllegalStateException("invalid field declaration path");++path;}
                else{if(path==0 || w.fieldDeclarationPath!=path-1 || w.fieldDeclarationEdge!=0xffffffffL || w.fieldDeclarationInterfaceIndex!=0xffffffffL)throw new IllegalStateException("invalid terminal field declaration");terminal=true;}}
                if(!terminal)throw new IllegalStateException("missing field declaration terminal");}
            if(interfaceWire){for(Link link:links){validateIdentity(link.left,sourceCount);validateIdentity(link.right,sourceCount);}for(Witness witness:witnesses)validateIdentity(witness.entity,sourceCount);}
            for(Witness w:witnesses)if(w.inheritedDetailPresent){
                if((w.inheritedPath!=0xffffffffL && w.inheritedPath>=witnesses.length)||(w.inheritedBranch!=0xffffffffL && w.inheritedBranch>=witnesses.length)||(w.inheritedItem==1&&w.inheritedAux!=0xffffffffL&&w.inheritedAux>=witnesses.length))throw new IllegalStateException("invalid inherited index");
                if(w.inheritedItem!=0&&w.inheritedPath==0xffffffffL)throw new IllegalStateException("missing inherited path");
                if(w.inheritedItem>=2&&w.inheritedBranch==0xffffffffL)throw new IllegalStateException("missing inherited branch");
            }}
        private static void validateIdentity(Identity id,int sourceCount){
            if(id.relation>9 || id.sourceIndex>=sourceCount || (id.relation<=6 ? id.dexPc!=0xffffffffL : id.dexPc==0xffffffffL))
                throw new IllegalStateException("invalid v19 value identity");
        }
        public int bindingCount(){return bindings.length;}public Binding binding(int i){return bindings[i];}
        public int proofBindingCount(){return proofBindings.length;}public Binding proofBinding(int i){return proofBindings[i];}
        public int linkCount(){return links.length;}public Link link(int i){return links[i];}
        public int witnessCount(){return witnesses.length;}public Witness witness(int i){return witnesses[i];}
    }
}
