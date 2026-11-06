package io.github.jichuo1.dexmeguviz;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/** Copied static paths; status payloads may contain frontiers even with no result rows. */
public final class ExpandResult {
    public final boolean statusPayload,terminal;
    public final int lifecycle,relation,executionStatus,coverage,decision,reason,candidatesCount;
    public final long errorOffset,entityVisited,entityTotal,methodVisited,methodTotal,eventsCollected,unknownRows;
    public final String errorMessage,queryId,snapshotId;
    public final Profile profile;
    public final long rootNode,uniqueIdentity,identityCount,totalCandidates;
    public final boolean scopeSourcesKnown;private final int[] scopeSources;
    private final Input[] inputs;private final Source[] sources;private final Operator[] operators;
    private final ExpandProfile[] expandProfiles;private final Row[] rows;private final Frontier[] frontiers;
    private ExpandResult(Reader r){
        if(r.i()!=0x45474d44)throw new IllegalStateException("unknown expand wire");statusPayload=r.bool();lifecycle=r.i();terminal=r.bool();errorOffset=r.l();errorMessage=r.ascii();queryId=r.ascii();snapshotId=r.ascii();
        if(queryId==null||!queryId.startsWith("query:v5:")||snapshotId==null)throw new IllegalStateException("invalid expand identity");
        relation=r.i();executionStatus=r.i();coverage=r.i();decision=r.i();reason=r.i();candidatesCount=r.i();
        if(relation<0||relation>6||executionStatus<0||executionStatus>12||coverage<0||coverage>1||decision<0||decision>3||candidatesCount<0||candidatesCount>4096)throw new IllegalStateException("invalid expand outcome");
        entityVisited=r.l();entityTotal=r.l();methodVisited=r.l();methodTotal=r.l();eventsCollected=r.l();unknownRows=r.l();profile=new Profile(r);rootNode=r.u();uniqueIdentity=r.u();identityCount=r.u();totalCandidates=r.u();
        inputs=new Input[r.count(8)];for(int i=0;i<inputs.length;i++){inputs[i]=new Input(r);if(inputs[i].inputIndex!=i)throw new IllegalStateException("input identity");}
        sources=new Source[r.count(64)];for(int i=0;i<sources.length;i++){sources[i]=new Source(r);if(sources[i].sourceIndex!=i||sources[i].inputIndex<0||sources[i].inputIndex>=inputs.length)throw new IllegalStateException("source identity");}
        r.sourceCount=sources.length;
        scopeSourcesKnown=r.bool();scopeSources=new int[r.count(64)];for(int i=0;i<scopeSources.length;i++){scopeSources[i]=r.i();if(scopeSources[i]<0||scopeSources[i]>=sources.length)throw new IllegalStateException("scope identity");}
        if(scopeSourcesKnown?scopeSources.length!=profile.scopeSourceCount:scopeSources.length!=0)throw new IllegalStateException("scope count");
        operators=new Operator[r.count(128)];for(int i=0;i<operators.length;i++)operators[i]=new Operator(r);
        expandProfiles=new ExpandProfile[r.count(128)];for(int i=0;i<expandProfiles.length;i++)expandProfiles[i]=new ExpandProfile(r);
        rows=new Row[r.count(4096)];for(int i=0;i<rows.length;i++)rows[i]=new Row(r);
        frontiers=new Frontier[r.count(100000)];for(int i=0;i<frontiers.length;i++)frontiers[i]=new Frontier(r);
        if(statusPayload?rows.length!=0:rows.length!=candidatesCount)throw new IllegalStateException("row count");
        if(r.data.hasRemaining())throw new IllegalStateException("trailing expand data");
    }
    static ExpandResult decode(byte[] bytes){if(bytes==null)throw new NullPointerException("expand bytes");try{return new ExpandResult(new Reader(bytes));}catch(java.nio.BufferUnderflowException e){throw new IllegalStateException("truncated expand data",e);}}
    public int inputCount(){return inputs.length;}public Input input(int i){return inputs[i];}
    public int sourceCount(){return sources.length;}public Source source(int i){return sources[i];}
    public int scopeSourceCount(){return scopeSources.length;}public int scopeSource(int i){return scopeSources[i];}
    public int operatorCount(){return operators.length;}public Operator operator(int i){return operators[i];}
    public int expandProfileCount(){return expandProfiles.length;}public ExpandProfile expandProfile(int i){return expandProfiles[i];}
    public int rowCount(){return rows.length;}public Row row(int i){return rows[i];}
    public int frontierCount(){return frontiers.length;}public Frontier frontier(int i){return frontiers[i];}
    private static void identity(Identity v,Reader r,boolean absent){
        if(absent&&v.sourceIndex==0xffffffffL&&v.localIndex==0xffffffffL)return;
        if(v.relation>9||v.sourceIndex>=r.sourceCount||(v.relation<=6?v.dexPc!=0xffffffffL:v.dexPc==0xffffffffL))throw new IllegalStateException("invalid expand identity");
    }
    private static final class Reader {
        final ByteBuffer data;boolean typeWire;int sourceCount;
        Reader(byte[] bytes){if(bytes.length>8*1024*1024)throw new IllegalStateException("expand exceeds wire limit");data=ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);}
        int i(){return data.getInt();} long u(){return Integer.toUnsignedLong(i());} long l(){long v=data.getLong();if(v<0)throw new IllegalStateException("unsigned expand counter overflow");return v;}
        boolean bool(){int v=i();if(v!=0&&v!=1)throw new IllegalStateException("invalid expand boolean");return v!=0;}
        int count(int max){int n=i();if(n<0||n>max||n>data.remaining())throw new IllegalStateException("invalid expand count");return n;}
        String ascii(){int n=i();if(n==-1)return null;if(n<0||n>1024||n>data.remaining())throw new IllegalStateException("invalid expand string");byte[] b=new byte[n];data.get(b);for(byte x:b)if(x<0)throw new IllegalStateException("non-ASCII expand identity");return new String(b,StandardCharsets.US_ASCII);}
        String text(){int n=i();if(n==-1)return null;if(n<0||n>1048576||n>data.remaining()/2)throw new IllegalStateException("invalid expand text");char[] c=new char[n];for(int i=0;i<n;i++)c[i]=data.getChar();return new String(c);}
        byte[] path(){int n=count(32);byte[] p=new byte[n];data.get(p);for(byte b:p)if(b!=0&&b!=1)throw new IllegalStateException("invalid expand path");return p;}
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
        private Entity(Reader r){relation=r.i();sourceIndex=r.i();if(relation<0||relation>6||sourceIndex<0||sourceIndex>=r.sourceCount)throw new IllegalStateException("entity identity");localIndex=r.u();referenceIndex=r.u();recordOffset=r.u();boolean dk=r.bool();long d=r.u();boolean fk=r.bool();long f=r.u();boolean ck=r.bool();long c=r.u();definitionOffset=dk?Long.valueOf(d):null;accessFlags=fk?Long.valueOf(f):null;codeOffset=ck?Long.valueOf(c):null;owner=r.text();name=r.text();prototype=r.text();typeDescriptor=r.text();stringValue=r.text();}
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
        private Value(Reader r){kind=r.i();if(kind==0){entity=new Entity(r);use=null;}else if(kind==1){entity=null;use=new Use(r);}else throw new IllegalStateException("unknown expand value kind");}
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

    public static final class ExpandProfile {
        public final long nodeId,visited,edges,paths,decodedMethods,unresolved,unknownFrontiers,reverseBuilds,reverseReuses;
        private ExpandProfile(Reader r){nodeId=r.u();visited=r.l();edges=r.l();paths=r.l();decodedMethods=r.l();unresolved=r.l();unknownFrontiers=r.l();reverseBuilds=r.l();reverseReuses=r.l();}
    }
    public static final class Witness {
        public final long kind,nodeId,matched,dexPc,opcode,referenceIndex,referenceKind,extraProto,codeUnits,operatorNode;public final Identity entity;
        private Witness(Reader r){kind=r.u();nodeId=r.u();matched=r.u();dexPc=r.u();opcode=r.u();referenceIndex=r.u();referenceKind=r.u();extraProto=r.u();codeUnits=r.u();operatorNode=r.u();entity=new Identity(r);identity(entity,r,false);if(kind<1||kind>7||matched>2)throw new IllegalStateException("expand witness");}
    }
    public static final class Hop {
        public final Identity caller,resolved;public final long dexPc,codeOffset,opcode,targetMethodRef,candidateCount;public final boolean resolutionComplete;public final Entity targetSymbol;
        private Hop(Reader r){caller=new Identity(r);resolved=new Identity(r);identity(caller,r,false);identity(resolved,r,false);dexPc=r.u();codeOffset=r.u();opcode=r.u();targetMethodRef=r.u();candidateCount=r.u();resolutionComplete=r.bool();targetSymbol=new Entity(r);
            if(caller.relation!=0||resolved.relation!=0||targetSymbol.relation!=3||targetSymbol.sourceIndex!=caller.sourceIndex||targetSymbol.referenceIndex!=targetMethodRef||candidateCount==0||dexPc==0xffffffffL||!((opcode>=0x6e&&opcode<=0x72)||(opcode>=0x74&&opcode<=0x78)))throw new IllegalStateException("expand hop");}
    }
    public static final class Evidence {
        private final Binding[] bindings,proofs;private final Link[] links;private final Witness[] seed,walk,emit;private final Hop[] hops;
        private Evidence(Reader r){bindings=new Binding[r.count(100000)];for(int i=0;i<bindings.length;i++)bindings[i]=new Binding(r);links=new Link[r.count(100000)];for(int i=0;i<links.length;i++){links[i]=new Link(r);identity(links[i].left,r,false);identity(links[i].right,r,false);}proofs=new Binding[r.count(100000)];for(int i=0;i<proofs.length;i++)proofs[i]=new Binding(r);seed=readWitnesses(r);walk=readWitnesses(r);emit=readWitnesses(r);hops=new Hop[r.count(100000)];for(int i=0;i<hops.length;i++)hops[i]=new Hop(r);}
        private static Witness[] readWitnesses(Reader r){Witness[] a=new Witness[r.count(100000)];for(int i=0;i<a.length;i++)a[i]=new Witness(r);return a;}
        public int bindingCount(){return bindings.length;}public Binding binding(int i){return bindings[i];}
        public int proofCount(){return proofs.length;}public Binding proof(int i){return proofs[i];}
        public int linkCount(){return links.length;}public Link link(int i){return links[i];}
        public int seedWitnessCount(){return seed.length;}public Witness seedWitness(int i){return seed[i];}
        public int walkWitnessCount(){return walk.length;}public Witness walkWitness(int i){return walk[i];}
        public int emitWitnessCount(){return emit.length;}public Witness emitWitness(int i){return emit[i];}
        public int hopCount(){return hops.length;}public Hop hop(int i){return hops[i];}
    }
    public static final class Path {
        public final long nodeId;public final boolean uncertain;public final Identity seed,endpoint;public final Evidence evidence;
        private Path(Reader r){nodeId=r.u();uncertain=r.bool();seed=new Identity(r);endpoint=new Identity(r);identity(seed,r,false);identity(endpoint,r,false);evidence=new Evidence(r);}
    }
    public static final class RowEvidence {
        private final Binding[] bindings,proofs;private final Link[] links;private final Witness[] witnesses;
        private RowEvidence(Reader r){bindings=new Binding[r.count(100000)];for(int i=0;i<bindings.length;i++)bindings[i]=new Binding(r);links=new Link[r.count(100000)];for(int i=0;i<links.length;i++){links[i]=new Link(r);identity(links[i].left,r,false);identity(links[i].right,r,false);}proofs=new Binding[r.count(100000)];for(int i=0;i<proofs.length;i++)proofs[i]=new Binding(r);witnesses=new Witness[r.count(100000)];for(int i=0;i<witnesses.length;i++)witnesses[i]=new Witness(r);}
        public int bindingCount(){return bindings.length;}public Binding binding(int i){return bindings[i];}
        public int proofCount(){return proofs.length;}public Binding proof(int i){return proofs[i];}
        public int linkCount(){return links.length;}public Link link(int i){return links[i];}
        public int witnessCount(){return witnesses.length;}public Witness witness(int i){return witnesses[i];}
    }
    public static final class Row {
        public final Entity value;public final RowEvidence evidence;private final Path[] paths;
        private Row(Reader r){value=new Entity(r);evidence=new RowEvidence(r);paths=new Path[r.count(100000)];for(int i=0;i<paths.length;i++){paths[i]=new Path(r);}}
        public int pathCount(){return paths.length;}public Path path(int i){return paths[i];}
    }
    public static final class Frontier {
        public final long nodeId,depth,reason,dexPc,targetMethodRef;public final boolean hasTargetSymbol;public final Identity seed,current,caller;public final Entity targetSymbol;public final Evidence prefix;
        private Frontier(Reader r){nodeId=r.u();depth=r.u();reason=r.u();dexPc=r.u();targetMethodRef=r.u();hasTargetSymbol=r.bool();seed=new Identity(r);current=new Identity(r);caller=new Identity(r);identity(seed,r,false);identity(current,r,false);identity(caller,r,true);targetSymbol=hasTargetSymbol?new Entity(r):null;prefix=new Evidence(r);if(reason>3||prefix.hopCount()!=depth)throw new IllegalStateException("frontier");}
    }
}
