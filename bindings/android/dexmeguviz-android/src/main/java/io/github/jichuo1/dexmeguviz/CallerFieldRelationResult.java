package io.github.jichuo1.dexmeguviz;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/** Static relations between caller class and the selected field's declaring class.
 * These observations do not authenticate ClassLoader, accessibility or ART resolution.
 */
public final class CallerFieldRelationResult {
    private static final long NONE=0xffffffffL;
    public final UseGraphResult graph;
    private final Relation[] relations;
    private CallerFieldRelationResult(UseGraphResult graph,Relation[] relations){this.graph=graph;this.relations=relations;}
    public int rowCount(){return relations.length;}
    public Relation relation(int index){return relations[index];}
    public enum Status { SELF, ANCESTOR, EXTERNAL, UNKNOWN }
    public static final class Node {
        public final long sourceIndex,classOrdinal,parentIndex,edgeKind,interfaceIndex;
        private Node(long source,long ordinal,long parent,long edge,long iface){sourceIndex=source;classOrdinal=ordinal;parentIndex=parent;edgeKind=edge;interfaceIndex=iface;}
    }
    public static final class Edge {
        public final int from,to;public final long kind,interfaceIndex;
        private Edge(int from,int to,long kind,long iface){this.from=from;this.to=to;this.kind=kind;interfaceIndex=iface;}
    }
    /** A required interface/Object convention check; it is not an ancestry edge. */
    public static final class InterfaceObjectCheck {
        public final int interfaceNode;public final long objectSource,objectClass;
        private InterfaceObjectCheck(int node,long source,long ordinal){interfaceNode=node;objectSource=source;objectClass=ordinal;}
    }
    /** UNKNOWN is a per-returned-row classification; original query decision stays in graph. */
    public static final class Relation {
        public final Status status;public final long reason,callerSource,callerClass,targetSource,targetClass,targetField,eventSource,eventCaller,eventPc;
        private final Node[] nodes;private final Edge[] edges;private final InterfaceObjectCheck[] objectChecks;
        private Relation(Status status,long reason,long cs,long cc,long ts,long tc,long tf,long es,long ec,long ep,Node[] nodes,Edge[] edges,InterfaceObjectCheck[] objectChecks){
            this.status=status;this.reason=reason;callerSource=cs;callerClass=cc;targetSource=ts;targetClass=tc;targetField=tf;eventSource=es;eventCaller=ec;eventPc=ep;this.nodes=nodes;this.edges=edges;this.objectChecks=objectChecks;
        }
        public int nodeCount(){return nodes.length;}public Node node(int i){return nodes[i];}
        public int edgeCount(){return edges.length;}public Edge edge(int i){return edges[i];}
        public int interfaceObjectCheckCount(){return objectChecks.length;}public InterfaceObjectCheck interfaceObjectCheck(int i){return objectChecks[i];}
    }
    private static long u(ByteBuffer b){return Integer.toUnsignedLong(b.getInt());}
    private static void check(boolean value,String message){if(!value)throw new IllegalStateException(message);}
    private static boolean scoped(UseGraphResult g,long source){for(int i=0;i<g.scopeSourceCount();++i)if(g.scopeSource(i)==source)return true;return false;}
    private static void classIdentity(UseGraphResult g,long source,long ordinal){
        check(source<g.sourceCount()&&scoped(g,source)&&ordinal<Integer.toUnsignedLong(g.source((int)source).classCount),"invalid caller relation class identity");
    }
    private static boolean edgeValid(long kind,long iface){return (kind==1&&iface!=NONE)||(kind==2&&iface==NONE);}
    static CallerFieldRelationResult decode(byte[][] payload){
        if(payload==null||payload.length!=2||payload[0]==null||payload[1]==null)throw new IllegalStateException("invalid caller relation envelope");
        try{
            check((long)payload[0].length+payload[1].length<=8L*1024*1024,"caller relation envelope exceeds limit");
            UseGraphResult graph=UseGraphResult.decode(payload[0]);check(graph.queryId!=null&&graph.queryId.startsWith("query:v19:")&&(graph.requiredCapabilities&268435456)!=0,"wrong caller relation query");
            ByteBuffer b=ByteBuffer.wrap(payload[1]).order(ByteOrder.LITTLE_ENDIAN);check(b.getInt()==0x52464d44,"unknown caller relation wire");int rows=b.getInt();check(rows==graph.rowCount(),"caller relation row count mismatch");Relation[] relations=new Relation[rows];
            for(int row=0;row<rows;++row){
                int n=b.getInt();check(n>=1&&n<=100000&&n<=b.remaining()/68,"invalid caller relation record count");
                long[][] v=new long[n][17];for(int i=0;i<n;++i)for(int j=0;j<17;++j)v[i][j]=u(b);
                long[] head=v[0];check(head[2]==0&&head[0]==Integer.toUnsignedLong(graph.rootNode)&&head[1]==head[0]&&head[3]>=1&&head[3]<=4,"invalid caller relation header");
                Status status=Status.values()[(int)head[3]-1];long reason=head[4];check(status==Status.UNKNOWN ? reason>=1&&reason<=5 : reason==0,"invalid caller relation reason");
                classIdentity(graph,head[5],head[6]);classIdentity(graph,head[11],head[12]);
                UseGraphResult.Row base=graph.row(row);check(base.value.kind==0&&base.linkCount()==1,"caller relation base shape mismatch");UseGraphResult.Link link=base.link(0);
                check(link.key==4&&link.left.sourceIndex==head[5]&&link.right.sourceIndex==head[14]&&link.right.localIndex==head[15]&&link.right.dexPc==head[16],"caller relation event mismatch");
                long terminalSource=NONE,terminalField=NONE,terminalClass=NONE;for(int i=0;i<base.witnessCount();++i){UseGraphResult.Witness w=base.witness(i);if(!w.fieldDeclarationDetailPresent)continue;if(w.fieldDeclarationItem==0){terminalSource=w.entity.sourceIndex;terminalClass=w.entity.localIndex;}else{terminalField=w.entity.localIndex;check(terminalSource==w.entity.sourceIndex,"field terminal source mismatch");}}
                check(terminalSource==head[11]&&terminalClass==head[12]&&terminalField==head[13],"caller relation field mismatch");
                int nodeCount=0,edgeCount=0,checkCount=0;boolean edgesStarted=false,checksStarted=false;
                for(int i=1;i<n;++i){if(v[i][2]==1){check(!edgesStarted&&!checksStarted,"caller relation node after edge");++nodeCount;}
                    else if(v[i][2]==2){check(!checksStarted,"caller relation edge after Object check");edgesStarted=true;++edgeCount;}
                    else{check(v[i][2]==3,"invalid caller relation item");checksStarted=true;++checkCount;}}
                check(status==Status.UNKNOWN ? n==1 : nodeCount>=1,"invalid caller relation node count");Node[] nodes=new Node[nodeCount];Edge[] edges=new Edge[edgeCount];InterfaceObjectCheck[] objectChecks=new InterfaceObjectCheck[checkCount];
                for(int i=0;i<nodeCount;++i){long[] x=v[i+1];check(x[0]==head[0]&&x[1]==head[1]&&x[7]==i,"invalid caller relation node index");classIdentity(graph,x[5],x[6]);
                    if(i==0)check(x[5]==head[5]&&x[6]==head[6]&&x[8]==NONE&&x[9]==0&&x[10]==NONE,"invalid caller relation root");
                    else check(x[8]<i&&edgeValid(x[9],x[10]),"invalid caller relation parent");nodes[i]=new Node(x[5],x[6],x[8],x[9],x[10]);}
                boolean[] parentEdge=new boolean[nodeCount];int[] indegree=new int[nodeCount],headEdge=new int[nodeCount],next=new int[edgeCount];java.util.Arrays.fill(headEdge,-1);
                for(int i=0;i<edgeCount;++i){long[] x=v[1+nodeCount+i];check(x[0]==head[0]&&x[1]==head[1]&&x[7]<nodeCount&&x[8]<nodeCount&&edgeValid(x[9],x[10]),"invalid caller relation edge");int from=(int)x[7],to=(int)x[8];edges[i]=new Edge(from,to,x[9],x[10]);++indegree[to];next[i]=headEdge[from];headEdge[from]=i;
                    Node child=nodes[to];if(child.parentIndex==from&&child.edgeKind==x[9]&&child.interfaceIndex==x[10])parentEdge[to]=true;}
                boolean[] objectChecked=new boolean[nodeCount];long objectSource=NONE,objectOrdinal=NONE;
                for(int i=0;i<checkCount;++i){long[] x=v[1+nodeCount+edgeCount+i];check(x[0]==head[0]&&x[1]==head[1]&&x[7]<nodeCount&&x[8]==NONE&&x[9]==NONE&&x[10]==NONE,"invalid interface Object check");classIdentity(graph,x[5],x[6]);int node=(int)x[7];check(!objectChecked[node],"duplicate interface Object check");objectChecked[node]=true;
                    if(objectSource!=NONE)check(objectSource==x[5]&&objectOrdinal==x[6],"inconsistent interface Object identity");objectSource=x[5];objectOrdinal=x[6];objectChecks[i]=new InterfaceObjectCheck(node,x[5],x[6]);}
                if(status==Status.SELF)check(nodeCount==1&&edgeCount==0&&checkCount==0&&head[5]==head[11]&&head[6]==head[12],"invalid self relation");
                else if(status==Status.ANCESTOR){check(nodeCount>=2&&edgeCount==0&&checkCount==0,"invalid ancestor relation");for(int i=1;i<nodeCount;++i)check(nodes[i].parentIndex==i-1,"invalid ancestor path");Node last=nodes[nodeCount-1];check(last.sourceIndex==head[11]&&last.classOrdinal==head[12],"ancestor target mismatch");}
                else if(status==Status.EXTERNAL){check(nodeCount>=1,"invalid external closure");for(int i=0;i<nodeCount;++i){check(nodes[i].sourceIndex!=head[11]||nodes[i].classOrdinal!=head[12],"external includes target");if(i>0){check(parentEdge[i],"external parent edge missing");if(nodes[i].edgeKind==1)check(objectChecked[i],"interface Object check missing");}}
                    int[] queue=new int[nodeCount];int start=0,end=0,seen=0;for(int i=0;i<nodeCount;++i)if(indegree[i]==0)queue[end++]=i;
                    while(start<end){int x=queue[start++];++seen;for(int e=headEdge[x];e!=-1;e=next[e])if(--indegree[edges[e].to]==0)queue[end++]=edges[e].to;}check(seen==nodeCount,"cyclic external closure");}
                relations[row]=new Relation(status,reason,head[5],head[6],head[11],head[12],head[13],head[14],head[15],head[16],nodes,edges,objectChecks);
            }
            check(!b.hasRemaining(),"extra caller relation bytes");return new CallerFieldRelationResult(graph,relations);
        }catch(java.nio.BufferUnderflowException|java.nio.BufferOverflowException e){throw new IllegalStateException("truncated caller relation wire",e);}
    }
}
