package io.github.jichuo1.dexmeguviz;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
public final class JniGraphDump {
    private static String q(String s){if(s==null)return "null";StringBuilder b=new StringBuilder("\"");for(int i=0;i<s.length();i++){int c=s.charAt(i);b.append(String.format("\\u%04x",c));}return b.append('"').toString();}
    private static String num(Long x){return x==null?"null":x.toString();}
    private static String entity(GraphResult.Entity x){return "{\"relation\":"+x.relation+",\"source_index\":"+x.sourceIndex+",\"local_index\":"+x.localIndex+",\"reference_index\":"+x.referenceIndex+",\"record_offset\":"+x.recordOffset+",\"definition_offset\":"+num(x.definitionOffset)+",\"access_flags\":"+num(x.accessFlags)+",\"code_offset\":"+num(x.codeOffset)+",\"owner\":"+q(x.owner)+",\"name\":"+q(x.name)+",\"prototype\":"+q(x.prototype)+",\"type_descriptor\":"+q(x.typeDescriptor)+",\"string_value\":"+q(x.stringValue)+"}";}
    private static String path(byte[] b){StringBuilder out=new StringBuilder("[");for(int i=0;i<b.length;i++){if(i>0)out.append(',');out.append((int)b[i]);}return out.append(']').toString();}
    private static String binding(GraphResult.Binding b){return "{\"operator_node\":"+b.operatorNode+",\"label\":"+q(b.label)+",\"path\":"+path(b.path())+",\"entity\":"+entity(b.entity)+"}";}
    public static void main(String[] args)throws Exception{
        byte[] dex=Files.readAllBytes(Path.of(args[0])), query=Files.readAllBytes(Path.of(args[1]));
        try(var snap=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"one","two"})){
            var g=snap.queryGraph(query);StringBuilder b=new StringBuilder();
            b.append("{\"query_id\":").append(q(g.queryId)).append(",\"execution_status\":").append(g.executionStatus).append(",\"coverage\":").append(g.coverage).append(",\"decision\":").append(g.decision).append(",\"reason\":").append(g.reason).append(",\"visited_rows\":").append(g.visitedRows).append(",\"total_rows\":").append(g.totalRows).append(",\"unknown_rows\":").append(g.unknownRows).append(",\"identity_count\":").append(g.identityCount).append(",\"root_node\":").append(g.rootNode).append(",\"unique_identity\":").append(g.uniqueIdentity).append(",\"work\":").append(g.profile.workUnits).append(",\"matches\":").append(g.profile.matchesSeen).append(",\"operators\":[");
            for(int i=0;i<g.operatorCount();i++){if(i>0)b.append(',');var x=g.operator(i);b.append('[').append(x.nodeId).append(',').append(x.op).append(',').append(x.inputRows).append(',').append(x.outputRows).append(',').append(x.unknownRows).append(',').append(x.visitedRows).append(',').append(x.totalRows).append(',').append(x.complete).append(']');}b.append("],\"rows\":[");
            for(int i=0;i<g.rowCount();i++){if(i>0)b.append(',');var x=g.row(i);b.append("{\"entity\":").append(entity(x.entity)).append(",\"bindings\":[");
                for(int j=0;j<x.bindingCount();j++){if(j>0)b.append(',');b.append(binding(x.binding(j)));}b.append("],\"proof\":[");
                for(int j=0;j<x.proofBindingCount();j++){if(j>0)b.append(',');b.append(binding(x.proofBinding(j)));}b.append("],\"links\":[");
                for(int j=0;j<x.linkCount();j++){if(j>0)b.append(',');var l=x.link(j);b.append('[').append(l.nodeId).append(',').append(l.key).append(',').append(l.leftSource).append(',').append(l.leftRelation).append(',').append(l.leftLocal).append(',').append(l.rightSource).append(',').append(l.rightRelation).append(',').append(l.rightLocal).append(']');}b.append("],\"witnesses\":[");
                for(int j=0;j<x.witnessCount();j++){if(j>0)b.append(',');var w=x.witness(j);b.append('[').append(w.kind).append(',').append(w.nodeId).append(',').append(w.matched).append(',').append(w.operatorNode).append(',').append(w.sourceIndex).append(',').append(w.relation).append(',').append(w.localIndex).append(']');}b.append("]}");
            }b.append("]}");System.out.println(b);
        }
    }
}
