package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class JniGraphTest {
    static void check(boolean x,String why){if(!x)throw new AssertionError(why);}
    static byte[] json(String x){return x.getBytes(StandardCharsets.UTF_8);}
    static void reject(int status,Runnable f){try{f.run();throw new AssertionError("accepted unsupported query");}catch(NativeEngine.NativeFailure x){check(x.status==status,"status "+x.status);}}
    static String graph(String expr){return "{\"schema_version\":1,\"relation\":"+expr+",\"intent\":\"enumerate\"}";}
    static String scan(String relation){return "{\"op\":\"scan\",\"relation\":\""+relation+"\"}";}
    static String join(String op){return "{\"op\":\""+op+"\",\"on\":\"local_owner\",\"left\":"+scan("method_defs")+",\"right\":"+scan("class_defs")+"}";}
    public static void main(String[] args)throws Exception{
        byte[] dex=Files.readAllBytes(Path.of(args[0])), strings=Files.readAllBytes(Path.of(args[1]));GraphResult retained;
        try(var snap=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"one","two"})){
            GraphResult g=snap.queryGraph(json(graph(join("join"))));retained=g;
            check(g.queryId.startsWith("query:v3:")&&g.coverage==1&&g.executionStatus==0,"status");
            check(g.inputCount()==2&&g.sourceCount()==2&&g.rowCount()==2&&g.scopeSourceCount()==2,"counts");
            check(g.visitedRows==12&&g.totalRows==12&&g.operatorCount()==3,"profile counts");
            check(g.source(0).slot.equals("one")&&g.source(1).slot.equals("two")&&!g.source(0).occurrenceId.equals(g.source(1).occurrenceId),"source identity");
            var info=snap.info();check(g.snapshotId.equals(info.snapshotId),"snapshot id");
            for(int i=0;i<2;i++){var gs=g.source(i);var ds=info.source(i);check(gs.sourceIndex==ds.sourceIndex&&gs.inputIndex==ds.inputIndex&&gs.sourceBytes==ds.sourceBytes&&gs.slot.equals(ds.slot)&&gs.occurrenceId.equals(ds.occurrenceId)&&gs.sourceSha256.equals(ds.sourceSha256)&&gs.contentId.equals(ds.contentId)&&gs.logicalDexId.equals(ds.logicalDexId),"source fidelity");}
            for(int i=0;i<2;i++){
                var row=g.row(i);check(row.entity.relation==0&&row.entity.sourceIndex==i&&row.entity.recordOffset==621,"root entity");
                check(row.entity.owner.equals("Lcatalog/Child;")&&row.entity.name.equals("abstractMethod"),"root fields");
                check(row.bindingCount()==2&&row.proofBindingCount()==0&&row.linkCount()==1&&row.witnessCount()==2,"full evidence");
                var left=row.binding(0);var right=row.binding(1);check(left.path().length==1&&left.path()[0]==0&&right.path()[0]==1,"binding paths");
                check(left.entity.sourceIndex==i&&right.entity.sourceIndex==i&&right.entity.typeDescriptor.equals("Lcatalog/Child;"),"binding identities");
                var link=row.link(0);check(link.nodeId==0&&link.key==2&&link.leftSource==i&&link.rightSource==i&&link.leftRelation==0&&link.rightRelation==1,"link");
                check(row.witness(0).kind==1&&row.witness(1).kind==1&&row.witness(0).operatorNode==1&&row.witness(1).operatorNode==2,"witnesses");
                byte[] path=left.path();path[0]=1;check(left.path()[0]==0,"path defensive copy");
            }
            GraphResult projected=snap.queryGraph(json("{\"schema_version\":1,\"relation\":"+join("join")+",\"projection\":[\"identity\"]}"));
            check(projected.row(0).entity.owner==null&&projected.row(0).entity.name==null&&projected.row(0).entity.prototype==null,"root projection");
            check(projected.row(0).binding(0).entity.owner.equals("Lcatalog/Child;")&&projected.row(0).binding(1).entity.typeDescriptor.equals("Lcatalog/Child;"),"binding independent projection");
            GraphResult semiProjected=snap.queryGraph(json("{\"schema_version\":1,\"relation\":"+join("semi_join")+",\"projection\":[\"identity\"]}"));
            check(semiProjected.row(0).entity.owner==null&&semiProjected.row(0).proofBinding(0).entity.typeDescriptor.equals("Lcatalog/Child;"),"proof independent projection");
            GraphResult semi=snap.queryGraph(json(graph(join("semi_join"))));
            check(semi.rowCount()==2&&semi.row(0).proofBindingCount()==1&&semi.row(0).linkCount()==1,"semi proof");
            check(semi.row(0).proofBinding(0).operatorNode==0&&semi.row(0).proofBinding(0).path()[0]==1,"semi path");
            String group="{\"op\":\"group_by_owner\",\"inputs\":["+scan("method_defs")+","+scan("field_defs")+"],\"min\":1}";
            GraphResult grouped=snap.queryGraph(json(graph(group)));check(grouped.rowCount()==0&&grouped.unknownRows>0&&grouped.coverage==1,"incomplete group");
            String scoped="{\"op\":\"scan\",\"relation\":\"method_defs\",\"scope\":{\"slots\":[\"one\"]}}";
            reject(3,()->snap.queryGraph(json(graph(scoped))));
            reject(4,()->snap.queryGraph(new byte[65537]));
            reject(3,()->snap.queryGraph(json("{\"schema_version\":1,\"relation\":\"method_defs\"}")));
            reject(3,()->snap.queryGraph(json(graph(scan("string_uses")))));
            reject(4,()->snap.queryGraph(json("{\"schema_version\":1,\"relation\":"+scan("method_defs")+",\"max_results\":4097}")));
        }
        check(retained.row(0).binding(1).entity.typeDescriptor.equals("Lcatalog/Child;"),"copy survives close");
        try(var snap=NativeEngine.openRawDex(strings,"value")){
            GraphResult g=snap.queryGraph(json(graph(scan("string_values"))));
            var direct=snap.queryEntities(json("{\"schema_version\":1,\"relation\":\"string_values\"}"));
            check(g.rowCount()==direct.candidateCount(),"string count");boolean empty=false,nul=false;
            for(int i=0;i<g.rowCount();i++){String v=g.row(i).entity.stringValue;check(v.equals(direct.candidate(i).stringValue),"string exact");empty|=v.isEmpty();nul|=v.indexOf('\0')>=0;}
            check(empty&&nul,"empty and embedded NUL");
        }
        byte[] apk=Files.readAllBytes(Path.of(args[2])),resource=Files.readAllBytes(Path.of(args[3])),large=Files.readAllBytes(Path.of(args[4]));
        try(var empty=NativeEngine.openSources(new byte[][]{resource},new String[]{"resource"},new int[]{NativeEngine.SOURCE_APK},new boolean[]{true})){
            var g=empty.queryGraph(json(graph(scan("method_defs"))));check(g.sourceCount()==0&&g.inputCount()==1&&g.rowCount()==0&&g.coverage==1&&g.input(0).allowNoDex,"empty APK source");
        }
        try(var mixed=NativeEngine.openSources(new byte[][]{dex,apk,resource,dex},new String[]{"raw","base","resource","split"},new int[]{1,2,2,1},new boolean[]{false,false,true,false})){
            var g=mixed.queryGraph(json(graph(scan("method_defs"))));var metadata=mixed.info();check(g.inputCount()==4&&g.sourceCount()==5&&g.source(4).inputIndex==3,"APK source mapping");
            for(int i=0;i<5;i++){var s=g.source(i);var ref=metadata.source(i);check(s.sourceIndex==ref.sourceIndex&&s.inputIndex==ref.inputIndex&&s.slot.equals(ref.slot)&&s.occurrenceId.equals(ref.occurrenceId)&&java.util.Objects.equals(s.archiveEntryName,ref.archiveEntryName)&&s.archiveEntryIndex==Integer.toUnsignedLong(ref.archiveEntryIndex),"APK occurrence "+i);}
            check(g.source(1).archiveEntryName.equals("classes.dex")&&g.source(3).archiveEntryName.equals("classes10.dex"),"APK entry names");
            for(int i=0;i<g.rowCount();i++){var row=g.row(i).entity;check(row.sourceIndex>=0&&row.sourceIndex<g.sourceCount(),"row source");}
        }
        try(var limited=NativeEngine.openRawDex(large,"large")){
            String scanStrings=scan("string_values");String twice="{\"op\":\"union\",\"semantics\":\"bag\",\"inputs\":["+scanStrings+","+scanStrings+"]}";reject(4,()->limited.queryGraph(json(graph(twice))));
            var after=limited.queryGraph(json(graph(scan("method_defs"))));check(after.executionStatus==0,"failed copy did not close snapshot");
        }
        try{GraphResult.decode(new byte[]{1,2,3});throw new AssertionError("truncation accepted");}catch(IllegalStateException expected){}
        System.out.println("PASS v3 graph JNI copy, source identities, graph evidence, budgets and rejection");
    }
}




