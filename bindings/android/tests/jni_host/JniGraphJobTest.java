package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Objects;

public final class JniGraphJobTest {
    static void check(boolean x,String m){if(!x)throw new AssertionError(m);}
    static byte[] json(String s){return s.getBytes(StandardCharsets.UTF_8);}
    static String scan(String x){return "{\"op\":\"scan\",\"relation\":\""+x+"\"}";}
    static String query(String x){return "{\"schema_version\":1,\"relation\":"+x+",\"intent\":\"enumerate\"}";}
    static String join(String op){return "{\"op\":\""+op+"\",\"on\":\"local_owner\",\"left\":"+scan("method_defs")+",\"right\":"+scan("class_defs")+"}";}
    static void reject(int status,Runnable f){try{f.run();throw new AssertionError("accepted unsupported");}catch(NativeEngine.NativeFailure e){check(e.status==status,"unexpected status "+e.status);}}
    static void entity(GraphResult.Entity a,GraphResult.Entity b){
        check(a.relation==b.relation&&a.sourceIndex==b.sourceIndex&&a.localIndex==b.localIndex&&a.referenceIndex==b.referenceIndex&&a.recordOffset==b.recordOffset&&
              Objects.equals(a.definitionOffset,b.definitionOffset)&&Objects.equals(a.accessFlags,b.accessFlags)&&Objects.equals(a.codeOffset,b.codeOffset)&&
              Objects.equals(a.owner,b.owner)&&Objects.equals(a.name,b.name)&&Objects.equals(a.prototype,b.prototype)&&Objects.equals(a.typeDescriptor,b.typeDescriptor)&&Objects.equals(a.stringValue,b.stringValue),"entity");
    }
    static void binding(GraphResult.Binding a,GraphResult.Binding b){check(a.operatorNode==b.operatorNode&&Objects.equals(a.label,b.label)&&Arrays.equals(a.path(),b.path()),"binding");entity(a.entity,b.entity);}
    static void row(GraphResult.Row a,GraphResult.Row b){
        entity(a.entity,b.entity);check(a.bindingCount()==b.bindingCount()&&a.proofBindingCount()==b.proofBindingCount()&&a.linkCount()==b.linkCount()&&a.witnessCount()==b.witnessCount(),"evidence counts");
        for(int i=0;i<a.bindingCount();i++)binding(a.binding(i),b.binding(i));
        for(int i=0;i<a.proofBindingCount();i++)binding(a.proofBinding(i),b.proofBinding(i));
        for(int i=0;i<a.linkCount();i++){var x=a.link(i);var y=b.link(i);check(x.nodeId==y.nodeId&&x.key==y.key&&x.leftSource==y.leftSource&&x.leftRelation==y.leftRelation&&x.leftLocal==y.leftLocal&&x.rightSource==y.rightSource&&x.rightRelation==y.rightRelation&&x.rightLocal==y.rightLocal,"link");}
        for(int i=0;i<a.witnessCount();i++){var x=a.witness(i);var y=b.witness(i);check(x.kind==y.kind&&x.nodeId==y.nodeId&&x.matched==y.matched&&x.dexPc==y.dexPc&&x.opcode==y.opcode&&x.referenceIndex==y.referenceIndex&&x.referenceKind==y.referenceKind&&x.extraProto==y.extraProto&&x.codeUnits==y.codeUnits&&x.operatorNode==y.operatorNode&&x.sourceIndex==y.sourceIndex&&x.relation==y.relation&&x.localIndex==y.localIndex,"witness");}
    }
    static ArrayList<GraphResult.Row> drain(NativeEngine.GraphJob job,GraphResult expected){
        ArrayList<GraphResult.Row> rows=new ArrayList<>();
        for(int i=0;i<1000;i++){
            var poll=job.next(1000);if(poll.kind==1){check(poll.batch==null,"timeout");continue;}if(poll.kind==2){check(poll.batch==null,"EOS");return rows;}
            check(poll.kind==0&&poll.batch!=null&&poll.batch.coverage==1&&poll.batch.decision==0,"provisional");
            check(poll.batch.queryId.equals(expected.queryId)&&poll.batch.snapshotId.equals(expected.snapshotId)&&poll.batch.inputCount()==expected.inputCount()&&poll.batch.sourceCount()==expected.sourceCount(),"identity");
            for(int j=0;j<poll.batch.rowCount();j++)rows.add(poll.batch.row(j));
        }
        throw new AssertionError("timeout");
    }
    static void verify(NativeEngine.SourceSetSnapshot snap,String expression){
        var q=json(query(expression));var expected=snap.queryGraph(q);
        try(var job=snap.startGraphJob(q,1,1,0)){
            var rows=drain(job,expected);var status=job.waitFor(10000);
            check(status.terminal&&status.executionStatus==expected.executionStatus&&status.coverage==expected.coverage&&status.unknownRows==expected.unknownRows&&status.candidateCount==rows.size(),"terminal");
            check(status.queryId.equals(expected.queryId)&&status.snapshotId.equals(expected.snapshotId)&&rows.size()==expected.rowCount(),"rows");
            for(int i=0;i<rows.size();i++)row(rows.get(i),expected.row(i));
        }
    }
    public static void main(String[] args)throws Exception{
        byte[] dex=Files.readAllBytes(Path.of(args[0])),resource=Files.readAllBytes(Path.of(args[1]));
        GraphResult.Row retained;
        try(var snap=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"one","two"})){
            verify(snap,join("join"));verify(snap,join("semi_join"));verify(snap,scan("string_values"));verify(snap,"{\"op\":\"scan\",\"relation\":\"field_refs\",\"where\":{\"flags_contains\":1}}");
            String labelled="{\"op\":\"label\",\"input\":"+scan("method_defs")+",\"label\":\"M\"}";
            String filtered="{\"op\":\"filter\",\"input\":"+labelled+",\"where\":{\"name\":\"abstractMethod\"}}";
            String twice="{\"op\":\"union\",\"semantics\":\"bag\",\"inputs\":["+filtered+","+filtered+"]}";
            verify(snap,filtered);verify(snap,twice);verify(snap,"{\"op\":\"distinct\",\"identity\":\"tuple\",\"input\":"+twice+"}");
            verify(snap,"{\"op\":\"group_by_owner\",\"inputs\":["+scan("method_defs")+","+scan("field_defs")+"],\"min\":1}");
            var manyQuery=json(query(scan("string_values")));var many=snap.queryGraph(manyQuery);check(many.rowCount()>2,"backpressure fixture");
            try(var cancelled=snap.startGraphJob(manyQuery,1,1,0)){
                boolean queued=false;
                for(int i=0;i<200;i++){var st=cancelled.status();if(!st.terminal&&st.candidateCount>=1){queued=true;break;}Thread.sleep(10);}
                check(queued,"queued before cancellation");cancelled.cancel();var rows=drain(cancelled,many);var st=cancelled.waitFor(10000);
                check(st.terminal&&st.executionStatus==9&&st.coverage==1&&st.candidateCount==rows.size(),"cancelled terminal and delivered batches");
            }
            var result=snap.queryGraph(json(query(join("join"))));
            var job=snap.startGraphJob(json(query(join("join"))),1,1,0);var rows=drain(job,result);retained=rows.get(0);check(job.waitFor(10000).terminal,"terminal");job.close();
            reject(3,()->snap.startGraphJob(json("{\"schema_version\":1,\"relation\":\"method_defs\"}"),1,1,0));
            reject(3,()->snap.startGraphJob(json(query(scan("string_uses"))),1,1,0));
            reject(3,()->snap.startGraphJob(json(query("{\"op\":\"scan\",\"relation\":\"method_defs\",\"scope\":{\"slots\":[\"one\"]}}")),1,1,0));
            reject(4,()->snap.startGraphJob(new byte[65537],1,1,0));
            try{snap.startGraphJob(json(query(scan("method_defs"))),0,1,0);throw new AssertionError("bad batch");}catch(IllegalArgumentException expected){}
        }
        check(retained.binding(1).entity.typeDescriptor.equals("Lcatalog/Child;"),"batch survives close");
        try(var snap=NativeEngine.openSources(new byte[][]{resource},new String[]{"resource"},new int[]{2},new boolean[]{true});var job=snap.startGraphJob(json(query(scan("method_defs"))),1,1,0)){
            var poll=job.next(10000);check(poll.kind==2&&poll.batch==null,"empty source EOS");var s=job.waitFor(10000);check(s.terminal&&s.executionStatus==0&&s.coverage==1&&s.candidateCount==0,"empty status");
        }
        var snap=NativeEngine.openRawDex(dex,"single");var q=json(query(scan("method_defs")));var expected=snap.queryGraph(q);var job=snap.startGraphJob(q,1,1,0);snap.close();
        try(job){check(drain(job,expected).size()==expected.rowCount()&&job.waitFor(10000).terminal,"close while job exists");}
        System.out.println("PASS v3 graph Job batches, evidence, origins, terminal and rejection");
    }
}



