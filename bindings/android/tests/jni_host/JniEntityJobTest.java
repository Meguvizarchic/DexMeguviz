package io.github.jichuo1.dexmeguviz;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Objects;

public final class JniEntityJobTest {
    private static void check(boolean value,String what){if(!value)throw new AssertionError(what);}
    private static byte[] json(String value){return value.getBytes(StandardCharsets.UTF_8);}
    private static byte[] query(String relation){return json("{\"schema_version\":1,\"relation\":\""+relation+"\",\"where\":true,\"intent\":\"enumerate\"}");}
    private static void status(int expected,Runnable call){try{call.run();throw new AssertionError("expected native failure");}catch(NativeEngine.NativeFailure e){check(e.status==expected,"status "+e.status);}}
    private static NativeEngine.EntityJobStatus terminal(NativeEngine.EntityJob job){
        for(int i=0;i<20;i++){var s=job.waitFor(1000);if(s.terminal)return s;}
        throw new AssertionError("terminal timeout");
    }
    private static ArrayList<NativeEngine.EntityCandidate> drain(NativeEngine.EntityJob job){
        var rows=new ArrayList<NativeEngine.EntityCandidate>();
        for(int i=0;i<1000;i++){
            var poll=job.next(1000);
            if(poll.kind==1){check(poll.batch==null,"timeout with batch");continue;}
            if(poll.kind==2){check(poll.batch==null,"EOS with batch");return rows;}
            check(poll.kind==0&&poll.batch!=null&&poll.batch.coverage==1&&poll.batch.decision==0,"provisional batch");
            for(int j=0;j<poll.batch.candidateCount();j++)rows.add(poll.batch.candidate(j));
        }
        throw new AssertionError("stream timeout");
    }
    private static void equal(NativeEngine.EntityCandidate a,NativeEngine.EntityCandidate b){
        check(a.relation==b.relation&&a.sourceIndex==b.sourceIndex&&a.inputIndex==b.inputIndex&&
              a.localIndex==b.localIndex&&a.referenceIndex==b.referenceIndex&&a.recordOffset==b.recordOffset&&
              Objects.equals(a.definitionOffset,b.definitionOffset)&&Objects.equals(a.accessFlags,b.accessFlags)&&
              Objects.equals(a.codeOffset,b.codeOffset)&&Objects.equals(a.owner,b.owner)&&Objects.equals(a.name,b.name)&&
              Objects.equals(a.prototype,b.prototype)&&Objects.equals(a.typeDescriptor,b.typeDescriptor)&&
              Objects.equals(a.stringValue,b.stringValue)&&Objects.equals(a.sourceSlot,b.sourceSlot)&&
              Objects.equals(a.occurrenceId,b.occurrenceId),"entity batch differs from synchronous row");
    }
    public static void main(String[] args)throws Exception {
        byte[] dex=Files.readAllBytes(Path.of(args[0])),resource=Files.readAllBytes(Path.of(args[1]));
        String[] relations={"method_defs","class_defs","field_defs","method_refs","field_refs","string_values","type_refs"};
        NativeEngine.EntityCandidate kept=null;
        try(var snap=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"a","b"})){
            for(String relation:relations){
                var expected=snap.queryEntities(query(relation));
                try(var job=snap.startEntityJob(query(relation),2,1,0)){
                    var rows=drain(job);var end=terminal(job);
                    check(end.executionStatus==0&&end.coverage==1&&end.candidateCount==rows.size(),"successful terminal "+relation);
                    check(end.queryId.equals(expected.queryId)&&end.snapshotId.equals(expected.snapshotId),"identity "+relation);
                    check(rows.size()==expected.candidateCount(),"row count "+relation);
                    for(int i=0;i<rows.size();i++)equal(rows.get(i),expected.candidate(i));
                    if(!rows.isEmpty())kept=rows.get(0);
                }
            }
            var unknown=json("{\"schema_version\":1,\"relation\":\"field_refs\",\"where\":{\"flags_contains\":0},\"intent\":\"enumerate\"}");
            var expected=snap.queryEntities(unknown);
            try(var job=snap.startEntityJob(unknown,1,1,0)){
                var rows=drain(job);var end=terminal(job);
                check(rows.size()==expected.candidateCount()&&end.unknownRows==expected.unknownRows&&end.unknownRows>0,"unknown preserved");
            }
            status(3,()->snap.startEntityJob(json("{\"schema_version\":1,\"relation\":\"class_defs\",\"scope\":{\"slots\":[\"a\"]}}"),1,1,0));
            status(3,()->snap.startEntityJob(json("{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"field_refs\"}}"),1,1,0));
            status(3,()->snap.startEntityJob(json("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"using_strings\":{\"all\":[\"x\"]}}}"),1,1,0));
            status(3,()->snap.startEntityJob(json("{\"schema_version\":1,\"relation\":\"class_defs\",\"where\":{\"flags\":{\"domain\":\"reflection\",\"mode\":\"contains\",\"value\":1}},\"required_capabilities\":[\"reflection_flags_static\"]}"),1,1,0));
            status(3,()->snap.startEntityJob(json("{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"field_refs\",\"where\":{\"flags\":{\"domain\":\"reflection\",\"mode\":\"contains\",\"value\":1}}},\"intent\":\"enumerate\",\"required_capabilities\":[\"reflection_flags_static\",\"reflection_relational\"]}"),1,1,0));
            status(4,()->snap.startEntityJob(json("{\"schema_version\":1,\"relation\":\"class_defs\",\"max_results\":4097}"),1,1,0));
            try(var limited=snap.startEntityJob(json("{\"schema_version\":1,\"relation\":\"field_defs\",\"max_results\":1}"),1,1,0)){
                var rows=drain(limited);var end=terminal(limited);
                check(rows.size()==1&&end.executionStatus==4&&end.coverage==1&&end.reason==4,"result limit cannot imply completion");
            }
            try(var cancelling=snap.startEntityJob(query("string_values"),1,1,0)){
                check(!cancelling.waitFor(0).terminal,"backpressure wait timeout");
                check(cancelling.next(10000).kind==0,"first batch");cancelling.cancel();
                check(terminal(cancelling).executionStatus==9,"cancelled terminal");drain(cancelling);
            }
        }
        check(kept!=null&&kept.sourceSlot!=null,"copied row survives close");
        try(var empty=NativeEngine.openSources(new byte[][]{resource},new String[]{"res"},new int[]{NativeEngine.SOURCE_APK},new boolean[]{true});
            var job=empty.startEntityJob(json("{\"schema_version\":1,\"relation\":\"class_defs\",\"intent\":\"exists\"}"),1,1,0)){
            check(drain(job).isEmpty(),"empty stream");var end=terminal(job);
            check(end.executionStatus==0&&end.coverage==1&&end.decision==1,"empty incomplete scope");
        }
        var snap=NativeEngine.openRawDex(dex,"single");var job=snap.startEntityJob(query("field_defs"),1,1,0);snap.close();
        try(job){check(drain(job).size()==3&&terminal(job).executionStatus==0,"job survives snapshot close");}
        System.out.println("PASS seven entity roots, provisional rows, status, origins, cancellation and rejection");
    }
}
