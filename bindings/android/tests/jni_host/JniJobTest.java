package io.github.jichuo1.dexmeguviz;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public final class JniJobTest {
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    private static byte[] query(String intent,String name) {
        return ("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\""+name+"\"},\"intent\":\""+intent+"\",\"max_results\":100}").getBytes(StandardCharsets.UTF_8);
    }
    private static NativeEngine.JobStatus terminal(NativeEngine.Job job) {
        for(int i=0;i<20;i++){var status=job.waitFor(1000);if(status.terminal)return status;}
        throw new AssertionError("job failed to reach terminal state");
    }
    private static int drain(NativeEngine.Job job, ArrayList<NativeEngine.MethodCandidate> copied) {
        int count=0;
        for(int i=0;i<100;i++){
            var poll=job.next(1000);
            if(poll.kind==1){check(poll.batch==null,"timeout carries no batch");continue;}
            if(poll.kind==2){check(poll.batch==null,"EOS carries no batch");return count;}
            check(poll.kind==0&&poll.batch!=null&&poll.batch.coverage==1&&poll.batch.decision==0,"provisional batch");
            for(int j=0;j<poll.batch.candidateCount();j++){copied.add(poll.batch.candidate(j));++count;}
        }
        throw new AssertionError("stream did not reach end");
    }
    private static void status(int expected,Runnable run) {
        try{run.run();throw new AssertionError("expected native status "+expected);}
        catch(NativeEngine.NativeFailure failure){check(failure.status==expected,"unexpected native status "+failure.status);}
    }
    private static void invalid(Runnable run) {
        try{run.run();throw new AssertionError("invalid input accepted");}catch(IllegalArgumentException expected){}
    }
    public static void main(String[] args)throws Exception {
        check(args.length==3,"fixture arguments");
        byte[] first=Files.readAllBytes(Path.of(args[0])),second=Files.readAllBytes(Path.of(args[1])),resource=Files.readAllBytes(Path.of(args[2]));
        var candidates=new ArrayList<NativeEngine.MethodCandidate>();NativeEngine.Job job;
        var set=NativeEngine.openRawDexSet(new byte[][]{first,second},new String[]{"base","split"});
        var snapshot=set.info().snapshotId;
        job=set.startMethodJob(query("enumerate","uses"),1,1,0);set.close();
        try(job){
            check(drain(job,candidates)==1,"one match after snapshot close");
            var finalStatus=terminal(job);
            check(finalStatus.terminal&&finalStatus.executionStatus==0&&finalStatus.coverage==1&&finalStatus.decision==0,"final enumerate state");
            check(finalStatus.candidateCount==1&&finalStatus.snapshotId.equals(snapshot)&&finalStatus.queryId.startsWith("query:v1:"),"job identity and count");
        }
        check(candidates.get(0).name.equals("uses")&&candidates.get(0).sourceIndex==1&&candidates.get(0).sourceSlot.equals("split"),"copied batch origin survives close");
        try(var single=NativeEngine.openRawDex(first,"single");var unique=single.startMethodJob(query("unique","locate"),1,1,0)) {
            var rows=new ArrayList<NativeEngine.MethodCandidate>();check(drain(unique,rows)==1,"single source candidate");
            var end=terminal(unique);check(end.coverage==1&&end.decision==1&&end.reason==5,"incomplete scope cannot prove unique");
        }
        try(var duplicate=NativeEngine.openRawDexSet(new byte[][]{first,first},new String[]{"a","b"});
            var unique=duplicate.startMethodJob(query("unique","locate"),1,1,0)) {
            var rows=new ArrayList<NativeEngine.MethodCandidate>();check(drain(unique,rows)==2,"duplicate occurrence candidates");
            var end=terminal(unique);check(end.coverage==1&&end.decision==2&&end.reason==2,"two matches prove ambiguity");
            check(!rows.get(0).occurrenceId.equals(rows.get(1).occurrenceId),"occurrences remain separate");
        }
        try(var empty=NativeEngine.openSources(new byte[][]{resource},new String[]{"res"},new int[]{NativeEngine.SOURCE_APK},new boolean[]{true});
            var missing=empty.startMethodJob(query("exists","absent"),1,1,0)) {
            check(drain(missing,new ArrayList<>())==0,"resource-only stream empty");
            var end=terminal(missing);check(end.coverage==1&&end.decision==1&&end.reason==5,"empty incomplete scope remains undetermined");
        }
        try(var bodies=NativeEngine.openRawDex(second,"body")) {
            byte[] bodyQuery="{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"using_strings\":{\"all\":[{\"op\":\"exact\",\"value\":\"code-use-q03\"}]}},\"intent\":\"enumerate\"}".getBytes(StandardCharsets.UTF_8);
            try(var bodyJob=bodies.startMethodJob(bodyQuery,1,1,0)) {
                var rows=new ArrayList<NativeEngine.MethodCandidate>();check(drain(bodyJob,rows)==1&&rows.get(0).name.equals("uses"),"method-body predicate job");
                check(terminal(bodyJob).executionStatus==0,"method-body terminal state");
            }
            status(3,()->bodies.startMethodJob("{\"schema_version\":1,\"relation\":\"class_defs\"}".getBytes(StandardCharsets.UTF_8),1,1,0));
            status(3,()->bodies.startMethodJob("{\"schema_version\":1,\"relation\":\"method_defs\",\"scope\":{\"slots\":[\"body\"]}}".getBytes(StandardCharsets.UTF_8),1,1,0));
            status(4,()->bodies.startMethodJob("{\"schema_version\":1,\"relation\":\"method_defs\",\"max_results\":4097}".getBytes(StandardCharsets.UTF_8),1,1,0));
        }
        byte[][] many=new byte[8][];String[] names=new String[8];for(int i=0;i<8;i++){many[i]=first;names[i]="s"+i;}
        try(var large=NativeEngine.openRawDexSet(many,names);var queued=large.startMethodJob(query("enumerate","locate"),1,16,0)) {
            var completed=terminal(queued);check(completed.executionStatus==0&&completed.candidateCount==8,"terminal may precede draining");
            check(drain(queued,new ArrayList<>())==8,"terminal alone did not consume queued batches");
            check(terminal(queued).executionStatus==0,"status remains successful after draining");
        }
        try(var large=NativeEngine.openRawDexSet(many,names);var timed=large.startMethodJob(query("enumerate","locate"),1,1,0)) {
            check(!timed.waitFor(0).terminal,"wait timeout does not cancel a backpressured stream");
            check(drain(timed,new ArrayList<>())==8,"timed wait leaves all batches available");
            check(terminal(timed).executionStatus==0,"timed wait leaves successful terminal state");
        }
        try(var large=NativeEngine.openRawDexSet(many,names);var cancelling=large.startMethodJob(query("enumerate","locate"),1,1,0)) {
            var firstPoll=cancelling.next(10000);check(firstPoll.kind==0,"first provisional batch");
            cancelling.cancel();var end=terminal(cancelling);check(end.terminal&&end.executionStatus==9,"cancel while queue bounded");
            drain(cancelling,new ArrayList<>());
        }
        try(var snap=NativeEngine.openRawDex(first,"limits")) {
            invalid(()->snap.startMethodJob(query("enumerate","locate"),0,1,0));
            invalid(()->snap.startMethodJob(query("enumerate","locate"),1,17,0));
            invalid(()->snap.startMethodJob(query("enumerate","locate"),1,1,86400001L));
            var held=new ArrayList<NativeEngine.Job>();
            try{
                for(int i=0;i<64;i++){var current=snap.startMethodJob(query("exists","absent"),1,1,0);check(terminal(current).terminal,"quota job terminal");held.add(current);}
                status(4,()->snap.startMethodJob(query("exists","absent"),1,1,0));
            }finally{for(var current:held)current.close();}
            try(var recovered=snap.startMethodJob(query("exists","absent"),1,1,0)){
                invalid(()->recovered.waitFor(-1));invalid(()->recovered.waitFor(60001));invalid(()->recovered.next(60001));check(terminal(recovered).terminal,"quota recovered");
            }
        }
        var shared=NativeEngine.openRawDexSet(many,names);var racing=shared.startMethodJob(query("enumerate","locate"),1,1,0);
        var pool=Executors.newFixedThreadPool(2);var ready=new CountDownLatch(1);
        try{
            var reader=pool.submit(()->{ready.countDown();try{racing.next(60000);}catch(IllegalStateException|NativeEngine.NativeFailure acceptable){}});
            var closer=pool.submit(()->{try{check(ready.await(5,TimeUnit.SECONDS),"reader started");racing.cancel();racing.close();}catch(InterruptedException e){throw new AssertionError(e);}});
            reader.get(10,TimeUnit.SECONDS);closer.get(10,TimeUnit.SECONDS);
        }finally{racing.close();shared.close();pool.shutdownNow();}
        System.out.println("PASS JNI Job provisional batches, terminal state, cancellation, quota and lifetime");
    }
}
