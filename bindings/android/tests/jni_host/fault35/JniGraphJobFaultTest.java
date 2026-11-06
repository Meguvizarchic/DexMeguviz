package io.github.jichuo1.dexmeguviz;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/** Test-only deterministic scheduling; uses an instrumented host JNI copy. */
public final class JniGraphJobFaultTest {
    private static native void arm(int gate);
    private static native boolean awaitGate(int gate,int timeoutMs);
    private static native void release(int gate);
    private static native void failNextMaterialization(); private static native void failNextPoll(); private static native void failNextDecode(); private static native void failNextWire();
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    private static void internal(Runnable action){
        try{action.run();throw new AssertionError("expected poisoned stream");}
        catch(NativeEngine.NativeFailure failure){check(failure.status==6,"unexpected native status "+failure.status);}
    }
    private static void oom(Runnable action){
        try{action.run();throw new AssertionError("expected injected OOM");}
        catch(OutOfMemoryError expected){check(expected.getMessage().contains("test injection"),"wrong OOM");}
    }
    private static byte[] query(){return ("{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"field_defs\",\"where\":{\"name\":\"instanceField\"}},\"intent\":\"enumerate\",\"max_results\":10}").getBytes(StandardCharsets.UTF_8);}
    private static void waitTerminal(NativeEngine.GraphJob job){
        for(int i=0;i<20;i++){var status=job.waitFor(1000);if(status.terminal){check(status.executionStatus==0&&status.coverage==1&&status.candidateCount==1,"successful terminal with queued candidate");return;}}
        throw new AssertionError("job did not reach terminal");
    }
    public static void main(String[] args)throws Exception{
        check(args.length==1,"fixture argument");byte[] dex=Files.readAllBytes(Path.of(args[0]));
        check(NativeEngine.abiVersion()==1,"native library loaded");
        ExecutorService threads=Executors.newFixedThreadPool(2);
        try(NativeEngine.Snapshot snapshot=NativeEngine.openRawDex(dex,"fault-test")){
            // A second consumer passes the first failed-delivery check and is
            // suspended before it attempts the consumer lock. The first
            // consumer then loses a batch during Java materialization.
            try(NativeEngine.GraphJob job=snapshot.startGraphJob(query(),1,4,0)){
                waitTerminal(job);arm(0);
                Future<?> late=threads.submit(()->internal(()->job.next(0)));
                check(awaitGate(0,10000),"late consumer reached first gate");
                failNextMaterialization();oom(()->job.next(0));release(0);
                late.get(10,TimeUnit.SECONDS);internal(job::status);internal(()->job.next(0));
            }
            // A status call observes the successful native terminal state,
            // then pauses before the final failure check while delivery fails.
            try(NativeEngine.GraphJob job=snapshot.startGraphJob(query(),1,4,0)){
                waitTerminal(job);arm(2);
                Future<?> status=threads.submit(()->internal(job::status));
                check(awaitGate(2,10000),"status reached final gate");
                failNextMaterialization();oom(()->job.next(0));release(2);
                status.get(10,TimeUnit.SECONDS);internal(job::status);
            }
            // A consumer holding the native consumer lock prevents a second
            // simultaneous next(), without poisoning the normal stream.
            try(NativeEngine.GraphJob job=snapshot.startGraphJob(query(),1,4,0)){
                waitTerminal(job);arm(1);
                Future<NativeEngine.GraphJobPoll> first=threads.submit(()->job.next(0));
                check(awaitGate(1,10000),"first consumer holds lock");
                try{job.next(0);throw new AssertionError("concurrent consumer accepted");}
                catch(IllegalStateException expected){}
                release(1);check(first.get(10,TimeUnit.SECONDS).kind==0,"first batch remains available");
                check(job.next(0).kind==2&&job.status().terminal,"normal EOS and terminal");
            }
            // A Java decode exception after bytes were serialized must poison the stream.
            try(NativeEngine.GraphJob job=snapshot.startGraphJob(query(),1,4,0)){
                waitTerminal(job);failNextDecode();oom(()->job.next(0));internal(job::status); // decode-failure
            }
            // A native serializer exception after dequeue must also poison the stream.
            try(NativeEngine.GraphJob job=snapshot.startGraphJob(query(),1,4,0)){
                waitTerminal(job);failNextWire();
                try{job.next(0);throw new AssertionError("expected wire error");}catch(NativeEngine.NativeFailure failure){check(failure.status==4,"wire budget status");}
                internal(job::status); // wire-failure
            }
            // The result was copied, but construction of its poll wrapper
            // fails before Java receives the consumed batch.
            try(NativeEngine.GraphJob job=snapshot.startGraphJob(query(),1,4,0)){
                waitTerminal(job);failNextPoll();oom(()->job.next(0));internal(job::status); // poll-construction-failure
            }
        }finally{for(int i=0;i<3;i++)release(i);threads.shutdownNow();}
        System.out.println("PASS deterministic JNI graph job delivery failure and consumer races");
    }
}
