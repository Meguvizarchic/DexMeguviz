package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.concurrent.*;
public final class UseGraphJobFaultTest {
 private static native void arm(int gate);private static native boolean awaitGate(int gate,int timeoutMs);private static native void release(int gate);private static native void fail(int mode);
 static void check(boolean b,String m){if(!b)throw new AssertionError(m);}static void internal(Runnable r){try{r.run();throw new AssertionError("not poisoned");}catch(NativeEngine.NativeFailure e){check(e.status==6,"status "+e.status);}}
 static byte[] query(){return "{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"}}".getBytes(StandardCharsets.UTF_8);}
 static void terminal(NativeEngine.UseGraphJob j){for(int i=0;i<20;i++){var s=j.waitFor(1000);if(s.terminal){check(s.executionStatus==0&&s.candidateCount==2,"terminal");return;}}throw new AssertionError("no terminal");}
 static void failedNext(NativeEngine.UseGraphJob j,int mode){fail(mode);try{j.next(0);throw new AssertionError("no injected failure");}catch(NativeEngine.NativeFailure e){check(mode==1&&e.status==4,"unexpected native failure "+e.status);}catch(OutOfMemoryError e){check(mode>1&&e.getMessage().contains("test injection"),"unexpected OOM");}}
 public static void main(String[] args)throws Exception{byte[] dex=Files.readAllBytes(Path.of(args[0]));var workers=Executors.newFixedThreadPool(2);
  try(var snapshot=NativeEngine.openRawDex(dex,"fault")){
   try(var j=snapshot.startUseGraphJob(query(),1,4,0)){terminal(j);arm(0);Future<?> late=workers.submit(()->internal(()->j.next(0)));check(awaitGate(0,10000),"late gate");failedNext(j,2);release(0);late.get(10,TimeUnit.SECONDS);internal(j::status);internal(()->j.next(0));}
   try(var j=snapshot.startUseGraphJob(query(),1,4,0)){terminal(j);arm(2);Future<?> status=workers.submit(()->internal(j::status));check(awaitGate(2,10000),"status gate");failedNext(j,2);release(2);status.get(10,TimeUnit.SECONDS);internal(j::status);}
   try(var j=snapshot.startUseGraphJob(query(),1,4,0)){terminal(j);arm(1);Future<NativeEngine.UseGraphJobPoll> first=workers.submit(()->j.next(0));check(awaitGate(1,10000),"consumer gate");try{j.next(0);throw new AssertionError("concurrent accepted");}catch(IllegalStateException expected){}release(1);check(first.get(10,TimeUnit.SECONDS).kind==0,"first delivered");check(j.next(0).kind==0&&j.next(0).kind==2&&j.status().terminal,"normal completion");}
   {var j=snapshot.startUseGraphJob(query(),1,4,0);terminal(j);arm(1);Future<NativeEngine.UseGraphJobPoll> first=workers.submit(()->j.next(0));check(awaitGate(1,10000),"close gate");j.close();release(1);check(first.get(10,TimeUnit.SECONDS).kind==0,"in-flight close retains job");try{j.status();throw new AssertionError("closed status accepted");}catch(IllegalStateException expected){}}
   for(int mode:new int[]{1,2,3,4})try(var j=snapshot.startUseGraphJob(query(),1,4,0)){terminal(j);failedNext(j,mode);internal(j::status);internal(()->j.next(0));}
  }finally{for(int i=0;i<3;i++)release(i);workers.shutdownNow();}
  System.out.println("PASS injected delivery failures, poisoned next/status, concurrent consumer and status race");
 }
}
