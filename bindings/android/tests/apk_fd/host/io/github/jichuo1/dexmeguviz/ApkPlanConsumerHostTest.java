package io.github.jichuo1.dexmeguviz;
import android.content.pm.ApplicationInfo;
import io.github.jichuo1.dexmeguviz.examples.ApkPlanExample;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.concurrent.*;
public final class ApkPlanConsumerHostTest {
 static void check(boolean b,String message){if(!b)throw new AssertionError(message);}
 static String sha(Path path)throws Exception {StringBuilder b=new StringBuilder();for(byte x:MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)))b.append(String.format("%02x",x&255));return b.toString();}
 static ApkFdLimits limits(){long m=1024L*1024;return new ApkFdLimits(256*m,128*m,128*m,256*m,64*m,128*m,1000,16*m,8*m);}
 static ApplicationInfo metadata(String base,String resource){ApplicationInfo a=new ApplicationInfo();a.packageName="sample.pkg";a.sourceDir=base;a.splitNames=new String[]{"res"};a.splitSourceDirs=new String[]{resource};return a;}
 public static void main(String[] args)throws Exception{
  check(args.length==3,"base/resource/large fixtures");String base=Path.of(args[0]).toAbsolutePath().toString(),resource=Path.of(args[1]).toAbsolutePath().toString();String digest=sha(Path.of(base));
  ExecutorService worker=Executors.newSingleThreadExecutor();CountDownLatch block=new CountDownLatch(1),started=new CountDownLatch(1);
  try{
   worker.submit(()->{started.countDown();try{if(!block.await(30,TimeUnit.SECONDS))throw new AssertionError("timeout");}catch(InterruptedException e){throw new RuntimeException(e);}});check(started.await(30,TimeUnit.SECONDS),"worker started");
   ApplicationInfo info=metadata(base,resource);boolean[] allow={true};String[] expected={digest,null};Future<ApkPlanExample.Report> pending=ApkPlanExample.submit(worker,info,false,allow,expected,limits());
   info.sourceDir=base+".missing";info.splitSourceDirs[0]=resource+".missing";info.splitNames[0]="mutated";allow[0]=false;expected[0]="0".repeat(64);block.countDown();
   ApkPlanExample.Report report=pending.get(60,TimeUnit.SECONDS);check(report.inputCount==2&&report.sourceCount>0&&report.methods.candidateCount()==1&&report.methods.decision==3&&report.methods.coverage==1,"worker captured plan and queried incomplete set");
  }finally{block.countDown();worker.shutdownNow();}
  ExecutorService edgeWorker=Executors.newSingleThreadExecutor();
  try{
   ApplicationInfo empty=new ApplicationInfo();empty.sourceDir=resource;
   ApkPlanExample.Report noDex=ApkPlanExample.submit(edgeWorker,empty,true,null,null,limits()).get(60,TimeUnit.SECONDS);
   check(noDex.inputCount==1&&noDex.sourceCount==0&&noDex.methods.executionStatus==0&&noDex.methods.coverage==1&&noDex.methods.candidateCount()==0&&noDex.methods.decision==1&&noDex.methods.reason==5,"no DEX remains undetermined in incomplete scope");
   ApplicationInfo big=new ApplicationInfo();big.sourceDir=Path.of(args[2]).toAbsolutePath().toString();
   ApkPlanExample.Report many=ApkPlanExample.submit(edgeWorker,big,false,null,null,limits()).get(60,TimeUnit.SECONDS);
   check(many.methods.totalMethods>=4500&&many.methods.executionStatus==0&&many.methods.coverage==1&&many.methods.candidateCount()==1&&many.methods.decision==3,"EXISTS succeeds with more than 4096 methods");
   try(AndroidApkSources.Opened o=AndroidApkSources.open(big,false,null,null,limits())){
    byte[] enumeration="{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":true,\"intent\":\"enumerate\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    NativeEngine.QueryResult bounded=o.snapshot.queryMethods(enumeration);
    check(bounded.totalMethods>=4500&&bounded.executionStatus==4&&bounded.reason==4&&bounded.coverage==1&&bounded.candidateCount()==4096,"old unbounded enumeration hits result limit");
   }
  }finally{edgeWorker.shutdownNow();}
  ApplicationInfo info=metadata(base,resource);ApkMetadataPlan plan=AndroidApkSources.plan(info,false,new boolean[]{true});info.sourceDir=base+".missing";
  NativeEngine.SourceSetSnapshot held;String identity;
  try(AndroidApkSources.Opened x=AndroidApkSources.open(plan,new String[]{digest,null},limits())){
   check(x.plan==plan,"same reviewed plan object");held=x.snapshot;var observed=x.snapshot.info();identity=observed.snapshotId;
   check(!observed.sourceScopeComplete&&observed.inputCount()==2&&observed.input(1).sourceCount==0&&observed.input(0).sourceSha256.equals(digest),"ordered inputs and verified bytes");
  }
  try{held.info();throw new AssertionError("closed snapshot still live");}catch(IllegalStateException expected){}
  try(AndroidApkSources.Opened old=AndroidApkSources.open(metadata(base,resource),false,new boolean[]{true},new String[]{digest,null},limits())){check(old.snapshot.info().snapshotId.equals(identity),"legacy ApplicationInfo open unchanged");}
  try{AndroidApkSources.open(plan,new String[]{"0".repeat(64),null},limits());throw new AssertionError("digest mismatch accepted");}catch(NativeEngine.NativeFailure expected){check(expected.status==8,"digest mismatch classification");}
  try(AndroidApkSources.Opened again=AndroidApkSources.open(plan,null,limits())){check(again.snapshot.info().snapshotId.equals(identity),"open after failure");}
  try{AndroidApkSources.open((ApkMetadataPlan)null,null,limits());throw new AssertionError("null plan accepted");}catch(NullPointerException expected){}
  System.out.println("PASS reviewed plan, background query, resource split, old open and closure");
 }
}
