package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
public final class ClassAnnotationJobHostTest {
 static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
 static byte[] q(String field){return ("{\"schema_version\":1,\"relation\":\"class_defs\",\"required_capabilities\":[\"class_annotation_static\"],\"where\":{\"annotation\":{\"type\":\"Lfixture/Complex;\",\"element\":{\"name\":\""+field+"\",\"int\":-7}}}}").getBytes(StandardCharsets.UTF_8);}
 static void reject(int code,Runnable f){try{f.run();throw new AssertionError("expected native failure");}catch(NativeEngine.NativeFailure e){check(e.status==code,"status "+e.status);}}
 static void invalid(Runnable f){try{f.run();throw new AssertionError("expected invalid limits");}catch(IllegalArgumentException expected){}}
 static NativeEngine.EntityJobStatus terminal(NativeEngine.EntityJob job){for(int i=0;i<20;i++){var s=job.waitFor(1000);if(s.terminal)return s;}throw new AssertionError("terminal timeout");}
 static ArrayList<NativeEngine.EntityCandidate> drain(NativeEngine.EntityJob job){var rows=new ArrayList<NativeEngine.EntityCandidate>();for(int i=0;i<100;i++){var p=job.next(1000);if(p.kind==1){check(p.batch==null,"timeout batch");continue;}if(p.kind==2){check(p.batch==null,"EOS batch");return rows;}check(p.kind==0&&p.batch!=null&&p.batch.coverage==1&&p.batch.decision==0&&p.batch.queryId.startsWith("query:v24:"),"provisional batch");for(int j=0;j<p.batch.candidateCount();j++)rows.add(p.batch.candidate(j));}throw new AssertionError("drain timeout");}
 public static void main(String[] a)throws Exception{
  check(a.length==1,"fixture");byte[] dex=Files.readAllBytes(Path.of(a[0]));byte[] match=q("n"),missing=q("absent");
  byte[] scope=new String(match,StandardCharsets.UTF_8).replace("\"where\":","\"scope\":{\"slots\":[\"one\"]},\"where\":").getBytes(StandardCharsets.UTF_8);
  byte[] old="{\"schema_version\":1,\"relation\":\"class_defs\"}".getBytes(StandardCharsets.UTF_8);
  var set=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"one","two"});String sid=set.info().snapshotId;
  reject(3,()->set.startEntityJob(match,1,1,0));reject(3,()->ClassAnnotationQuery.startJob(set,old,1,1,0));reject(3,()->ClassAnnotationQuery.startJob(set,scope,1,1,0));
  invalid(()->ClassAnnotationQuery.startJob(set,match,0,1,0));invalid(()->ClassAnnotationQuery.startJob(set,match,1,17,0));invalid(()->ClassAnnotationQuery.startJob(set,match,1,1,86400001L));
  try{ClassAnnotationQuery.startJob(set,null,1,1,0);throw new AssertionError("null query accepted");}catch(NullPointerException expected){}
  var live=ClassAnnotationQuery.startJob(set,match,1,1,0);set.close();ArrayList<NativeEngine.EntityCandidate> kept;
  try(live){kept=drain(live);var status=terminal(live);check(kept.size()==2&&status.terminal&&status.executionStatus==0&&status.coverage==1&&status.candidateCount==2&&status.unknownRows==0&&status.queryId.startsWith("query:v24:")&&sid.equals(status.snapshotId),"final identity and source lifetime");}
  try{live.status();throw new AssertionError("closed job accepted");}catch(IllegalStateException expected){}
  check(kept.get(0).sourceIndex==0&&kept.get(1).sourceIndex==1&&"one".equals(kept.get(0).sourceSlot)&&"two".equals(kept.get(1).sourceSlot)&&!kept.get(0).occurrenceId.equals(kept.get(1).occurrenceId),"distinct source identities");
  check("Lfixture/Annotated;".equals(kept.get(0).typeDescriptor),"copied result lifetime");
  try(var sample=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"one","two"});var unknown=ClassAnnotationQuery.startJob(sample,missing,1,1,0)){
   check(drain(unknown).isEmpty(),"Unknown yields no batch");var status=terminal(unknown);check(status.executionStatus==0&&status.coverage==1&&status.unknownRows==2&&status.reason==6,"Unknown terminal");
  }
  try(var sample=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"one","two"});var job=ClassAnnotationQuery.startJob(sample,match,1,1,0)){
   check(!job.waitFor(1000).terminal,"bounded queue backpressures before cancel");job.cancel();var status=terminal(job);check(status.terminal&&status.executionStatus==9,"cancel terminal");drain(job);
  }
  var closed=NativeEngine.openRawDex(dex,"closed");closed.close();try{ClassAnnotationQuery.startJob(closed,match,1,1,0);throw new AssertionError("closed accepted");}catch(IllegalStateException expected){}catch(NativeEngine.NativeFailure expected){check(expected.status==7,"closed status");}
  try{ClassAnnotationQuery.startJob((NativeEngine.Snapshot)null,match,1,1,0);throw new AssertionError("null snapshot accepted");}catch(NullPointerException expected){}
  System.out.println("PASS v24 EntityJob provisional batches, terminal, unknown, source lifetime and cancellation");
 }
}
