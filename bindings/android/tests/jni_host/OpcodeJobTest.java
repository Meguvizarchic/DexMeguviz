package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
public final class OpcodeJobTest {
 static void check(boolean b,String m){if(!b)throw new AssertionError(m);}
 static void unsupported(Runnable f){try{f.run();throw new AssertionError("expected unsupported");}catch(NativeEngine.NativeFailure e){check(e.status==3,"status "+e.status);}}
 static NativeEngine.JobStatus terminal(NativeEngine.Job j){for(int i=0;i<20;i++){var s=j.waitFor(1000);if(s.terminal)return s;}throw new AssertionError("terminal timeout");}
 static ArrayList<NativeEngine.MethodCandidate> drain(NativeEngine.Job j){var rows=new ArrayList<NativeEngine.MethodCandidate>();for(int i=0;i<100;i++){var x=j.next(1000);if(x.kind==1)continue;if(x.kind==2)return rows;check(x.kind==0&&x.batch!=null&&x.batch.coverage==1&&x.batch.decision==0,"provisional");for(int k=0;k<x.batch.candidateCount();k++)rows.add(x.batch.candidate(k));}throw new AssertionError("drain timeout");}
 public static void main(String[] a)throws Exception{
  byte[] dex=Files.readAllBytes(Path.of(a[0]));
  byte[] q=("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\",\"opcodes\":{\"mode\":\"contains\",\"values\":[26,-1,96],\"negative_wildcards\":true}},\"required_capabilities\":[\"opcode_sequence\"]}").getBytes(StandardCharsets.UTF_8);
  byte[] v1="{\"schema_version\":1,\"relation\":\"method_defs\"}".getBytes(StandardCharsets.UTF_8);
  byte[] scoped=new String(q,StandardCharsets.UTF_8).replace("\"required_capabilities\"","\"scope\":{\"slots\":[\"a\"]},\"required_capabilities\"").getBytes(StandardCharsets.UTF_8);
  try(var s=NativeEngine.openRawDex(dex,"a")){
   var sync=OpcodeQuery.execute(s,q);check(sync.candidateCount()==1,"sync baseline");
   unsupported(()->s.startMethodJob(q,1,1,0));unsupported(()->s.startOpcodeJob(v1,1,1,0));unsupported(()->s.startOpcodeJob(scoped,1,1,0));
   try(var job=OpcodeQuery.startJob(s,q,1,1,0)){var rows=drain(job);var end=terminal(job);check(rows.size()==1&&rows.get(0).name.equals(sync.candidate(0).name),"async equals sync");check(end.executionStatus==0&&end.queryId.equals(sync.queryId)&&end.candidateCount==1,"terminal identity");}
   try{s.startOpcodeJob(q,0,1,0);throw new AssertionError("invalid limits accepted");}catch(IllegalArgumentException expected){}
  }
  byte[][] many=new byte[8][];String[] slots=new String[8];for(int i=0;i<8;i++){many[i]=dex;slots[i]="s"+i;}
  try(var s=NativeEngine.openRawDexSet(many,slots);var job=OpcodeQuery.startJob(s,q,1,1,0)){
   var first=job.next(10000);check(first.kind==0&&first.batch.candidateCount()==1,"first batch");job.cancel();var end=terminal(job);check(end.executionStatus==9,"cancel status "+end.executionStatus);drain(job);
  }
  var set=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"a","b"});var job=set.startOpcodeJob(q,1,1,0);set.close();
  try(job){var rows=drain(job);check(rows.size()==2&&rows.get(0).sourceIndex!=rows.get(1).sourceIndex,"sources survive close");check(terminal(job).executionStatus==0,"source set terminal");}
  System.out.println("PASS v23 Job batches, sync equivalence, rejection, cancellation and source lifetime");
 }
}
