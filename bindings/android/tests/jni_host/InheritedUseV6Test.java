package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;

public final class InheritedUseV6Test {
 static void check(boolean ok,String message){if(!ok)throw new AssertionError(message);}
 static byte[] query(String scope){return ("{\"schema_version\":1,\"required_capabilities\":[\"inherited_fields\"],"+scope+"\"relation\":{\"op\":\"join\",\"on\":\"caller\",\"left\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"},\"right\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"all\":[{\"name\":\"uses\"},{\"declares_fields\":{\"scope\":\"inherited\",\"where\":{\"name\":\"unseen\"},\"min\":0,\"max\":0}}]}}},\"max_results\":100}").getBytes(StandardCharsets.UTF_8);}
 static void same(UseGraphResult.Row a,UseGraphResult.Row b){
  check(a.value.kind==1&&b.value.kind==1,"use value");var x=a.value.use;var y=b.value.use;
  check(x.relation==y.relation&&x.sourceIndex==y.sourceIndex&&x.callerOrdinal==y.callerOrdinal&&x.callerMethodRef==y.callerMethodRef&&x.dexPc==y.dexPc&&x.opcode==y.opcode&&x.targetDomain==y.targetDomain&&x.targetIndex==y.targetIndex&&x.extraProto==y.extraProto,"batch event identity");
  check(a.linkCount()==b.linkCount()&&a.bindingCount()==b.bindingCount()&&a.proofBindingCount()==b.proofBindingCount()&&a.witnessCount()==b.witnessCount(),"batch evidence counts");
  for(int i=0;i<a.witnessCount();i++){var u=a.witness(i);var v=b.witness(i);check(u.kind==v.kind&&u.nodeId==v.nodeId&&u.matched==v.matched&&u.entity.sourceIndex==v.entity.sourceIndex&&u.entity.localIndex==v.entity.localIndex&&u.inheritedDetailPresent==v.inheritedDetailPresent,"witness identity");if(u.inheritedDetailPresent)check(u.inheritedItem==v.inheritedItem&&u.inheritedPath==v.inheritedPath&&u.inheritedAux==v.inheritedAux&&u.inheritedBranch==v.inheritedBranch&&u.inheritedDetail==v.inheritedDetail,"inherited witness data");}
 }
 static void rejected(Runnable action){try{action.run();throw new AssertionError("legacy profile accepted");}catch(NativeEngine.NativeFailure e){check(e.status==3,"expected unsupported");}}
 static ArrayList<UseGraphResult> drain(NativeEngine.UseGraphJob job){var out=new ArrayList<UseGraphResult>();for(int i=0;i<100;i++){var p=job.next(1000);if(p.kind==2)return out;if(p.kind==1)continue;check(p.kind==0&&p.batch!=null&&p.batch.coverage==1&&p.batch.decision==0,"provisional batch");out.add(p.batch);}throw new AssertionError("missing EOS");}
 public static void main(String[] args)throws Exception{
  byte[] child=Files.readAllBytes(Path.of(args[0])),root=Files.readAllBytes(Path.of(args[1]));String scope="\"scope\":{\"slots\":[\"a\",\"b\",\"root\"]},";byte[] q=query(scope);UseGraphResult held;
  try(var s=NativeEngine.openRawDexSet(new byte[][]{child,child,root},new String[]{"a","b","root"})){
   rejected(()->s.queryUseGraph(q));rejected(()->s.startUseGraphJob(q,1,1,0));rejected(()->s.queryAdvanced(q));
   held=s.queryInheritedUseGraph(q);check(held.queryId.startsWith("query:v6:")&&held.coverage==0&&held.profile.scopeComplete&&held.rowCount()>0,"completed v6 graph");
   int witness=0;for(int i=0;i<held.rowCount();i++){var row=held.row(i);check(row.value.kind==1&&row.linkCount()>0,"use and caller link");for(int j=0;j<row.witnessCount();j++){var w=row.witness(j);if(w.kind==8){check(w.inheritedDetailPresent,"inherited fields missing");witness++;}}}check(witness>0,"no inherited witness");
   try(var job=s.startInheritedUseGraphJob(q,1,4,0)){var batches=drain(job);int n=0;for(var b:batches){check(b.queryId.equals(held.queryId),"query id");for(int j=0;j<b.rowCount();j++)same(held.row(n++),b.row(j));}var end=job.waitFor(10000);check(end.terminal&&end.executionStatus==0&&end.candidateCount==held.rowCount()&&end.coverage==held.coverage&&end.unknownRows==held.unknownRows&&n==held.rowCount(),"job terminal");}
   var partial=s.queryInheritedUseGraph(query(""));check(partial.coverage==1&&partial.rowCount()==0&&partial.unknownRows>0,"incomplete scope");
   System.out.println("v6 rows="+held.rowCount()+" inheritedWitnesses="+witness+" partialUnknown="+partial.unknownRows);
  }
  check(held.row(0).witnessCount()>0,"copied result after close");
  try(var s=NativeEngine.openRawDex(child,"a")){var partial=s.queryInheritedUseGraph(query(""));check(partial.coverage==1&&partial.rowCount()==0&&partial.unknownRows>0,"single snapshot");try(var job=s.startInheritedUseGraphJob(query(""),1,4,0)){check(drain(job).isEmpty(),"single no batch");var end=job.waitFor(10000);check(end.terminal&&end.executionStatus==0&&end.coverage==1&&end.unknownRows>0,"single job status");}}
  System.out.println("PASS v6 inherited use graph sync/job, scope and old entrance rejection");
 }
}
