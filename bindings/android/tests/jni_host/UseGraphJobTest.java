package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;

public final class UseGraphJobTest {
 static void ok(boolean v,String m){if(!v)throw new AssertionError(m);}
 static byte[] q(String s){return s.getBytes(StandardCharsets.UTF_8);}
 static String query(String intent,boolean v9,String extra){return "{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"},\"intent\":\""+intent+"\",\"max_results\":100"+(v9?",\"required_capabilities\":[\"use_streaming\"]":"")+extra+"}";}
 static void unsupported(Runnable action){try{action.run();throw new AssertionError("must reject");}catch(NativeEngine.NativeFailure e){ok(e.status==3,"unsupported status "+e.status);}}
 static ArrayList<UseGraphResult> drain(NativeEngine.UseGraphJob job){var rows=new ArrayList<UseGraphResult>();for(int i=0;i<100;i++){var p=job.next(1000);if(p.kind==2)return rows;if(p.kind==1)continue;ok(p.kind==0&&p.batch!=null&&p.batch.coverage==1&&p.batch.decision==0,"provisional");rows.add(p.batch);}throw new AssertionError("missing EOS");}
 static void compare(UseGraphResult a,UseGraphResult b,int index){var x=a.row(index).value.use;var y=b.row(0).value.use;ok(x.relation==y.relation&&x.sourceIndex==y.sourceIndex&&x.callerOrdinal==y.callerOrdinal&&x.callerMethodRef==y.callerMethodRef&&x.dexPc==y.dexPc&&x.opcode==y.opcode&&x.targetDomain==y.targetDomain&&x.targetIndex==y.targetIndex&&x.extraProto==y.extraProto,"event mismatch");}
 public static void main(String[] args)throws Exception{
  byte[] dex=Files.readAllBytes(Path.of(args[0]));var s=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"a","b"});UseGraphResult held=null;
  for(boolean v9:new boolean[]{false,true})for(String intent:new String[]{"enumerate","exists","unique"}){
   byte[] query=q(query(intent,v9,""));UseGraphResult synchronous=s.queryUseGraph(query);try(var job=s.startUseGraphJob(query,1,16,0)){
    var rows=drain(job);var st=job.waitFor(10000);ok(st.terminal&&st.executionStatus==0&&st.coverage==1,"terminal");ok(st.queryId.equals(synchronous.queryId)&&st.snapshotId.equals(synchronous.snapshotId),"identity");ok(st.candidateCount==rows.size()&&rows.size()==synchronous.rowCount(),"count");
    for(int i=0;i<rows.size();i++){ok(rows.get(i).rowCount()==1,"batch size");compare(synchronous,rows.get(i),i);ok(rows.get(i).sourceCount()==2&&!rows.get(i).source(0).occurrenceId.equals(rows.get(i).source(1).occurrenceId),"occurrence");}
    if(intent.equals("enumerate")){ok(rows.size()==4,"bag size");ok(st.entityVisited==synchronous.entityVisited&&st.entityTotal==synchronous.entityTotal&&st.methodVisited==synchronous.methodVisited&&st.methodTotal==synchronous.methodTotal&&st.eventsCollected==synchronous.eventsCollected&&st.unknownRows==synchronous.unknownRows,"v2 terminal counters");held=rows.get(3);}
   }
  }
  var queued=s.startUseGraphJob(q(query("enumerate",false,"")),1,1,0);boolean full=false;for(int i=0;i<200;i++){var st=queued.status();if(st.candidateCount==1&&!st.terminal){full=true;break;}Thread.sleep(5);}ok(full,"queue full");ok(!queued.waitFor(0).terminal,"timeout did not cancel");queued.cancel();var partial=drain(queued);var end=queued.waitFor(10000);ok(end.terminal&&end.executionStatus==9&&!partial.isEmpty(),"cancel outcome");queued.close();
  try(var limited=s.startUseGraphJob(q(query("enumerate",false,"").replace("\"max_results\":100","\"max_results\":1")),1,4,0)){ok(drain(limited).size()==1,"limit rows");var st=limited.waitFor(10000);ok(st.terminal&&st.executionStatus==4&&st.reason==4,"limit status");}
  try(var budget=s.startUseGraphJob(q(query("enumerate",false,",\"max_work\":1")),1,2,0)){ok(drain(budget).isEmpty(),"budget batch");var st=budget.waitFor(10000);ok(st.terminal&&st.executionStatus==4&&st.reason!=4,"budget status");}
  unsupported(()->s.startUseGraphJob(q(query("exists",false,"").replace("\"schema_version\":1,","\"schema_version\":1,\"scope\":{\"slots\":[\"a\"]},")),1,1,0));
  unsupported(()->s.startUseGraphJob(q("{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"invoke_sites\",\"scope\":{\"slots\":[\"a\"]}}}"),1,1,0));
  String v16="{\"schema_version\":1,\"required_capabilities\":[\"use_target_symbol\"],\"relation\":{\"op\":\"join\",\"on\":\"target_symbol\",\"left\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"},\"right\":{\"op\":\"scan\",\"relation\":\"method_defs\"}},\"max_results\":100}";
  String v18="{\"schema_version\":1,\"required_capabilities\":[\"inherited_fields\",\"use_target_symbol\",\"inherited_target_symbol\"],\"relation\":{\"op\":\"join\",\"on\":\"target_symbol\",\"left\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"},\"right\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"all\":[{\"name\":\"uses\"},{\"declares_fields\":{\"scope\":\"inherited\",\"where\":{\"name\":\"unseen\"},\"min\":0,\"max\":0}}]}}},\"max_results\":100}";
  ok(s.queryUseGraph(q(v16)).queryId.startsWith("query:v16:"),"valid v16 query");ok(s.queryUseGraph(q(v18)).queryId.startsWith("query:v18:"),"valid v18 query");
  unsupported(()->s.startUseGraphJob(q(v16),1,1,0));unsupported(()->s.startUseGraphJob(q(v18),1,1,0));
  unsupported(()->s.startGraphJob(q(query("enumerate",false,"")),1,1,0));
  byte[] unusual=Files.readAllBytes(Path.of(args[1]));try(var single=NativeEngine.openRawDex(unusual,"domains")){
   for(boolean v9:new boolean[]{false,true})try(var job=single.startUseGraphJob(q(query("enumerate",v9,"")),1,4,0)){
    var rows=drain(job);ok(rows.size()==2,"special events");var x=rows.get(0).row(0).value.use;var y=rows.get(1).row(0).value.use;
    ok(x.dexPc==0&&x.opcode==0xfa&&x.targetDomain==3&&x.extraProto==0&&y.dexPc==4&&y.opcode==0xfc&&y.targetDomain==4&&y.extraProto==0xffffffffL,"poly and custom");ok(job.waitFor(10000).terminal,"domain terminal");
   }
  }
  byte[] malformed=Files.readAllBytes(Path.of(args[2]));try(var bad=NativeEngine.openRawDex(malformed,"bad")){
   for(boolean v9:new boolean[]{false,true})try(var job=bad.startUseGraphJob(q(query("unique",v9,"")),1,4,0)){ok(drain(job).isEmpty(),"incomplete method not published");var st=job.waitFor(10000);ok(st.terminal&&st.executionStatus==2,"corrupt status");}
  }
  String semi="{\"schema_version\":1,\"relation\":{\"op\":\"semi_join\",\"on\":\"caller\",\"left\":{\"op\":\"scan\",\"relation\":\"method_defs\"},\"right\":{\"op\":\"scan\",\"relation\":\"invoke_sites\",\"where\":{\"pc\":3}}}}";
  try(var job=s.startUseGraphJob(q(semi),1,16,0)){var rows=drain(job);ok(rows.size()==2,"semi rows");for(var row:rows){ok(row.row(0).proofBindingCount()==1&&row.row(0).proofBinding(0).value.use.dexPc==3&&row.row(0).linkCount()==1,"proof link");}ok(job.waitFor(10000).terminal,"semi terminal");}
  try(var job=s.startUseGraphJob(q(semi.replace("\"pc\":3","\"pc\":999")),1,16,0)){ok(drain(job).isEmpty(),"unknown rows");ok(job.waitFor(10000).unknownRows>0,"unknown retained");}
  var inFlight=s.startUseGraphJob(q(query("enumerate",false,"")),2,4,0);s.close();ok(drain(inFlight).size()==2&&inFlight.waitFor(10000).terminal,"snapshot close");inFlight.close();ok(held.row(0).value.use.sourceIndex==1,"retained batch");
  try{inFlight.status();throw new AssertionError("closed accepted");}catch(IllegalStateException expected){}
  System.out.println("PASS v4/v9 provisional use jobs, status, identity, duplicates, backpressure, cancel, limits, admission and lifetimes");
 }
}
