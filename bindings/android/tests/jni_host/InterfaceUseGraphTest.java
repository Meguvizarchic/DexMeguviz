package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;

public final class InterfaceUseGraphTest {
 static void check(boolean ok,String message){if(!ok)throw new AssertionError(message);}
 static byte[] query(boolean resolved,boolean ambiguous){String scope=ambiguous?"\"scope\":{\"slots\":[\"child\",\"left\",\"alt\",\"top\",\"root\"]},":"\"scope\":{\"slots\":[\"child\",\"left\",\"top\",\"root\"]},";String domain=resolved?"inherited_interfaces_resolved":"inherited_interfaces";return ("{\"schema_version\":1,"+scope+"\"relation\":{\"op\":\"join\",\"on\":\"caller\",\"left\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"},\"right\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"all\":[{\"name\":\"uses\"},{\"declares_fields\":{\"scope\":\""+domain+"\",\"where\":{\"name\":\"diamond\"},\"min\":1,\"max\":1}}]}}},\"max_results\":100}").getBytes(StandardCharsets.UTF_8);}
 static void reject(Runnable action){try{action.run();throw new AssertionError("unsupported profile accepted");}catch(NativeEngine.NativeFailure e){check(e.status==3,"unsupported code "+e.status);}}
 static ArrayList<UseGraphResult> drain(NativeEngine.UseGraphJob job){var rows=new ArrayList<UseGraphResult>();for(int i=0;i<100;i++){var p=job.next(1000);if(p.kind==2)return rows;if(p.kind==1)continue;check(p.kind==0&&p.batch!=null&&p.batch.coverage==1&&p.batch.decision==0,"provisional");rows.add(p.batch);}throw new AssertionError("missing EOS");}
 static void compare(UseGraphResult.Row a,UseGraphResult.Row b){check(a.value.kind==1&&b.value.kind==1,"event kind");var x=a.value.use;var y=b.value.use;check(x.sourceIndex==y.sourceIndex&&x.callerOrdinal==y.callerOrdinal&&x.dexPc==y.dexPc&&x.targetIndex==y.targetIndex,"event identity");check(a.linkCount()==b.linkCount()&&a.witnessCount()==b.witnessCount()&&a.bindingCount()==b.bindingCount(),"evidence count");for(int i=0;i<a.witnessCount();i++){var u=a.witness(i);var v=b.witness(i);check(u.kind==v.kind&&u.nodeId==v.nodeId&&u.entity.sourceIndex==v.entity.sourceIndex&&u.entity.localIndex==v.entity.localIndex&&u.interfaceDetailPresent==v.interfaceDetailPresent,"witness identity");if(u.interfaceDetailPresent)check(u.interfaceResolved==v.interfaceResolved&&u.interfaceItem==v.interfaceItem&&u.interfaceBranch==v.interfaceBranch&&u.interfaceNode==v.interfaceNode&&u.interfaceAux==v.interfaceAux&&u.interfaceDetail==v.interfaceDetail,"interface evidence");}}
 public static void main(String[] args)throws Exception{
  byte[] child=Files.readAllBytes(Path.of(args[0])),left=Files.readAllBytes(Path.of(args[1])),alt=Files.readAllBytes(Path.of(args[2])),top=Files.readAllBytes(Path.of(args[3])),root=Files.readAllBytes(Path.of(args[4]));UseGraphResult saved=null;
  try(var s=NativeEngine.openRawDexSet(new byte[][]{child,left,alt,top,root},new String[]{"child","left","alt","top","root"})){
   for(boolean resolved:new boolean[]{false,true}){byte[] q=query(resolved,resolved);reject(()->s.queryUseGraph(q));reject(()->s.startUseGraphJob(q,1,1,0));reject(()->s.queryAdvanced(q));reject(()->s.queryInheritedUseGraph(q));
    var result=s.queryInterfaceUseGraph(q);check(result.queryId.startsWith(resolved?"query:v11:":"query:v8:")&&result.coverage==0&&result.rowCount()==1,"interface graph result");var row=result.row(0);int details=0,edges=0,fields=0,choices=0;for(int i=0;i<row.witnessCount();i++){var w=row.witness(i);if(w.interfaceDetailPresent){check(w.interfaceResolved==resolved,"version tag");details++;if(w.interfaceItem==2)edges++;if(w.interfaceItem==4)fields++;if(w.interfaceItem==6)choices++;
      System.out.println("DETAIL "+(resolved?"v11":"v8")+" "+w.nodeId+" "+w.matched+" "+w.operatorNode+" "+w.entity.sourceIndex+" "+w.entity.relation+" "+w.entity.localIndex+" "+w.interfaceItem+" "+w.interfaceBranch+" "+w.interfaceNode+" "+w.interfaceAux+" "+w.interfaceDetail);}}check(details>0&&edges>0&&fields>0&&(!resolved||choices>0),"full interface witness");
    try(var job=s.startInterfaceUseGraphJob(q,1,4,0)){var batches=drain(job);check(batches.size()==1&&batches.get(0).rowCount()==1,"job row");compare(row,batches.get(0).row(0));var end=job.waitFor(10000);check(end.terminal&&end.executionStatus==0&&end.coverage==result.coverage&&end.candidateCount==1,"job terminal");}
    System.out.println((resolved?"v11":"v8")+" details="+details+" edges="+edges+" fields="+fields+" choices="+choices);saved=result;
   }
  }
  check(saved!=null&&saved.row(0).witnessCount()>0,"result after close");System.out.println("PASS v8/v11 interface use graph sync/job");
 }
}
