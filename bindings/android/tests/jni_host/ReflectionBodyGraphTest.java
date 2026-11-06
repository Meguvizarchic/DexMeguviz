package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;

public final class ReflectionBodyGraphTest {
 static void check(boolean b,String m){if(!b)throw new AssertionError(m);}
 static byte[] bytes(String s){return s.getBytes(StandardCharsets.UTF_8);}
 static String scan="{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"all\":[{\"name\":\"uses\"},{\"flags\":{\"domain\":\"reflection\",\"value\":8}},{\"using_strings\":{\"all\":[\"used-string\"]}},{\"invokes\":{\"all\":[{\"name\":\"sink\"}]}},{\"field_access\":{\"all\":[{\"name\":\"counter\",\"access\":\"read\"}]}}]}}";
 static String query="{\"schema_version\":1,\"relation\":"+scan+",\"required_capabilities\":[\"reflection_flags_static\",\"reflection_relational\",\"reflection_body_relational\"]}";
 static void reject(Runnable f){try{f.run();throw new AssertionError("accepted unsupported");}catch(NativeEngine.NativeFailure e){check(e.status==3,"wrong status "+e.status);}}
 static void evidence(GraphResult.Row row){check(row.entity.relation==0&&row.entity.localIndex==2&&row.entity.referenceIndex==3&&"uses".equals(row.entity.name),"method identity");boolean s=false,i=false,f=false;for(int k=0;k<row.witnessCount();k++){var w=row.witness(k);if(w.kind==2){check(w.dexPc==0&&w.opcode==26&&w.referenceIndex==10,"string witness");s=true;}if(w.kind==3){check(w.dexPc==2&&w.opcode==113&&w.referenceIndex==4,"invoke witness");i=true;}if(w.kind==4){check(w.dexPc==5&&w.opcode==96&&w.referenceIndex==0,"field witness");f=true;}}check(s&&i&&f,"missing body witness");}
 public static void main(String[] args)throws Exception{
  check(args.length==2,"arguments");byte[] dex=Files.readAllBytes(Path.of(args[0])),unknown=Files.readAllBytes(Path.of(args[1]));GraphResult.Row retained;
  try(var snap=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"one","two"})){
   var actual=snap.queryGraph(bytes(query));check(actual.queryId.startsWith("query:v17:")&&(actual.requiredCapabilities&33554432)!=0&&actual.demandMask==7&&actual.coverage==1&&actual.rowCount()==2,"sync result");
   check(!actual.source(0).occurrenceId.equals(actual.source(1).occurrenceId),"source identity");for(int j=0;j<2;j++){check(actual.row(j).entity.sourceIndex==j,"source order");evidence(actual.row(j));}
   try(var job=snap.startGraphJob(bytes(query),1,1,0)){ArrayList<GraphResult.Row> rows=new ArrayList<>();for(int n=0;n<100;n++){var poll=job.next(1000);if(poll.kind==1)continue;if(poll.kind==2)break;check(poll.kind==0&&poll.batch!=null&&poll.batch.coverage==1&&poll.batch.decision==0,"provisional");check(poll.batch.queryId.equals(actual.queryId)&&poll.batch.snapshotId.equals(actual.snapshotId),"job identity");for(int i=0;i<poll.batch.rowCount();i++)rows.add(poll.batch.row(i));}
    var status=job.waitFor(10000);check(status.terminal&&status.executionStatus==0&&status.coverage==1&&status.candidateCount==2&&rows.size()==2,"job terminal");for(var row:rows)evidence(row);retained=rows.get(0);}
   reject(()->snap.queryEntities(bytes(query)));reject(()->snap.queryUseGraph(bytes(query)));
   reject(()->snap.queryGraph(bytes(query.replace(",\"reflection_body_relational\"",""))));
   reject(()->snap.queryGraph(bytes(query.replace("\"relation\":"+scan,"\"scope\":{\"slots\":[\"one\"]},\"relation\":"+scan))));
  }
  evidence(retained);
  try(var snap=NativeEngine.openRawDex(unknown,"unknown")){var result=snap.queryGraph(bytes(query));check(result.coverage==1&&result.rowCount()==0&&result.unknownRows==1,"unknown result");try(var job=snap.startGraphJob(bytes(query),1,1,0)){var poll=job.next(10000);check(poll.kind==2&&poll.batch==null,"unknown EOS");var status=job.waitFor(10000);check(status.terminal&&status.executionStatus==0&&status.coverage==1&&status.candidateCount==0&&status.unknownRows==1,"unknown terminal");}}
  System.out.println("PASS v17 host JNI graph sync/Job and witness copying");
 }
}
