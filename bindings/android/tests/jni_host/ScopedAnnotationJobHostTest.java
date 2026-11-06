package io.github.jichuo1.dexmeguviz;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
public final class ScopedAnnotationJobHostTest {
 static void check(boolean v,String m){if(!v)throw new AssertionError(m);}
 static byte[] q24(String slots,String name){return ("{\"schema_version\":1,\"relation\":\"class_defs\",\"required_capabilities\":[\"class_annotation_static\"],\"scope\":{\"slots\":"+slots+"},\"where\":{\"annotation\":{\"type\":\"Lfixture/Complex;\",\"element\":{\"name\":\""+name+"\",\"int\":-7}}}}").getBytes(StandardCharsets.UTF_8);}
 static byte[] q25(String slots,String name,String value){return ("{\"schema_version\":1,\"relation\":\"class_defs\",\"required_capabilities\":[\"class_annotation_static\",\"class_annotation_string_static\"],\"scope\":{\"slots\":"+slots+"},\"where\":{\"annotation\":{\"type\":\"Lstringfixture/Tag;\",\"element\":{\"name\":\""+name+"\",\"string\":\""+value+"\"}}}}").getBytes(StandardCharsets.UTF_8);}
 static void reject(int n,Runnable f){try{f.run();throw new AssertionError("expected rejection");}catch(NativeEngine.NativeFailure e){check(e.status==n,"status "+e.status);}}
 static ArrayList<NativeEngine.EntityCandidate> drain24(ScopedClassAnnotationQuery.Job job){var rows=new ArrayList<NativeEngine.EntityCandidate>();for(int i=0;i<100;i++){var p=job.next(1000);if(p.kind==1)continue;if(p.kind==2)return rows;check(p.kind==0&&p.batch.coverage==1&&p.batch.decision==0,"provisional v24");for(int j=0;j<p.batch.candidateCount();j++)rows.add(p.batch.candidate(j));}throw new AssertionError("drain timeout");}
 static ArrayList<NativeEngine.EntityCandidate> drain25(ScopedClassAnnotationStringQuery.Job job){var rows=new ArrayList<NativeEngine.EntityCandidate>();for(int i=0;i<100;i++){var p=job.next(1000);if(p.kind==1)continue;if(p.kind==2)return rows;check(p.kind==0&&p.batch.coverage==1&&p.batch.decision==0,"provisional v25");for(int j=0;j<p.batch.candidateCount();j++)rows.add(p.batch.candidate(j));}throw new AssertionError("drain timeout");}
 public static void main(String[] args)throws Exception{
  check(args.length==5,"fixtures");byte[] dex=Files.readAllBytes(Path.of(args[0])),a=Files.readAllBytes(Path.of(args[1])),b=Files.readAllBytes(Path.of(args[2])),multi=Files.readAllBytes(Path.of(args[3])),res=Files.readAllBytes(Path.of(args[4]));
  var set=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"one","two"});String sid=set.info().snapshotId;var job=ScopedClassAnnotationQuery.start(set,q24("[\"two\"]","n"),1,1,0);var saved=job.scope;set.close();
  try(job){var rows=drain24(job);var end=job.waitFor(10000);check(rows.size()==1&&rows.get(0).sourceIndex==1&&"two".equals(rows.get(0).sourceSlot),"selected occurrence");check(end.terminal&&end.executionStatus==0&&end.coverage==0&&end.candidateCount==1&&sid.equals(end.snapshotId)&&end.queryId.startsWith("query:v24:"),"verified terminal");}
  check(saved.inputSlotCount()==1&&"two".equals(saved.inputSlot(0))&&saved.sourceIndex(0)==1&&!saved.sourceScopeAuthenticated&&!saved.snapshotScopeComplete,"scope copied after close");
  try(var two=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"one","two"})){
   try(var empty=ScopedClassAnnotationQuery.start(two,q24("[]","n"),1,1,0)){check(drain24(empty).isEmpty(),"empty rows");var st=empty.waitFor(10000);check(st.terminal&&st.executionStatus==0&&st.coverage==0&&empty.scope.sourceCount()==0,"empty scope terminal");}
   try(var unknown=ScopedClassAnnotationQuery.start(two,q24("[\"one\"]","absent"),1,1,0)){check(drain24(unknown).isEmpty(),"unknown rows");var st=unknown.waitFor(10000);check(st.terminal&&st.executionStatus==0&&st.coverage==1&&st.unknownRows==1,"unknown terminal");}
   try(var cancel=ScopedClassAnnotationQuery.start(two,q24("[\"one\",\"two\"]","n"),1,1,0)){check(!cancel.waitFor(1000).terminal,"backpressure");cancel.cancel();var st=cancel.waitFor(10000);check(st.terminal&&st.executionStatus==9,"cancel reason preserved");drain24(cancel);}
   reject(3,()->ClassAnnotationQuery.startJob(two,q24("[\"one\"]","n"),1,1,0));reject(8,()->ScopedClassAnnotationQuery.start(two,q24("[\"missing\"]","n"),1,1,0));
  }
  try(var mixed=NativeEngine.openSources(new byte[][]{multi,res},new String[]{"apk","res"},new int[]{NativeEngine.SOURCE_APK,NativeEngine.SOURCE_APK},new boolean[]{false,true})){
   try(var m=ScopedClassAnnotationQuery.start(mixed,q24("[\"apk\"]","n"),1,2,0)){var rows=drain24(m);var st=m.waitFor(10000);check(rows.size()==2&&m.scope.sourceCount()==2&&rows.get(0).sourceIndex==0&&rows.get(1).sourceIndex==1&&st.terminal&&st.executionStatus==0,"multi DEX scope");}
   try(var resource=ScopedClassAnnotationQuery.start(mixed,q24("[\"res\"]","n"),1,1,0)){check(drain24(resource).isEmpty(),"resource-only rows");var st=resource.waitFor(10000);check(resource.scope.inputSlotCount()==1&&resource.scope.sourceCount()==0&&st.terminal&&st.executionStatus==0&&st.coverage==0,"resource-only terminal");}
  }
  try(var sources=NativeEngine.openRawDexSet(new byte[][]{a,b},new String[]{"one","two"})){
   try(var v25=ScopedClassAnnotationStringQuery.start(sources,q25("[\"two\"]","value","bbbb"),1,1,0)){var rows=drain25(v25);var st=v25.waitFor(10000);check(rows.size()==1&&rows.get(0).sourceIndex==1&&st.terminal&&st.executionStatus==0&&st.queryId.startsWith("query:v25:"),"source local string");}
   try(var missing=ScopedClassAnnotationStringQuery.start(sources,q25("[\"one\"]","absent","x"),1,1,0)){check(drain25(missing).isEmpty(),"v25 Unknown rows");var st=missing.waitFor(10000);check(st.terminal&&st.executionStatus==0&&st.unknownRows==6&&st.coverage==1,"v25 Unknown terminal");}
   reject(3,()->ClassAnnotationStringQuery.startJob(sources,q25("[\"one\"]","value","aaaa"),1,1,0));reject(3,()->ScopedClassAnnotationStringQuery.start(sources,q24("[\"one\"]","n"),1,1,0));
  }
  System.out.println("PASS scoped v24/v25 annotation EntityJob batch and terminal scopes");
 }
}
