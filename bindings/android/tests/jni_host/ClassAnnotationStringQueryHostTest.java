package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
public final class ClassAnnotationStringQueryHostTest {
 static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
 static byte[] json(String name,String value,String extra){return ("{\"schema_version\":1,\"relation\":\"class_defs\",\"required_capabilities\":[\"class_annotation_static\",\"class_annotation_string_static\"],\"where\":{\"annotation\":{\"type\":\"Lstringfixture/Tag;\",\"element\":{\"name\":\""+name+"\",\"string\":\""+value+"\"}}}"+extra+"}").getBytes(StandardCharsets.UTF_8);}
 static void reject(int status,Runnable f){try{f.run();throw new AssertionError("expected status "+status);}catch(NativeEngine.NativeFailure e){check(e.status==status,"status "+e.status);}}
 static NativeEngine.EntityJobStatus terminal(NativeEngine.EntityJob job){for(int i=0;i<20;i++){var s=job.waitFor(1000);if(s.terminal)return s;}throw new AssertionError("terminal timeout");}
 static ArrayList<NativeEngine.EntityCandidate> drain(NativeEngine.EntityJob job){var rows=new ArrayList<NativeEngine.EntityCandidate>();for(int i=0;i<100;i++){var p=job.next(1000);if(p.kind==1){check(p.batch==null,"timeout batch");continue;}if(p.kind==2){check(p.batch==null,"EOS batch");return rows;}check(p.kind==0&&p.batch!=null&&p.batch.coverage==1&&p.batch.decision==0&&p.batch.queryId.startsWith("query:v25:"),"provisional batch");for(int j=0;j<p.batch.candidateCount();j++)rows.add(p.batch.candidate(j));}throw new AssertionError("drain timeout");}
 static void result(NativeEngine.EntityResult r,int count,long unknown){check(r.executionStatus==0&&r.relation==1&&r.queryId.startsWith("query:v25:")&&r.coverage==1&&r.candidateCount()==count&&r.unknownRows==unknown,"v25 result");if(unknown>0)check(r.reason==6,"unknown reason");}
 public static void main(String[] args)throws Exception{
  check(args.length==3,"expected a.dex, b.dex and resource apk");byte[] a=Files.readAllBytes(Path.of(args[0])),b=Files.readAllBytes(Path.of(args[1])),resource=Files.readAllBytes(Path.of(args[2]));
  byte[] qa=json("value","aaaa",""),qb=json("value","bbbb",""),missing=json("absent","x","");
  byte[] v24="{\"schema_version\":1,\"relation\":\"class_defs\",\"required_capabilities\":[\"class_annotation_static\"],\"where\":{\"annotation\":{\"type\":\"Lstringfixture/Tag;\"}}}".getBytes(StandardCharsets.UTF_8);
  String not=new String(missing,StandardCharsets.UTF_8).replace("\"where\":{\"annotation\":", "\"where\":{\"not\":{\"annotation\":");not=not.substring(0,not.length()-1)+"}}";byte[] negated=not.getBytes(StandardCharsets.UTF_8);
  var set=NativeEngine.openRawDexSet(new byte[][]{a,b},new String[]{"one","two"});NativeEngine.EntityResult kept;
  try{
   kept=ClassAnnotationStringQuery.execute(set,qa);result(kept,1,0);check(kept.candidate(0).sourceIndex==0&&"one".equals(kept.candidate(0).sourceSlot)&&"Lstringfixture/Collision;".equals(kept.candidate(0).typeDescriptor),"source one string");
   var rb=ClassAnnotationStringQuery.execute(set,qb);result(rb,1,0);check(rb.candidate(0).sourceIndex==1&&"two".equals(rb.candidate(0).sourceSlot),"same local index, different text");
   result(ClassAnnotationStringQuery.execute(set,json("value","", "")),2,0);
   result(ClassAnnotationStringQuery.execute(set,missing),0,12);result(ClassAnnotationStringQuery.execute(set,negated),4,12);
   var scoped=ScopedClassAnnotationStringQuery.execute(set,json("value","bbbb",",\"scope\":{\"slots\":[\"two\"]}"));
   check(scoped.query.coverage==0&&scoped.query.candidateCount()==1&&scoped.query.candidate(0).sourceIndex==1&&scoped.scope.sourceCount()==1&&scoped.scope.sourceIndex(0)==1&&"two".equals(scoped.scope.inputSlot(0))&&!scoped.scope.sourceScopeAuthenticated&&!scoped.scope.snapshotScopeComplete,"scoped source");
   var two=ScopedClassAnnotationStringQuery.execute(set,json("value","\\u96ea",",\"scope\":{\"slots\":[\"two\",\"one\"]}"));
   check(two.query.candidateCount()==2&&two.scope.sourceCount()==2&&"one".equals(two.scope.inputSlot(0))&&"two".equals(two.scope.inputSlot(1))&&!two.query.candidate(0).occurrenceId.equals(two.query.candidate(1).occurrenceId),"two occurrence scope");
   var unknown=ScopedClassAnnotationStringQuery.execute(set,json("absent","x",",\"scope\":{\"slots\":[\"one\"]}"));check(unknown.query.unknownRows==6&&unknown.query.candidateCount()==0&&unknown.query.coverage==1,"scoped Unknown");
   reject(3,()->ClassAnnotationQuery.execute(set,qa));reject(3,()->ClassAnnotationQuery.startJob(set,qa,1,1,0));
   reject(3,()->ScopedClassAnnotationQuery.execute(set,json("value","aaaa",",\"scope\":{\"slots\":[\"one\"]}")));
   reject(3,()->ClassAnnotationStringQuery.execute(set,v24));reject(3,()->ClassAnnotationStringQuery.startJob(set,v24,1,1,0));reject(3,()->ScopedClassAnnotationStringQuery.execute(set,v24));
   byte[] v24Scoped=new String(v24,StandardCharsets.UTF_8).replace("\"where\":","\"scope\":{\"slots\":[\"one\"]},\"where\":").getBytes(StandardCharsets.UTF_8);reject(3,()->ScopedClassAnnotationStringQuery.execute(set,v24Scoped));
   reject(3,()->ClassAnnotationStringQuery.execute(set,json("value","aaaa",",\"scope\":{\"slots\":[\"one\"]}")));reject(3,()->ScopedClassAnnotationStringQuery.execute(set,qa));
   reject(8,()->ScopedClassAnnotationStringQuery.execute(set,json("value","aaaa",",\"scope\":{\"slots\":[\"missing\"]}")));
   reject(1,()->ScopedClassAnnotationStringQuery.execute(set,json("value","aaaa",",\"scope\":{\"slots\":[\"one\",\"one\"]}")));
   byte[] snow=json("value","\\u96ea","");try(var job=ClassAnnotationStringQuery.startJob(set,snow,1,1,0)){
    check(!job.waitFor(1000).terminal,"backpressure");job.cancel();var end=terminal(job);check(end.terminal&&end.executionStatus==9,"cancel status");drain(job);
   }
   try(var job=ClassAnnotationStringQuery.startJob(set,missing,1,1,0)){check(drain(job).isEmpty(),"unknown batches");var end=terminal(job);check(end.executionStatus==0&&end.unknownRows==12&&end.coverage==1&&end.reason==6&&end.queryId.startsWith("query:v25:"),"unknown terminal");}
  }finally{set.close();}
  var archive=new java.io.ByteArrayOutputStream();try(var zip=new java.util.zip.ZipOutputStream(archive)){for(String name:new String[]{"classes.dex","classes2.dex"}){zip.putNextEntry(new java.util.zip.ZipEntry(name));zip.write(a);zip.closeEntry();}}
  try(var mixed=NativeEngine.openSources(new byte[][]{archive.toByteArray(),resource},new String[]{"apk","res"},new int[]{NativeEngine.SOURCE_APK,NativeEngine.SOURCE_APK},new boolean[]{false,true})){
   var multi=ScopedClassAnnotationStringQuery.execute(mixed,json("value","aaaa",",\"scope\":{\"slots\":[\"apk\"]}"));
   check(multi.scope.sourceCount()==2&&multi.query.candidateCount()==2&&multi.query.candidate(0).sourceIndex==0&&multi.query.candidate(1).sourceIndex==1&&!multi.query.candidate(0).occurrenceId.equals(multi.query.candidate(1).occurrenceId),"multi DEX slot occurrence expansion");
   var empty=ScopedClassAnnotationStringQuery.execute(mixed,json("value","aaaa",",\"scope\":{\"slots\":[\"res\"]}"));
   check(empty.scope.inputSlotCount()==1&&empty.scope.sourceCount()==0&&empty.query.candidateCount()==0&&empty.query.coverage==0,"resource only slot");
  }
  var lifetimeSet=NativeEngine.openRawDexSet(new byte[][]{a,b},new String[]{"one","two"});String snapshotId=lifetimeSet.info().snapshotId;
  var live=ClassAnnotationStringQuery.startJob(lifetimeSet,json("value","\\u96ea",""),1,2,0);lifetimeSet.close();
  try(live){var rows=drain(live);var end=terminal(live);check(rows.size()==2&&rows.get(0).sourceIndex==0&&rows.get(1).sourceIndex==1&&!rows.get(0).occurrenceId.equals(rows.get(1).occurrenceId),"async rows preserve source occurrences after snapshot close");
   check(end.terminal&&end.executionStatus==0&&end.candidateCount==2&&end.queryId.startsWith("query:v25:")&&snapshotId.equals(end.snapshotId),"async final identity");}
  check("Lstringfixture/Collision;".equals(kept.candidate(0).typeDescriptor),"copied after close");
  System.out.println("PASS v25 string JNI, scoped occurrences, Unknown and EntityJob cancellation");
 }
}
