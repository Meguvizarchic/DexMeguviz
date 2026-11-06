package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
public final class ScopedClassAnnotationQueryHostTest {
 static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
 static byte[] query(String slots,String where,String intent){return ("{\"schema_version\":1,\"relation\":\"class_defs\",\"required_capabilities\":[\"class_annotation_static\"],\"scope\":{\"slots\":"+slots+"},\"intent\":\""+intent+"\",\"where\":"+where+"}").getBytes(StandardCharsets.UTF_8);}
 static String where(String name,int n){return "{\"annotation\":{\"type\":\"Lfixture/Complex;\",\"visibility\":1,\"element\":{\"name\":\""+name+"\",\"int\":"+n+"}}}";}
 static void rejected(int status,Runnable f){try{f.run();throw new AssertionError("expected status "+status);}catch(NativeEngine.NativeFailure e){check(e.status==status,"status "+e.status);}}
 static void nul(Runnable f){try{f.run();throw new AssertionError("expected null error");}catch(NullPointerException expected){}}
 public static void main(String[] args)throws Exception{
  check(args.length==3,"fixtures");byte[] dex=Files.readAllBytes(Path.of(args[0]));byte[] multi=Files.readAllBytes(Path.of(args[1])),resource=Files.readAllBytes(Path.of(args[2]));
  NativeEngine.SourceSetSnapshot set=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"one","two"});
  byte[] both=query("[\"two\",\"one\"]",where("n",-7),"enumerate");
  byte[] one=query("[\"two\"]",where("n",-7),"enumerate");
  byte[] noScope="{\"schema_version\":1,\"relation\":\"class_defs\",\"required_capabilities\":[\"class_annotation_static\"],\"where\":{\"annotation\":{\"type\":\"Lfixture/Complex;\"}}}".getBytes(StandardCharsets.UTF_8);
  ScopedClassAnnotationQuery.Result retained;
  try{
   retained=ScopedClassAnnotationQuery.execute(set,both);var r=retained.query;
   check(r.queryId.startsWith("query:v24:")&&r.executionStatus==0&&r.coverage==0&&r.candidateCount()==2&&r.unknownRows==0,"both source result");
   check(retained.scope.inputSlotCount()==2&&retained.scope.inputSlot(0).equals("one")&&retained.scope.inputSlot(1).equals("two"),"canonical slots");
   check(retained.scope.sourceCount()==2&&retained.scope.sourceIndex(0)==0&&retained.scope.sourceIndex(1)==1&&!retained.scope.snapshotScopeComplete&&!retained.scope.sourceScopeAuthenticated,"declared source scope");
   check(r.candidate(0).sourceIndex==0&&r.candidate(1).sourceIndex==1&&r.candidate(0).sourceSlot.equals("one")&&r.candidate(1).sourceSlot.equals("two")&&!r.candidate(0).occurrenceId.equals(r.candidate(1).occurrenceId),"distinct occurrence identities");
   var selected=ScopedClassAnnotationQuery.execute(set,one);check(selected.query.candidateCount()==1&&selected.query.candidate(0).sourceIndex==1&&selected.query.candidate(0).sourceSlot.equals("two")&&selected.scope.sourceCount()==1&&selected.scope.sourceIndex(0)==1,"single selected source");
   var unknown=ScopedClassAnnotationQuery.execute(set,query("[\"one\"]",where("absent",0),"enumerate"));check(unknown.query.candidateCount()==0&&unknown.query.unknownRows==1&&unknown.query.coverage==1&&unknown.query.reason==6,"Unknown retained");
   var negated=ScopedClassAnnotationQuery.execute(set,query("[\"one\"]","{\"not\":"+where("absent",0)+"}","enumerate"));check(negated.query.candidateCount()==3&&negated.query.unknownRows==1&&negated.query.coverage==1,"NOT keeps Unknown");for(int i=0;i<negated.query.candidateCount();i++)check(negated.query.candidate(i).localIndex!=0,"NOT excluded Unknown class");
   var empty=ScopedClassAnnotationQuery.execute(set,query("[]",where("n",-7),"exists"));check(empty.query.candidateCount()==0&&empty.query.unknownRows==0&&empty.query.coverage==0&&empty.query.decision==2&&empty.scope.inputSlotCount()==0&&empty.scope.sourceCount()==0,"empty declared scope");
   rejected(8,()->ScopedClassAnnotationQuery.execute(set,query("[\"missing\"]",where("n",-7),"exists")));
   rejected(1,()->ScopedClassAnnotationQuery.execute(set,query("[\"one\",\"one\"]",where("n",-7),"exists")));
   rejected(3,()->ClassAnnotationQuery.execute(set,both));rejected(3,()->ScopedClassAnnotationQuery.execute(set,noScope));
   nul(()->ScopedClassAnnotationQuery.execute(set,null));
  }finally{set.close();}
  check(retained.scope.sourceIndex(1)==1&&"Lfixture/Annotated;".equals(retained.query.candidate(0).typeDescriptor),"copied after close");rejected(7,()->ScopedClassAnnotationQuery.execute(set,both));
  nul(()->ScopedClassAnnotationQuery.execute((NativeEngine.Snapshot)null,both));nul(()->ScopedClassAnnotationQuery.execute((NativeEngine.SourceSetSnapshot)null,both));
  try(NativeEngine.Snapshot single=NativeEngine.openRawDex(dex,"single")){var r=ScopedClassAnnotationQuery.execute(single,query("[\"single\"]",where("n",-7),"unique"));check(r.query.candidateCount()==1&&r.query.coverage==0&&r.query.decision==3&&r.scope.sourceIndex(0)==0,"single snapshot subset");}
  try(NativeEngine.SourceSetSnapshot mixed=NativeEngine.openSources(new byte[][]{multi,resource},new String[]{"base","res"},new int[]{NativeEngine.SOURCE_APK,NativeEngine.SOURCE_APK},new boolean[]{false,true})){
   var all=ScopedClassAnnotationQuery.execute(mixed,query("[\"base\"]",where("n",-7),"enumerate"));
   check(all.scope.inputSlotCount()==1&&all.scope.sourceCount()==2&&all.scope.sourceIndex(0)==0&&all.scope.sourceIndex(1)==1,"multi DEX slot expands in order");
   check(all.query.candidateCount()==2&&all.query.candidate(0).sourceIndex==0&&all.query.candidate(1).sourceIndex==1&&!all.query.candidate(0).occurrenceId.equals(all.query.candidate(1).occurrenceId),"multi DEX rows remain distinct");
   var onlyResources=ScopedClassAnnotationQuery.execute(mixed,query("[\"res\"]",where("n",-7),"exists"));
   check(onlyResources.scope.inputSlotCount()==1&&onlyResources.scope.sourceCount()==0&&onlyResources.query.candidateCount()==0&&onlyResources.query.coverage==0&&onlyResources.query.decision==2,"resource-only static scope");
  }
  System.out.println("PASS scoped v24 class annotation inputs, Unknown, rejection and copied lifetime");
 }
}
