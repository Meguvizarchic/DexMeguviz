package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
public final class UnifiedSnapshotHostTest {
 static void check(boolean ok,String message){if(!ok)throw new AssertionError(message);}
 public static void main(String[] args)throws Exception{
  check(args.length==1,"APK fixture required");long m=1024L*1024;
  ApkFdLimits limits=new ApkFdLimits(128*m,64*m,64*m,128*m,32*m,64*m,1000,16*m,8*m);
  ApkMetadataPlan plan=ApkMetadataPlan.from(Path.of(args[0]).toAbsolutePath().toString(),null,null,false,null);
  MethodSourceObservation.Observation saved;
  try(AndroidApkSources.Opened opened=AndroidApkSources.open(plan,null,limits)){
   String method="{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\"access\"}}";
   MethodSourceObservation.Result observed=MethodSourceObservation.query(opened,method.getBytes(StandardCharsets.UTF_8));
   check(!observed.sourceScopeComplete&&observed.allInputMethodsScanned&&observed.observedCandidateCount()==1,"single observed caller and incomplete app scope");saved=observed.observedCandidate(0);
   String graph="{\"schema_version\":1,\"required_capabilities\":[\"field_declaration_static\"],\"scope\":{\"slots\":[\"base\"]},\"relation\":{\"op\":\"semi_join\",\"on\":\"caller\",\"left\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"name\":\"access\"}},\"right\":{\"op\":\"scan\",\"relation\":\"field_uses\",\"where\":{\"target_field_declaration\":{\"scope\":\"inherited\"}}}},\"intent\":\"enumerate\"}";
   UseGraphResult joined=opened.snapshot.queryFieldDeclarationGraph(graph.getBytes(StandardCharsets.UTF_8));
   check(joined.snapshotId.equals(observed.snapshotId)&&joined.queryId.startsWith("query:v19:")&&joined.rowCount()==1&&joined.unknownRows==0,"same snapshot caller graph");
   var row=joined.row(0);check(row.value.kind==0&&row.value.entity.sourceIndex==saved.candidate.sourceIndex&&saved.input.inputIndex==0&&saved.source.occurrenceId.equals(saved.candidate.occurrenceId),"caller source occurrence matches observation");
   check(row.linkCount()==1&&row.link(0).key==4&&row.link(0).left.sourceIndex==saved.candidate.sourceIndex&&row.link(0).right.sourceIndex==saved.candidate.sourceIndex,"caller link identity");
   check(row.proofBindingCount()==1&&row.proofBinding(0).value.kind==1&&row.proofBinding(0).value.use.dexPc==0,"one definite event proof");
   int path=0,field=0;for(int i=0;i<row.witnessCount();i++){var w=row.witness(i);if(!w.fieldDeclarationDetailPresent)continue;if(w.fieldDeclarationItem==0){check(w.entity.sourceIndex==1+path,"class path source");path++;}else{check(w.entity.sourceIndex==2&&w.fieldDeclarationPath==1,"field definition source");field++;}}
   check(path==2&&field==1,"one bounded field path");
  }
  check(saved.source.occurrenceId.equals(saved.candidate.occurrenceId),"observation copied after snapshot close");
  System.out.println("PASS same APK snapshot observation and caller field graph identity");
 }
}
