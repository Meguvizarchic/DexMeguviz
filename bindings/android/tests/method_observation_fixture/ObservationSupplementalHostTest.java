package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
public final class ObservationSupplementalHostTest {
 public static void main(String[] args)throws Exception {
  if(args.length!=1)throw new AssertionError("resource APK required");long m=1024L*1024;ApkFdLimits limits=new ApkFdLimits(128*m,64*m,64*m,128*m,32*m,64*m,1000,16*m,8*m);
  ApkMetadataPlan plan=ApkMetadataPlan.from(Path.of(args[0]).toAbsolutePath().toString(),null,null,true,null);
  try(AndroidApkSources.Opened opened=AndroidApkSources.open(plan,null,limits)) {
   var r=MethodSourceObservation.query(opened,"{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":true,\"intent\":\"exists\"}".getBytes(StandardCharsets.UTF_8));
   if(!r.allInputMethodsScanned||r.sourceScopeComplete||r.coverage!=1||r.decision!=1||r.observedCandidateCount()!=0||r.inputs.inputCount()!=1||r.inputs.input(0).sourceCount!=0)throw new AssertionError("resource-only zero remains undetermined");
  }
  try {AndroidApkSources.open(plan,new String[]{"0".repeat(64)},limits);throw new AssertionError("digest mismatch accepted");}
  catch(NativeEngine.NativeFailure e) {if(e.status!=8)throw new AssertionError("wrong digest status: "+e.status);}
  System.out.println("PASS resource-only unknown and exact SHA mismatch");
 }
}
