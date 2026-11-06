import io.github.jichuo1.dexmeguviz.*;import java.io.File;import java.nio.charset.StandardCharsets;import java.util.*;import java.util.concurrent.atomic.AtomicInteger;
public final class ParallelDexQueryHostTest {
 static byte[] q(String s){return s.getBytes(StandardCharsets.UTF_8);}
 public static void main(String[] args)throws Exception {
  File apk=new File(args[0]);var limits=new TrustedApkDexSource.Limits(2,8,1<<20,100,8L<<20,4L<<20);
  byte[] first=q("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\"second\"}}");
  var rule=ParallelDexQuery.Rule.method(first);Arrays.fill(first,(byte)0);
  var second=ParallelDexQuery.Rule.method(q("{\"schema_version\":1,\"relation\":\"method_defs\",\"intent\":\"exists\",\"where\":{\"name\":\"absent\"}}"));
  var seen=new AtomicInteger();
  var result=ParallelDexQuery.map(apk,"fixture",TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,limits,Arrays.asList(rule,second),32L<<20,true,1L<<20,1000000L,(entry,snapshot,values)->{
   if(values.size()!=2||values.get(0).kind!=ParallelDexQuery.Kind.METHOD)throw new AssertionError("rule order");
   if(!values.get(0).method().snapshotId.equals(snapshot.info().snapshotId))throw new AssertionError("snapshot");seen.incrementAndGet();return snapshot.info().snapshotId;
  });
  if(result.sources!=2||seen.get()!=2||result.ordered.get(0).source.ordinal!=1||result.ordered.get(1).source.ordinal!=2||
     !result.ordered.get(0).source.inputSlot.equals("fixture")||result.ordered.get(0).value.equals(result.ordered.get(1).value))throw new AssertionError("source order or occurrence identity");
  byte[] reflection=java.nio.file.Files.readAllBytes(java.nio.file.Path.of(args[1]));
  var onlyReflection=ParallelDexQuery.map(apk,"fixture",TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,limits,
      Arrays.asList(ParallelDexQuery.Rule.reflectionMethodUses(reflection)),32L<<20,true,0,0,(entry,snapshot,values)->{
       if(values.size()!=1||values.get(0).kind!=ParallelDexQuery.Kind.REFLECTION_METHOD_USES||values.get(0).reflection().executionStatus!=0)throw new AssertionError("reflection");return values.get(0).reflection().snapshotId;});
  if(onlyReflection.sources!=2||onlyReflection.ordered.get(0).value.equals(onlyReflection.ordered.get(1).value))throw new AssertionError("reflection-only or source identity");
  try{var tooMany=new TrustedApkDexSource.Limits(17,8,1<<20,100,8L<<20,4L<<20);ParallelDexQuery.map(apk,"fixture",TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,tooMany,Arrays.asList(rule),32L<<20,true,0,0,(e,s,v)->0);throw new AssertionError("session capacity accepted");}catch(IllegalArgumentException expected){}
  var resource=new File(args[2]);var setLimits=new TrustedApkDexSource.SourceSetLimits(limits,3,4,24L<<20,8L<<20);
  var set=ParallelDexQuery.mapAll(Arrays.asList(new TrustedApkDexSource.Input(apk,"base",false),new TrustedApkDexSource.Input(resource,"res",true),new TrustedApkDexSource.Input(apk,"split",false)),
      TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,setLimits,Arrays.asList(rule),32L<<20,true,1L<<20,1000000L,(entry,snapshot,values)->snapshot.info().snapshotId);
  if(set.inputs.size()!=3||set.inputs.get(1).sources!=0||!set.inputs.get(1).allowNoDex||set.sources!=4)throw new AssertionError("resource split");
  if(!set.ordered.get(0).source.inputSlot.equals("base")||!set.ordered.get(2).source.inputSlot.equals("split")||set.ordered.get(0).source.inputIndex!=0||set.ordered.get(2).source.inputIndex!=2||set.ordered.get(0).value.equals(set.ordered.get(2).value))throw new AssertionError("split identity/order");
  var unicode=ParallelDexQuery.mapAll(Arrays.asList(new TrustedApkDexSource.Input(apk,"\uD800",false),new TrustedApkDexSource.Input(apk,"\uD801",false)),
      TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,new TrustedApkDexSource.SourceSetLimits(limits,2,4,24L<<20,8L<<20),Arrays.asList(rule),32L<<20,false,0,0,(entry,snapshot,values)->snapshot.info().snapshotId);
  if(!unicode.ordered.get(0).source.inputSlot.equals("\uD800")||!unicode.ordered.get(2).source.inputSlot.equals("\uD801")||unicode.ordered.get(0).value.equals(unicode.ordered.get(2).value))throw new AssertionError("unicode source identity");
  try {ParallelDexQuery.map(apk,"fixture",TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,limits,Arrays.asList(rule),32L<<20,false,0,0,(entry,snapshot,values)->{throw new IllegalStateException("mapper sentinel");});throw new AssertionError("failure was lost");}
  catch(IllegalStateException expected){if(!expected.getMessage().equals("mapper sentinel"))throw expected;}
  System.out.println("PASS rule copy, duplicate-byte occurrences, resource/split, UTF16 slot, reflection-only, worker capacity and atomic failure");
 }
}
