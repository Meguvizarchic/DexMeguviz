package io.github.jichuo1.dexmeguviz;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

public final class MethodSourceObservationHostTest {
 static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
 interface Action{void run()throws Exception;}
 static void fails(Class<? extends Throwable> type,Action action){try{action.run();throw new AssertionError("expected "+type);}catch(Throwable e){if(!type.isInstance(e))throw new AssertionError("wrong exception",e);}}
 static byte[] query(String intent,String extra){return ("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\"marker\"},\"intent\":\""+intent+"\""+extra+"}").getBytes(StandardCharsets.UTF_8);}
 static ApkFdLimits limits(){long m=1024L*1024;return new ApkFdLimits(128*m,64*m,64*m,128*m,32*m,64*m,1000,16*m,8*m);}
 static ApkMetadataPlan plan(String base,String copy,String resource,ClassLoader loader,Object token){return ApkMetadataPlan.from("fixture.pkg",new ApkMetadataPlan.LoaderDeclaration(loader,token),base,new String[]{"copy","resource"},new String[]{copy,resource},false,new boolean[]{false,true});}
 public static void main(String[] args)throws Exception{
  check(args.length==4,"base copy resource and classes directory");String base=Path.of(args[0]).toAbsolutePath().toString(),copy=Path.of(args[1]).toAbsolutePath().toString(),resource=Path.of(args[2]).toAbsolutePath().toString();System.clearProperty("dmg.observation.initialized");Object token=new Object();
  try(URLClassLoader first=new URLClassLoader(new java.net.URL[]{Path.of(args[3]).toUri().toURL()},null);URLClassLoader second=new URLClassLoader(new java.net.URL[]{Path.of(args[3]).toUri().toURL()},null)){
   ApkMetadataPlan plan=plan(base,copy,resource,first,token);MethodSourceObservation.Observation saved;
   try(AndroidApkSources.Opened opened=AndroidApkSources.open(plan,null,limits())){
    MethodSourceObservation.Result observed=MethodSourceObservation.query(opened,query("enumerate",""));
    check(observed.allInputMethodsScanned&&!observed.sourceScopeComplete&&observed.executionStatus==0&&observed.coverage==1&&observed.observedCandidateCount()==2,"full input scan remains globally incomplete");
    check(observed.inputs.inputCount()==3&&observed.inputs.input(2).sourceCount==0&&observed.inputs.sourceCount()==2,"resource-only input retained");
    var one=observed.observedCandidate(0);var two=observed.observedCandidate(1);saved=one;
    check(!one.inputScanIncomplete&&!two.inputScanIncomplete&&one.input.inputIndex==0&&two.input.inputIndex==1&&one.input.slot.equals("base")&&two.input.slot.equals("split.copy"),"source to input and slot mapping");
    check(one.input.sourceSha256.equals(two.input.sourceSha256)&&one.source.sourceSha256.equals(two.source.sourceSha256)&&!one.source.occurrenceId.equals(two.source.occurrenceId)&&one.source.archiveEntryName.equals("classes.dex")&&one.source.archiveEntryIndex==0,"duplicate bytes retain occurrences");
    fails(IllegalArgumentException.class,()->one.bind(second,token));fails(IllegalArgumentException.class,()->one.bind(first,new Object()));
    RuntimeMethodBinder.Result bound=one.bind(first,token);check(bound.status==RuntimeMethodBinder.Status.BOUND&&bound.origin==RuntimeMethodBinder.Origin.UNVERIFIED&&bound.expectedInvocationKind==RuntimeMethodBinder.InvocationKind.STATIC&&bound.initiatingLoader==first&&bound.definingLoader==first&&bound.isForGeneration(token),"declared binding");
    MethodSourceObservation.Result early=MethodSourceObservation.query(opened,query("exists",""));check(!early.allInputMethodsScanned&&!early.sourceScopeComplete&&early.observedCandidateCount()==1&&early.observedCandidate(0).inputScanIncomplete&&early.decision==3,"early positive remains partial input scan");
    MethodSourceObservation.Result limit=MethodSourceObservation.query(opened,query("enumerate",",\"max_results\":1"));check(!limit.allInputMethodsScanned&&limit.executionStatus==4&&limit.reason==4&&limit.observedCandidateCount()==1&&limit.observedCandidate(0).inputScanIncomplete,"result limit explicit");
    MethodSourceObservation.Result unique=MethodSourceObservation.query(opened,new String(query("unique",""),StandardCharsets.UTF_8).replace("marker","other").getBytes(StandardCharsets.UTF_8));
    check(unique.allInputMethodsScanned&&!unique.sourceScopeComplete&&unique.observedCandidateCount()==2&&unique.decision==2&&unique.reason==2&&!unique.observedCandidate(0).inputScanIncomplete,"two last-position unique witnesses and completed traversal do not assert full application uniqueness");
    MethodSourceObservation.Result absent=MethodSourceObservation.query(opened,"{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\"absent\"},\"intent\":\"exists\"}".getBytes(StandardCharsets.UTF_8));check(absent.allInputMethodsScanned&&!absent.sourceScopeComplete&&absent.observedCandidateCount()==0&&absent.decision==1,"zero remains undetermined");
    fails(IllegalStateException.class,()->MethodSourceObservation.query(opened,query("enumerate",",\"projection\":[\"name\"]")));
    fails(NativeEngine.NativeFailure.class,()->MethodSourceObservation.query(opened,"{".getBytes(StandardCharsets.UTF_8)));
   }
   check(saved.bind(first,token).status==RuntimeMethodBinder.Status.BOUND,"copied observation survives snapshot close");
   try(AndroidApkSources.Opened closed=AndroidApkSources.open(plan,null,limits())){closed.close();fails(IllegalStateException.class,()->MethodSourceObservation.query(closed,query("enumerate","")));}
   ApkMetadataPlan oneInput=ApkMetadataPlan.from("fixture.pkg",new ApkMetadataPlan.LoaderDeclaration(first,token),base,null,null,false,null);
   try(AndroidApkSources.Opened opened=AndroidApkSources.open(oneInput,null,limits())){
    MethodSourceObservation.Result last=MethodSourceObservation.query(opened,new String(query("exists",""),StandardCharsets.UTF_8).replace("marker","other").getBytes(StandardCharsets.UTF_8));
    check(last.allInputMethodsScanned&&!last.sourceScopeComplete&&last.decision==3&&last.observedCandidateCount()==1&&!last.observedCandidate(0).inputScanIncomplete,"last input method matches EXISTS without claiming complete candidate enumeration");
   }
   ApkMetadataPlan wrong=plan(base,copy,resource,second,token);try(AndroidApkSources.Opened opened=AndroidApkSources.open(wrong,null,limits())){var bound=MethodSourceObservation.query(opened,query("enumerate","")).observedCandidate(0).bind(second,token);check(bound.status==RuntimeMethodBinder.Status.BOUND&&bound.declaringClass!=saved.bind(first,token).declaringClass&&bound.origin==RuntimeMethodBinder.Origin.UNVERIFIED,"same class name distinct loader");}
   ClassLoader child=new ClassLoader(first){};ApkMetadataPlan delegated=plan(base,copy,resource,child,token);try(AndroidApkSources.Opened opened=AndroidApkSources.open(delegated,null,limits())){var bound=MethodSourceObservation.query(opened,query("enumerate","")).observedCandidate(0).bind(child,token);check(bound.status==RuntimeMethodBinder.Status.BOUND&&bound.initiatingLoader==child&&bound.definingLoader==first,"parent delegation preserved");}
   ApkMetadataPlan undeclared=ApkMetadataPlan.from(base,null,null,false,null);try(AndroidApkSources.Opened opened=AndroidApkSources.open(undeclared,null,limits())){var value=MethodSourceObservation.query(opened,query("enumerate","")).observedCandidate(0);fails(IllegalStateException.class,()->value.bind(first,token));}
   fails(NativeEngine.NativeFailure.class,()->AndroidApkSources.open(plan,new String[]{"0".repeat(64),null,null},limits()));
   check(System.getProperty("dmg.observation.initialized")==null,"binding must not initialize target");
  }
  check(MethodSourceObservation.inputScanFinished(0,0,0,2,2)&&!MethodSourceObservation.inputScanFinished(0,0,1,2,2)&&!MethodSourceObservation.inputScanFinished(4,4,0,2,2)&&!MethodSourceObservation.inputScanFinished(0,0,0,1,2),"unknown, limit, early partial classification");
  System.out.println("PASS method observations, partials, ownership and unverified binding");
 }
}
