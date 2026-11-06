package io.github.jichuo1.dexmeguviz;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
public final class MethodSourceObservationValidationTest {
 static void check(boolean b,String s){if(!b)throw new AssertionError(s);}
 static <T>T construct(Class<T> c,Class<?>[] types,Object...values)throws Exception{Constructor<T> k=c.getDeclaredConstructor(types);k.setAccessible(true);return k.newInstance(values);}
 static NativeEngine.MethodCandidate candidate(NativeEngine.MethodCandidate c,int source,int input,String slot,String occurrence)throws Exception{return construct(NativeEngine.MethodCandidate.class,new Class<?>[]{long.class,long.class,long.class,long.class,String.class,String.class,String.class,int.class,int.class,String.class,String.class},c.methodIndex,c.accessFlags,c.declarationOffset,c.codeOffset,c.owner,c.name,c.prototype,source,input,slot,occurrence);}
 static NativeEngine.QueryResult query(NativeEngine.QueryResult q,String snapshot,long unknown,int status,int reason,NativeEngine.MethodCandidate[] candidates)throws Exception{return construct(NativeEngine.QueryResult.class,new Class<?>[]{int.class,int.class,int.class,int.class,int.class,int.class,int.class,long.class,String.class,String.class,NativeEngine.MethodCandidate[].class},status,q.coverage,q.decision,reason,q.visitedMethods,q.totalMethods,q.projectionMask,unknown,q.queryId,snapshot,candidates);}
 static NativeEngine.RawDexSourceInfo source(NativeEngine.RawDexSourceInfo s,int input,String slot,String occurrence,String hash)throws Exception{return construct(NativeEngine.RawDexSourceInfo.class,new Class<?>[]{int.class,int.class,long.class,String.class,String.class,String.class,String.class,String.class,String.class,int.class},s.sourceIndex,input,s.sourceBytes,slot,hash,s.contentId,occurrence,s.logicalDexId,s.archiveEntryName,s.archiveEntryIndex);}
 static NativeEngine.SourceSetInfo info(NativeEngine.SourceSetInfo s,NativeEngine.RawDexSourceInfo[] sources,NativeEngine.InputInfo[] inputs)throws Exception{return construct(NativeEngine.SourceSetInfo.class,new Class<?>[]{String.class,boolean.class,NativeEngine.RawDexSourceInfo[].class,NativeEngine.InputInfo[].class},s.snapshotId,s.sourceScopeComplete,sources,inputs);}
 static Object invoke(ApkMetadataPlan p,NativeEngine.SourceSetInfo i,NativeEngine.QueryResult q)throws Exception{Method m=MethodSourceObservation.class.getDeclaredMethod("assemble",ApkMetadataPlan.class,NativeEngine.SourceSetInfo.class,NativeEngine.QueryResult.class);m.setAccessible(true);try{return m.invoke(null,p,i,q);}catch(InvocationTargetException e){if(e.getCause() instanceof Exception)throw (Exception)e.getCause();throw e;}}
 interface Action{void run()throws Exception;}
 static void bad(Action a)throws Exception{try{a.run();throw new AssertionError("forged metadata accepted");}catch(IllegalStateException expected){}}
 public static void main(String[] args)throws Exception{
  check(args.length==3,"base/copy/resource");String base=Path.of(args[0]).toAbsolutePath().toString(),copy=Path.of(args[1]).toAbsolutePath().toString(),resource=Path.of(args[2]).toAbsolutePath().toString();long m=1024L*1024;ApkFdLimits limits=new ApkFdLimits(128*m,64*m,64*m,128*m,32*m,64*m,1000,16*m,8*m);
  ApkMetadataPlan plan=ApkMetadataPlan.from(base,new String[]{"copy","resource"},new String[]{copy,resource},false,new boolean[]{false,true});
  try(AndroidApkSources.Opened opened=AndroidApkSources.open(plan,null,limits)){
   var i=opened.snapshot.info();var q=opened.snapshot.queryMethods("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\"marker\"},\"intent\":\"enumerate\"}".getBytes(StandardCharsets.UTF_8));var c=q.candidate(0);var sources=new NativeEngine.RawDexSourceInfo[]{i.source(0),i.source(1)};var inputs=new NativeEngine.InputInfo[]{i.input(0),i.input(1),i.input(2)};var values=new NativeEngine.MethodCandidate[]{q.candidate(0),q.candidate(1)};
   bad(()->invoke(plan,i,query(q,i.snapshotId+"wrong",0,0,0,values)));
   bad(()->invoke(plan,i,query(q,i.snapshotId,0,0,0,new NativeEngine.MethodCandidate[]{candidate(c,99,c.inputIndex,c.sourceSlot,c.occurrenceId)})));
   bad(()->invoke(plan,i,query(q,i.snapshotId,0,0,0,new NativeEngine.MethodCandidate[]{candidate(c,c.sourceIndex,1,c.sourceSlot,c.occurrenceId)})));
   bad(()->invoke(plan,i,query(q,i.snapshotId,0,0,0,new NativeEngine.MethodCandidate[]{candidate(c,c.sourceIndex,c.inputIndex,"wrong",c.occurrenceId)})));
   bad(()->invoke(plan,i,query(q,i.snapshotId,0,0,0,new NativeEngine.MethodCandidate[]{candidate(c,c.sourceIndex,c.inputIndex,c.sourceSlot,"wrong")})));
   var sourceBad=new NativeEngine.RawDexSourceInfo[]{source(sources[0],1,sources[0].slot,sources[0].occurrenceId,sources[0].sourceSha256),sources[1]};bad(()->invoke(plan,info(i,sourceBad,inputs),q));
   var duplicate=new NativeEngine.RawDexSourceInfo[]{sources[0],source(sources[1],1,sources[1].slot,sources[0].occurrenceId,sources[1].sourceSha256)};bad(()->invoke(plan,info(i,duplicate,inputs),q));
   var hash=new NativeEngine.RawDexSourceInfo[]{source(sources[0],0,sources[0].slot,sources[0].occurrenceId,"bad"),sources[1]};bad(()->invoke(plan,info(i,hash,inputs),q));
   var unknown=(MethodSourceObservation.Result)invoke(plan,i,query(q,i.snapshotId,1,0,0,values));check(!unknown.allInputMethodsScanned&&unknown.observedCandidate(0).inputScanIncomplete&&!unknown.sourceScopeComplete,"unknown never complete");
   var limit=(MethodSourceObservation.Result)invoke(plan,i,query(q,i.snapshotId,0,4,4,values));check(!limit.allInputMethodsScanned&&limit.observedCandidate(0).inputScanIncomplete,"limit never complete");
  }
  System.out.println("PASS synthetic identity mismatches and Unknown classification");
 }
}
