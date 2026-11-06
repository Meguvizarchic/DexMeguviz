package io.github.jichuo1.dexmeguviz;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.*;
public final class RuntimeMethodBinderTest {
 private static void check(boolean ok,String text){if(!ok)throw new AssertionError(text);}
 private static RuntimeMethodBinder.Result bind(ClassLoader l,Object gen,String name,String p){return RuntimeMethodBinder.bindDescriptor(l,gen,"Lfixture/Target;",name,p);}
 public static void main(String[] args)throws Exception{
  check(args.length==4,"fixture dir, dex, static classes, static dex");URL url=Path.of(args[0]).toUri().toURL();Object generation=new Object(), nextGeneration=new Object();
  try(URLClassLoader first=new URLClassLoader(new URL[]{url},null);URLClassLoader second=new URLClassLoader(new URL[]{url},null);URLClassLoader statics=new URLClassLoader(new URL[]{Path.of(args[2]).toUri().toURL()},null)){
   check(System.getProperty("dexmeguviz.binder.fixture.initialized")==null,"fixture initialized early");
   var a=bind(first,generation,"combine","(I[[Ljava/lang/String;[J)I");
   check(a.status==RuntimeMethodBinder.Status.BOUND && a.origin==RuntimeMethodBinder.Origin.UNVERIFIED && a.expectedInvocationKind==RuntimeMethodBinder.InvocationKind.UNKNOWN && a.actualInvocationKind==RuntimeMethodBinder.InvocationKind.INSTANCE,"descriptor-only invocation unknown");
   check(a.method.getDeclaringClass()==a.declaringClass && a.definingLoaderKnown && a.definingLoader==first && a.initiatingLoader==first,"loader identity");
   check(a.isForGeneration(generation) && !a.isForGeneration(nextGeneration),"generation identity");
   check(a.method.getParameterTypes()[1]==String[][].class && a.method.getParameterTypes()[2]==long[].class,"signature classes");
   var child=new ClassLoader(first){};var delegated=bind(child,generation,"combine","(Ljava/lang/String;)V");
   check(delegated.status==RuntimeMethodBinder.Status.BOUND&&delegated.initiatingLoader==child&&delegated.definingLoaderKnown&&delegated.definingLoader==first,"parent delegation");
   var b=bind(second,generation,"identity","(Lfixture/Payload;)Lfixture/Payload;");
   var c=bind(first,generation,"identity","(Lfixture/Payload;)Lfixture/Payload;");
   check(b.status==RuntimeMethodBinder.Status.BOUND&&c.status==RuntimeMethodBinder.Status.BOUND&&b.declaringClass!=c.declaringClass&&b.method.getParameterTypes()[0]!=c.method.getParameterTypes()[0],"separate loader types");
   String arrayProto="([Lfixture/Payload;[[Lfixture/Payload;)[[Lfixture/Payload;";
   var arrA=bind(first,generation,"arrays",arrayProto);var arrB=bind(second,generation,"arrays",arrayProto);
   check(arrA.status==RuntimeMethodBinder.Status.BOUND&&arrB.status==RuntimeMethodBinder.Status.BOUND,"custom array match");
   var payloadA=Class.forName("fixture.Payload",false,first);var payloadB=Class.forName("fixture.Payload",false,second);
   check(arrA.method.getParameterTypes()[0].getComponentType()==payloadA && arrA.method.getParameterTypes()[1].getComponentType().getComponentType()==payloadA && arrA.method.getReturnType().getComponentType().getComponentType()==payloadA,"first loader custom array identities");
   check(arrB.method.getParameterTypes()[0].getComponentType()==payloadB && arrB.method.getReturnType().getComponentType().getComponentType()==payloadB && payloadA!=payloadB,"second loader custom array identities");
   ClassLoader mixed=new ClassLoader(null){@Override protected Class<?> loadClass(String n,boolean resolve)throws ClassNotFoundException {if(n.equals("fixture.Target"))return first.loadClass(n);if(n.equals("fixture.Payload"))return second.loadClass(n);return super.loadClass(n,resolve);}};
   check(bind(mixed,generation,"arrays",arrayProto).status==RuntimeMethodBinder.Status.SIGNATURE_MISMATCH,"mixed custom array loader mismatch");
   var cov=bind(first,generation,"adapt","()Ljava/lang/String;");var bridge=bind(first,generation,"adapt","()Ljava/lang/Object;");
   check(cov.status==RuntimeMethodBinder.Status.BOUND&&!cov.method.isBridge()&&bridge.status==RuntimeMethodBinder.Status.BOUND&&bridge.method.isBridge()&&bridge.method.getDeclaringClass()==cov.declaringClass,"return descriptor distinguishes bridge");
   var mismatch=bind(first,generation,"combine","(I[[Ljava/lang/String;[J)J");check(mismatch.status==RuntimeMethodBinder.Status.SIGNATURE_MISMATCH,"return mismatch");
   var hidden=bind(first,generation,"hidden","(I)Ljava/lang/String;");check(hidden.status==RuntimeMethodBinder.Status.BOUND&&!hidden.method.isAccessible(),"no access override");
   check(bind(first,generation,"<init>","()V").status==RuntimeMethodBinder.Status.UNSUPPORTED_MEMBER,"constructor excluded");
   for(String invalid:new String[]{"", "(V)V", "([V)V", "(I", "()Vx", "(Ljava/lang/String)V", "("+"[".repeat(256)+"I)V"})
     check(bind(first,generation,"combine",invalid).status==RuntimeMethodBinder.Status.INVALID_INPUT,"invalid "+invalid);
   check(RuntimeMethodBinder.bindDescriptor(first,generation,"Lmissing/Owner;","run","()V").status==RuntimeMethodBinder.Status.OWNER_NOT_FOUND,"missing owner");
   check(bind(first,generation,"identity","(Lmissing/Type;)Lfixture/Payload;").status==RuntimeMethodBinder.Status.SIGNATURE_TYPE_NOT_FOUND,"missing parameter");
   ClassLoader failing=new ClassLoader(null){@Override protected Class<?> loadClass(String n,boolean resolve){throw new IllegalStateException("fixture");}};
   check(bind(failing,generation,"x","()V").status==RuntimeMethodBinder.Status.LOADER_ERROR,"loader error");
   var bootstrap=RuntimeMethodBinder.bindDescriptor(null,generation,"Ljava/lang/String;","length","()I");check(bootstrap.status==RuntimeMethodBinder.Status.BOUND&&bootstrap.definingLoaderKnown&&bootstrap.definingLoader==null,"bootstrap loader");
   check(bind(first,null,"combine","(Ljava/lang/String;)V").status==RuntimeMethodBinder.Status.INVALID_INPUT,"generation required");
   ExecutorService pool=Executors.newFixedThreadPool(4);try{var tasks=new java.util.ArrayList<Future<RuntimeMethodBinder.Result>>();for(int i=0;i<40;i++)tasks.add(pool.submit(()->bind(first,generation,"combine","(I[[Ljava/lang/String;[J)I")));for(var f:tasks)check(f.get().status==RuntimeMethodBinder.Status.BOUND,"concurrent bind");}finally{pool.shutdown();}
   String q="{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"all\":[{\"owner\":\"Lfixture/Target;\"},{\"name\":\"combine\"},{\"prototype\":\"(I[[Ljava/lang/String;[J)I\"}]},\"intent\":\"enumerate\",\"max_results\":16,\"max_work\":1000000}";
   try(NativeEngine.SourceSetSnapshot snap=NativeEngine.openRawDexSet(new byte[][]{Files.readAllBytes(Path.of(args[1])),Files.readAllBytes(Path.of(args[1]))},new String[]{"one","two"})){
    var result=snap.queryMethods(q.getBytes(StandardCharsets.UTF_8));check(result.candidateCount()==2,"JNI candidate count");
    var x=RuntimeMethodBinder.bind(first,generation,result.candidate(0));var y=RuntimeMethodBinder.bind(first,generation,result.candidate(1));
    check(x.status==RuntimeMethodBinder.Status.BOUND&&y.status==RuntimeMethodBinder.Status.BOUND&&x.origin==RuntimeMethodBinder.Origin.UNVERIFIED&&x.expectedInvocationKind==RuntimeMethodBinder.InvocationKind.INSTANCE&&x.actualInvocationKind==RuntimeMethodBinder.InvocationKind.INSTANCE,"JNI bind");
    var opposite=RuntimeMethodBinder.bind(statics,generation,result.candidate(0));check(opposite.status==RuntimeMethodBinder.Status.INVOCATION_MISMATCH&&opposite.expectedInvocationKind==RuntimeMethodBinder.InvocationKind.INSTANCE&&opposite.actualInvocationKind==RuntimeMethodBinder.InvocationKind.STATIC&&opposite.method==null,"instance candidate/static runtime mismatch");
    check(x.sourceIndex==0&&y.sourceIndex==1&&"one".equals(x.sourceSlot)&&"two".equals(y.sourceSlot)&&!x.occurrenceId.equals(y.occurrenceId),"occurrence retained");
   }
   try(var snap=NativeEngine.openRawDex(Files.readAllBytes(Path.of(args[3])),"static")){var res=snap.queryMethods(q.getBytes(StandardCharsets.UTF_8));check(res.candidateCount()==1,"static candidate count");var opposite=RuntimeMethodBinder.bind(first,generation,res.candidate(0));check(opposite.status==RuntimeMethodBinder.Status.INVOCATION_MISMATCH&&opposite.expectedInvocationKind==RuntimeMethodBinder.InvocationKind.STATIC&&opposite.actualInvocationKind==RuntimeMethodBinder.InvocationKind.INSTANCE&&opposite.method==null,"static candidate/instance runtime mismatch");var correct=RuntimeMethodBinder.bind(statics,generation,res.candidate(0));check(correct.status==RuntimeMethodBinder.Status.BOUND&&correct.actualInvocationKind==RuntimeMethodBinder.InvocationKind.STATIC,"static candidate match");}
   check(System.getProperty("dexmeguviz.binder.fixture.initialized")==null,"binder must not initialize target");
  }
  System.out.println("PASS explicit binder: exact declared signature, loaders, token, JNI occurrences, no initialization");
 }
}
