package io.github.jichuo1.dexmeguviz;

import java.lang.reflect.Constructor;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.concurrent.Executors;

public final class RuntimeMemberBinderTest {
 private static final String OWNER="Lfixture/MemberTarget;";
 private static void check(boolean ok,String message){if(!ok)throw new AssertionError(message);}
 private static byte[] q(String r){return ("{\"schema_version\":1,\"relation\":\""+r+"\",\"where\":true,\"intent\":\"enumerate\",\"max_results\":4096}").getBytes(StandardCharsets.UTF_8);}
 private static NativeEngine.EntityCandidate entityWithoutFlags(NativeEngine.EntityCandidate c)throws Exception{
  Constructor<?> ctor=NativeEngine.EntityCandidate.class.getDeclaredConstructors()[0];ctor.setAccessible(true);
  return (NativeEngine.EntityCandidate)ctor.newInstance(c.relation,c.sourceIndex,c.inputIndex,c.localIndex,c.referenceIndex,c.recordOffset,
   c.definitionOffset!=null,c.definitionOffset==null?0L:c.definitionOffset,false,0L,c.codeOffset!=null,c.codeOffset==null?0L:c.codeOffset,
   c.owner,c.name,c.prototype,c.typeDescriptor,c.stringValue,c.sourceSlot,c.occurrenceId);
 }
 private static NativeEngine.MethodCandidate methodWithFlags(NativeEngine.MethodCandidate c,long flags)throws Exception{
  Constructor<NativeEngine.MethodCandidate> ctor=NativeEngine.MethodCandidate.class.getDeclaredConstructor(long.class,long.class,long.class,long.class,String.class,String.class,String.class,int.class,int.class,String.class,String.class);ctor.setAccessible(true);
  return ctor.newInstance(c.methodIndex,flags,c.declarationOffset,c.codeOffset,c.owner,c.name,c.prototype,c.sourceIndex,c.inputIndex,c.sourceSlot,c.occurrenceId);
 }
 public static void main(String[] args)throws Exception{
  check(args.length==4,"fixture classes, dex, static classes, static dex");Object generation=new Object(),next=new Object();URL url=Path.of(args[0]).toUri().toURL();
  try(URLClassLoader first=new URLClassLoader(new URL[]{url},null);URLClassLoader second=new URLClassLoader(new URL[]{url},null);
      URLClassLoader staticLoader=new URLClassLoader(new URL[]{Path.of(args[2]).toUri().toURL()},null)){
   check(System.getProperty("dexmeguviz.member.fixture.initialized")==null,"initialized at start");
   String cproto="(I[[Lfixture/Payload;)V";var ctor=RuntimeMemberBinder.bindConstructorDescriptor(first,generation,OWNER,cproto);
   check(ctor.status==RuntimeMemberBinder.Status.BOUND&&ctor.memberVerified&&ctor.constructor!=null&&ctor.field==null&&ctor.origin==RuntimeMethodBinder.Origin.UNVERIFIED,"constructor");
   check(ctor.expectedInvocationKind==RuntimeMethodBinder.InvocationKind.UNKNOWN&&ctor.actualInvocationKind==RuntimeMethodBinder.InvocationKind.INSTANCE,"constructor descriptor expectation");
   check(!ctor.constructor.isAccessible()&&ctor.definingLoaderKnown&&ctor.definingLoader==first&&ctor.isForGeneration(generation)&&!ctor.isForGeneration(next),"constructor identity/lifecycle");
   var payload=Class.forName("fixture.Payload",false,first);check(ctor.constructor.getParameterTypes()[1].getComponentType().getComponentType()==payload,"constructor array type");
   var secondCtor=RuntimeMemberBinder.bindConstructorDescriptor(second,generation,OWNER,cproto);
   check(secondCtor.status==RuntimeMemberBinder.Status.BOUND&&secondCtor.declaringClass!=ctor.declaringClass&&secondCtor.constructor.getParameterTypes()[1].getComponentType().getComponentType()!=payload,"separate loader constructor");
   ClassLoader mixed=new ClassLoader(null){@Override protected Class<?> loadClass(String n,boolean resolve)throws ClassNotFoundException{if(n.equals("fixture.MemberTarget"))return first.loadClass(n);if(n.equals("fixture.Payload"))return second.loadClass(n);return super.loadClass(n,resolve);}};
   check(RuntimeMemberBinder.bindConstructorDescriptor(mixed,generation,OWNER,cproto).status==RuntimeMemberBinder.Status.SIGNATURE_MISMATCH,"mixed constructor types");
   var child=new ClassLoader(first){};var delegated=RuntimeMemberBinder.bindConstructorDescriptor(child,generation,OWNER,"()V");
   check(delegated.status==RuntimeMemberBinder.Status.BOUND&&delegated.initiatingLoader==child&&delegated.definingLoader==first,"delegated constructor");
   check(RuntimeMemberBinder.bindConstructorDescriptor(first,generation,OWNER,"()I").status==RuntimeMemberBinder.Status.INVALID_INPUT,"constructor return void");
   check(RuntimeMemberBinder.bindConstructorDescriptor(first,generation,OWNER,"(Lmissing/Type;)V").status==RuntimeMemberBinder.Status.SIGNATURE_TYPE_NOT_FOUND,"constructor missing type");
   var f=RuntimeMemberBinder.bindFieldDescriptor(first,generation,OWNER,"payloads","[Lfixture/Payload;",null);
   check(f.status==RuntimeMemberBinder.Status.BOUND&&f.expectedInvocationKind==RuntimeMethodBinder.InvocationKind.UNKNOWN&&f.actualInvocationKind==RuntimeMethodBinder.InvocationKind.INSTANCE&&!f.field.isAccessible(),"unknown expected field");
   check(f.field.getType().getComponentType()==payload,"field type identity");
   var g=RuntimeMemberBinder.bindFieldDescriptor(first,generation,OWNER,"matrix","[[Lfixture/Payload;",Boolean.FALSE);
   check(g.status==RuntimeMemberBinder.Status.BOUND&&g.field.getType().getComponentType().getComponentType()==payload,"field two dimensional");
   check(RuntimeMemberBinder.bindFieldDescriptor(mixed,generation,OWNER,"matrix","[[Lfixture/Payload;",null).status==RuntimeMemberBinder.Status.SIGNATURE_MISMATCH,"mixed field types");
   var wrong=RuntimeMemberBinder.bindFieldDescriptor(first,generation,OWNER,"instanceField","I",Boolean.TRUE);
   check(wrong.status==RuntimeMemberBinder.Status.INVOCATION_MISMATCH&&wrong.field==null&&wrong.actualInvocationKind==RuntimeMethodBinder.InvocationKind.INSTANCE,"field static mismatch");
   var twinI=RuntimeMemberBinder.bindFieldDescriptor(first,generation,"Lfixture/TwinFields;","xxxx","I",null);
   var twinJ=RuntimeMemberBinder.bindFieldDescriptor(first,generation,"Lfixture/TwinFields;","xxxx","J",null);
   check(twinI.status==RuntimeMemberBinder.Status.BOUND&&twinJ.status==RuntimeMemberBinder.Status.BOUND&&twinI.field.getType()==int.class&&twinJ.field.getType()==long.class,"same name different field descriptors");
   check(RuntimeMemberBinder.bindFieldDescriptor(first,generation,OWNER,"instanceField","V",null).status==RuntimeMemberBinder.Status.INVALID_INPUT,"void field denied");
   var only=RuntimeMemberBinder.bindOwnerDescriptor(first,generation,OWNER);
   check(only.status==RuntimeMemberBinder.Status.OWNER_ONLY&&only.declaringClass!=null&&!only.memberVerified&&only.constructor==null&&only.field==null&&only.origin==RuntimeMethodBinder.Origin.UNVERIFIED,"owner only");
   var bootstrap=RuntimeMemberBinder.bindOwnerDescriptor(null,generation,"Ljava/lang/String;");check(bootstrap.status==RuntimeMemberBinder.Status.OWNER_ONLY&&bootstrap.definingLoaderKnown&&bootstrap.definingLoader==null,"bootstrap");
   var pool=Executors.newFixedThreadPool(4);try{var tasks=new ArrayList<java.util.concurrent.Future<RuntimeMemberBinder.Result>>();for(int i=0;i<40;i++)tasks.add(pool.submit(()->RuntimeMemberBinder.bindFieldDescriptor(first,generation,OWNER,"matrix","[[Lfixture/Payload;",null)));for(var task:tasks)check(task.get().status==RuntimeMemberBinder.Status.BOUND,"concurrency");}finally{pool.shutdown();}
   NativeEngine.EntityCandidate retained=null;NativeEngine.MethodCandidate init=null,clinit=null;
   byte[] dex=Files.readAllBytes(Path.of(args[1]));try(var snap=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"one","two"})){
    var fields=snap.queryEntities(q("field_defs"));NativeEngine.EntityCandidate instance=null,staticField=null,secondInstance=null,twinInt=null,twinLong=null;
    for(int i=0;i<fields.candidateCount();i++){var row=fields.candidate(i);if(OWNER.equals(row.owner)&&"instanceField".equals(row.name)){if(row.sourceIndex==0)instance=row;else secondInstance=row;}if(OWNER.equals(row.owner)&&"staticField".equals(row.name)&&row.sourceIndex==0)staticField=row;if("Lfixture/TwinFields;".equals(row.owner)&&"xxxx".equals(row.name)&&row.sourceIndex==0){if("I".equals(row.typeDescriptor))twinInt=row;if("J".equals(row.typeDescriptor))twinLong=row;}}
    check(instance!=null&&secondInstance!=null&&staticField!=null&&twinInt!=null&&twinLong!=null,"JNI field rows");
    check(RuntimeMemberBinder.bindField(first,generation,twinInt).field.getType()==int.class&&RuntimeMemberBinder.bindField(first,generation,twinLong).field.getType()==long.class,"JNI same name different field types");
    var x=RuntimeMemberBinder.bindField(first,generation,instance);var y=RuntimeMemberBinder.bindField(first,generation,secondInstance);
    check(x.status==RuntimeMemberBinder.Status.BOUND&&y.status==RuntimeMemberBinder.Status.BOUND&&x.origin==RuntimeMethodBinder.Origin.UNVERIFIED&&x.expectedInvocationKind==RuntimeMethodBinder.InvocationKind.INSTANCE&&x.sourceIndex!=y.sourceIndex&&!x.occurrenceId.equals(y.occurrenceId),"field occurrence");
    check(RuntimeMemberBinder.bindField(staticLoader,generation,instance).status==RuntimeMemberBinder.Status.INVOCATION_MISMATCH,"candidate instance/runtime static");
    check(RuntimeMemberBinder.bindField(staticLoader,generation,staticField).status==RuntimeMemberBinder.Status.INVOCATION_MISMATCH,"candidate static/runtime instance");
    var unknown=RuntimeMemberBinder.bindField(first,generation,entityWithoutFlags(instance));check(unknown.status==RuntimeMemberBinder.Status.BOUND&&unknown.expectedInvocationKind==RuntimeMethodBinder.InvocationKind.UNKNOWN,"candidate missing flags");
    retained=instance;
    var refs=snap.queryEntities(q("field_refs"));check(refs.candidateCount()>0&&RuntimeMemberBinder.bindField(first,generation,refs.candidate(0)).status==RuntimeMemberBinder.Status.UNSUPPORTED_RELATION,"field ref rejected");
    var classes=snap.queryEntities(q("class_defs"));NativeEngine.EntityCandidate owner=null;for(int i=0;i<classes.candidateCount();i++)if("Lfixture/MemberTarget;".equals(classes.candidate(i).typeDescriptor)){owner=classes.candidate(i);break;}
    check(owner!=null,"class row");check(RuntimeMemberBinder.bindField(first,generation,owner).status==RuntimeMemberBinder.Status.UNSUPPORTED_RELATION,"class is not field definition");var actualOwner=RuntimeMemberBinder.bindClass(first,generation,owner);check(actualOwner.status==RuntimeMemberBinder.Status.OWNER_ONLY&&!actualOwner.memberVerified&&actualOwner.sourceSlot!=null,"class owner only");
    var methods=snap.queryMethods(q("method_defs"));for(int i=0;i<methods.candidateCount();i++){var m=methods.candidate(i);if(OWNER.equals(m.owner)&&m.sourceIndex==0&&"<init>".equals(m.name)&&cproto.equals(m.prototype))init=m;if(OWNER.equals(m.owner)&&m.sourceIndex==0&&"<clinit>".equals(m.name))clinit=m;}
    check(init!=null&&clinit!=null,"constructor and clinit rows");var ci=RuntimeMemberBinder.bindConstructor(first,generation,init);
    check(ci.status==RuntimeMemberBinder.Status.BOUND&&ci.expectedInvocationKind==RuntimeMethodBinder.InvocationKind.INSTANCE,"candidate constructor");
    var forged=RuntimeMemberBinder.bindConstructor(first,generation,methodWithFlags(init,init.accessFlags|8L));check(forged.status==RuntimeMemberBinder.Status.INVOCATION_MISMATCH&&forged.constructor==null,"forged static constructor rejected");
    check(RuntimeMemberBinder.bindConstructor(first,generation,clinit).status==RuntimeMemberBinder.Status.INVALID_INPUT,"clinit not constructor");
    check(RuntimeMemberBinder.bindOwnerAnchor(first,generation,methodWithFlags(clinit,clinit.accessFlags&~8L)).status==RuntimeMemberBinder.Status.INVALID_INPUT,"nonstatic clinit anchor rejected");
    var classInit=RuntimeMemberBinder.bindOwnerAnchor(staticLoader,generation,clinit);check(classInit.status==RuntimeMemberBinder.Status.OWNER_ONLY&&!classInit.memberVerified&&classInit.constructor==null&&classInit.field==null,"clinit owner cannot claim runtime member");
    check(RuntimeMemberBinder.bindOwnerAnchor(first,generation,init).status==RuntimeMemberBinder.Status.OWNER_ONLY,"constructor owner anchor");
   }
   check(RuntimeMemberBinder.bindField(first,generation,retained).status==RuntimeMemberBinder.Status.BOUND,"field after snapshot close");
   check(RuntimeMemberBinder.bindConstructor(first,generation,init).status==RuntimeMemberBinder.Status.BOUND,"constructor after snapshot close");
   check(System.getProperty("dexmeguviz.member.fixture.initialized")==null,"no target initialization");
   check(System.getProperty("dexmeguviz.member.fixture.initialized")==null,"still not initialized");
  }
  System.out.println("PASS constructor, field and owner binder static scope and loader identity");
 }
}
