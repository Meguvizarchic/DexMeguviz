package io.github.jichuo1.dexmeguviz;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.security.Permission;
public final class MemberBinderSecurityTest {
 public static void main(String[] args)throws Exception{
  try(URLClassLoader loader=new URLClassLoader(new java.net.URL[]{Path.of(args[0]).toUri().toURL()},null)){
   Class.forName("fixture.MemberTarget",false,loader);Class.forName("fixture.Payload",false,loader);
   Object generation=new Object();String owner="Lfixture/MemberTarget;";
   System.setSecurityManager(new SecurityManager(){public void checkPermission(Permission p){if(p instanceof RuntimePermission && p.getName().equals("getClassLoader"))throw new SecurityException("injected");}});
   try{
    var field=RuntimeMemberBinder.bindFieldDescriptor(loader,generation,owner,"instanceField","I",null);
    var ctor=RuntimeMemberBinder.bindConstructorDescriptor(loader,generation,owner,"(I[[Lfixture/Payload;)V");
    var type=RuntimeMemberBinder.bindOwnerDescriptor(loader,generation,owner);
    for(var v:new RuntimeMemberBinder.Result[]{field,ctor,type})if(v.status!=RuntimeMemberBinder.Status.REFLECTION_ERROR||v.definingLoaderKnown||v.definingLoader!=null||v.field!=null||v.constructor!=null)throw new AssertionError("security exception not classified");
   }finally{System.setSecurityManager(null);}
   if(System.getProperty("dexmeguviz.member.fixture.initialized")!=null)throw new AssertionError("target initialized");
  }
  System.out.println("PASS member binder restricted defining loader");
 }
}
