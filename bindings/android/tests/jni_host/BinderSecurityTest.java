package io.github.jichuo1.dexmeguviz;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.security.Permission;
public final class BinderSecurityTest {
 public static void main(String[] args)throws Exception{
  try(URLClassLoader loader=new URLClassLoader(new java.net.URL[]{Path.of(args[0]).toUri().toURL()},null)){
   Class.forName("fixture.Target",false,loader);
   System.setSecurityManager(new SecurityManager(){public void checkPermission(Permission p){if(p instanceof RuntimePermission && p.getName().equals("getClassLoader"))throw new SecurityException("injected getClassLoader denied");}});
   try {
    RuntimeMethodBinder.Result value=RuntimeMethodBinder.bindDescriptor(loader,new Object(),"Lfixture/Target;","combine","(I[[Ljava/lang/String;[J)I");
    if(value.status!=RuntimeMethodBinder.Status.REFLECTION_ERROR||value.method!=null||value.definingLoaderKnown||value.definingLoader!=null)throw new AssertionError("expected classified REFLECTION_ERROR, got "+value.status);
    System.out.println("PASS security exception classified without recursive loader access");
   }finally{System.setSecurityManager(null);}
  }
 }
}
