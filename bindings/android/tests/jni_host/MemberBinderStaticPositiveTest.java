package io.github.jichuo1.dexmeguviz;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
public final class MemberBinderStaticPositiveTest {
 public static void main(String[] args)throws Exception{
  var loader=new URLClassLoader(new java.net.URL[]{Path.of(args[0]).toUri().toURL()},null);var token=new Object();var dex=Files.readAllBytes(Path.of(args[1]));
  try(var s=NativeEngine.openRawDexSet(new byte[][]{dex},new String[]{"slot"})){
   var rows=s.queryEntities("{\"schema_version\":1,\"relation\":\"field_defs\",\"where\":true}".getBytes(StandardCharsets.UTF_8));
   NativeEngine.EntityCandidate found=null;for(int i=0;i<rows.candidateCount();i++){var x=rows.candidate(i);if("Lfixture/MemberTarget;".equals(x.owner)&&"staticField".equals(x.name)){found=x;break;}}
   if(found==null||found.accessFlags==null||(found.accessFlags&8L)==0)throw new AssertionError("static candidate");
   var result=RuntimeMemberBinder.bindField(loader,token,found);if(result.status!=RuntimeMemberBinder.Status.BOUND||result.field==null||result.expectedInvocationKind!=RuntimeMethodBinder.InvocationKind.STATIC||result.actualInvocationKind!=RuntimeMethodBinder.InvocationKind.STATIC||result.origin!=RuntimeMethodBinder.Origin.UNVERIFIED)throw new AssertionError("static match");
  }
  if(System.getProperty("dexmeguviz.member.fixture.initialized")!=null)throw new AssertionError("target initialized");loader.close();System.out.println("PASS raw static field candidate binds matching static field");
 }
}
