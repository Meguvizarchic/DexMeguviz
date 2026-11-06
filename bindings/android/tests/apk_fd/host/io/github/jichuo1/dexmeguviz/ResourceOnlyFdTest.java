package io.github.jichuo1.dexmeguviz;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
public final class ResourceOnlyFdTest {
 public static void main(String[] args)throws Exception{
  if(args.length!=2)throw new AssertionError("helper and resource");System.load(args[0]);int fd=FdHarness.open(args[1]);if(fd<0)throw new AssertionError("open fixture");
  var lim=new ApkFdLimits(16L<<20,16L<<20,16L<<20,16L<<20,8L<<20,8L<<20,1000,1L<<20,1L<<20);
  try(var s=NativeEngine.openApkFdSources(new int[]{fd},new long[]{0},new long[]{Files.size(Path.of(args[1]))},new String[]{"resource"},new boolean[]{true},null,lim)){
   var info=s.info();if(info.inputCount()!=1||info.sourceCount()!=0||info.sourceScopeComplete||info.input(0).sourceCount!=0)throw new AssertionError("empty source input identity");
   var r=s.queryMethods("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":true,\"intent\":\"exists\"}".getBytes(StandardCharsets.UTF_8));
   if(r.executionStatus!=0||r.coverage!=1||r.decision!=1||r.candidateCount()!=0)throw new AssertionError("empty incomplete scope must not prove absence");
  }finally{if(FdHarness.close(fd)!=0)throw new AssertionError("caller fd close");}
  System.out.println("PASS resource-only fd retains input and incomplete absence");
 }
}
