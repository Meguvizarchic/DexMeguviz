package io.github.jichuo1.dexmeguviz;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
public final class DexMemberSymbolsTest {
 static void check(boolean x,String m){if(!x)throw new AssertionError(m);}
 static void fail(int status,Runnable r){try{r.run();throw new AssertionError("expected native failure");}catch(NativeEngine.NativeFailure e){check(e.status==status,"unexpected status");}}
 static void test(NativeEngine.Snapshot s){
  long[] f=DexSourceExport.fieldRefAt(s,0);check(f.length==3,"field tuple");
  check(DexSourceExport.typeAt(s,f[0],100).equals("Lfixture/Annotated;"),"field owner");
  check(DexSourceExport.stringAt(s,f[1],100).equals("value"),"field name");
  check(DexSourceExport.typeAt(s,f[2],100).equals("I"),"field type");
  long[] m=DexSourceExport.methodRefAt(s,2);check(m.length==3,"method tuple");
  check(DexSourceExport.typeAt(s,m[0],100).equals("Lfixture/Annotated;"),"method owner");
  check(DexSourceExport.stringAt(s,m[1],100).equals("run"),"method name");
  check(DexSourceExport.prototypeAt(s,m[2],100).equals("(Ljava/lang/String;)V"),"method prototype");
  long[] external=DexSourceExport.methodRefAt(s,10);
  check(DexSourceExport.typeAt(s,external[0],100).equals("Ljava/lang/Object;"),"external reference owner");
  check(DexSourceExport.stringAt(s,external[1],100).equals("<init>"),"external method name");
  check(DexSourceExport.prototypeAt(s,external[2],100).equals("()V"),"external prototype");
  f[0]=0xffffffffL;check(!Arrays.equals(f,DexSourceExport.fieldRefAt(s,0)),"independent arrays");
  fail(1,()->DexSourceExport.fieldRefAt(s,0xffffffffL));fail(1,()->DexSourceExport.methodRefAt(s,0xffffffffL));
  fail(1,()->DexSourceExport.prototypeAt(s,0xffffffffL,100));fail(4,()->DexSourceExport.prototypeAt(s,m[2],1));
 }
 public static void main(String[] args)throws Exception{
  byte[] data=Files.readAllBytes(Path.of(args[0]));NativeEngine.Snapshot single=NativeEngine.openRawDex(data,"member");
  test(single);single.close();fail(7,()->DexSourceExport.fieldRefAt(single,0));
  try(var set=NativeEngine.openRawDexSet(new byte[][]{data,data},new String[]{"a","b"})){
   long[] f=DexSourceExport.fieldRefAt(set,1,0);long[] m=DexSourceExport.methodRefAt(set,1,2);
   check(DexSourceExport.stringAt(set,1,f[1],100).equals("value"),"source field name");
   check(DexSourceExport.prototypeAt(set,1,m[2],100).equals("(Ljava/lang/String;)V"),"source prototype");
   fail(1,()->DexSourceExport.fieldRefAt(set,2,0));fail(1,()->DexSourceExport.methodRefAt(set,2,0));
  }
  System.out.println("PASS source-local field/method reference indices, prototypes, bounds and lifetime");
 }
}
