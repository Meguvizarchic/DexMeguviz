package io.github.jichuo1.dexmeguviz;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
public final class ApkFdJniHostTest {
 static void check(boolean v,String s){if(!v)throw new AssertionError(s);}
 static void failure(int status,Runnable r){try{r.run();throw new AssertionError("expected NativeFailure");}catch(NativeEngine.NativeFailure e){check(e.status==status,"status="+e.status);}}
 static void invalid(Runnable r){try{r.run();throw new AssertionError("expected invalid input");}catch(IllegalArgumentException e){}}
 static String sha(byte[] data)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));}
 static ApkFdLimits limits(){return new ApkFdLimits(512L<<20,256L<<20,256L<<20,512L<<20,128L<<20,128L<<20,1000,16L<<20,8L<<20);}
 static NativeEngine.SourceSetSnapshot open(int[] fds,long[] offsets,long[] lengths,String[] slots,boolean[] allow,String[] expected){return NativeEngine.openApkFdSources(fds,offsets,lengths,slots,allow,expected,limits());}
 public static void main(String[] args)throws Exception{
  check(args.length==6,"helper, small, resource, over16, over128, prefixed");System.load(args[0]);Path small=Path.of(args[1]),resource=Path.of(args[2]),over16=Path.of(args[3]),over128=Path.of(args[4]),prefixed=Path.of(args[5]);byte[] smallBytes=Files.readAllBytes(small),resourceBytes=Files.readAllBytes(resource);String digest=sha(smallBytes);
  int a=FdHarness.open(small.toString()),b=FdHarness.open(resource.toString());check(a>=0&&b>=0&&FdHarness.seek(a,7)==7,"fixture descriptors");
  NativeEngine.SourceSetSnapshot kept=null;
  try(var old=NativeEngine.openSources(new byte[][]{smallBytes,resourceBytes},new String[]{"base","split.res"},new int[]{NativeEngine.SOURCE_APK,NativeEngine.SOURCE_APK},new boolean[]{false,true})){
   kept=open(new int[]{a,b},new long[]{0,0},new long[]{Files.size(small),Files.size(resource)},new String[]{"base","split.res"},new boolean[]{false,true},new String[]{digest,null});
   var x=old.info();var y=kept.info();check(x.snapshotId.equals(y.snapshotId)&&y.inputCount()==2&&!y.sourceScopeComplete,"old/new snapshot identity");
   check(y.input(0).sourceSha256.equals(digest)&&y.input(1).sourceCount==0&&y.input(1).allowNoDex,"source digest and observed zero dex");
   check(FdHarness.position(a)==7,"fd position preserved");check(FdHarness.close(a)==0&&FdHarness.close(b)==0,"caller fd retained ownership");a=b=-1;
   check(kept.info().snapshotId.equals(x.snapshotId),"snapshot survives caller fd close");
   var result=kept.queryMethods("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":true,\"intent\":\"enumerate\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));check(result.candidateCount()>0&&result.coverage==1,"queries survive close and incomplete scope");
  }finally{if(kept!=null)kept.close();if(a>=0)FdHarness.close(a);if(b>=0)FdHarness.close(b);}
  int resourceFd=FdHarness.open(resource.toString());check(resourceFd>=0,"resource fd");try{failure(2,()->open(new int[]{resourceFd},new long[]{0},new long[]{resourceBytes.length},new String[]{"resource"},new boolean[]{false},null));}finally{FdHarness.close(resourceFd);}
  int eightFd=FdHarness.open(small.toString());check(eightFd>=0,"eight fd");try{int[] eight=new int[8];long[] offsets=new long[8],lengths=new long[8];String[] slots=new String[8];boolean[] flags=new boolean[8];for(int i=0;i<8;i++){eight[i]=eightFd;lengths[i]=smallBytes.length;slots[i]="s"+i;}try(var s=open(eight,offsets,lengths,slots,flags,null)){var info=s.info();check(info.inputCount()==8&&info.sourceCount()>=8&&!info.sourceScopeComplete,"eight inputs");check(!info.source(0).occurrenceId.equals(info.source(info.sourceCount()-1).occurrenceId),"eight source occurrences");}}finally{FdHarness.close(eightFd);}
  int pref=FdHarness.open(prefixed.toString());check(pref>=0&&FdHarness.seek(pref,3)==3,"prefixed fd");try(var s=open(new int[]{pref},new long[]{12},new long[]{smallBytes.length},new String[]{"base"},new boolean[]{false},new String[]{digest})){check(s.info().input(0).sourceSha256.equals(digest)&&FdHarness.position(pref)==3,"range and position");}finally{FdHarness.close(pref);}
  int valid=FdHarness.open(small.toString());check(valid>=0,"valid fd");try{
   failure(8,()->open(new int[]{valid},new long[]{0},new long[]{smallBytes.length},new String[]{"x"},new boolean[]{false},new String[]{"0".repeat(64)}));
   invalid(()->open(new int[]{valid},new long[]{Long.MAX_VALUE},new long[]{1},new String[]{"x"},new boolean[]{false},null));
   invalid(()->open(new int[]{valid,valid},new long[]{0,0},new long[]{1,1},new String[]{"x","x"},new boolean[]{false,false},null));
   int[] nine=new int[9];long[] nineLong=new long[9];String[] names=new String[9];boolean[] flags=new boolean[9];for(int i=0;i<9;i++){nine[i]=valid;names[i]="s"+i;}invalid(()->open(nine,nineLong,nineLong,names,flags,null));
  }finally{FdHarness.close(valid);}
  int big=FdHarness.open(over16.toString());check(big>=0,"large fd");try(var s=open(new int[]{big},new long[]{0},new long[]{Files.size(over16)},new String[]{"big"},new boolean[]{false},null)){check(s.info().input(0).inputBytes>16L*1024*1024,"fd accepts >16MiB");}finally{FdHarness.close(big);}
  byte[] oldBytes=Files.readAllBytes(over16);failure(4,()->NativeEngine.openSources(new byte[][]{oldBytes},new String[]{"big"},new int[]{NativeEngine.SOURCE_APK},new boolean[]{false}));
  int huge=FdHarness.open(over128.toString());check(huge>=0,"huge fd");try(var s=open(new int[]{huge},new long[]{0},new long[]{Files.size(over128)},new String[]{"huge"},new boolean[]{false},null)){check(s.info().input(0).inputBytes>128L*1024*1024,"fd accepts >128MiB");}finally{FdHarness.close(huge);}
  System.out.println("PASS fd JNI old identity, budgets, resource-only, position and lifetime");
 }
}
