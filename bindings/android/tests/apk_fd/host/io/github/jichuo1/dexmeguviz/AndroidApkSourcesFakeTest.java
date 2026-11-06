package io.github.jichuo1.dexmeguviz;
import android.content.pm.ApplicationInfo;
import android.os.ParcelFileDescriptor;
import java.io.IOException;
import java.io.File;
import java.util.Arrays;
public final class AndroidApkSourcesFakeTest {
 static void check(boolean ok,String what){if(!ok)throw new AssertionError(what);}
 static void bad(Class<? extends Throwable> type,Thrower f){try{f.run();throw new AssertionError("expected "+type.getName());}catch(Throwable e){if(!type.isInstance(e))throw new AssertionError("wrong exception",e);}}
 interface Thrower {void run()throws Exception;}
 static String path(String n){return new File(System.getProperty("java.io.tmpdir"),n).getAbsolutePath();}
 static ApkFdLimits budget(){return new ApkFdLimits(4096,1024,1024,2048,512,1024,32,512,256);}
 static ApplicationInfo info(){ApplicationInfo x=new ApplicationInfo();x.packageName="fixture.pkg";x.sourceDir=path("base.apk");x.splitNames=new String[]{"feature","res"};x.splitSourceDirs=new String[]{path("feature.apk"),path("res.apk")};return x;}
 static void files(){ParcelFileDescriptor.reset();ParcelFileDescriptor.sizes.put(path("base.apk"),128L);ParcelFileDescriptor.sizes.put(path("feature.apk"),64L);ParcelFileDescriptor.sizes.put(path("res.apk"),32L);}
 public static void main(String[] args)throws Exception{
  ApplicationInfo x=info();boolean[] allows={false,true};ApkMetadataPlan plan=AndroidApkSources.plan(x,false,allows);x.splitNames[0]="changed";allows[1]=false;
  check(plan.entries().size()==3&&plan.entries().get(1).slot.equals("split.feature")&&plan.entries().get(2).allowNoDex,"captured immutable plan");
  bad(UnsupportedOperationException.class,()->plan.entries().clear());Object generation=new Object();ClassLoader loader=new ClassLoader(){};var declaration=new ApkMetadataPlan.LoaderDeclaration(loader,generation);var observed=AndroidApkSources.plan(info(),declaration,false,new boolean[]{false,true});
  check("fixture.pkg".equals(observed.packageName)&&observed.loaderDeclaration.loader==loader&&observed.loaderDeclaration.generation==generation,"metadata claims retained");
  bad(NullPointerException.class,()->new ApkMetadataPlan.LoaderDeclaration(null,null));
  bad(IllegalArgumentException.class,()->ApkMetadataPlan.from("relative.apk",null,null,false,null));
  bad(IllegalArgumentException.class,()->ApkMetadataPlan.from(new File(path("base")).toPath().getRoot().toString(),null,null,false,null));
  bad(IllegalArgumentException.class,()->ApkMetadataPlan.from(path(".."),null,null,false,null));
  files();ApplicationInfo relative=info();relative.sourceDir="relative.apk";int before=NativeEngine.pathCalls;bad(IllegalArgumentException.class,()->AndroidApkSources.open(relative,false,new boolean[]{false,true},null,budget()));check(NativeEngine.pathCalls==before,"invalid path before native");
  files();ApplicationInfo malformed=info();malformed.sourceDir=path("bad-\ud800.apk");before=NativeEngine.pathCalls;bad(IllegalArgumentException.class,()->AndroidApkSources.open(malformed,false,new boolean[]{false,true},null,budget()));check(NativeEngine.pathCalls==before,"malformed Unicode never replaced or opened");
  files();ApplicationInfo unicode=info();unicode.sourceDir=path("valid-\ud83d\ude80.apk");ParcelFileDescriptor.sizes.put(unicode.sourceDir,128L);try(var opened=AndroidApkSources.open(unicode,false,new boolean[]{false,true},null,budget())){check(opened.plan.entries().get(0).path.equals(unicode.sourceDir),"supplementary path roundtrip");}
  bad(IllegalArgumentException.class,()->ApkMetadataPlan.from(path("base"),new String[]{"x"},null,false,new boolean[]{true}));
  bad(IllegalArgumentException.class,()->ApkMetadataPlan.from(path("base"),new String[]{"x","x"},new String[]{path("a"),path("b")},false,new boolean[]{true,true}));
  bad(IllegalArgumentException.class,()->ApkMetadataPlan.from(path("base"),new String[]{"x"},new String[]{path("base")},false,new boolean[]{true}));
  bad(IllegalArgumentException.class,()->ApkMetadataPlan.from(path("base"),new String[]{"x y"},new String[]{path("a")},false,new boolean[]{true}));
  String[] many=new String[8],paths=new String[8];boolean[] flags=new boolean[8];for(int i=0;i<8;i++){many[i]="s"+i;paths[i]=path("p"+i);}bad(IllegalArgumentException.class,()->ApkMetadataPlan.from(path("base"),many,paths,false,flags));
  bad(IllegalArgumentException.class,()->new ApkFdLimits((1L<<30)+1,1,1,1,1,1,1,1,1));bad(IllegalArgumentException.class,()->new ApkFdLimits(1,(512L<<20)+1,1,1,1,1,1,1,1));
  files();try(var opened=AndroidApkSources.open(info(),false,new boolean[]{false,true},null,budget())){
   check(Arrays.equals(NativeEngine.slots,new String[]{"base","split.feature","split.res"})&&NativeEngine.allow[2],"metadata arguments");check(!opened.snapshot.closed&&ParcelFileDescriptor.created.isEmpty(),"Java adapter creates no PFD");
  }check(NativeEngine.last.closed,"snapshot close");
  files();ParcelFileDescriptor.sizes.remove(path("feature.apk"));bad(IOException.class,()->AndroidApkSources.open(info(),false,new boolean[]{false,true},null,budget()));
  ParcelFileDescriptor.reset();var a=new ParcelFileDescriptor("caller-a",100);var b=new ParcelFileDescriptor("caller-b",100);
  var evilSelf=new ParcelFileDescriptor("evil-self",100){@Override public ParcelFileDescriptor dup(){return this;}};
  var evilOther=new ParcelFileDescriptor("evil-other",100){@Override public ParcelFileDescriptor dup(){return a;}};
  try(var snapshot=AndroidApkSources.openBorrowed(new ParcelFileDescriptor[]{a,b,evilSelf,evilOther},new long[]{0,0,0,0},new long[]{100,100,100,100},new String[]{"a","b","e1","e2"},new boolean[]{false,true,false,false},null,budget())){
   check(!a.closed&&!b.closed&&!evilSelf.closed&&!evilOther.closed&&ParcelFileDescriptor.duplicateCount==0&&ParcelFileDescriptor.instanceDupCalls==0&&ParcelFileDescriptor.created.isEmpty(),"no dup or caller close");
   check(NativeEngine.keepAlive.length==4&&NativeEngine.keepAlive[0]==a&&NativeEngine.keepAlive[2]==evilSelf,"PFD array passed for JNI strong reference");
  }
  int calls=NativeEngine.fdCalls;bad(IllegalArgumentException.class,()->AndroidApkSources.openBorrowed(new ParcelFileDescriptor[]{a,b},new long[]{0,0},new long[]{100,100},new String[]{"same","same"},new boolean[]{false,false},null,budget()));check(NativeEngine.fdCalls==calls,"duplicate slots fail before native");
  bad(IllegalArgumentException.class,()->ApkFdInputs.validate(new int[]{1},new long[]{Long.MAX_VALUE},new long[]{1},new String[]{"a"},new boolean[]{false},null,budget()));bad(IllegalArgumentException.class,()->ApkFdInputs.validate(new int[]{1},new long[]{0},new long[]{1},new String[]{"a"},new boolean[]{false},new String[]{"A".repeat(64)},budget()));
  System.out.println("PASS fake Android metadata and borrowed PFD ownership");
 }
}
