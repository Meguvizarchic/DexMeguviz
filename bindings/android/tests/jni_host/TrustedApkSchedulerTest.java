import io.github.jichuo1.dexmeguviz.TrustedApkDexSource;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.zip.*;
public class TrustedApkSchedulerTest {
 static void check(boolean x,String s){if(!x)throw new AssertionError(s);}
 static Path apk(Path dir,String name,int[] order)throws Exception{Path file=dir.resolve(name);try(var zip=new ZipOutputStream(Files.newOutputStream(file))){for(int n:order){zip.putNextEntry(new ZipEntry(n==1?"classes.dex":"classes"+n+".dex"));zip.write(new byte[]{(byte)n,2,3});zip.closeEntry();}}return file;}
 public static void main(String[] args)throws Exception{
  boolean fast=Boolean.parseBoolean(args[0]);Path dir=Files.createTempDirectory(Path.of(args[1]),"skew-");Path a=apk(dir,"base.apk",new int[]{4,2,1,3}),b=apk(dir,"split.apk",new int[]{2,1});
  var limits=new TrustedApkDexSource.Limits(2,8,1024,64,100000,10000);
  var set=new TrustedApkDexSource.SourceSetLimits(limits,2,16,200000,20000);
  var inputs=List.of(new TrustedApkDexSource.Input(a.toFile(),"base",false),new TrustedApkDexSource.Input(b.toFile(),"split",false));
  AtomicInteger active=new AtomicInteger(),peak=new AtomicInteger();AtomicBoolean firstDone=new AtomicBoolean(),thirdBeforeFirstDone=new AtomicBoolean();
  long start=System.nanoTime();
  var result=TrustedApkDexSource.mapAll(inputs,TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,set,(entry,bytes)->{
   int now=active.incrementAndGet();peak.accumulateAndGet(now,Math::max);
   try {if(entry.inputIndex==0&&entry.ordinal==1){Thread.sleep(750);firstDone.set(true);}else{if(entry.inputIndex==0&&entry.ordinal==3&&!firstDone.get())thirdBeforeFirstDone.set(true);Thread.sleep(140);}return entry.inputSlot+":"+entry.ordinal+":"+bytes[0];}
   finally{active.decrementAndGet();}
  });
  long elapsed=TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-start);
  List<String> actual=result.ordered.stream().map(x->x.value).toList();
  check(actual.equals(List.of("base:1:1","base:2:2","base:3:3","base:4:4","split:1:1","split:2:2")),"source order");
  check(result.sources==6&&result.inputs.get(0).sources==4&&result.inputs.get(1).sources==2,"source counts");
  check(peak.get()<=2&&active.get()==0,"bounded workers");check(thirdBeforeFirstDone.get()==fast,"completion refill");
  AtomicInteger failingActive=new AtomicInteger();boolean failed=false;
  try{TrustedApkDexSource.mapAll(inputs,TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,set,(entry,bytes)->{
    failingActive.incrementAndGet();try{if(entry.inputIndex==0&&entry.ordinal==2)throw new IllegalStateException("sentinel");Thread.sleep(100);return entry.name;}
    finally{failingActive.decrementAndGet();}
  });}catch(IllegalStateException ex){failed="sentinel".equals(ex.getMessage());}
  check(failed&&failingActive.get()==0,"failure propagation and worker drain");
  System.out.println("PASS fast="+fast+" elapsed_ms="+elapsed+" peak="+peak+" refilled_before_first_done="+thirdBeforeFirstDone+" ordered=6 sources=6 error=propagated workers=drained");
 }
}
