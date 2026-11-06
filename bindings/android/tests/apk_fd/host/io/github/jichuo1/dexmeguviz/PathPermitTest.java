package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.concurrent.*;
public final class PathPermitTest {
 static final ApkFdLimits LIMITS=new ApkFdLimits(128L<<20,64L<<20,64L<<20,128L<<20,32L<<20,64L<<20,1000,16L<<20,8L<<20);
 static byte[] path(String p){return Path.of(p).toAbsolutePath().toString().getBytes(StandardCharsets.UTF_8);}
 static NativeEngine.SourceSetSnapshot open(byte[] p){return NativeEngine.openApkPaths(new byte[][]{p},new String[]{"base"},new boolean[]{false},null,LIMITS);}
 static void expect(int status,Runnable r){try{r.run();throw new AssertionError("expected native failure");}catch(NativeEngine.NativeFailure e){if(e.status!=status)throw new AssertionError("expected "+status+" got "+e.status,e);}}
 public static void main(String[] args)throws Exception{
  if(args.length!=2)throw new AssertionError("small apk and missing path");NativeEngine.abiVersion();byte[] good=path(args[0]),missing=path(args[1]);
  ExecutorService pool=Executors.newFixedThreadPool(64);ArrayList<Future<?>> futures=new ArrayList<>();PathTestHooks.arm();
  try{
   for(int i=0;i<64;i++)futures.add(pool.submit(()->{try(var snapshot=open(good)){if(snapshot.info().inputCount()!=1)throw new AssertionError("input");}}));
   long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(30);while(PathTestHooks.entered()!=64&&System.nanoTime()<until)Thread.sleep(10);
   if(PathTestHooks.entered()!=64||PathTestHooks.opened()!=0)throw new AssertionError("64 reservations must precede opens");
   expect(4,()->open(good));if(PathTestHooks.opened()!=0)throw new AssertionError("65th opened path before reservation");
  }finally{PathTestHooks.release();}
  try{for(var f:futures)f.get(60,TimeUnit.SECONDS);}finally{pool.shutdownNow();}
  for(int i=0;i<70;i++)expect(8,()->open(missing));try(var success=open(good)){if(success.info().inputCount()!=1)throw new AssertionError("permit leaked after missing path");}
  for(int i=0;i<70;i++){PathTestHooks.failNextClose();expect(6,()->open(good));}
  try(var success=open(good)){if(success.info().inputCount()!=1)throw new AssertionError("published snapshot leaked after close failure");}
  System.out.println("PASS path permit pre-open bound, failure release and close rollback");
 }
}
