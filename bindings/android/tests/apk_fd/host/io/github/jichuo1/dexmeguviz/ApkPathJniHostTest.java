package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
public final class ApkPathJniHostTest {
 static void check(boolean v,String text){if(!v)throw new AssertionError(text);}
 static void failure(int status,Runnable r){try{r.run();throw new AssertionError("expected NativeFailure");}catch(NativeEngine.NativeFailure e){check(e.status==status,"status "+e.status);}}
 static void invalid(Runnable r){try{r.run();throw new AssertionError("expected invalid");}catch(IllegalArgumentException expected){}}
 static final ApkFdLimits LIMITS=new ApkFdLimits(256L<<20,128L<<20,128L<<20,256L<<20,64L<<20,128L<<20,1000,16L<<20,8L<<20);
 static NativeEngine.SourceSetSnapshot open(byte[][] paths){String[] slots=new String[paths.length];boolean[] allow=new boolean[paths.length];for(int i=0;i<slots.length;i++)slots[i]="p"+i;return NativeEngine.openApkPaths(paths,slots,allow,null,LIMITS);}
 public static void main(String[] args)throws Exception{
  check(args.length==3,"helper, small, output dir");System.load(args[0]);Path fixture=Path.of(args[1]),out=Path.of(args[2]);Path unicode=out.resolve("path-\ud83d\ude80.apk");Files.copy(fixture,unicode);String raw=unicode.toAbsolutePath().toString();byte[] valid=raw.getBytes(StandardCharsets.UTF_8);
  try(var s=open(new byte[][]{valid})){check(s.info().inputCount()==1&&!s.info().sourceScopeComplete&&s.info().sourceCount()>0,"unicode native path open");}
  invalid(()->open(new byte[][]{new byte[]{(byte)0xc0,(byte)0x80}}));invalid(()->open(new byte[][]{new byte[]{'/',0,'a'}}));
  invalid(()->open(new byte[][]{"relative.apk".getBytes(StandardCharsets.UTF_8)}));
  String root=Path.of(raw).getRoot().toString();invalid(()->open(new byte[][]{root.getBytes(StandardCharsets.UTF_8)}));
  byte[] traversal=(out.toAbsolutePath().toString()+java.io.File.separator+".."+java.io.File.separator+"x.apk").getBytes(StandardCharsets.UTF_8);invalid(()->open(new byte[][]{traversal}));
  byte[] missing=out.resolve("missing.apk").toAbsolutePath().toString().getBytes(StandardCharsets.UTF_8);failure(8,()->open(new byte[][]{valid,missing}));
  int before=FdHarness.handleCount();check(before>0,"handle count");for(int i=0;i<24;i++)failure(8,()->open(new byte[][]{valid,missing}));int after=FdHarness.handleCount();check(after>=0&&after<=before+2,"possible handle leak "+before+" -> "+after);
  System.out.println("PASS native path UTF8, rollback and bounded handle count");
 }
}
