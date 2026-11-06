import io.github.jichuo1.dexmeguviz.NativeEngine;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.HexFormat;
public class DirectFillLimitsTest {
 static void check(boolean v,String m){if(!v)throw new AssertionError(m);}
 static void budget(Runnable r){try{r.run();throw new AssertionError("expected budget failure");}catch(NativeEngine.NativeFailure e){check(e.status==4,"wrong status="+e.status);}}
 public static void main(String[] args)throws Exception{
  byte[] small=Files.readAllBytes(Path.of(args[0]));byte[] large=Files.readAllBytes(Path.of(args[1]));
  try(var a=NativeEngine.openRawDex(small,"slot");var b=NativeEngine.openRawDexWithLimits(small,"slot",32L<<20,256L<<20)){var x=a.info();var y=b.info();check(x.sourceSha256.equals(y.sourceSha256)&&x.snapshotId.equals(y.snapshotId)&&x.methodDefCount==y.methodDefCount&&!y.sourceScopeComplete,"small identity");}
  check(large.length>(16<<20),"fixture size");budget(()->NativeEngine.openRawDex(large,"slot"));budget(()->NativeEngine.openRawDexWithLimits(large,"slot",16L<<20,256L<<20));budget(()->NativeEngine.openRawDexWithLimits(large,"slot",32L<<20,8L<<20));
  String digest=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(large));try(var snap=NativeEngine.openRawDexWithLimits(large,"slot",32L<<20,256L<<20)){var i=snap.info();check(i.stringCount==10&&i.sourceBytes==large.length&&digest.equals(i.sourceSha256)&&!i.sourceScopeComplete,"large metadata");large[0]=0;check(snap.info().sourceSha256.equals(digest),"immutable snapshot");}
  System.out.println("PASS default compatibility, explicit limits, large DEX and immutable snapshot");
 }
}