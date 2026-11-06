package io.github.jichuo1.dexmeguviz;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public final class MethodFactsWireControl {
 static void reject(byte[] input){try{MethodFactsResult.decode(input);throw new AssertionError("bad wire accepted");}catch(IllegalStateException expected){}}
 public static void main(String[] args)throws Exception{
  byte[] dex=Files.readAllBytes(Path.of(args[0]));try(var snapshot=NativeEngine.openRawDex(dex,"wire")){
   var field=NativeEngine.Snapshot.class.getDeclaredField("token");field.setAccessible(true);
   var nativeMethod=NativeEngine.class.getDeclaredMethod("nativeInspectMethodFacts",long.class,int.class,long.class,boolean.class,int.class,int.class,long.class,long.class);nativeMethod.setAccessible(true);
   byte[] valid=(byte[])nativeMethod.invoke(null,field.getLong(snapshot),0,3L,false,63,128,1000000L,0L);
   if(MethodFactsResult.decode(valid).stringCount()!=1)throw new AssertionError("valid wire");
   reject(Arrays.copyOf(valid,valid.length-1));byte[] zeroMask=valid.clone();Arrays.fill(zeroMask,36,40,(byte)0);reject(zeroMask);
   byte[] falseMask=valid.clone();falseMask[36]=1;falseMask[37]=falseMask[38]=falseMask[39]=0;reject(falseMask);
   byte[] overflow=valid.clone();overflow[71]=(byte)0x80;reject(overflow);
  }
  System.out.println("PASS method facts wire truncation, masks and unsigned counters");
 }
}
