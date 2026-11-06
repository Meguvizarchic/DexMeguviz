package io.github.jichuo1.dexmeguviz;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
public final class DexSourceExportTest {
 private static void check(boolean b,String msg){if(!b)throw new AssertionError(msg);}
 private static void failure(int status,Runnable op){try{op.run();throw new AssertionError("expected native failure");}catch(NativeEngine.NativeFailure e){check(e.status==status,"failure status "+e.status);}}
 public static void main(String[] args)throws Exception{
  byte[] dex=Files.readAllBytes(Path.of(args[0]));byte[] saved;
  NativeEngine.Snapshot snapshot=NativeEngine.openRawDex(dex,"test");
  saved=DexSourceExport.copy(snapshot,dex.length);check(Arrays.equals(dex,saved),"raw copy");saved[0]^=1;check(Arrays.equals(dex,DexSourceExport.copy(snapshot,dex.length)),"independent copy");
  failure(4,()->DexSourceExport.copy(snapshot,dex.length-1));try{DexSourceExport.copy(snapshot,0);throw new AssertionError("zero limit");}catch(IllegalArgumentException expected){}
  snapshot.close();failure(7,()->DexSourceExport.copy(snapshot,dex.length));
  try(var set=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"one","two"})){check(Arrays.equals(dex,DexSourceExport.copy(set,1,dex.length)),"source set index");failure(1,()->DexSourceExport.copy(set,2,dex.length));}
  var buffer=new java.io.ByteArrayOutputStream();try(var zip=new java.util.zip.ZipOutputStream(buffer)){for(String name:new String[]{"classes.dex","classes2.dex"}){zip.putNextEntry(new java.util.zip.ZipEntry(name));zip.write(dex);zip.closeEntry();}}
  try(var set=NativeEngine.openSources(new byte[][]{buffer.toByteArray()},new String[]{"apk"},new int[]{NativeEngine.SOURCE_APK},new boolean[]{false})){check(Arrays.equals(dex,DexSourceExport.copy(set,0,dex.length))&&Arrays.equals(dex,DexSourceExport.copy(set,1,dex.length)),"decompressed APK sources");}
  System.out.println("PASS static DEX bytes, source occurrence, size limit, close and copied lifetime");
 }
}
