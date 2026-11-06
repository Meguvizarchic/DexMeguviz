package io.github.jichuo1.dexmeguviz;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
public final class DexStreamSourcesTest {
 static void check(boolean x,String m){if(!x)throw new AssertionError(m);}
 public static void main(String[] args)throws Exception {
  check(args.length==3,"fixtures");byte[] first=Files.readAllBytes(Path.of(args[0])),second=Files.readAllBytes(Path.of(args[1])),apk=Files.readAllBytes(Path.of(args[2]));check(!Arrays.equals(first,second),"distinct source fixtures");
  try(var set=NativeEngine.openRawDexSet(new byte[][]{first,second},new String[]{"first","second"})){
   var a=new ByteArrayOutputStream();var b=new ByteArrayOutputStream();long[] sizes=DexStreamExport.writeAll(set,new OutputStream[]{a,b},Math.max(first.length,second.length),(long)first.length+second.length,73);
   check(Arrays.equals(sizes,new long[]{first.length,second.length})&&Arrays.equals(a.toByteArray(),first)&&Arrays.equals(b.toByteArray(),second),"ordered distinct sources");
   var only=new ByteArrayOutputStream();check(DexStreamExport.writeTo(set,1,only,second.length,91)==second.length&&Arrays.equals(only.toByteArray(),second),"selected distinct source");
  }
  Map<String,byte[]> entries=new HashMap<>();try(var zip=new ZipInputStream(new ByteArrayInputStream(apk))){for(ZipEntry e;(e=zip.getNextEntry())!=null;){if(e.getName().equals("classes.dex")||e.getName().equals("classes2.dex")||e.getName().equals("classes10.dex"))entries.put(e.getName(),zip.readAllBytes());zip.closeEntry();}}
  check(entries.size()==3,"expected compressed entries");String[] names={"classes.dex","classes2.dex","classes10.dex"};long total=0,max=0;for(String name:names){long n=entries.get(name).length;total+=n;max=Math.max(max,n);}
  try(var set=NativeEngine.openSources(new byte[][]{apk},new String[]{"apk"},new int[]{NativeEngine.SOURCE_APK},new boolean[]{false})){
   check(set.info().sourceCount()==3,"expanded source count");var a=new ByteArrayOutputStream();var b=new ByteArrayOutputStream();var c=new ByteArrayOutputStream();long[] n=DexStreamExport.writeAll(set,new OutputStream[]{a,b,c},max,total,67);
   check(n.length==3&&Arrays.equals(a.toByteArray(),entries.get(names[0]))&&Arrays.equals(b.toByteArray(),entries.get(names[1]))&&Arrays.equals(c.toByteArray(),entries.get(names[2])),"compressed DEX order and bytes");
   var only=new ByteArrayOutputStream();DexStreamExport.writeTo(set,2,only,max,71);check(Arrays.equals(only.toByteArray(),entries.get(names[2])),"compressed selected source");
  }
  System.out.println("PASS distinct source and deflated multi-DEX order/bytes");
 }
}
