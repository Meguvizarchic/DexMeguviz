package io.github.jichuo1.dexmeguviz;
import java.nio.file.*;
public final class DexSourceSymbolsTest {
 static void check(boolean x){if(!x)throw new AssertionError();}
 public static void main(String[] a)throws Exception{
  byte[] data=Files.readAllBytes(Path.of(a[0]));
  try(var s=NativeEngine.openRawDex(data,"symbol")){
   var r=Annotations.collect(s,Annotations.Target.classType(2),new Annotations.Limits(256,1000000,100000,0));
   var item=r.item(0);var element=item.element(0);
   check(DexSourceExport.stringAt(s,element.nameIndex,100).equals(element.name));
   check(DexSourceExport.typeAt(s,item.typeIndex,100).equals(item.descriptor));
   try{DexSourceExport.stringAt(s,element.nameIndex,1);throw new AssertionError();}catch(NativeEngine.NativeFailure e){check(e.status==4);}
   try{DexSourceExport.stringAt(s,0xffffffffL,100);throw new AssertionError();}catch(NativeEngine.NativeFailure e){check(e.status==1);}
  }
  try(var s=NativeEngine.openRawDexSet(new byte[][]{data,data},new String[]{"a","b"})){
   var item=Annotations.collect(s,1,Annotations.Target.classType(2),new Annotations.Limits(256,1000000,100000,0)).item(0);
   check(DexSourceExport.typeAt(s,1,item.typeIndex,100).equals(item.descriptor));
  }
  final char[][] expected={{(char)0xd800},{(char)0xdc00},{(char)0xd800,'x',(char)0xdc00,0,(char)0xd83d,(char)0xde00},{}};
  for(int i=0;i<expected.length;i++){
   byte[] unicode=Files.readAllBytes(Path.of(a[i+1]));String text;
   try(var s=NativeEngine.openRawDex(unicode,"unicode")){
    text=DexSourceExport.stringAt(s,i==3?0:7,Math.max(1,expected[i].length));
    check(text.equals(new String(expected[i])));
    if(expected[i].length>1)try{DexSourceExport.stringAt(s,7,expected[i].length-1);throw new AssertionError();}catch(NativeEngine.NativeFailure e){check(e.status==4);}
   }
   check(text.equals(new String(expected[i])));
  }
  System.out.println("PASS source-local string/type and bounded UTF-16 symbols");
 }
}
