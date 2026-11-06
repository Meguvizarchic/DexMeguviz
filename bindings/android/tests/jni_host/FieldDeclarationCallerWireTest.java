package io.github.jichuo1.dexmeguviz;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
public final class FieldDeclarationCallerWireTest {
 static void check(boolean ok,String message){if(!ok)throw new AssertionError(message);}
 static byte[] pattern(int... values){ByteBuffer b=ByteBuffer.allocate(values.length*4).order(ByteOrder.LITTLE_ENDIAN);for(int v:values)b.putInt(v);return b.array();}
 static int find(byte[] bytes,byte[] needle){outer:for(int i=0;i<=bytes.length-needle.length;i++){for(int j=0;j<needle.length;j++)if(bytes[i+j]!=needle[j])continue outer;return i;}throw new AssertionError("pattern absent");}
 static void put(byte[] bytes,int at,int word,int value){ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(at+word*4,value);}
 static void rejected(byte[] bytes,String expected){try{UseGraphResult.decode(bytes);throw new AssertionError("forged wire accepted");}catch(IllegalStateException e){check(expected.equals(e.getMessage()),"unexpected rejection: "+e);}}
 public static void main(String[] args)throws Exception{
  check(args.length==2,"args");Path dir=Path.of(args[0]);String[] names={"caller-a.dex","caller-b.dex","child.dex","parent.dex","object.dex"},slots={"callerA","callerB","child","parent","object"};byte[][] data=new byte[names.length][];for(int i=0;i<names.length;i++)data[i]=Files.readAllBytes(dir.resolve(names[i]));byte[] query=Files.readString(Path.of(args[1]),StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8);
  try(NativeEngine.SourceSetSnapshot snapshot=NativeEngine.openRawDexSet(data,slots)){
   var token=NativeEngine.SourceSetSnapshot.class.getDeclaredField("token");token.setAccessible(true);var nativeQuery=NativeEngine.class.getDeclaredMethod("nativeQueryFieldDeclarationGraph",long.class,byte[].class,boolean.class);nativeQuery.setAccessible(true);
   byte[] raw=(byte[])nativeQuery.invoke(null,token.getLong(snapshot),query,true);check(UseGraphResult.decode(raw).rowCount()==4,"valid wire");
   byte[] root=pattern(1,2,0,-1,1,0,0,0,-1,0);int at=find(raw,root);byte[] bad=raw.clone();put(bad,at,6,17);rejected(bad,"invalid field declaration path");
   byte[] next=pattern(1,3,0,-1,1,0,1,2,-1,0);at=find(raw,next);bad=raw.clone();put(bad,at,0,2);put(bad,at,5,1);put(bad,at,6,0);put(bad,at,7,-1);rejected(bad,"field declaration after terminal");
   byte[] link=pattern(4,0,0,0,-1,9,0,0,0);at=find(raw,link);bad=raw.clone();put(bad,at,6,1);rejected(bad,"invalid v19 caller link");
   bad=raw.clone();put(bad,at,8,-1);rejected(bad,"invalid v19 value identity");
   try{UseGraphResult.decode(java.util.Arrays.copyOf(raw,raw.length-1));throw new AssertionError("truncated wire accepted");}catch(IllegalStateException expected){}
  }
  System.out.println("PASS v19 caller wire rejects corrupted paths, double terminal and caller identity");
 }
}
