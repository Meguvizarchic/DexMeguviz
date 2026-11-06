package io.github.jichuo1.dexmeguviz;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class AnnotationArrayMatcherTest {
 static void ok(boolean value,String label){if(!value)throw new AssertionError(label);}
 static void fails(Class<? extends Throwable> type,Runnable f){try{f.run();}catch(Throwable t){if(type.isInstance(t))return;throw t;}throw new AssertionError("expected "+type.getName());}
 static void u32(ByteArrayOutputStream b,long n){for(int i=0;i<4;i++)b.write((int)(n>>>(i*8))&255);}
 static void u64(ByteArrayOutputStream b,long n){for(int i=0;i<8;i++)b.write((int)(n>>>(i*8))&255);}
 static void ascii(ByteArrayOutputStream b,String s){if(s==null){u32(b,0xffffffffL);return;}byte[] v=s.getBytes(StandardCharsets.US_ASCII);u32(b,v.length);b.writeBytes(v);}
 static void text(ByteArrayOutputStream b,String s){u32(b,s.length());for(int i=0;i<s.length();i++){b.write(s.charAt(i)&255);b.write(s.charAt(i)>>>8);}}
 static void blob(ByteArrayOutputStream b,byte[] x){u32(b,x.length);b.writeBytes(x);}
 static AnnotationResult.Item synthetic(byte[] encoded){
  var b=new ByteArrayOutputStream();u32(b,0x41474d44);u32(b,0);u32(b,0);u32(b,0);u32(b,2);u32(b,0xffffffffL);u32(b,1);u64(b,0);
  for(int i=0;i<7;i++)ascii(b,"s");ascii(b,null);ascii(b,null);u32(b,0xffffffffL);u64(b,0);u32(b,0);u32(b,0);u32(b,0);
  u32(b,1);u32(b,0);u32(b,1);u32(b,10);u32(b,11);text(b,"Lx;");byte[] full=new byte[encoded.length+2];System.arraycopy(encoded,0,full,2,encoded.length);blob(b,full);
  u32(b,0);u32(b,encoded[0]&31);u32(b,(encoded[0]&255)>>>5);u32(b,13);text(b,"x");blob(b,encoded);return AnnotationResult.decode(b.toByteArray()).item(0);
 }
 static int exact(AnnotationResult.Item i,String descriptor,String name,int[] kinds,long[] values,EncodedValue.Limits limits){return AnnotationArrayMatcher.exact(i,descriptor,1,name,kinds,values,10,limits);}
 public static void main(String[] args)throws Exception {
  var limits=new EncodedValue.Limits(1024,100,10);var emptyKinds=new int[0];var emptyValues=new long[0];
  byte[] dex=Files.readAllBytes(Path.of(args[0]));
  try(var snapshot=NativeEngine.openRawDex(dex,"array")) {
   var r=Annotations.collect(snapshot,Annotations.Target.classType(2),new Annotations.Limits(256,1000000,100000,10000));var item=r.item(0);
   int[] both={EncodedValue.INT,EncodedValue.INT};
   ok(exact(item,"Lfixture/Complex;","ints",both,new long[]{1,2},limits)==AnnotationMatcher.MATCH,"real int array");
   ok(exact(item,"Lfixture/Complex;","ints",both,new long[]{2,1},limits)==AnnotationMatcher.NO_MATCH,"order");
   ok(exact(item,"Lfixture/Complex;","ints",new int[]{EncodedValue.INT},new long[]{1},limits)==AnnotationMatcher.NO_MATCH,"length");
   ok(exact(item,"Lfixture/Complex;","absent",emptyKinds,emptyValues,limits)==AnnotationMatcher.UNKNOWN,"unknown default");
   ok(exact(item,"Lfixture/Complex;","n",emptyKinds,emptyValues,limits)==AnnotationMatcher.NO_MATCH,"not array");
   fails(EncodedValue.DecodeException.class,()->exact(item,"Lfixture/Complex;","ints",emptyKinds,emptyValues,new EncodedValue.Limits(1024,2,10)));
   fails(EncodedValue.DecodeException.class,()->exact(item,"Lfixture/Complex;","ints",emptyKinds,emptyValues,new EncodedValue.Limits(1024,100,1)));
   fails(IllegalArgumentException.class,()->exact(item,"Lfixture/Complex;","ints",emptyKinds,emptyValues,new EncodedValue.Limits(1,100,10)));
  }
  var empty=synthetic(new byte[]{0x1c,0});
  ok(exact(empty,"Lx;","x",emptyKinds,emptyValues,new EncodedValue.Limits(2,1,1))==AnnotationMatcher.MATCH,"empty array");
  var mixed=synthetic(new byte[]{0x1c,6,0,(byte)255,0x23,(byte)255,(byte)255,0x70,0,0,0,(byte)0x80,0x17,2,0x3f,0x1e});
  int[] kinds={EncodedValue.BYTE,EncodedValue.CHAR,EncodedValue.FLOAT,EncodedValue.STRING,EncodedValue.BOOLEAN,EncodedValue.NULL};
  long[] values={-1,65535,0x80000000L,2,1,0};
  ok(exact(mixed,"Lx;","x",kinds,values,limits)==AnnotationMatcher.MATCH,"mixed raw values");
  values[3]=3;ok(exact(mixed,"Lx;","x",kinds,values,limits)==AnnotationMatcher.NO_MATCH,"local index mismatch");
  var nestedArray=synthetic(new byte[]{0x1c,2,4,3,0x1c,0});
  var nestedAnnotation=synthetic(new byte[]{0x1c,1,0x1d,0,0});
  fails(UnsupportedOperationException.class,()->exact(nestedArray,"Lx;","x",emptyKinds,emptyValues,limits));
  fails(UnsupportedOperationException.class,()->exact(nestedAnnotation,"Lx;","x",emptyKinds,emptyValues,limits));
  fails(IllegalArgumentException.class,()->exact(empty,"Lx;","x",new int[]{EncodedValue.ARRAY},new long[]{0},limits));
  fails(IllegalArgumentException.class,()->exact(empty,"Lx;","x",new int[]{EncodedValue.INT},new long[]{0},new EncodedValue.Limits(10,1,10)));
  System.out.println("PASS explicit exact array, empty, order, mixed values, unknown, budgets and nested rejection");
 }
}
