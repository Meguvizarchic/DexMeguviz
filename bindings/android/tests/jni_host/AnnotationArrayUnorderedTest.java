package io.github.jichuo1.dexmeguviz;
import java.nio.file.Files;
import java.nio.file.Path;

public final class AnnotationArrayUnorderedTest {
 static void ok(boolean v,String m){if(!v)throw new AssertionError(m);}
 static int run(AnnotationResult.Item item,String descriptor,String name,int[] k,long[] v,boolean equal,EncodedValue.Limits l){return AnnotationArrayMatcher.unorderedScalars(item,descriptor,1,name,k,v,equal,10,l);}
 public static void main(String[] args)throws Exception {
  var l=new EncodedValue.Limits(1024,100,10);int[] two={EncodedValue.INT,EncodedValue.INT};
  try(var s=NativeEngine.openRawDex(Files.readAllBytes(Path.of(args[0])),"unordered")){
   var item=Annotations.collect(s,Annotations.Target.classType(2),new Annotations.Limits(256,1000000,100000,10000)).item(0);
   ok(run(item,"Lfixture/Complex;","ints",two,new long[]{2,1},true,l)==1,"unordered equals");
   ok(run(item,"Lfixture/Complex;","ints",new int[]{EncodedValue.INT},new long[]{2},false,l)==1,"unordered subset");
   ok(run(item,"Lfixture/Complex;","ints",new int[]{EncodedValue.INT},new long[]{2},true,l)==0,"equal requires count");
   ok(run(item,"Lfixture/Complex;","ints",new int[0],new long[0],false,l)==1,"empty subset");
   ok(run(item,"Lfixture/Complex;","ints",new int[0],new long[0],true,l)==0,"empty equality");
   ok(run(item,"Lfixture/Complex;","ints",two,new long[]{1,1},false,l)==0,"multiplicity");
   ok(run(item,"Lfixture/Complex;","missing",new int[0],new long[0],false,l)==2,"missing remains unknown");
  }
  var negzero=AnnotationArrayMatcherTest.synthetic(new byte[]{0x1c,1,0x70,0,0,0,(byte)0x80});
  ok(run(negzero,"Lx;","x",new int[]{EncodedValue.FLOAT},new long[]{0},true,l)==1,"signed zero");
  var nan=AnnotationArrayMatcherTest.synthetic(new byte[]{0x1c,1,0x70,0,0,(byte)0xc0,0x7f});
  ok(run(nan,"Lx;","x",new int[]{EncodedValue.FLOAT},new long[]{0x7fc00000L},true,l)==0,"NaN");
  var nested=AnnotationArrayMatcherTest.synthetic(new byte[]{0x1c,1,0x1c,0});
  AnnotationArrayMatcherTest.fails(UnsupportedOperationException.class,()->run(nested,"Lx;","x",new int[0],new long[0],false,l));
  AnnotationArrayMatcherTest.fails(IllegalArgumentException.class,()->run(nested,"Lx;","x",new int[]{EncodedValue.STRING},new long[]{0},false,l));
  System.out.println("PASS unordered scalar multiplicity, IEEE zeros and NaN, limits and unknown");
 }
}
