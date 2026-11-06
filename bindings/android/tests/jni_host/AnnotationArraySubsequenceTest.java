package io.github.jichuo1.dexmeguviz;
import java.nio.file.Files;
import java.nio.file.Path;

public final class AnnotationArraySubsequenceTest {
 static void ok(boolean v,String s){if(!v)throw new AssertionError(s);}
 static void fails(Class<? extends Throwable> type,Runnable f){try{f.run();}catch(Throwable t){if(type.isInstance(t))return;throw t;}throw new AssertionError("expected "+type.getName());}
 static int sub(AnnotationResult.Item item,String descriptor,String name,int[] kinds,long[] values,EncodedValue.Limits limits){return AnnotationArrayMatcher.subsequence(item,descriptor,1,name,kinds,values,10,limits);}
 public static void main(String[] args)throws Exception {
  var l=new EncodedValue.Limits(1024,100,10);int[] none={};long[] zero={};
  byte[] dex=Files.readAllBytes(Path.of(args[0]));
  try(var snap=NativeEngine.openRawDex(dex,"seq")){
   var r=Annotations.collect(snap,Annotations.Target.classType(2),new Annotations.Limits(256,1000000,100000,10000));var i=r.item(0);
   ok(sub(i,"Lfixture/Complex;","ints",new int[]{4},new long[]{2},l)==AnnotationMatcher.MATCH,"real subsequence");
   ok(sub(i,"Lfixture/Complex;","ints",new int[]{4,4},new long[]{2,1},l)==AnnotationMatcher.NO_MATCH,"order");
   ok(sub(i,"Lfixture/Complex;","ints",none,zero,l)==AnnotationMatcher.MATCH,"empty on array");
   ok(sub(i,"Lfixture/Complex;","absent",none,zero,l)==AnnotationMatcher.UNKNOWN,"missing default unknown");
   ok(sub(i,"Lfixture/Complex;","n",none,zero,l)==AnnotationMatcher.NO_MATCH,"non-array");
   fails(EncodedValue.DecodeException.class,()->sub(i,"Lfixture/Complex;","ints",none,zero,new EncodedValue.Limits(1024,2,10)));
   fails(IllegalArgumentException.class,()->sub(i,"Lfixture/Complex;","ints",none,zero,new EncodedValue.Limits(1,100,10)));
  }
  var i=AnnotationArrayMatcherTest.synthetic(new byte[]{0x1c,4,4,1,4,2,4,1,4,3});
  ok(sub(i,"Lx;","x",new int[]{4,4,4},new long[]{1,1,3},l)==AnnotationMatcher.MATCH,"duplicates with gap");
  ok(sub(i,"Lx;","x",new int[]{4,4,4},new long[]{1,1,1},l)==AnnotationMatcher.NO_MATCH,"duplicate occurrence count");
  ok(sub(i,"Lx;","x",new int[]{4,4},new long[]{2,1},l)==AnnotationMatcher.MATCH,"ordered gap");
  ok(sub(i,"Lx;","x",new int[]{4,4},new long[]{3,1},l)==AnnotationMatcher.NO_MATCH,"reverse fails");
  var empty=AnnotationArrayMatcherTest.synthetic(new byte[]{0x1c,0});
  ok(sub(empty,"Lx;","x",none,zero,new EncodedValue.Limits(2,1,1))==AnnotationMatcher.MATCH,"empty on empty");
  ok(sub(empty,"Lx;","x",new int[]{4},new long[]{1},l)==AnnotationMatcher.NO_MATCH,"nonempty on empty");
  var nested=AnnotationArrayMatcherTest.synthetic(new byte[]{0x1c,2,4,1,0x1c,0});
  fails(UnsupportedOperationException.class,()->sub(nested,"Lx;","x",none,zero,l));
  fails(UnsupportedOperationException.class,()->sub(nested,"Lx;","x",new int[]{4},new long[]{1},l));
  var nestedAnn=AnnotationArrayMatcherTest.synthetic(new byte[]{0x1c,1,0x1d,0,0});
  fails(UnsupportedOperationException.class,()->sub(nestedAnn,"Lx;","x",none,zero,l));
  fails(IllegalArgumentException.class,()->sub(i,"Lx;","x",new int[]{4},new long[]{1},new EncodedValue.Limits(100,1,5)));
  System.out.println("PASS independent ordered subsequence, duplicates, empty, unknown, nested rejection and bounds");
 }
}
