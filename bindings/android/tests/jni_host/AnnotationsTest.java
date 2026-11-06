package io.github.jichuo1.dexmeguviz;
import java.nio.file.Files;
import java.nio.file.Path;

public final class AnnotationsTest {
 static void check(boolean ok,String m){if(!ok)throw new AssertionError(m);}
 static void status(int expected,Runnable r){try{r.run();throw new AssertionError("expected native status "+expected);}catch(NativeEngine.NativeFailure e){check(e.status==expected,"status "+e.status);}}
 public static void main(String[] args)throws Exception {
  byte[] dex=Files.readAllBytes(Path.of(args[0]));var limits=new Annotations.Limits(256,1000000,100000,10000);AnnotationResult held;
  try(var snapshot=NativeEngine.openRawDex(dex,"ann")){
   held=Annotations.collect(snapshot,Annotations.Target.classType(2),limits);check(held.targetKind==Annotations.CLASS&&held.sourceIndex==0&&held.itemCount()==2,"class annotations");
   for(int i=0;i<held.itemCount();i++){var item=held.item(i);byte[] encoded=item.encodedAnnotation();check(java.util.Arrays.equals(encoded,java.util.Arrays.copyOfRange(dex,(int)item.encodedOffset,(int)item.encodedOffset+encoded.length)),"annotation raw bytes");for(int k=0;k<item.elementCount();k++){var element=item.element(k);byte[] value=element.encodedValue();check(java.util.Arrays.equals(value,java.util.Arrays.copyOfRange(dex,(int)element.valueOffset,(int)element.valueOffset+value.length)),"element raw bytes");}}
   var first=held.item(0);check(first.visibility==1&&first.typeIndex==3&&first.elementCount()==5&&first.descriptor!=null&&first.encodedAnnotation().length>0,"class annotation metadata");
   var array=first.element(0);var nested=first.element(2);check(array.name.equals("ints")&&array.valueKind==0x1c&&array.encodedValue().length>=4,"array encoded value");check(nested.valueKind==0x1d&&nested.encodedValue().length>1,"nested encoded value");
   byte[] copy=nested.encodedValue();int original=copy[0];copy[0]^=1;check(nested.encodedValue()[0]==original,"element defensive copy");byte[] body=first.encodedAnnotation();byte prev=body[0];body[0]^=1;check(first.encodedAnnotation()[0]==prev,"annotation defensive copy");
   check(Annotations.collect(snapshot,Annotations.Target.field(0),limits).itemCount()==1,"field annotations");check(Annotations.collect(snapshot,Annotations.Target.method(2),limits).itemCount()==1,"method annotations");check(Annotations.collect(snapshot,Annotations.Target.parameter(2,0),limits).itemCount()==1,"parameter annotations");check(Annotations.collect(snapshot,Annotations.Target.method(1),limits).itemCount()==0,"known empty annotations");
   status(3,()->Annotations.collect(snapshot,Annotations.Target.classType(8),limits));status(1,()->Annotations.collect(snapshot,Annotations.Target.parameter(2,1),limits));status(4,()->Annotations.collect(snapshot,Annotations.Target.classType(2),new Annotations.Limits(256,1000000,1,0)));status(4,()->Annotations.collect(snapshot,Annotations.Target.classType(2),new Annotations.Limits(1,1000000,100000,0)));
  }
  check(held.item(0).element(2).encodedValue().length>1,"result survives snapshot close");
  try(var set=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"one","two"})){
   var a=Annotations.collect(set,0,Annotations.Target.classType(2),limits);var b=Annotations.collect(set,1,Annotations.Target.classType(2),limits);check(a.sourceIndex==0&&b.sourceIndex==1&&!a.occurrenceId.equals(b.occurrenceId)&&a.contentId.equals(b.contentId),"source occurrences");}
  try{AnnotationResult.decode(new byte[]{0,0,0,0});throw new AssertionError("invalid wire accepted");}catch(IllegalStateException expected){}
  System.out.println("PASS annotation targets, nested encoded bytes, bounds and copied lifetime");
 }
}
