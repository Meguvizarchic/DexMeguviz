package io.github.jichuo1.dexmeguviz;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public final class BoundAnnotationTextTest {
 static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
 static void fails(Class<? extends Throwable> type,Runnable f){try{f.run();}catch(Throwable t){if(type.isInstance(t))return;throw t;}throw new AssertionError("expected "+type.getName());}
 static void u32(ByteArrayOutputStream b,long n){for(int i=0;i<4;i++)b.write((int)(n>>>(i*8))&255);}
 static void u64(ByteArrayOutputStream b,long n){for(int i=0;i<8;i++)b.write((int)(n>>>(i*8))&255);}
 static void ascii(ByteArrayOutputStream b,String s){if(s==null){u32(b,0xffffffffL);return;}byte[] v=s.getBytes(StandardCharsets.US_ASCII);u32(b,v.length);b.writeBytes(v);}
 static AnnotationResult changedIdentity(AnnotationResult r,long sourceIndex,String occurrenceId){
  var b=new ByteArrayOutputStream();u32(b,0x41474d44);u32(b,sourceIndex);u32(b,r.inputIndex);u32(b,r.targetKind);u32(b,r.targetRef);u32(b,r.parameterIndex);u32(b,0);u64(b,r.workUnits);
  for(String s:new String[]{r.snapshotId,r.slot,r.role,r.sourceSha256,r.contentId,occurrenceId,r.logicalDexId,r.archiveSha256,r.archiveEntryName})ascii(b,s);
  u32(b,r.archiveEntryIndex);u64(b,r.sourceBytes);u32(b,r.crcVerified?1:0);u32(b,r.headerConsistencyVerified?1:0);u32(b,r.expectedDigestVerified?1:0);return AnnotationResult.decode(b.toByteArray());
 }
 static int match(BoundAnnotationText b,String expected){return b.text(0,"Lfixture/Complex;",1,"str",EncodedValue.STRING,expected,20,new EncodedValue.Limits(1024,100,20));}
 public static void main(String[] args)throws Exception {
  byte[] dex=Files.readAllBytes(Path.of(args[0])),other=Files.readAllBytes(Path.of(args[1]));
  var al=new Annotations.Limits(256,1000000,100000,10000);var vl=new EncodedValue.Limits(1024,100,20);
  AnnotationResult result;
  try(var original=NativeEngine.openRawDex(dex,"same")) { result=Annotations.collect(original,Annotations.Target.classType(2),al); }
  try(var reopened=NativeEngine.openRawDex(dex,"same")) {
   String expected=DexSourceExport.stringAt(reopened,42,1024);var bound=BoundAnnotationText.bind(result,reopened,1024);
   check(match(bound,expected)==AnnotationMatcher.MATCH,"reopened static identity same; not same object");
   check(match(bound,expected+"!")==AnnotationMatcher.NO_MATCH,"text mismatch");
   check(bound.text(0,"Lfixture/Complex;",1,"missing",EncodedValue.STRING,expected,20,vl)==AnnotationMatcher.UNKNOWN,"missing/default unknown");
   check(bound.text(0,"Lfixture/Complex;",1,"type",EncodedValue.TYPE,DexSourceExport.typeAt(reopened,8,1024),20,vl)==AnnotationMatcher.MATCH,"type text");
   fails(IllegalArgumentException.class,()->BoundAnnotationText.bind(result,reopened,0));
   fails(IllegalArgumentException.class,()->bound.text(0,"Lfixture/Complex;",1,"str",EncodedValue.STRING,expected,1,vl));
   String typeText=DexSourceExport.typeAt(reopened,8,1024);check(typeText.length()>1,"limit fixture");
   var low=BoundAnnotationText.bind(result,reopened,1);
   try { low.text(0,"Lfixture/Complex;",1,"type",EncodedValue.TYPE,typeText,20,vl);throw new AssertionError("expected text budget failure"); }
   catch(NativeEngine.NativeFailure e) { check(e.status==4,"text budget status"); }
   fails(IllegalArgumentException.class,()->bound.text(0,"Lfixture/Complex;",1,"str",EncodedValue.STRING,expected,20,new EncodedValue.Limits(1,100,20)));
  }
  try(var wrong=NativeEngine.openRawDex(dex,"different-slot")){fails(IllegalArgumentException.class,()->BoundAnnotationText.bind(result,wrong,100));}
  try(var set=NativeEngine.openRawDexSet(new byte[][]{other,dex},new String[]{"other","target"})) {
   var fromSecond=Annotations.collect(set,1,Annotations.Target.classType(2),al);
   var bound=BoundAnnotationText.bind(fromSecond,set,1024);String expected=DexSourceExport.stringAt(set,1,42,1024);
   check(match(bound,expected)==AnnotationMatcher.MATCH,"second distinct source");
   fails(IllegalArgumentException.class,()->BoundAnnotationText.bind(changedIdentity(fromSecond,0,fromSecond.occurrenceId),set,1024));
   fails(IllegalArgumentException.class,()->BoundAnnotationText.bind(changedIdentity(fromSecond,1,"wrong"),set,1024));
   try(var otherOrder=NativeEngine.openRawDexSet(new byte[][]{dex,other},new String[]{"target","other"})){fails(IllegalArgumentException.class,()->BoundAnnotationText.bind(fromSecond,otherOrder,1024));}
   var starting=new CountDownLatch(1);
   Thread closer=new Thread(()->{starting.countDown();set.close();});
   synchronized(set){
    closer.start();check(starting.await(5,TimeUnit.SECONDS),"closer started");
    check(match(bound,expected)==AnnotationMatcher.MATCH,"identity and resolution while holding close lock");
    check(closer.isAlive(),"close cannot pass held monitor");
   }
   closer.join(5000);check(!closer.isAlive(),"close finishes after unlock");
   fails(IllegalStateException.class,()->match(bound,expected));
   check(fromSecond.itemCount()==2,"copied result survives close");
  }
  System.out.println("PASS bound source identity, two distinct sources, static reopen, unknown, limits and synchronized close");
 }
}
