package io.github.jichuo1.dexmeguviz;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public final class DexStreamExportTest {
 private static void check(boolean x,String message){if(!x)throw new AssertionError(message);}
 private static final class Probe extends ByteArrayOutputStream {
  boolean flushed,closed;
  @Override public void flush(){flushed=true;}
  @Override public void close(){closed=true;}
 }
 private static final class FailAfter extends OutputStream {
  final ByteArrayOutputStream bytes=new ByteArrayOutputStream();int calls;
  @Override public void write(int b)throws IOException {throw new IOException("unexpected single byte");}
  @Override public void write(byte[] b,int off,int len)throws IOException {if(calls++>0)throw new IOException("expected failure");bytes.write(b,off,len);}
 }
 private static final class CloseDuringWrite extends OutputStream {
  final NativeEngine.Snapshot snapshot;int calls,bytes;
  CloseDuringWrite(NativeEngine.Snapshot snapshot){this.snapshot=snapshot;}
  @Override public void write(int b)throws IOException {throw new IOException("unexpected single byte");}
  @Override public void write(byte[] b,int off,int len)throws IOException {
   calls++;bytes+=len;if(calls==1){Thread closer=new Thread(snapshot::close,"test-snapshot-close");closer.setDaemon(true);closer.start();
    try{closer.join(5000);}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException("interrupted",e);}
    if(closer.isAlive())throw new AssertionError("snapshot monitor held while calling output stream");}
  }
 }
 public static void main(String[] args)throws Exception {
  check(args.length==2,"fixture arguments");byte[] dex=Files.readAllBytes(Path.of(args[0])),resource=Files.readAllBytes(Path.of(args[1]));
  try(NativeEngine.Snapshot s=NativeEngine.openRawDex(dex,"stream")){
   Probe out=new Probe();check(DexStreamExport.writeTo(s,out,dex.length,37)==dex.length,"single count");check(Arrays.equals(dex,out.toByteArray()),"single bytes");check(!out.closed&&!out.flushed,"caller owns stream");
   Probe fail=new Probe();try{DexStreamExport.writeTo(s,fail,dex.length-1,37);throw new AssertionError("limit accepted");}catch(IllegalArgumentException expected){}check(fail.size()==0,"limit preflight");
   try{DexStreamExport.writeTo(s,fail,dex.length,0);throw new AssertionError("zero chunk accepted");}catch(IllegalArgumentException expected){}check(fail.size()==0,"invalid chunk preflight");
   FailAfter partial=new FailAfter();try{DexStreamExport.writeTo(s,partial,dex.length,37);throw new AssertionError("write failure lost");}catch(IOException expected){}check(partial.bytes.size()==37,"partial stream retained");
  }
  NativeEngine.Snapshot closed=NativeEngine.openRawDex(dex,"close");CloseDuringWrite closing=new CloseDuringWrite(closed);
  try{DexStreamExport.writeTo(closed,closing,dex.length,37);throw new AssertionError("closed snapshot accepted");}catch(NativeEngine.NativeFailure expected){check(expected.status==7,"closed status");}
  check(closing.calls==1&&closing.bytes==37,"close callback and no lock held");closed.close();
  try(NativeEngine.SourceSetSnapshot set=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"one","two"})){
   Probe first=new Probe(),second=new Probe();long[] counts=DexStreamExport.writeAll(set,new OutputStream[]{first,second},dex.length,(long)dex.length*2,31);
   check(Arrays.equals(counts,new long[]{dex.length,dex.length}),"source counts");check(Arrays.equals(dex,first.toByteArray())&&Arrays.equals(dex,second.toByteArray()),"source occurrence bytes");check(!first.closed&&!second.flushed,"source stream ownership");
   Probe selected=new Probe();check(DexStreamExport.writeTo(set,1,selected,dex.length,29)==dex.length&&Arrays.equals(dex,selected.toByteArray()),"selected source");
   Probe a=new Probe(),b=new Probe();try{DexStreamExport.writeAll(set,new OutputStream[]{a,b},dex.length,(long)dex.length*2-1,31);throw new AssertionError("total limit accepted");}catch(IllegalArgumentException expected){}check(a.size()==0&&b.size()==0,"total limit preflight");
   try{DexStreamExport.writeAll(set,new OutputStream[]{a,a},dex.length,(long)dex.length*2,31);throw new AssertionError("duplicate stream accepted");}catch(IllegalArgumentException expected){}check(a.size()==0,"distinct stream preflight");
   try{DexStreamExport.writeAll(set,new OutputStream[]{a},dex.length,(long)dex.length*2,31);throw new AssertionError("count mismatch accepted");}catch(IllegalArgumentException expected){}check(a.size()==0,"count preflight");
   try{DexStreamExport.writeTo(set,2,a,dex.length,31);throw new AssertionError("source index accepted");}catch(IllegalArgumentException expected){}check(a.size()==0,"source index preflight");
  }
  try(NativeEngine.SourceSetSnapshot set=NativeEngine.openSources(new byte[][]{dex,resource},new String[]{"one","resource"},new int[]{NativeEngine.SOURCE_RAW_DEX,NativeEngine.SOURCE_APK},new boolean[]{false,true})){
   Probe out=new Probe();long[] counts=DexStreamExport.writeAll(set,new OutputStream[]{out},dex.length,dex.length,64);check(counts.length==1&&Arrays.equals(dex,out.toByteArray()),"resource-only input excluded");
  }
  try(NativeEngine.SourceSetSnapshot set=NativeEngine.openSources(new byte[][]{resource},new String[]{"resource"},new int[]{NativeEngine.SOURCE_APK},new boolean[]{true})){
   check(DexStreamExport.writeAll(set,new OutputStream[]{},1,1,64).length==0,"empty source set");
  }
  System.out.println("PASS streaming source bytes, multi-source limits, partial failure and close behavior");
 }
}
