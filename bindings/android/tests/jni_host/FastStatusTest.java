import io.github.jichuo1.dexmeguviz.FastDexQuery;
import java.nio.file.*;
import java.util.Arrays;
public class FastStatusTest {
 static void check(boolean b,String s){if(!b)throw new AssertionError(s);}
 static void expect(FastDexQuery.Plans p,byte[] bytes,int expected,String what){
  var l=new FastDexQuery.Limits(32L<<20,4096,10000,1<<20,1048576,1048576,8<<20);
  try {p.scan(bytes,FastDexQuery.InputAssumption.CALLER_ASSERTS_VALID_SORTED_DEX,l);throw new AssertionError(what+" unexpectedly accepted");}
  catch(FastDexQuery.Failure e){check(e.status==expected,what+" expected "+expected+" got "+e.status);System.out.println(what+" status="+e.status);}
 }
 public static void main(String[] args)throws Exception{
  byte[] dex=Files.readAllBytes(Path.of(args[0]));byte[] query=Files.readAllBytes(Path.of(args[1]));
  try(var p=FastDexQuery.compile(new byte[][]{query},new boolean[]{false})){
   var l=new FastDexQuery.Limits(32L<<20,4096,10000,1<<20,1048576,1048576,8<<20);
   var result=p.scan(dex,FastDexQuery.InputAssumption.CALLER_ASSERTS_VALID_SORTED_DEX,l);check(result.rules.get(0).executionStatus==0,"valid dex");
   byte[] x=dex.clone();x[6]='1';expect(p,x,3,"unsupported 041");
   x=dex.clone();x[6]='6';expect(p,x,3,"unsupported 036");
   x=dex.clone();x[6]='x';expect(p,x,2,"non-numeric version");
   x=dex.clone();x[0]='x';expect(p,x,2,"invalid magic");
   x=dex.clone();x[36]=0;expect(p,x,2,"invalid standard header");
   expect(p,Arrays.copyOf(dex,7),2,"truncated header");
  }
  System.out.println("PASS status classification");
 }
}
