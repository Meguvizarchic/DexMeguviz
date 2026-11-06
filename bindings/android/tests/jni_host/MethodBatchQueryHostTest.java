package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Objects;
public final class MethodBatchQueryHostTest {
 static void check(boolean b,String m){if(!b)throw new AssertionError(m);}
 static byte[] bytes(String s){return s.getBytes(StandardCharsets.UTF_8);}
 static void failure(int status,int index,Runnable r){try{r.run();throw new AssertionError("expected batch failure");}catch(MethodBatchQuery.Failure e){check(e.status==status&&e.failureIndex==index,"failure "+e.status+"/"+e.failureIndex);}}
 static void invalid(Runnable r){try{r.run();throw new AssertionError("expected invalid");}catch(IllegalArgumentException expected){}}
 static void equal(NativeEngine.QueryResult a,NativeEngine.QueryResult b){
  check(a.executionStatus==b.executionStatus&&a.coverage==b.coverage&&a.decision==b.decision&&a.reason==b.reason&&a.unknownRows==b.unknownRows&&a.candidateCount()==b.candidateCount()&&a.queryId.equals(b.queryId)&&a.snapshotId.equals(b.snapshotId),"result state");
  for(int i=0;i<a.candidateCount();++i){var x=a.candidate(i);var y=b.candidate(i);check(x.methodIndex==y.methodIndex&&x.sourceIndex==y.sourceIndex&&x.inputIndex==y.inputIndex&&Objects.equals(x.owner,y.owner)&&Objects.equals(x.name,y.name)&&Objects.equals(x.prototype,y.prototype)&&Objects.equals(x.sourceSlot,y.sourceSlot)&&Objects.equals(x.occurrenceId,y.occurrenceId),"result row identity");}
 }
 public static void main(String[] args)throws Exception{
  check(args.length==2,"q03 and many-class fixtures");byte[] dex=Files.readAllBytes(Path.of(args[0]));
  byte[] body=bytes("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"using_strings\":{\"all\":[{\"op\":\"exact\",\"value\":\"code-use-q03\"}]}}}");
  byte[] empty=bytes("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\"doesNotExist\"}}");
  byte[] limit=bytes("{\"schema_version\":1,\"relation\":\"method_defs\",\"max_results\":1}");
  byte[] scope=bytes("{\"schema_version\":1,\"relation\":\"method_defs\",\"scope\":{\"slots\":[\"a\"]}} ");
  byte[] oldClass=bytes("{\"schema_version\":1,\"relation\":\"class_defs\"}");
  MethodBatchQuery.Result saved;var set=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"a","b"});
  try{
   byte[][] rules={body,body,empty};var off=MethodBatchQuery.execute(set,rules,0,0);saved=MethodBatchQuery.execute(set,rules,1<<20,1000000);
   check(saved.size()==3&&saved.profile.cacheHits>0,"real shared facts");check(off.profile.cacheHits==0,"disabled cache");
   for(int i=0;i<rules.length;i++){var scalar=set.queryMethods(rules[i]);equal(scalar,saved.get(i));equal(scalar,off.get(i));}
   check(saved.get(0).candidateCount()==2&&saved.get(0).candidate(0).sourceIndex!=saved.get(0).candidate(1).sourceIndex,"source occurrences");
   byte[] ordered=bytes("{\"schema_version\":1,\"relation\":\"method_defs\",\"intent\":\"top_n\",\"max_results\":1,\"order_by\":[{\"field\":\"name\",\"direction\":\"asc\"}]}");
   equal(set.queryMethods(ordered),MethodBatchQuery.execute(set,new byte[][]{ordered},0,0).get(0));
   var limited=MethodBatchQuery.execute(set,new byte[][]{limit},0,0);check(limited.get(0).executionStatus==4&&limited.get(0).reason==4&&limited.get(0).coverage==1,"per-rule result limit preserved");
   byte[] tooLittleWork=bytes("{\"schema_version\":1,\"relation\":\"method_defs\",\"max_work\":1}");failure(4,1,()->MethodBatchQuery.execute(set,new byte[][]{body,tooLittleWork},0,0));
   byte[] v25=bytes("{\"schema_version\":1,\"relation\":\"class_defs\",\"required_capabilities\":[\"class_annotation_static\",\"class_annotation_string_static\"],\"where\":{\"annotation\":{\"type\":\"Lfixture/Complex;\",\"element\":{\"name\":\"str\",\"string\":\"x\"}}}}");failure(3,1,()->MethodBatchQuery.execute(set,new byte[][]{body,v25},0,0));
   failure(1,1,()->MethodBatchQuery.execute(set,new byte[][]{body,bytes("{broken")},0,0));
   failure(1,1,()->MethodBatchQuery.execute(set,new byte[][]{body,null},0,0));
   failure(3,1,()->MethodBatchQuery.execute(set,new byte[][]{body,scope},0,0));failure(3,1,()->MethodBatchQuery.execute(set,new byte[][]{body,oldClass},0,0));
   invalid(()->MethodBatchQuery.execute(set,new byte[0][],0,0));invalid(()->MethodBatchQuery.execute(set,new byte[33][],0,0));invalid(()->MethodBatchQuery.execute(set,new byte[][]{body},-1,0));
   invalid(()->MethodBatchQuery.execute(set,new byte[][]{body},16777217L,0));invalid(()->MethodBatchQuery.execute(set,new byte[][]{body},0,100000001L));
   byte[] padded=Arrays.copyOf(body,65536);Arrays.fill(padded,body.length,padded.length,(byte)' ');byte[][] many=new byte[17][];Arrays.fill(many,padded);failure(4,16,()->MethodBatchQuery.execute(set,many,0,0));
  }finally{set.close();}
  check(saved.get(0).candidate(0).name!=null&&saved.size()==3,"copied lifetime");
  try(var one=NativeEngine.openRawDex(dex,"one")){var batch=MethodBatchQuery.execute(one,new byte[][]{body},0,0);equal(one.queryMethods(body),batch.get(0));}
  byte[] large=Files.readAllBytes(Path.of(args[1]));try(var many=NativeEngine.openRawDex(large,"large")){
   int perRule=many.info().methodDefCount;check(perRule>128&&4096/perRule<32,"many-class fixture capacity");byte[][] group=new byte[32][];Arrays.fill(group,bytes("{\"schema_version\":1,\"relation\":\"method_defs\"}"));failure(4,4096/perRule,()->MethodBatchQuery.execute(many,group,0,0));
  }
  System.out.println("PASS method batch native sharing, scalar parity, failure index and bounds");
 }
}
