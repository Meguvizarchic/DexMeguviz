package io.github.jichuo1.dexmeguviz;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/** Host-only draft; requires the as-yet-unmerged ScopedMethodBatchQuery bridge. */
public final class ScopedMethodBatchHostTest {
  static void check(boolean ok,String why){if(!ok)throw new AssertionError(why);}
  static byte[] b(String text){return text.getBytes(StandardCharsets.UTF_8);}
  static byte[] q(String slots,String where){return b("{\"schema_version\":1,\"relation\":\"method_defs\",\"scope\":{\"slots\":"+slots+"},\"where\":"+where+"}");}
  static void failAt(int status,int index,Runnable f){try{f.run();throw new AssertionError("expected indexed failure");}catch(MethodBatchQuery.Failure e){check(e.status==status&&e.failureIndex==index,"failure index "+e.failureIndex+", status "+e.status);}}
  static void equal(NativeEngine.QueryResult a,NativeEngine.QueryResult c){
    check(a.executionStatus==c.executionStatus&&a.coverage==c.coverage&&a.decision==c.decision&&a.reason==c.reason&&a.unknownRows==c.unknownRows&&a.queryId.equals(c.queryId)&&a.snapshotId.equals(c.snapshotId)&&a.candidateCount()==c.candidateCount(),"result state");
    for(int i=0;i<a.candidateCount();i++){var x=a.candidate(i);var y=c.candidate(i);check(x.methodIndex==y.methodIndex&&x.inputIndex==y.inputIndex&&x.sourceIndex==y.sourceIndex&&Objects.equals(x.owner,y.owner)&&Objects.equals(x.name,y.name)&&Objects.equals(x.prototype,y.prototype)&&Objects.equals(x.sourceSlot,y.sourceSlot)&&Objects.equals(x.occurrenceId,y.occurrenceId),"row identity");}
  }
  static void sameScope(ScopedMethodQuery.Scope a,ScopedMethodBatchQuery.Scope c){check(a.inputSlotCount()==c.inputSlotCount()&&a.sourceCount()==c.sourceCount(),"scope counts");for(int i=0;i<a.inputSlotCount();i++)check(a.inputSlot(i).equals(c.inputSlot(i)),"scope slot");for(int i=0;i<a.sourceCount();i++)check(a.sourceIndex(i)==c.sourceIndex(i),"source index");check(!c.snapshotScopeComplete&&!c.sourceScopeAuthenticated,"declaration boundary");}
  public static void main(String[] args)throws Exception {
    check(args.length==4,"base multidex APK, resource-only APK, code-use-q03 DEX, many-method DEX");
    byte[] base=Files.readAllBytes(Path.of(args[0])),resource=Files.readAllBytes(Path.of(args[1])),dex=Files.readAllBytes(Path.of(args[2]));
    var set=NativeEngine.openSources(new byte[][]{base,resource,dex,dex},new String[]{"base","resource","a","b"},new int[]{NativeEngine.SOURCE_APK,NativeEngine.SOURCE_APK,NativeEngine.SOURCE_RAW_DEX,NativeEngine.SOURCE_RAW_DEX},new boolean[]{false,true,false,false});
    String strings="{\"using_strings\":{\"all\":[{\"op\":\"exact\",\"value\":\"code-use-q03\"}]}}";
    byte[] ab=q("[\"a\",\"b\"]",strings), missing=q("[\"a\",\"b\"]","{\"name\":\"not-present\"}"),
      other=q("[\"a\"]",strings), noScope=b("{\"schema_version\":1,\"relation\":\"method_defs\"}"),
      unknown=q("[\"unknown\"]",strings),duplicate=q("[\"a\",\"a\"]",strings);
    var batch=ScopedMethodBatchQuery.execute(set,new byte[][]{ab,ab,missing},1<<20,1000000);
    check(batch.size()==3&&batch.profile.cacheHits>0,"real repeated facts cache hit");
    for(int i=0;i<3;i++){byte[] rule=i==2?missing:ab;var scalar=ScopedMethodQuery.execute(set,rule);sameScope(scalar.scope,batch.scope);equal(scalar.query,batch.get(i));}
    byte[] reversed=q("[\"b\",\"a\"]",strings);
    var normalized=ScopedMethodBatchQuery.execute(set,new byte[][]{ab,reversed},0,0);equal(ScopedMethodQuery.execute(set,reversed).query,normalized.get(1));
    byte[] limited=b("{\"schema_version\":1,\"relation\":\"method_defs\",\"scope\":{\"slots\":[\"a\",\"b\"]},\"max_results\":1}");
    var resultLimit=ScopedMethodBatchQuery.execute(set,new byte[][]{limited},0,0);check(resultLimit.get(0).executionStatus==4&&resultLimit.get(0).reason==4&&resultLimit.get(0).coverage==1,"per-item ResultLimit");equal(ScopedMethodQuery.execute(set,limited).query,resultLimit.get(0));
    var two=batch.get(0);check(two.candidateCount()==2,"both occurrences");check(two.candidate(0).sourceIndex!=two.candidate(1).sourceIndex&&!two.candidate(0).occurrenceId.equals(two.candidate(1).occurrenceId),"distinct occurrence identities");
    byte[] empty=q("[]",strings),res=q("[\"resource\"]",strings),multi=q("[\"base\"]","{\"name\":\"not-present\"}");
    var emptyResult=ScopedMethodBatchQuery.execute(set,new byte[][]{empty,empty},0,0);check(emptyResult.scope.inputSlotCount()==0&&emptyResult.scope.sourceCount()==0,"empty declared scope");equal(ScopedMethodQuery.execute(set,empty).query,emptyResult.get(0));
    var resourceResult=ScopedMethodBatchQuery.execute(set,new byte[][]{res},0,0);check(resourceResult.scope.inputSlotCount()==1&&resourceResult.scope.sourceCount()==0,"resource-only slot");
    var multiResult=ScopedMethodBatchQuery.execute(set,new byte[][]{multi},0,0);check(multiResult.scope.sourceCount()>1,"multidex source mapping");sameScope(ScopedMethodQuery.execute(set,multi).scope,multiResult.scope);equal(ScopedMethodQuery.execute(set,multi).query,multiResult.get(0));
    failAt(8,1,()->ScopedMethodBatchQuery.execute(set,new byte[][]{ab,other},0,0));
    failAt(3,1,()->ScopedMethodBatchQuery.execute(set,new byte[][]{ab,noScope},0,0));
    failAt(8,0,()->ScopedMethodBatchQuery.execute(set,new byte[][]{unknown},0,0));
    failAt(1,0,()->ScopedMethodBatchQuery.execute(set,new byte[][]{duplicate},0,0));
    failAt(1,1,()->ScopedMethodBatchQuery.execute(set,new byte[][]{ab,b("{bad")},0,0));
    byte[] shortWork=b("{\"schema_version\":1,\"relation\":\"method_defs\",\"scope\":{\"slots\":[\"a\",\"b\"]},\"max_work\":1}");
    failAt(4,1,()->ScopedMethodBatchQuery.execute(set,new byte[][]{ab,shortWork},0,0));
    try{MethodBatchQuery.execute(set,new byte[][]{ab},0,0);throw new AssertionError("old batch accepted scope");}catch(MethodBatchQuery.Failure expected){check(expected.status==3,"old batch status");}
    set.close();check(batch.get(0).candidate(0).name!=null&&batch.scope.inputSlot(0)!=null,"copied result after close");
    try{ScopedMethodBatchQuery.execute(set,new byte[][]{ab},0,0);throw new AssertionError("closed snapshot accepted");}catch(NativeEngine.NativeFailure expected){check(expected.status==7,"closed status");}
    try(var one=NativeEngine.openRawDex(dex,"one")){byte[] scoped=q("[\"one\"]",strings);var single=ScopedMethodBatchQuery.execute(one,new byte[][]{scoped},0,0);equal(ScopedMethodQuery.execute(one,scoped).query,single.get(0));}
    byte[] many=Files.readAllBytes(Path.of(args[3]));try(var large=NativeEngine.openRawDex(many,"large")){
      int count=large.info().methodDefCount;check(count>128&&4096/count<32,"aggregate fixture");byte[] all=b("{\"schema_version\":1,\"relation\":\"method_defs\",\"scope\":{\"slots\":[\"large\"]}}");byte[][] rules=new byte[32][];java.util.Arrays.fill(rules,all);failAt(4,4096/count,()->ScopedMethodBatchQuery.execute(large,rules,0,0));
    }
    System.out.println("PASS scoped batch JNI: parity, per-source identity, failure and limits");
  }
}
