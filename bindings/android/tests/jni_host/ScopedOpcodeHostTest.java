package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
/** Fixed host JNI check; scope is caller-declared rather than loader-authenticated. */
public final class ScopedOpcodeHostTest {
 private static void check(boolean v,String m){if(!v)throw new AssertionError(m);}
 private static byte[] query(String slots,String intent,String name){return ("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\""+name+"\",\"opcodes\":{\"mode\":\"contains\",\"values\":[26,-1,96],\"negative_wildcards\":true}},\"intent\":\""+intent+"\",\"max_results\":100,\"scope\":{\"slots\":"+slots+"},\"required_capabilities\":[\"opcode_sequence\"]}").getBytes(StandardCharsets.UTF_8);}
 private static void rejected(int status,Runnable f){try{f.run();throw new AssertionError("expected rejection");}catch(NativeEngine.NativeFailure e){check(e.status==status,"status "+e.status);}}
 public static void main(String[] args)throws Exception {
  check(args.length==3,"fixtures");byte[] base=Files.readAllBytes(Path.of(args[0])),resource=Files.readAllBytes(Path.of(args[1])),code=Files.readAllBytes(Path.of(args[2]));
  var set=NativeEngine.openSources(new byte[][]{base,resource,code},new String[]{"base","resource","code"},new int[]{NativeEngine.SOURCE_APK,NativeEngine.SOURCE_APK,NativeEngine.SOURCE_RAW_DEX},new boolean[]{false,true,false});
  byte[] q=query("[\"code\"]","unique","uses");rejected(3,()->OpcodeQuery.execute(set,q));rejected(3,()->ScopedMethodQuery.execute(set,q));
  var r=ScopedOpcodeQuery.execute(set,q);check(r.query.queryId.startsWith("query:v23:")&&r.query.executionStatus==0&&r.query.coverage==0&&r.query.decision==3&&r.query.candidateCount()==1,"selected opcode unique");
  check(r.scope.inputSlotCount()==1&&r.scope.inputSlot(0).equals("code")&&r.scope.sourceCount()==1&&r.scope.sourceIndex(0)==3&&!r.scope.snapshotScopeComplete&&!r.scope.sourceScopeAuthenticated,"declared code scope");
  check(r.query.candidate(0).sourceIndex==3&&r.query.candidate(0).inputIndex==2&&r.query.candidate(0).sourceSlot.equals("code"),"occurrence");
  var resourceOnly=ScopedOpcodeQuery.execute(set,query("[\"resource\"]","exists","uses"));check(resourceOnly.query.coverage==0&&resourceOnly.query.decision==2&&resourceOnly.scope.sourceCount()==0,"empty resource");
  var empty=ScopedOpcodeQuery.execute(set,query("[]","exists","uses"));check(empty.query.coverage==0&&empty.query.decision==2&&empty.scope.inputSlotCount()==0&&empty.scope.sourceCount()==0,"empty scope");
  var merged=ScopedOpcodeQuery.execute(set,query("[\"code\",\"base\"]","enumerate","uses"));check(merged.scope.inputSlotCount()==2&&merged.scope.inputSlot(0).equals("base")&&merged.scope.inputSlot(1).equals("code")&&merged.scope.sourceCount()==4&&merged.scope.sourceIndex(3)==3,"canonical slots, multidex order");
  rejected(8,()->ScopedOpcodeQuery.execute(set,query("[\"missing\"]","exists","uses")));rejected(1,()->ScopedOpcodeQuery.execute(set,query("[\"code\",\"code\"]","exists","uses")));
  rejected(3,()->ScopedOpcodeQuery.execute(set,"{\"schema_version\":1,\"relation\":\"method_defs\"}".getBytes(StandardCharsets.UTF_8)));
  set.close();check(r.scope.sourceIndex(0)==3&&r.query.candidate(0).name.equals("uses"),"copied after close");rejected(7,()->ScopedOpcodeQuery.execute(set,q));
  try(var single=NativeEngine.openRawDex(code,"solo")){var one=ScopedOpcodeQuery.execute(single,query("[\"solo\"]","unique","uses"));check(one.query.candidateCount()==1&&one.scope.sourceIndex(0)==0&&!one.scope.sourceScopeAuthenticated,"single source");}
  System.out.println("PASS scoped opcode selected inputs, multidex/resource, exclusions and copied lifetime");
 }
}
