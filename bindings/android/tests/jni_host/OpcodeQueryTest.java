package io.github.jichuo1.dexmeguviz;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
public final class OpcodeQueryTest {
 static void check(boolean v,String m){if(!v)throw new AssertionError(m);}
 static byte[] query(String name,String mode,String codes){return ("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\""+name+"\",\"opcodes\":{\"mode\":\""+mode+"\",\"values\":["+codes+"],\"negative_wildcards\":true}},\"required_capabilities\":[\"opcode_sequence\"]}").getBytes(StandardCharsets.UTF_8);}
 public static void main(String[] args)throws Exception {
  byte[] dex=Files.readAllBytes(Path.of(args[0]));byte[] q=query("uses","contains","26,-1,96");
  try(NativeEngine.Snapshot s=NativeEngine.openRawDex(dex,"single")){
   var r=OpcodeQuery.execute(s,q);check(r.queryId.startsWith("query:v23:")&&r.candidateCount()==1&&r.candidate(0).name.equals("uses")&&r.coverage==1,"single wildcard");
   check(OpcodeQuery.execute(s,query("uses","ends_with","96,14")).candidateCount()==1,"suffix");
   check(OpcodeQuery.execute(s,query("nativeMethod","equals","")).candidateCount()==1,"empty native");
   try{OpcodeQuery.execute(s,query("uses","contains","2147483648"));throw new AssertionError("invalid opcode accepted");}catch(NativeEngine.NativeFailure e){check(e.status==1,"invalid opcode status");}
   try{OpcodeQuery.execute(s,query("uses","ends_with","256"));throw new AssertionError("non-byte default accepted");}catch(NativeEngine.NativeFailure e){check(e.status==3,"non-byte default status");}
   byte[] compat=new String(query("uses","ends_with","270"),StandardCharsets.UTF_8).replace("\"negative_wildcards\":true","\"negative_wildcards\":true,\"signed16_coercion\":true").getBytes(StandardCharsets.UTF_8);
   check(OpcodeQuery.execute(s,compat).candidateCount()==1,"explicit int16 coercion");
   byte[] wrap=new String(query("quiet","equals","-65522"),StandardCharsets.UTF_8).replace("\"negative_wildcards\":true","\"negative_wildcards\":true,\"signed16_coercion\":true").getBytes(StandardCharsets.UTF_8);
   check(OpcodeQuery.execute(s,wrap).candidateCount()==1,"signed int16 wrapping");
   byte[] idCompat=new String(query("uses","ends_with","14"),StandardCharsets.UTF_8).replace("\"negative_wildcards\":true","\"negative_wildcards\":true,\"signed16_coercion\":true").getBytes(StandardCharsets.UTF_8);
   check(!OpcodeQuery.execute(s,idCompat).queryId.equals(OpcodeQuery.execute(s,query("uses","ends_with","14")).queryId),"compat option in query identity");
   byte[] noOpt=new String(q,StandardCharsets.UTF_8).replace(",\"negative_wildcards\":true","").getBytes(StandardCharsets.UTF_8);
   try{OpcodeQuery.execute(s,noOpt);throw new AssertionError("default negative wildcard accepted");}catch(NativeEngine.NativeFailure e){check(e.status==3,"negative wildcard opt-in status");}
  }
  try(NativeEngine.SourceSetSnapshot s=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"a","b"})){
   var r=OpcodeQuery.execute(s,q);check(r.candidateCount()==2&&r.candidate(0).sourceIndex!=r.candidate(1).sourceIndex,"distinct source occurrences");
  }
  System.out.println("PASS OpcodeQuery JNI modes, wildcard, bodyless, invalid and source occurrence");
 }
}
