package io.github.jichuo1.dexmeguviz;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
public final class UseGraphHostTest {
 static void check(boolean v,String m){if(!v)throw new AssertionError(m);}
 static byte[] json(String x){return x.getBytes(StandardCharsets.UTF_8);}
 static String scan(String rel,String caps){return "{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\""+rel+"\"}"+caps+"}";}
 static byte[] fixture(String path,String sha)throws Exception {byte[] d=Files.readAllBytes(Path.of(path));check(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(d)).equals(sha),"fixture hash");return d;}
 static void event(UseGraphResult.Use x,int rel,int pc,int opcode,int domain,int target,long proto){check(x.relation==rel&&x.sourceIndex==0&&x.callerOrdinal==2&&x.callerMethodRef==3&&x.dexPc==pc&&x.opcode==opcode&&x.codeOffset==416&&x.targetDomain==domain&&x.targetIndex==target&&x.extraProto==proto,"event fields");check("Lfacts/Example;".equals(x.owner)&&"uses".equals(x.name)&&"()V".equals(x.prototype),"event names");}
 static void scanCase(String path,String sha,String rel,int relation,int[] pc,int[] opcode,int[] domains,int[] target,long[] proto)throws Exception {
  byte[] dex=fixture(path,sha);try(NativeEngine.Snapshot s=NativeEngine.openRawDex(dex,"fixture")){
   for(String caps:new String[]{"",",\"required_capabilities\":[\"use_streaming\"]"}){
    UseGraphResult x=s.queryUseGraph(json(scan(rel,caps)));check(x.queryId.startsWith(caps.isEmpty()?"query:v4:":"query:v9:"),"profile");check(x.rowCount()==2&&x.candidateCount==2&&x.eventsCollected==2&&x.unknownRows==0,"counts");check(!x.profile.scopeComplete&&x.scopeSourceCount()==1&&x.scopeSource(0)==0&&x.sourceCount()==1&&x.inputCount()==1,"scope");check(x.source(0).sourceSha256.equals(sha)&&x.source(0).slot.equals("fixture")&&x.input(0).slot.equals("fixture"),"source");
    for(int i=0;i<2;i++){check(x.row(i).value.kind==1,"tag");event(x.row(i).value.use,relation,pc[i],opcode[i],domains[i],target[i],proto[i]);if(relation==8){check(x.row(i).witnessCount()>0,"invoke witness");boolean found=false;for(int w=0;w<x.row(i).witnessCount();w++){UseGraphResult.Witness z=x.row(i).witness(w);if(z.kind==3&&z.dexPc==pc[i]&&z.referenceIndex==target[i]&&z.entity.relation==8&&z.entity.dexPc==pc[i])found=true;}check(found,"witness event identity");}}
   }
  }
 }
 public static void main(String[] args)throws Exception {
  String f=args[0];long none=0xffffffffL;
  scanCase(f+"/use_relations/two-invokes.dex","04656bbfe03c8b04e6f77d29b8cae8e7e06f18a038f85300658f8c691435648b","invoke_sites",8,new int[]{0,3},new int[]{0x71,0x71},new int[]{2,2},new int[]{4,4},new long[]{none,none});
  scanCase(f+"/use_relations/field-read-write.dex","7558a8945c3a87f727de782d885c687539d839e460497f6d2e86c2a7c7f46e8d","field_uses",9,new int[]{0,2},new int[]{0x60,0x67},new int[]{1,1},new int[]{0,0},new long[]{none,none});
  scanCase(f+"/use_relations/string-normal-jumbo.dex","65373dc14bb0b19b3fb4ae8fd236e83befbfee4b69b74e3a8d4a8b7db2637c04","string_uses",7,new int[]{0,2},new int[]{0x1a,0x1b},new int[]{0,0},new int[]{10,10},new long[]{none,none});
  scanCase(f+"/method_facts/invoke-domains-038.dex","ecf85d163c87d58f065335f0d932442be48b91b5efa3858e319a1c1cdf7313b0","invoke_sites",8,new int[]{0,4},new int[]{0xfa,0xfc},new int[]{3,4},new int[]{4,0},new long[]{0,none});
  byte[] dex=fixture(f+"/use_relations/two-invokes.dex","04656bbfe03c8b04e6f77d29b8cae8e7e06f18a038f85300658f8c691435648b");
  try(NativeEngine.Snapshot s=NativeEngine.openRawDex(dex,"fixture")){
   String semi="{\"schema_version\":1,\"relation\":{\"op\":\"semi_join\",\"on\":\"caller\",\"left\":{\"op\":\"scan\",\"relation\":\"method_defs\"},\"right\":{\"op\":\"scan\",\"relation\":\"invoke_sites\",\"where\":{\"pc\":3}}}}";
   UseGraphResult x=s.queryUseGraph(json(semi));check(x.rowCount()==1&&x.row(0).value.kind==0,"semi entity");UseGraphResult.Row row=x.row(0);check(row.proofBindingCount()==1&&row.linkCount()==1,"semi proof and link");UseGraphResult.Binding p=row.proofBinding(0);check(p.value.kind==1&&p.value.use.dexPc==3&&p.operatorNode==0&&p.path().length==1&&p.path()[0]==1,"proof event");UseGraphResult.Link l=row.link(0);check(l.left.localIndex==2&&l.left.dexPc==none&&l.right.localIndex==2&&l.right.dexPc==3,"link event identity");
   String unknown=semi.replace("\"pc\":3","\"pc\":999");
   UseGraphResult u=s.queryUseGraph(json(unknown));check(u.unknownRows==4&&u.rowCount()==0&&u.decision==0,"unknown retained");
   String projection=semi.substring(0,semi.length()-1)+",\"projection\":[\"identity\"]}";UseGraphResult projected=s.queryUseGraph(json(projection));check(projected.row(0).value.entity.owner==null&&projected.row(0).proofBinding(0).value.use.name.equals("uses"),"projection and proof");
   try{s.queryGraph(json(scan("invoke_sites","")));throw new AssertionError("legacy graph accepted use");}catch(NativeEngine.NativeFailure ok){check(ok.status==3,"legacy rejection");}
   for(String bad:new String[]{"{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"method_defs\"}}", "{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"},\"required_capabilities\":[\"unique_one_stream\"]}"}){try{s.queryUseGraph(json(bad));throw new AssertionError("accepted unsupported profile");}catch(NativeEngine.NativeFailure ok){check(ok.status==3,"unsupported status "+ok.status);}}
  }
  try(NativeEngine.SourceSetSnapshot s=NativeEngine.openRawDexSet(new byte[][]{dex,dex},new String[]{"a","b"})){UseGraphResult x=s.queryUseGraph(json(scan("invoke_sites","")));check(x.rowCount()==4&&x.sourceCount()==2&&!x.source(0).occurrenceId.equals(x.source(1).occurrenceId)&&x.source(0).contentId.equals(x.source(1).contentId),"duplicate source provenance");check(x.row(2).value.use.sourceIndex==1,"second source event");}
  try{UseGraphResult.decode(new byte[]{1,2});throw new AssertionError("accepted truncated wire");}catch(IllegalStateException ok){}
  System.out.println("use graph fixed fixtures, v4/v9, proof, source, rejection: PASS");
 }
}



