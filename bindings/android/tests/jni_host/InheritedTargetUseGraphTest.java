package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
public final class InheritedTargetUseGraphTest {
 static String quoted(String s){return "\""+s.replace("\\","\\\\").replace("\"","\\\"")+"\"";}
 static String q(String scope,String intent){return "{\"schema_version\":1,\"required_capabilities\":[\"inherited_fields\",\"use_target_symbol\",\"inherited_target_symbol\"],"+scope+"\"relation\":{\"op\":\"join\",\"on\":\"target_symbol\",\"left\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"},\"right\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"all\":[{\"name\":\"uses\"},{\"declares_fields\":{\"scope\":\"inherited\",\"where\":{\"name\":\"unseen\"},\"min\":0,\"max\":0}}]}}},\"intent\":\""+intent+"\",\"max_results\":100}";}
 static void check(boolean ok,String msg){if(!ok)throw new AssertionError(msg);}
 static void rejected(Runnable run,int code){try{run.run();throw new AssertionError("accepted unsupported request");}catch(NativeEngine.NativeFailure e){check(e.status==code,"status "+e.status+" expected "+code);}}
 public static void main(String[] args)throws Exception{
  check(args.length==3,"args");byte[] a=Files.readAllBytes(Path.of(args[0])),b=Files.readAllBytes(Path.of(args[1]));String[] keys={"input:0:"+args[0],"input:1:"+args[0],"input:2:"+args[1]};
  String scope="\"scope\":{\"slots\":["+quoted(keys[0])+","+quoted(keys[1])+","+quoted(keys[2])+"]},";String query=q(scope,"enumerate");Files.writeString(Path.of(args[2]).resolve("query.json"),query,StandardOpenOption.CREATE_NEW);
  UseGraphResult saved;
  try(var s=NativeEngine.openRawDexSet(new byte[][]{a,a,b},keys)){
   saved=s.queryUseGraph(query.getBytes(StandardCharsets.UTF_8));check(saved.queryId.startsWith("query:v18:"),"query profile");check(saved.explicitScope&&saved.coverage==0&&saved.profile.scopeComplete,"scope");check(saved.rowCount()==8&&saved.sourceCount()==3,"row count");
   System.out.println("RESULT "+saved.queryId+" "+saved.rowCount()+" "+saved.coverage+" "+saved.decision+" "+saved.unknownRows+" "+saved.scopeSourceCount());
   for(int i=0;i<saved.scopeSourceCount();i++)System.out.println("SCOPE "+saved.scopeSource(i));
   for(int i=0;i<saved.rowCount();i++){
    UseGraphResult.Row row=saved.row(i);check(row.linkCount()==1,"link");UseGraphResult.Link link=row.link(0);check(link.key==6&&link.left.relation==8&&link.right.relation==0,"link identity");int paths=0;
    for(int j=0;j<row.witnessCount();j++){UseGraphResult.Witness w=row.witness(j);if(w.kind==8){check(w.inheritedDetailPresent,"missing details");if(w.inheritedItem==1){if(w.inheritedPath==0)check(w.entity.sourceIndex==link.right.sourceIndex&&w.inheritedAux==0xffffffffL,"root path");else if(w.inheritedPath==1)check(w.entity.sourceIndex==2&&w.inheritedAux==0,"parent path");else throw new AssertionError("bad path");paths++;}
      System.out.println("INHERITED "+link.left.sourceIndex+" "+link.left.dexPc+" "+link.right.sourceIndex+" "+w.nodeId+" "+w.matched+" "+w.inheritedItem+" "+w.inheritedPath+" "+w.inheritedAux+" "+w.inheritedBranch+" "+w.inheritedDetail+" "+w.entity.sourceIndex+" "+w.entity.relation+" "+w.entity.localIndex);}
     else check(!w.inheritedDetailPresent,"non-inherited tag");}
    check(paths==2,"two path entries");
   }
   UseGraphResult unknown=s.queryUseGraph(q("","exists").getBytes(StandardCharsets.UTF_8));check(unknown.coverage==1&&unknown.decision==1&&unknown.unknownRows>0&&unknown.rowCount()==0,"partial unknown");
   String leftScope="\"relation\":\"invoke_sites\",\"scope\":{\"slots\":["+quoted(keys[0])+"]}}";
   String rightScope="\"relation\":\"method_defs\",\"scope\":{\"slots\":["+quoted(keys[1])+","+quoted(keys[2])+"]},\"where\":";
   String sub=q("","enumerate").replace("\"relation\":\"invoke_sites\"}",leftScope).replace("\"relation\":\"method_defs\",\"where\":",rightScope);
   UseGraphResult scopedSub=s.queryUseGraph(sub.getBytes(StandardCharsets.UTF_8));check(!scopedSub.explicitScope&&scopedSub.coverage==0&&scopedSub.rowCount()==2,"subtree scope");
   String missingParent=sub.replace(quoted(keys[1])+","+quoted(keys[2]),quoted(keys[1])).replace("\"intent\":\"enumerate\"","\"intent\":\"exists\"");
   UseGraphResult missing=s.queryUseGraph(missingParent.getBytes(StandardCharsets.UTF_8));check(missing.coverage==1&&missing.decision==1&&missing.unknownRows>0&&missing.rowCount()==0,"subtree missing parent");
   String v16="{\"schema_version\":1,\"required_capabilities\":[\"use_target_symbol\"],\"relation\":{\"op\":\"join\",\"on\":\"target_symbol\",\"left\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"},\"right\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\"}}},\"max_results\":100}";
   UseGraphResult old=s.queryUseGraph(v16.getBytes(StandardCharsets.UTF_8));check(old.queryId.startsWith("query:v16:")&&old.rowCount()==8,"old profile");for(int i=0;i<old.rowCount();i++)for(int j=0;j<old.row(i).witnessCount();j++)check(!old.row(i).witness(j).inheritedDetailPresent,"old format changed");
   rejected(()->s.queryGraph(query.getBytes(StandardCharsets.UTF_8)),3);rejected(()->s.queryUseGraph(v16.replace("\"relation\":{","\"scope\":{\"slots\":["+quoted(keys[0])+"]},\"relation\":{").getBytes(StandardCharsets.UTF_8)),3);
   rejected(()->s.queryUseGraph(query.replace(quoted(keys[2]),"\"not-present\"").getBytes(StandardCharsets.UTF_8)),8);
   try {UseGraphResult.decode(new byte[]{0,0,0,0});throw new AssertionError("invalid wire accepted");}catch(IllegalStateException expected){}
   var token=NativeEngine.SourceSetSnapshot.class.getDeclaredField("token");token.setAccessible(true);
   var nativeQuery=NativeEngine.class.getDeclaredMethod("nativeQueryUseGraph",long.class,byte[].class,boolean.class);nativeQuery.setAccessible(true);
   byte[] raw=(byte[])nativeQuery.invoke(null,token.getLong(s),query.getBytes(StandardCharsets.UTF_8),true);check(UseGraphResult.decode(raw).rowCount()==8,"raw valid");
   byte[] pattern={1,0,0,0,1,0,0,0,1,0,0,0,0,0,0,0,-1,-1,-1,-1,1,0,0,0};int rejectedIndices=0;
   for(int at=0;at<=raw.length-pattern.length;at++){boolean same=true;for(int k=0;k<pattern.length;k++)if(raw[at+k]!=pattern[k]){same=false;break;}if(!same)continue;
    byte[] bad=raw.clone();bad[at+8]=-2;bad[at+9]=-1;bad[at+10]=-1;bad[at+11]=127;
    try{UseGraphResult.decode(bad);}catch(IllegalStateException e){if("invalid inherited index".equals(e.getMessage()))rejectedIndices++;}}
   check(rejectedIndices>0,"invalid inherited path was not rejected");
   try{UseGraphResult.decode(java.util.Arrays.copyOf(raw,raw.length-1));throw new AssertionError("truncated wire accepted");}catch(IllegalStateException expected){}
  }
  check(saved.row(0).witnessCount()>0&&saved.row(0).witness(0)!=null,"copied result after close");
  System.out.println("PASS v18 use-graph JNI inherited evidence, scope, old wire and retained result");
 }
}
