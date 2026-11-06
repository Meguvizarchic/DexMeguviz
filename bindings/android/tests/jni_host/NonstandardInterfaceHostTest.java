package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
public final class NonstandardInterfaceHostTest {
 public static void main(String[] args)throws Exception{
  if(args.length!=1)throw new AssertionError("fixture path");Path dir=Path.of(args[0]);String[] files={"caller-interface.dex","interface-a-bad-super.dex","interface-common.dex","object.dex"},slots={"caller","bad-interface","target-interface","object"};byte[][] inputs=new byte[files.length][];for(int i=0;i<files.length;i++)inputs[i]=Files.readAllBytes(dir.resolve(files[i]));
  String q="{\"schema_version\":1,\"required_capabilities\":[\"field_declaration_static\",\"caller_field_relation_observation\"],\"scope\":{\"slots\":[\"caller\",\"bad-interface\",\"target-interface\",\"object\"]},\"relation\":{\"op\":\"join\",\"on\":\"caller\",\"left\":{\"op\":\"scan\",\"relation\":\"method_defs\"},\"right\":{\"op\":\"scan\",\"relation\":\"field_uses\",\"where\":{\"target_field_declaration\":{\"scope\":\"any\"}}}}}";
  try(NativeEngine.SourceSetSnapshot snapshot=NativeEngine.openRawDexSet(inputs,slots)){
   CallerFieldRelationResult r=snapshot.queryCallerFieldRelationGraph(q.getBytes(StandardCharsets.UTF_8));if(r.rowCount()!=2||r.graph.unknownRows!=2)throw new AssertionError("unexpected results");
   for(int i=0;i<r.rowCount();i++){var c=r.relation(i);if(c.status!=CallerFieldRelationResult.Status.ANCESTOR||c.nodeCount()!=3||c.node(0).sourceIndex!=0||c.node(1).sourceIndex!=1||c.node(2).sourceIndex!=2)throw new AssertionError("incorrect structural path");}
  }
  System.out.println("PASS nonstandard interface superclass structural JNI path; no ART validity claim");
 }
}
