package io.github.jichuo1.dexmeguviz;
import java.nio.file.Files;
import java.nio.file.Path;
public final class ScopedV18Gate {
 public static void main(String[] args) throws Exception {
  if(args.length!=3)throw new AssertionError("args");byte[] a=Files.readAllBytes(Path.of(args[0])),b=Files.readAllBytes(Path.of(args[1])),q=Files.readAllBytes(Path.of(args[2]));String[] slots={"input:0:"+args[0],"input:1:"+args[0],"input:2:"+args[1]};
  try(NativeEngine.SourceSetSnapshot snapshot=NativeEngine.openRawDexSet(new byte[][]{a,a,b},slots)) {
   UseGraphResult prior=snapshot.queryUseGraph(q);if(!prior.queryId.startsWith("query:v18:")||!prior.profile.scopeComplete||prior.rowCount()!=8)throw new AssertionError("old v18 regression");
   try{snapshot.queryUseGraphScopedV4(q);throw new AssertionError("v18 entered v4 opt-in");}catch(NativeEngine.NativeFailure expected){if(expected.status!=3)throw expected;}
  }
  System.out.println("PASS scoped-v4 rejects valid v18 while legacy v18 succeeds");
 }
}
