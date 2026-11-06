package io.github.jichuo1.dexmeguviz;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
public final class InheritedTargetRejectTest {
 static final String Q="{\"schema_version\":1,\"required_capabilities\":[\"inherited_fields\",\"use_target_symbol\",\"inherited_target_symbol\"],\"relation\":{\"op\":\"join\",\"on\":\"target_symbol\",\"left\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"},\"right\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"all\":[{\"name\":\"uses\"},{\"declares_fields\":{\"scope\":\"inherited\",\"where\":{\"name\":\"unseen\"},\"min\":0,\"max\":0}}]}}}}";
 static void rejected(Runnable r){try{r.run();throw new AssertionError("v18 accepted by unsupported JNI entry");}catch(NativeEngine.NativeFailure e){if(e.status!=3)throw new AssertionError("expected Unsupported, got "+e.status);}}
 public static void main(String[] args)throws Exception{if(args.length!=2)throw new AssertionError("args");byte[] a=Files.readAllBytes(Path.of(args[0])),b=Files.readAllBytes(Path.of(args[1])),q=Q.getBytes(StandardCharsets.UTF_8);if(!NativeEngine.capabilities().contains("dex-query-inherited-target-symbol-v18"))throw new AssertionError("new native capability absent");try(var s=NativeEngine.openRawDexSet(new byte[][]{a,a,b},new String[]{"one","two","parent"})){UseGraphResult u=s.queryUseGraph(q);if(!u.queryId.startsWith("query:v18:")||u.coverage!=1||u.unknownRows==0)throw new AssertionError("expected v18 partial unknown");rejected(()->s.queryGraph(q));rejected(()->s.queryEntities(q));}System.out.println("PASS v18 use graph partial and legacy JNI rejects");}
}
