package io.github.jichuo1.dexmeguviz;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
public final class BinderLifecycleTest {
 public static void main(String[] args)throws Exception {
  byte[] dex=Files.readAllBytes(Path.of(args[1]));String query="{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"all\":[{\"owner\":\"Lfixture/Target;\"},{\"name\":\"combine\"},{\"prototype\":\"(I[[Ljava/lang/String;[J)I\"}]},\"intent\":\"enumerate\",\"max_results\":16,\"max_work\":1000000}";
  NativeEngine.MethodCandidate candidate;
  try(var snap=NativeEngine.openRawDexSet(new byte[][]{dex},new String[]{"slot"})){var res=snap.queryMethods(query.getBytes(StandardCharsets.UTF_8));if(res.candidateCount()!=1)throw new AssertionError("expected candidate");candidate=res.candidate(0);}
  var loader=new URLClassLoader(new java.net.URL[]{Path.of(args[0]).toUri().toURL()},null);Object generation=new Object();var result=RuntimeMethodBinder.bind(loader,generation,candidate);loader.close();
  if(result.status!=RuntimeMethodBinder.Status.BOUND||result.origin!=RuntimeMethodBinder.Origin.UNVERIFIED||!result.isForGeneration(generation)||result.initiatingLoader!=loader||result.definingLoader!=loader||!"slot".equals(result.sourceSlot)||result.occurrenceId==null)throw new AssertionError("result survives snapshot and loader close");
  if(RuntimeMethodBinder.bind(loader,generation,null).status!=RuntimeMethodBinder.Status.INVALID_INPUT||RuntimeMethodBinder.bind(loader,null,null).isForGeneration(null))throw new AssertionError("invalid token/candidate");
  if(System.getProperty("dexmeguviz.binder.fixture.initialized")!=null)throw new AssertionError("initialization");System.out.println("PASS binder snapshot and loader close lifetime");
 }
}
