import io.github.jichuo1.dexmeguviz.MethodBatchQuery;
import io.github.jichuo1.dexmeguviz.NativeEngine;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class MethodStreamBatchTest {
    static byte[] q(String s){return s.getBytes(StandardCharsets.UTF_8);}
    public static void main(String[] args)throws Exception {
        byte[] dex=Files.readAllBytes(Path.of(args[0]));
        byte[][] rules={q("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\"second\"}}"),
            q("{\"schema_version\":1,\"relation\":\"method_defs\",\"intent\":\"exists\",\"where\":{\"name\":\"absent\"}}"),
            q("{\"schema_version\":1,\"relation\":\"method_defs\",\"max_results\":1}")};
        try(var stream=NativeEngine.openMethodStream(rules,32L<<20,256L<<20);
            var snap=stream.openRawDex(dex,"slot");var foreign=NativeEngine.openRawDex(dex,"slot")) {
            int[] selected={2,0,2};
            var fused=stream.queryMethodsBatch(snap,selected,1L<<20,1000000);
            MethodStreamTest.check(fused.size()==selected.length,"fused size");
            for(int i=0;i<selected.length;++i)MethodStreamTest.same(fused.get(i),stream.queryMethods(snap,selected[i]));
            int[] mixed={0,1};
            var fallback=stream.queryMethodsBatch(snap,mixed,0,0);
            for(int i=0;i<mixed.length;++i)MethodStreamTest.same(fallback.get(i),stream.queryMethods(snap,mixed[i]));
            try{stream.queryMethodsBatch(snap,new int[]{0,99},0,0);throw new AssertionError("bad index accepted");}
            catch(MethodBatchQuery.Failure expected){MethodStreamTest.check(expected.status==1&&expected.failureIndex==1,"failure index");}
            try{stream.queryMethodsBatch(foreign,new int[]{0},0,0);throw new AssertionError("foreign snapshot accepted");}
            catch(NativeEngine.NativeFailure expected){MethodStreamTest.check(expected.status==1,"foreign snapshot status");}
        }
        System.out.println("PASS precompiled selected plans, duplicate order, fallback, result status and failures");
    }
}
