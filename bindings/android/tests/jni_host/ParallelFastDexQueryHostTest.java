import io.github.jichuo1.dexmeguviz.FastDexQuery;
import io.github.jichuo1.dexmeguviz.ParallelFastDexQuery;
import io.github.jichuo1.dexmeguviz.TrustedApkDexSource;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

public final class ParallelFastDexQueryHostTest {
    static byte[] q(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    static void check(boolean value,String message) { if (!value) throw new AssertionError(message); }
    public static void main(String[] args) throws Exception {
        File code=new File(args[0]),resource=new File(args[1]);
        var limits=new TrustedApkDexSource.Limits(3,8,1<<20,100,8L<<20,4L<<20);
        var set=new TrustedApkDexSource.SourceSetLimits(limits,4,8,32L<<20,16L<<20);
        var scan=new FastDexQuery.Limits(1<<20,4096,10000,1<<20,1048576,1048576,8<<20);
        byte[][] rules={q("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\"second\"},\"intent\":\"enumerate\"}"),
            q("{\"schema_version\":1,\"relation\":\"class_defs\",\"intent\":\"enumerate\"}")};
        boolean[] calls={true,false};
        var sources=Arrays.asList(new TrustedApkDexSource.Input(code,"base",false),
            new TrustedApkDexSource.Input(resource,"res",true),new TrustedApkDexSource.Input(code,"split\ud800",false));
        var out=ParallelFastDexQuery.queryAll(sources,TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,set,
            FastDexQuery.InputAssumption.CALLER_ASSERTS_VALID_SORTED_DEX,scan,rules,calls);
        check(out.inputs.size()==3&&out.inputs.get(1).sources==0&&out.sources==4,"source count");
        check(out.ordered.get(0).source.inputSlot.equals("base")&&out.ordered.get(2).source.inputSlot.equals("split\ud800"),"source identity");
        for(var item:out.ordered){check(item.value.rules.size()==2,"rule count");for(var rule:item.value.rules)
            check(rule.coverage()==1&&rule.executionStatus==0&&rule.unknownRows==0&&!rule.resultLimit,"status");}
        try {
            ParallelFastDexQuery.queryAll(List.of(new TrustedApkDexSource.Input(resource,"res",true)),
                TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,set,FastDexQuery.InputAssumption.CALLER_ASSERTS_VALID_SORTED_DEX,
                scan,new byte[][]{q("{\"schema_version\":1,\"relation\":\"field_defs\"}")},new boolean[]{false});
            throw new AssertionError("unsupported query accepted for resource-only input");
        } catch(FastDexQuery.Failure expected) { check(expected.status==3,"unsupported status"); }
        try {
            ParallelFastDexQuery.query(code,"base",TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,limits,
                null,scan,rules,calls);throw new AssertionError("missing assumption accepted");
        } catch(NullPointerException expected) { }
        System.out.println("PASS ordered multi-APK, independent occurrences, partial status and precompiled rules");
    }
}
