import io.github.jichuo1.dexmeguviz.FastDexQuery;
import io.github.jichuo1.dexmeguviz.NativeApkFastQuery;
import io.github.jichuo1.dexmeguviz.ParallelFastDexQuery;
import io.github.jichuo1.dexmeguviz.TrustedApkDexSource;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Compare the native archive path with the existing Java archive path on shared fixtures. */
public final class NativeApkFastQueryHostTest {
    static void check(boolean value,String message) { if (!value) throw new AssertionError(message); }
    public static void main(String[] args) throws Exception {
        File code=new File(args[0]),resource=new File(args[1]);
        byte[][] rules={"{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\"second\"},\"intent\":\"enumerate\"}".getBytes(StandardCharsets.UTF_8),
            "{\"schema_version\":1,\"relation\":\"class_defs\",\"intent\":\"enumerate\"}".getBytes(StandardCharsets.UTF_8)};
        boolean[] calls={true,false};
        var scan=new FastDexQuery.Limits(1<<20,4096,10000,1<<20,1048576,1048576,8<<20);
        var trusted=new TrustedApkDexSource.Limits(3,8,1<<20,100,8L<<20,4L<<20);
        var set=new TrustedApkDexSource.SourceSetLimits(trusted,4,8,32L<<20,16L<<20);
        var oldInputs=Arrays.asList(new TrustedApkDexSource.Input(code,"base",false),
            new TrustedApkDexSource.Input(resource,"res",true),new TrustedApkDexSource.Input(code,"split\ud800",false));
        var old=ParallelFastDexQuery.queryAll(oldInputs,TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,set,
            FastDexQuery.InputAssumption.CALLER_ASSERTS_VALID_SORTED_DEX,scan,rules,calls);
        var limits=new NativeApkFastQuery.SourceLimits(3,4,8,8,100,8L<<20,32L<<20,4L<<20,16L<<20,1<<20,4L<<20,8L<<20,16384);
        var inputs=Arrays.asList(new NativeApkFastQuery.Input(code,"base",false),
            new NativeApkFastQuery.Input(resource,"res",true),new NativeApkFastQuery.Input(code,"split\ud800",false));
        try (var plans=FastDexQuery.compile(rules,calls)) {
            var out=NativeApkFastQuery.queryAll(inputs,NativeApkFastQuery.Policy.TRUSTED_IMMUTABLE_APK,
                FastDexQuery.InputAssumption.CALLER_ASSERTS_VALID_SORTED_DEX,limits,scan,plans,true,8<<20);
            check(out.inputs.size()==3&&out.inputs.get(1).sourceCount==0&&out.ordered.size()==old.ordered.size(),"source count");
            for(int i=0;i<out.ordered.size();i++) {
                var a=out.ordered.get(i);var b=old.ordered.get(i);
                check(a.slot.equals(b.source.inputSlot)&&a.inputIndex==b.source.inputIndex&&
                    a.ordinal==b.source.ordinal&&a.centralIndex==b.source.centralIndex&&a.crc==b.source.crc,"source occurrence");
                check(a.result.rules.size()==b.value.rules.size(),"rule count");
                for(int j=0;j<a.result.rules.size();j++) {
                    var x=a.result.rules.get(j);var y=b.value.rules.get(j);
                    check(x.executionStatus==y.executionStatus&&x.unknownRows==y.unknownRows&&
                        x.resultLimit==y.resultLimit&&x.coverage()==y.coverage()&&
                        x.methods.size()==y.methods.size()&&x.classes.size()==y.classes.size(),"rule result");
                }
            }
        }
        System.out.println("PASS native archive ordered sources and rule status match Java archive path");
    }
}
