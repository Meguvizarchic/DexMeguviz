import io.github.jichuo1.dexmeguviz.TrustedApkDexSource;
import java.io.File;
import java.nio.charset.StandardCharsets;

public final class InstalledSourceProbe {
    public static void main(String[] args) throws Exception {
        var result=TrustedApkDexSource.map(new File(args[0]), "base", TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,
            new TrustedApkDexSource.Limits(3,64,1024*1024,100000,512L*1024*1024,16L*1024*1024),
            (entry, bytes)->entry.name+":"+new String(bytes,StandardCharsets.UTF_8));
        if(result.ordered.size()!=3 || !result.ordered.get(0).value.equals("classes.dex:one") ||
            !result.ordered.get(1).value.equals("classes2.dex:two") || !result.ordered.get(2).value.equals("classes10.dex:ten") ||
            !result.ordered.get(0).source.inputSlot.equals("base") || result.ordered.get(0).source.centralIndex!=2 ||
            result.ordered.get(1).source.centralIndex!=3 || result.ordered.get(2).source.centralIndex!=1)throw new AssertionError("source occurrence/order");
        for (int i=1;i<args.length;i++) {
            try { TrustedApkDexSource.map(new File(args[i]), "base", TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,
                new TrustedApkDexSource.Limits(2,64,4,100000,512L*1024*1024,16), (entry,bytes)->entry.name); throw new AssertionError("invalid source accepted"); }
            catch (java.io.IOException expected) {}
        }
        System.out.println("PASS DEX order, exact length/CRC and resource limits");
    }
}
