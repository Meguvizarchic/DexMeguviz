import io.github.jichuo1.dexmeguviz.TrustedApkDexSource;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;

public final class SourceIdentityProbe {
    public static void main(String[] args) throws Exception {
        var strict=new TrustedApkDexSource.Limits(2,64,1024,1000,1024*1024,1024*1024);
        var same=TrustedApkDexSource.map(new File(args[0]),"split-a",TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,strict,(entry,bytes)->bytes);
        if(same.ordered.size()!=2 || same.ordered.get(0).source.centralIndex==same.ordered.get(1).source.centralIndex ||
           !same.ordered.get(0).source.inputSlot.equals("split-a") || !same.ordered.get(1).source.inputSlot.equals("split-a") ||
           !Arrays.equals(same.ordered.get(0).value,same.ordered.get(1).value))throw new AssertionError("occurrence identity");
        try {TrustedApkDexSource.map(new File(args[1]),"res",TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,strict,(entry,bytes)->entry.name);throw new AssertionError("empty accepted by default");}
        catch(IOException expected){}
        var allow=new TrustedApkDexSource.Limits(2,64,1024,1000,1024*1024,1024*1024,true);
        var resource=TrustedApkDexSource.map(new File(args[1]),"res",TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,allow,(entry,bytes)->entry.name);
        if(resource.sources!=0 || !resource.allowNoDex || !resource.inputSlot.equals("res") || resource.archiveBytes<=0 || !resource.ordered.isEmpty())throw new AssertionError("resource input identity");
        System.out.println("PASS distinct occurrences and explicit empty-source input");
    }
}
