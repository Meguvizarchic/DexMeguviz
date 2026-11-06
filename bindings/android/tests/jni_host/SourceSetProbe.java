import io.github.jichuo1.dexmeguviz.TrustedApkDexSource;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public final class SourceSetProbe {
    public static void main(String[] args) throws Exception {
        File dex=new File(args[0]),resource=new File(args[1]);
        var per=new TrustedApkDexSource.Limits(3,64,1024,1000,1024*1024,1024*1024);
        var limits=new TrustedApkDexSource.SourceSetLimits(per,8,4,4*1024*1024,1024*1024);
        var inputs=Arrays.asList(new TrustedApkDexSource.Input(dex,"base",false),new TrustedApkDexSource.Input(resource,"res",true),new TrustedApkDexSource.Input(dex,"split",false));
        var output=TrustedApkDexSource.mapAll(inputs,TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,limits,(entry,bytes)->bytes);
        if(output.inputs.size()!=3 || output.ordered.size()!=4 || output.inputs.get(1).sources!=0 || !output.inputs.get(1).allowNoDex ||
            output.ordered.get(0).source.inputIndex!=0 || output.ordered.get(1).source.inputIndex!=0 ||
            output.ordered.get(2).source.inputIndex!=2 || output.ordered.get(3).source.inputIndex!=2 ||
            !output.ordered.get(0).source.inputSlot.equals("base") || !output.ordered.get(2).source.inputSlot.equals("split") ||
            !Arrays.equals(output.ordered.get(0).value,output.ordered.get(2).value))throw new AssertionError("ordered source identity");
        AtomicInteger invoked=new AtomicInteger();
        try {TrustedApkDexSource.mapAll(Arrays.asList(inputs.get(0),new TrustedApkDexSource.Input(resource,"res",false)),
             TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,limits,(entry,bytes)->invoked.incrementAndGet());throw new AssertionError("invalid late source accepted");}
        catch(IOException expected){}
        if(invoked.get()!=0)throw new AssertionError("work began before validating source set");
        try {TrustedApkDexSource.mapAll(Arrays.asList(inputs.get(0),new TrustedApkDexSource.Input(dex,"base",false)),
             TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,limits,(entry,bytes)->entry.name);throw new AssertionError("duplicate slot accepted");}
        catch(IllegalArgumentException expected){}
        try {TrustedApkDexSource.mapAll(inputs,TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,
             new TrustedApkDexSource.SourceSetLimits(per,8,3,4*1024*1024,1024*1024),(entry,bytes)->entry.name);throw new AssertionError("source limit accepted");}
        catch(IOException expected){}
        try {TrustedApkDexSource.mapAll(inputs,TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,
             new TrustedApkDexSource.SourceSetLimits(per,8,4,4*1024*1024,10),(entry,bytes)->entry.name);throw new AssertionError("total dex limit accepted");}
        catch(IOException expected){}
        System.out.println("PASS ordered APKs, repeated bytes, resource split and all-input preparation");
    }
}
