import io.github.jichuo1.dexmeguviz.TrustedApkDexSource;
import java.io.File;
import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

public final class WorkerLifecycleProbe {
    public static void main(String[] args) throws Exception {
        CountDownLatch started=new CountDownLatch(1);AtomicBoolean finished=new AtomicBoolean(false);
        try {
            TrustedApkDexSource.map(new File(args[0]),"base",TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK,
                new TrustedApkDexSource.Limits(2,64,1024,100000,1024*1024,1024*1024),(entry,bytes)->{
                    if(entry.name.equals("classes.dex")){started.await();throw new IOException("test failure");}
                    started.countDown();long until=System.nanoTime()+300_000_000L;
                    while(System.nanoTime()<until)try{Thread.sleep(25);}catch(InterruptedException ignored){}
                    finished.set(true);return entry.name;
                });
            throw new AssertionError("expected failure");
        } catch(IOException expected) { if(!expected.getMessage().equals("test failure"))throw expected; }
        if(!finished.get())throw new AssertionError("mapper still running after return");
        System.out.println("PASS failure waits for in-flight mapper to exit");
    }
}
