package io.github.jichuo1.dexmeguviz;

import android.content.pm.ApplicationInfo;
import android.os.ParcelFileDescriptor;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/** Explicit adapter over caller-supplied metadata; it does not query PackageManager or a loader. */
public final class AndroidApkSources {
    private AndroidApkSources() {}
    /** The result owns the snapshot; closing it never closes caller-owned descriptors. */
    public static final class Opened implements AutoCloseable {
        public final ApkMetadataPlan plan;
        public final NativeEngine.SourceSetSnapshot snapshot;
        private Opened(ApkMetadataPlan plan,NativeEngine.SourceSetSnapshot snapshot){this.plan=plan;this.snapshot=snapshot;}
        @Override public void close(){snapshot.close();}
    }
    interface PathOpener<T extends AutoCloseable> {T open(byte[][] paths,String[] slots,boolean[] allow,String[] expected,ApkFdLimits limits)throws IOException;}
    interface FdOpener<T extends AutoCloseable> {T open(int[] fds,long[] offsets,long[] lengths,String[] slots,boolean[] allow,String[] expected,ApkFdLimits limits,Object[] keepAlive)throws IOException;}
    /** Copy metadata only; split ordering follows the supplied ApplicationInfo, not loader resolution. */
    public static ApkMetadataPlan plan(ApplicationInfo info,boolean baseAllowNoDex,boolean[] splitAllowNoDex){return plan(info,null,baseAllowNoDex,splitAllowNoDex);}
    /** Loader/generation are caller declarations, not runtime visibility proof. */
    public static ApkMetadataPlan plan(ApplicationInfo info,ApkMetadataPlan.LoaderDeclaration declaration,boolean baseAllowNoDex,boolean[] splitAllowNoDex){
        if(info==null)throw new NullPointerException("application info is required");
        return ApkMetadataPlan.from(info.packageName,declaration,info.sourceDir,info.splitNames,info.splitSourceDirs,baseAllowNoDex,splitAllowNoDex);
    }
    /** Opens only the supplied base/split paths. Native owns atomic close-on-exec descriptors until return. */
    public static Opened open(ApplicationInfo info,boolean baseAllowNoDex,boolean[] splitAllowNoDex,
                              String[] expectedSha256,ApkFdLimits limits)throws IOException {
        return open(info,null,baseAllowNoDex,splitAllowNoDex,expectedSha256,limits);
    }
    public static Opened open(ApplicationInfo info,ApkMetadataPlan.LoaderDeclaration declaration,boolean baseAllowNoDex,boolean[] splitAllowNoDex,
                              String[] expectedSha256,ApkFdLimits limits)throws IOException {
        return open(plan(info,declaration,baseAllowNoDex,splitAllowNoDex),expectedSha256,limits);
    }
    /** Opens the supplied metadata plan; the plan does not authenticate file contents or loader visibility. */
    public static Opened open(ApkMetadataPlan plan,String[] expectedSha256,ApkFdLimits limits)throws IOException {
        return openFiles(plan,expectedSha256,limits,(paths,slots,allow,expected,budget)->{
            NativeEngine.SourceSetSnapshot snapshot=NativeEngine.openApkPaths(paths,slots,allow,expected,budget);
            if(snapshot==null)throw new IOException("native opener returned no snapshot");
            try{return new Opened(plan,snapshot);}catch(RuntimeException|Error failure){try{snapshot.close();}catch(Throwable closeFailure){if(closeFailure!=failure)failure.addSuppressed(closeFailure);}throw failure;}
        });
    }
    /** Borrow only: caller must keep each descriptor open and unchanged until the synchronous return. */
    public static NativeEngine.SourceSetSnapshot openBorrowed(ParcelFileDescriptor[] input,long[] offsets,long[] lengths,
            String[] slots,boolean[] allowNoDex,String[] expectedSha256,ApkFdLimits limits)throws IOException {
        return openBorrowed0(input,offsets,lengths,slots,allowNoDex,expectedSha256,limits,NativeEngine::openApkFdSourcesRetained);
    }
    static byte[] strictPath(String value){
        try{
            ByteBuffer bytes=StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(value));
            if(bytes.remaining()<1||bytes.remaining()>32767)throw new IllegalArgumentException("invalid encoded path length");
            byte[] result=new byte[bytes.remaining()];bytes.get(result);return result;
        }catch(CharacterCodingException e){throw new IllegalArgumentException("path is not valid UTF-16",e);}
    }
    static <T extends AutoCloseable> T openFiles(ApkMetadataPlan plan,String[] expectedSha256,ApkFdLimits limits,PathOpener<T> opener)throws IOException {
        if(plan==null||limits==null||opener==null)throw new NullPointerException("plan, limits and opener are required");
        int count=plan.entries().size();String[] expected=expectedSha256==null?null:expectedSha256.clone();ApkFdInputs.hashes(expected,count);
        byte[][] paths=new byte[count][];String[] slots=new String[count];boolean[] allow=new boolean[count];
        for(int i=0;i<count;i++){ApkMetadataPlan.Entry entry=plan.entries().get(i);paths[i]=strictPath(entry.path);slots[i]=entry.slot;allow[i]=entry.allowNoDex;}
        T result=opener.open(paths,slots,allow,expected,limits);if(result==null)throw new IOException("opener returned no snapshot");return result;
    }
    static <T extends AutoCloseable> T openBorrowed0(ParcelFileDescriptor[] input,long[] offsets,long[] lengths,String[] slots,
            boolean[] allowNoDex,String[] expectedSha256,ApkFdLimits limits,FdOpener<T> opener)throws IOException {
        if(input==null||offsets==null||lengths==null||slots==null||allowNoDex==null||limits==null||opener==null)throw new NullPointerException("inputs and limits are required");
        int count=input.length;if(count<1||count>8||offsets.length!=count||lengths.length!=count||slots.length!=count||allowNoDex.length!=count||(expectedSha256!=null&&expectedSha256.length!=count))throw new IllegalArgumentException("invalid fd source count");
        ParcelFileDescriptor[] captured=input.clone();long[] at=offsets.clone(),sizes=lengths.clone();String[] keys=slots.clone();boolean[] allow=allowNoDex.clone();String[] expected=expectedSha256==null?null:expectedSha256.clone();
        ApkFdInputs.validate(new int[count],at,sizes,keys,allow,expected,limits);
        int[] fds=new int[count];for(int i=0;i<count;i++){
            if(captured[i]==null)throw new NullPointerException("descriptor is required");fds[i]=captured[i].getFd();
        }
        ApkFdInputs.validate(fds,at,sizes,keys,allow,expected,limits);
        T result=opener.open(fds,at,sizes,keys,allow,expected,limits,captured);if(result==null)throw new IOException("opener returned no snapshot");return result;
    }
}
