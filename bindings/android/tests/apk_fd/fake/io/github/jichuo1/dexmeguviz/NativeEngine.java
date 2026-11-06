package io.github.jichuo1.dexmeguviz;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import android.os.ParcelFileDescriptor;
public final class NativeEngine {
 public static SourceSetSnapshot last;public static int pathCalls,fdCalls;
 public static int[] fds;public static long[] offsets,lengths;public static String[] slots;public static boolean[] allow;public static Object[] keepAlive;
 public static final class SourceSetSnapshot implements AutoCloseable {public boolean closed;public void close(){closed=true;}}
 static SourceSetSnapshot openApkPaths(byte[][] paths,String[] keys,boolean[] allowed,String[] expected,ApkFdLimits limits)throws IOException{
  pathCalls++;slots=keys.clone();allow=allowed.clone();for(byte[] bytes:paths){String path=new String(bytes,StandardCharsets.UTF_8);if(!ParcelFileDescriptor.sizes.containsKey(path))throw new IOException("fake missing");}return last=new SourceSetSnapshot();
 }
 static SourceSetSnapshot openApkFdSourcesRetained(int[] f,long[] a,long[] n,String[] s,boolean[] z,String[] e,ApkFdLimits l,Object[] retained){fdCalls++;fds=f.clone();offsets=a.clone();lengths=n.clone();slots=s.clone();allow=z.clone();keepAlive=retained;return last=new SourceSetSnapshot();}
}
