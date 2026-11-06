package android.os;
import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.util.*;
public class ParcelFileDescriptor implements AutoCloseable {
 public static final int MODE_READ_ONLY=0x10000000;
 public static final Map<String,Long> sizes=new HashMap<>();public static final List<ParcelFileDescriptor> created=new ArrayList<>();
 public static String failOpen;public static int duplicateCount,instanceDupCalls,failDuplicateAt=-1;public static final Map<FileDescriptor,ParcelFileDescriptor> owners=new IdentityHashMap<>();public static IOException closeFailure;public static boolean failAllClose;
 private static int next=10;private final FileDescriptor descriptor=new FileDescriptor();public final String path;public final long size;public boolean closed;public boolean failClose;
 public ParcelFileDescriptor(String path,long size){this.path=path;this.size=size;owners.put(descriptor,this);}
 public static ParcelFileDescriptor open(File path,int mode)throws IOException {
  if(mode!=MODE_READ_ONLY)throw new AssertionError("not read only");String key=path.getPath();if(key.equals(failOpen)||!sizes.containsKey(key))throw new IOException("missing");
  ParcelFileDescriptor p=new ParcelFileDescriptor(key,sizes.get(key));p.failClose=failAllClose;created.add(p);return p;
 }
 public FileDescriptor getFileDescriptor(){return descriptor;}
 public ParcelFileDescriptor dup()throws IOException {instanceDupCalls++;return dup(getFileDescriptor());}
 public static ParcelFileDescriptor dup(FileDescriptor descriptor)throws IOException {ParcelFileDescriptor original=owners.get(descriptor);if(original==null||original.closed)throw new IOException("closed");if(++duplicateCount==failDuplicateAt)throw new IOException("dup failure");ParcelFileDescriptor p=new ParcelFileDescriptor(original.path,original.size);p.failClose=failAllClose;created.add(p);return p;}
 public long getStatSize(){return size;}
 public int getFd(){if(closed)throw new IllegalStateException("closed");return next++;}
 public void close()throws IOException{closed=true;if(failClose&&closeFailure!=null)throw closeFailure;}
 public static void reset(){sizes.clear();created.clear();owners.clear();failOpen=null;duplicateCount=0;instanceDupCalls=0;failDuplicateAt=-1;closeFailure=null;failAllClose=false;}
}
