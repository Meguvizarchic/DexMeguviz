package io.github.jichuo1.dexmeguviz;
import android.content.pm.ApplicationInfo;
import android.os.ParcelFileDescriptor;
import java.io.File;
public final class AndroidApkSourcesR8Test {
 static final class Resource implements AutoCloseable { boolean closed;public void close(){closed=true;} }
 public static void main(String[] args)throws Exception{
  String path=new File(System.getProperty("java.io.tmpdir"),"synthetic.apk").getAbsolutePath();ParcelFileDescriptor.reset();ParcelFileDescriptor.sizes.put(path,128L);
  ApplicationInfo info=new ApplicationInfo();info.packageName="fixture.pkg";info.sourceDir=path;Object generation=new Object();ClassLoader loader=AndroidApkSourcesR8Test.class.getClassLoader();
  ApkMetadataPlan plan=AndroidApkSources.plan(info,new ApkMetadataPlan.LoaderDeclaration(loader,generation),false,null);
  ApkFdLimits limits=new ApkFdLimits(4096,1024,1024,2048,512,1024,32,512,256);
  Resource snapshot=AndroidApkSources.openFiles(plan,null,limits,(paths,slots,allow,expected,budget)->{
   if(paths.length!=1||!"base".equals(slots[0])||!new String(paths[0],java.nio.charset.StandardCharsets.UTF_8).equals(path)||allow[0])throw new AssertionError("metadata");return new Resource();});
  if(!"fixture.pkg".equals(plan.packageName)||plan.loaderDeclaration.generation!=generation||!ParcelFileDescriptor.created.isEmpty()||snapshot.closed)throw new AssertionError("ownership");snapshot.close();
  System.out.println("PASS R8 fake Android APK metadata and owned fd");
 }
}
