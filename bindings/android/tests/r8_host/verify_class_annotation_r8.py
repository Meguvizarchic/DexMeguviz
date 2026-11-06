"""R8 classfile/DEX shrink and Windows JNI test of the v20 fixed fixture.
This is not an Android/ART run. The output directory must not already exist.
"""
import argparse,hashlib,json,os,pathlib,subprocess,zipfile
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from launcher_log import redact_launcher
p=argparse.ArgumentParser();p.add_argument('--preserve-java-options',action='store_true')
for name in ('root','aar','dll','fixture','java-home','stdlib','annotations','r8','android-jar','output'):p.add_argument('--'+name,type=pathlib.Path,required=True)
a=p.parse_args();root=a.root.resolve();out=a.output.resolve();
if out.exists():raise SystemExit('output directory exists')
java=a.java_home/'bin/java.exe';javac=a.java_home/'bin/javac.exe';source=root/'bindings/android/tests/jni_host/JniClassAnnotationGraphTest.java';inputs=[a.aar,a.dll,a.fixture,java,javac,a.java_home/'lib/modules',a.stdlib,a.annotations,a.r8,a.android_jar,source,pathlib.Path(__file__)];sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest();before={str(p.resolve()):sha(p) for p in inputs};out.mkdir(parents=True);records=[]
with zipfile.ZipFile(a.aar) as z:
 (out/'classes.jar').write_bytes(z.read('classes.jar'));(out/'consumer-rules.pro').write_bytes(z.read('proguard.txt'))
jar=out/'classes.jar';env=os.environ.copy()
if not a.preserve_java_options:
 for k in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):env.pop(k,None)
def run(name,args):
 args=list(map(str,args));r=subprocess.run(args,cwd=out,env=env,capture_output=True,timeout=600);(out/(name+'.stdout')).write_bytes(redact_launcher(r.stdout));(out/(name+'.stderr')).write_bytes(redact_launcher(r.stderr));records.append({'name':name,'argv':args,'exit_code':r.returncode,'stdout_sha256':hashlib.sha256(redact_launcher(r.stdout)).hexdigest(),'stderr_sha256':hashlib.sha256(redact_launcher(r.stderr)).hexdigest()});(out/'commands.json').write_text(json.dumps(records,indent=2));
 if r.returncode:raise SystemExit('failed '+name)
 return r.stdout
classes=out/'testclasses';classes.mkdir();run('javac',[javac,'--release','17','-cp',os.pathsep.join(map(str,[jar,a.stdlib])),'-d',classes,source])
program=out/'test.jar'
with zipfile.ZipFile(program,'w',zipfile.ZIP_DEFLATED) as z:
 for f in sorted(classes.rglob('*.class')):z.write(f,f.relative_to(classes).as_posix())
entry=out/'entry.pro';entry.write_text('-keep public class io.github.jichuo1.dexmeguviz.JniClassAnnotationGraphTest { public static void main(java.lang.String[]); }\n',encoding='utf8')
cf=out/'classfile';dex=out/'dex';cf.mkdir();dex.mkdir();common=[java,'-cp',a.r8,'com.android.tools.r8.R8','--release','--lib',a.stdlib,'--lib',a.annotations,'--pg-conf',out/'consumer-rules.pro','--pg-conf',entry,'--thread-count','2']
run('r8-classfile',common+['--lib',a.java_home,'--classfile','--output',cf,jar,program]);run('r8-dex',common+['--lib',a.android_jar,'--dex','--min-api','27','--output',dex,jar,program]);result=run('host',[java,'-ea','-Xcheck:jni','-Djava.library.path='+str(a.dll.parent),'-cp',os.pathsep.join(map(str,[cf,a.stdlib])),'io.github.jichuo1.dexmeguviz.JniClassAnnotationGraphTest',a.fixture]);assert b'PASS host Kotlin facade' in result
assert not any(t in (out/'host.stderr').read_bytes()+(out/'host.stdout').read_bytes() for t in (b'JNI DETECTED ERROR',b'FATAL ERROR in native method',b'WARNING in native method'))
assert list(dex.glob('classes*.dex'));after={str(p.resolve()):sha(p) for p in inputs};assert before==after
outputs={str(p.resolve()):sha(p) for p in out.rglob('*') if p.is_file()};(out/'summary.json').write_text(json.dumps({'outcome':'passed','scope':'same AAR R8 classfile and DEX; Windows host JNI fixed fixture; no ART or device','inputs_before':before,'inputs_after':after,'outputs_sha256':outputs,'commands':records},indent=2));print('PASS R8 classfile JNI and DEX shrink')
