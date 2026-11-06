"""Shrink an actual AAR with the installed R8, inspect DEX and run classfile output on a host JVM."""
from pathlib import Path
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from launcher_log import redact_launcher
from urllib.parse import unquote,urlsplit
from zipfile import ZipFile,ZIP_DEFLATED
import argparse,glob,hashlib,importlib.util,json,os,re,subprocess,sys

if not __debug__:raise SystemExit('R8 verification requires assertions enabled')
p=argparse.ArgumentParser();p.add_argument('--preserve-java-options',action='store_true')
for n in ('root','out','aar','aar-source-manifest','jni-dir','jni-summary','compiler-manifest','java-home','r8-jar','android-jar','unknown-dex'):
 p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();root=a.root.resolve();out=a.out.resolve();aar=a.aar.resolve();jni=a.jni_dir.resolve();jar=jni/'classes.jar';dll=jni/'build/Release/dexmeguviz.dll'
if out.exists():raise SystemExit('output exists')
sha=lambda x:hashlib.sha256(x.read_bytes()).hexdigest()
read=lambda x:json.loads(x.read_text(encoding='utf-8-sig'))
prior=read(a.jni_summary);source=read(a.aar_source_manifest);compiler=read(a.compiler_manifest)
assert prior['outcome']=='passed' and not prior['changed_inputs'] and sha(aar)==prior['aar_sha256'] and sha(jar)==prior['classes_sha256'] and sha(dll)==prior['host_jni_sha256']
for rel,h in source.items():assert sha(root/rel)==h,rel
actual_inputs=prior['actual_after_sha256']
for key in ('candidate_files','aar_build_inputs'):
 assert actual_inputs[key],key
 for rel,h in actual_inputs[key].items():assert sha(root/rel)==h,(key,rel)
for x in compiler:assert sha(Path(x['path']))==x['sha256'],x['path']
stdlib=next(Path(x['path']) for x in compiler if x['path'].endswith('kotlin-stdlib-2.4.21.jar'));annotations=next(Path(x['path']) for x in compiler if x['path'].endswith('annotations-13.0.jar'))
java=a.java_home/'bin/java.exe';javac=a.java_home/'bin/javac.exe';r8=a.r8_jar.resolve();android=a.android_jar.resolve();unknown=a.unknown_dex.resolve()
graph=root/'bindings/android/tests/jni_host/JniGraphJobTest.java';v15=root/'bindings/android/tests/jni_host/JniReflectionMethodUsesTest.java';typed=root/'bindings/android/tests/kotlin_host/KotlinTypedReflectionMethodUsesTest.kt';fixture=root/'tests/fixtures/generated/definition_catalog/definitions.dex';resource=root/'tests/fixtures/generated/multisource/resource-only.apk';uses=root/'tests/fixtures/generated/method_facts/method-uses.dex';oracle_path=root/'tools/evidence_verifier/verify.py';classfile_path=root/'bindings/android/tools/jni_classfile.py';rules_source=root/'bindings/android/dexmeguviz-android/consumer-rules.pro'
with ZipFile(aar) as z:
 assert hashlib.sha256(z.read('classes.jar')).hexdigest()==sha(jar)
 packaged_rules=z.read('proguard.txt').replace(b'\r\n',b'\n').replace(b'\r',b'\n')
 assert packaged_rules==rules_source.read_bytes().replace(b'\r\n',b'\n').replace(b'\r',b'\n')
inputs=[Path(__file__).resolve(),aar,jar,dll,a.jni_summary.resolve(),a.aar_source_manifest.resolve(),a.compiler_manifest.resolve(),java,javac,a.java_home/'lib/modules',r8,android,stdlib,annotations,unknown,graph,v15,typed,fixture,resource,uses,oracle_path,classfile_path,rules_source,*[Path(x['path']) for x in compiler]]
before={str(x.resolve()):sha(x) for x in inputs};out.mkdir(parents=True);(out/'inputs-before.json').write_text(json.dumps(before,indent=2)+'\n',encoding='utf-8')
env=os.environ.copy()
if not a.preserve_java_options:
 for n in ('JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','CLASSPATH'):env.pop(n,None)
env['PATH']=os.pathsep.join([str(dll.parent),*sorted(glob.glob(r'C:\Program Files\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64'),reverse=True),env.get('PATH','')]);env['PYTHONDONTWRITEBYTECODE']='1';records=[]
def run(name,cmd,marker=None):
 r=subprocess.run(list(map(str,cmd)),cwd=out,env=env,capture_output=True,timeout=600);(out/(name+'.stdout.log')).write_bytes(redact_launcher(r.stdout));(out/(name+'.stderr.log')).write_bytes(redact_launcher(r.stderr))
 records.append({'name':name,'exit_code':r.returncode,'argv':list(map(str,cmd)),'stdout_sha256':hashlib.sha256(redact_launcher(r.stdout)).hexdigest(),'stderr_sha256':hashlib.sha256(redact_launcher(r.stderr)).hexdigest()});(out/'commands.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
 if r.returncode or (marker and marker not in r.stdout):raise SystemExit('failed '+name)
 if name.startswith('host-') and any(x in r.stdout+r.stderr for x in (b'WARNING in native method',b'FATAL ERROR in native method',b'JNI DETECTED ERROR')):raise SystemExit('JNI warning')
 print(name,'passed',flush=True);return r
run('r8-version',[java,'-cp',r8,'com.android.tools.r8.R8','--version'])
classes=out/'test-classes';classes.mkdir();run('javac',[javac,'--release','17','-cp',jar,'-d',classes,graph,v15])
run('kotlinc',[java,'-cp',os.pathsep.join(x['path'] for x in compiler),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-jvm-target','17','-classpath',os.pathsep.join(map(str,(stdlib,annotations,jar))),typed,'-d',classes])
program=out/'tests.jar'
with ZipFile(program,'w',ZIP_DEFLATED) as z:
 for f in sorted(classes.rglob('*.class')):z.write(f,f.relative_to(classes).as_posix())
rules=out/'consumer-rules.pro';rules.write_bytes(packaged_rules);entry=out/'test-entry.pro';entry.write_text('''-keep public class io.github.jichuo1.dexmeguviz.JniGraphJobTest { public static void main(java.lang.String[]); }\n-keep public class io.github.jichuo1.dexmeguviz.JniReflectionMethodUsesTest { public static void main(java.lang.String[]); }\n-keep public class io.github.jichuo1.dexmeguviz.KotlinTypedReflectionMethodUsesTestKt { public static void main(java.lang.String[]); }\n''',encoding='utf-8')
cf=out/'r8-classfile';dex=out/'r8-dex';cf.mkdir();dex.mkdir();common=[java,'-cp',r8,'com.android.tools.r8.R8','--release','--lib',stdlib,'--lib',annotations,'--pg-conf',rules,'--pg-conf',entry,'--thread-count','2']
run('r8-classfile',common+['--lib',a.java_home,'--classfile','--output',cf,jar,program]);run('r8-dex',common+['--lib',android,'--dex','--min-api','27','--output',dex,jar,program])
def host(name,main,args,marker):
 log=out/(name+'-class-load.log');base=[java,'-ea','-Xcheck:jni','-Xlog:class+load=info:file='+str(log),'-Djava.library.path='+str(dll.parent),'-cp',os.pathsep.join(map(str,(cf,stdlib)))]
 run(name,base+[main,*args],marker);return log
graph_log=host('host-graph','io.github.jichuo1.dexmeguviz.JniGraphJobTest',[fixture,resource],b'PASS v3 graph Job')
v15_log=host('host-v15','io.github.jichuo1.dexmeguviz.JniReflectionMethodUsesTest',[uses,unknown],b'PASS JNI v15')
typed_log=host('host-typed','io.github.jichuo1.dexmeguviz.KotlinTypedReflectionMethodUsesTestKt',[uses,unknown],b'PASS typed v15 JNI')
for class_log,names in ((graph_log,('NativeEngine','NativeEngine$Snapshot','NativeEngine$SourceSetSnapshot','GraphResult')),(v15_log,('NativeEngine','NativeEngine$Snapshot','NativeEngine$SourceSetSnapshot','NativeEngine$EntityResult')),(typed_log,('NativeEngine','NativeEngine$SourceSetSnapshot','NativeEngine$EntityResult'))):
 log=class_log.read_text(encoding='utf-8',errors='replace')
 for name in names:
  hits=re.findall(r'\]\s+io\.github\.jichuo1\.dexmeguviz\.'+re.escape(name)+r'\s+source:\s+(\S+)',log);assert len(hits)==1,(name,hits)
  u=urlsplit(hits[0]);path=unquote(u.path);path=path[1:] if re.match(r'^/[A-Za-z]:/',path) else path
  assert u.scheme=='file' and Path(path).resolve()==cf.resolve(),(name,hits)
spec=importlib.util.spec_from_file_location('r8_dex_oracle',oracle_path);oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
class_spec=importlib.util.spec_from_file_location('r8_classfile',classfile_path);classfile=importlib.util.module_from_spec(class_spec);class_spec.loader.exec_module(classfile)
with ZipFile(jar) as z:
 expected=[]
 for name in z.namelist():
  if not re.fullmatch(r'io/github/jichuo1/dexmeguviz/NativeEngine(?:\$[^/]+)?\.class',name):continue
  cls=classfile.parse(z.read(name));owner='L'+cls['name'].decode('ascii')+';'
  for method in cls['methods']:
   if (method['access']&0x100) or method['name']==b'<init>':
    expected.append((owner,method['name'].decode('ascii'),method['descriptor'].decode('ascii'),method['access']&0x10f))
 original=classfile.parse(z.read('io/github/jichuo1/dexmeguviz/GraphResult.class'))
 graph_decode=[m for m in original['methods'] if m['name']==b'decode' and m['descriptor']==b'([B)Lio/github/jichuo1/dexmeguviz/GraphResult;'];assert len(graph_decode)==1
 expected.append(('Lio/github/jichuo1/dexmeguviz/GraphResult;','decode','([B)Lio/github/jichuo1/dexmeguviz/GraphResult;',graph_decode[0]['access']&0x10f))
dex_files=sorted(dex.glob('classes*.dex'));assert dex_files
actual={}
for file in dex_files:
 parsed=oracle.parse_dex(file)
 for row in parsed['definitions']:
  key=(row['owner'],row['name'],row['prototype']);assert key not in actual;actual[key]=row
assert not any(owner.startswith('Lkotlin/') for owner,_,_ in actual), 'host-provided Kotlin runtime bundled as program code'
for owner,name,desc,flags in expected:
 key=(owner,name,desc);assert key in actual,(key,'missing from R8 DEX')
 # JNI GetStaticMethodID does not require the original Java visibility. R8 may
 # widen GraphResult.decode while preserving its name, descriptor and staticness.
 mask=0x108 if owner=='Lio/github/jichuo1/dexmeguviz/GraphResult;' and name=='decode' else 0x10f
 assert actual[key]['access_flags']&mask==flags&mask,(key,flags,actual[key])
 assert (actual[key]['code_offset']==0 if flags&0x100 else actual[key]['code_offset']>0),(key,'unexpected code body')
after={str(x.resolve()):sha(x) for x in inputs};assert before==after
outputs={str(x.resolve()):sha(x) for x in [program,rules,entry,graph_log,v15_log,typed_log,*cf.rglob('*.class'),*dex_files]}
(out/'summary.json').write_text(json.dumps({'outcome':'passed','scope':'installed R8 classfile and DEX shrink; Windows JVM JNI smoke and independent DEX metadata; not Android/ART or all app configurations',
 'aar_sha256':sha(aar),'jni_sha256':sha(dll),'r8_sha256':sha(r8),'expected_jni_methods_and_constructors':len(expected),'dex_files':len(dex_files),
 'graph_decode_access_flags_before':graph_decode[0]['access'],'graph_decode_access_flags_after':actual[('Lio/github/jichuo1/dexmeguviz/GraphResult;','decode','([B)Lio/github/jichuo1/dexmeguviz/GraphResult;')]['access_flags'],'bundled_kotlin_definitions':0,
 'inputs_before':before,'inputs_after':after,'outputs_sha256':outputs,'commands':records},indent=2)+'\n',encoding='utf-8')
print('PASS R8 classfile host JNI and DEX JNI metadata')
