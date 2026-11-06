"""Isolated fixed-fixture host validation for the v3 JNI graph bridge."""
from pathlib import Path
import argparse,glob,hashlib,json,os,subprocess,time
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
root=a.root.resolve(strict=True);out=a.out.resolve();workspace=Path(r'<LOCAL_PATH>').resolve()
if not out.is_relative_to(workspace) or out==workspace or out.is_relative_to(root) or out.exists():raise SystemExit('output must be new directory outside source')
out.mkdir();sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
paths=[]
for folder in ('src','include','cli','cmake','third_party/miniz','bindings/android/dexmeguviz-android/src','bindings/android/tests/jni_host','bindings/android/tests/kotlin_host'):
    paths.extend(p for p in (root/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc')
paths.extend([root/'CMakeLists.txt',root/'bindings/android/tests/jni_host/CMakeLists.txt',root/'tests/fixtures/generators/generate_dex.py',root/'tests/fixtures/generated/definition_catalog/definitions.dex',root/'tests/fixtures/generated/multisource/reverse-stored.apk',root/'tests/fixtures/generated/multisource/resource-only.apk',root/'bindings/android/tests/jni_host/fixtures-entity32/empty-nul.dex'])
paths=list(dict.fromkeys(paths));before={str(x):sha(x) for x in paths};(out/'source-before.json').write_text(json.dumps(before,indent=2)+'\n',encoding='utf-8')
cmake=Path(r'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe');jdk=Path(r'C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot');java=jdk/'bin/java.exe';javac=jdk/'bin/javac.exe'
compiler_manifest=Path(r'<LOCAL_PATH>');compiler=json.loads(compiler_manifest.read_text(encoding='utf-8'))
for item in compiler:
    if sha(Path(item['path']))!=item['sha256']:raise SystemExit('Kotlin tool SHA mismatch')
stdlib=next(Path(x['path']) for x in compiler if x['path'].endswith('kotlin-stdlib-2.4.21.jar'));annotations=next(Path(x['path']) for x in compiler if x['path'].endswith('annotations-13.0.jar'))
compiler_cp=os.pathsep.join(x['path'] for x in compiler);env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1';env['PATH']=os.pathsep.join(sorted(glob.glob(r'C:\Program Files\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64'),reverse=True)+[env.get('PATH','')])
for key in ('JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','CLASSPATH'):env.pop(key,None)
records=[]
def run(name,cmd,marker=None):
    start=time.monotonic();r=subprocess.run([str(x) for x in cmd],cwd=root,env=env,capture_output=True,timeout=900);(out/(name+'.stdout.log')).write_bytes(r.stdout);(out/(name+'.stderr.log')).write_bytes(r.stderr);records.append({'name':name,'exit_code':r.returncode,'seconds':round(time.monotonic()-start,2),'argv':list(map(str,cmd))});(out/'commands.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8');print(name,r.returncode,flush=True)
    if r.returncode or (marker and marker not in r.stdout):raise SystemExit('test failure: '+name)
    if name in ('java-test','kotlin-test','differential') and any(x in r.stdout+r.stderr for x in (b'WARNING in native method',b'FATAL ERROR in native method',b'JNI DETECTED ERROR')):raise SystemExit('JNI warning: '+name)
    return r
build=out/'build';classes=out/'classes';kclasses=out/'kotlin';classes.mkdir();kclasses.mkdir()
run('configure',[cmake,'-S',root/'bindings/android/tests/jni_host','-B',build,'-DJDK_HOME='+str(jdk)])
run('build',[cmake,'--build',build,'--config','Release','--target','dexmeguviz_jni_host','dmg_graph_writer_test','--parallel','4'])
run('writer',[build/'Release/dmg_graph_writer_test.exe'],b'PASS bounded graph wire')
run('fixture',[Path(os.sys.executable),'-B',root/'bindings/android/tests/jni_host/generate_graph_large_fixture.py','--generator',root/'tests/fixtures/generators/generate_dex.py','--out',out/'large-fixture'],b'PASS generated large graph fixture')
java_src=root/'bindings/android/dexmeguviz-android/src/main/java/io/github/jichuo1/dexmeguviz';tests=root/'bindings/android/tests/jni_host'
run('javac',[javac,'--release','17','-d',classes,java_src/'NativeEngine.java',java_src/'GraphResult.java',tests/'JniGraphTest.java',tests/'JniGraphDump.java'])
native=build/'Release';fixture=root/'tests/fixtures/generated/definition_catalog/definitions.dex'
run('java-test',[java,'-ea','-Xcheck:jni','-Djava.library.path='+str(native),'-cp',classes,'io.github.jichuo1.dexmeguviz.JniGraphTest',fixture,tests/'fixtures-entity32/empty-nul.dex',root/'tests/fixtures/generated/multisource/reverse-stored.apk',root/'tests/fixtures/generated/multisource/resource-only.apk',out/'large-fixture/large.dex'],b'PASS v3 graph JNI copy')
cli=Path(r'<LOCAL_PATH>')
host_manifest=Path(r'<LOCAL_PATH>')
host=json.loads(host_manifest.read_text(encoding='utf-8-sig'))
for rel,digest in host.items():
    if rel=='CMakeLists.txt' or rel.startswith(('src/','include/','cli/','cmake/','third_party/miniz/')):
        if sha(root/rel)!=digest:raise SystemExit('reference CLI source mismatch: '+rel)
cli_sha=sha(cli);host_sha=sha(host_manifest)
reject=subprocess.run([str(os.sys.executable),'-O','-B',str(tests/'verify_graph_cli.py')],cwd=root,env=env,capture_output=True,timeout=60)
(out/'optimized-rejection.stdout.log').write_bytes(reject.stdout);(out/'optimized-rejection.stderr.log').write_bytes(reject.stderr)
records.append({'name':'optimized-rejection','exit_code':reject.returncode,'argv':[str(os.sys.executable),'-O','-B',str(tests/'verify_graph_cli.py')]})
if reject.returncode==0 or b'graph differential requires assertions enabled' not in reject.stderr:raise SystemExit('optimized mode not rejected')
run('differential',[Path(os.sys.executable),'-B',tests/'verify_graph_cli.py','--root',root,'--cli',cli,'--java',java,'--classes',classes,'--native',native],b'"outcome": "passed"')
if sha(cli)!=cli_sha or sha(host_manifest)!=host_sha:raise SystemExit('reference CLI inputs changed')
run('kotlinc',[java,'-cp',compiler_cp,'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-jvm-target','17','-classpath',os.pathsep.join(map(str,(classes,stdlib,annotations))),root/'bindings/android/dexmeguviz-android/src/main/kotlin/io/github/jichuo1/dexmeguviz/GraphQueryExecution.kt',root/'bindings/android/tests/kotlin_host/KotlinGraphBridgeTest.kt','-d',kclasses])
run('kotlin-test',[java,'-ea','-Xcheck:jni','-Djava.library.path='+str(native),'-cp',os.pathsep.join(map(str,(classes,kclasses,stdlib))),'io.github.jichuo1.dexmeguviz.KotlinGraphBridgeTestKt',fixture],b'PASS Kotlin graph JSON single and multi-source')
classes_for_javap=['NativeEngine','NativeEngine$Snapshot','NativeEngine$SourceSetSnapshot','GraphResult','GraphResult$Profile','GraphResult$Operator','GraphResult$Input','GraphResult$Source','GraphResult$Entity','GraphResult$Binding','GraphResult$Link','GraphResult$Witness','GraphResult$Row']
run('javap',[jdk/'bin/javap.exe','-public','-s','-classpath',classes,*['io.github.jichuo1.dexmeguviz.'+x for x in classes_for_javap]])
after={str(x):sha(x) for x in paths};changed=[name for name in before if before[name]!=after[name]]
if changed:raise SystemExit('source inputs changed: '+str(changed))
(out/'summary.json').write_text(json.dumps({'outcome':'passed','scope':'Windows JVM/JNI and 13 fixed CLI comparisons; not final AAR, Android or ART','source_sha256_before':before,'source_sha256_after':after,'commands':records,'dll_sha256':sha(native/'dexmeguviz.dll'),'cli_sha256':sha(cli),'cli_source_manifest_sha256':host_sha,'large_fixture_sha256':sha(out/'large-fixture/large.dex'),'compiler_manifest_sha256':sha(compiler_manifest)},indent=2)+'\n',encoding='utf-8')
print('PASS graph candidate host and Kotlin',flush=True)

