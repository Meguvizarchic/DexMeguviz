from pathlib import Path
import hashlib, json, os, subprocess, sys
sys.dont_write_bytecode = True
root=Path(__file__).resolve().parents[3]
out=root/'usegraph37-extra'
out.mkdir(exist_ok=True)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
paths=[root/'bindings/android/dexmeguviz-android/src/main/cpp/jni_use_graph.inc',root/'bindings/android/dexmeguviz-android/src/main/java/io/github/jichuo1/dexmeguviz/UseGraphResult.java',root/'bindings/android/dexmeguviz-android/src/main/kotlin/io/github/jichuo1/dexmeguviz/UseGraphQueryExecution.kt',root/'bindings/android/tests/UseGraphHostTest.java',root/'bindings/android/tests/UseGraphKotlinTest.kt',root/'tests/integration/use_query_test.py']
before={str(p):sha(p) for p in paths}
sys.path.insert(0,str(root/'tests/integration'))
from use_query_test import raw_fixture
fixed=['use_relations/two-invokes.dex','use_relations/field-read-write.dex','use_relations/string-normal-jumbo.dex','method_facts/invoke-domains-038.dex']
records={x:raw_fixture(root/'tests/fixtures/generated'/x) for x in fixed}
from relational_test import Oracle
for x in fixed:
 fixture=root/'tests/fixtures/generated'/x
 oracle=Oracle(root,[fixture],False)
 caller=oracle.entities[('method_defs',0,2)]
 assert (caller['reference_index'],caller['code_offset'],caller['owner'],caller['name'],caller['prototype'])==(3,416,'Lfacts/Example;','uses','()V')
 assert oracle.dataset['sources'][0]['source_sha256']==sha(fixture)
(out/'raw-oracle.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
manifest=Path(r'<LOCAL_PATH>')
compiler=json.loads(manifest.read_text(encoding='utf-8-sig'))
for x in compiler:
 assert sha(x['path'])==x['sha256'],x['path']
stdlib=next(x['path'] for x in compiler if x['path'].endswith('kotlin-stdlib-2.4.21.jar'))
annotations=next(x['path'] for x in compiler if x['path'].endswith('annotations-13.0.jar'))
cp=os.pathsep.join(x['path'] for x in compiler)
java=r'C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot\bin\java.exe'
classes=r'<LOCAL_PATH>'; kclasses=str(out/'classes')
commands=[('compile',[java,'-cp',cp,'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-jvm-target','17','-classpath',os.pathsep.join([classes,stdlib,annotations]),str(paths[2]),str(paths[4]),'-d',kclasses]),('run',[java,'-ea','-Xcheck:jni',r'-Djava.library.path=<LOCAL_PATH>','-cp',os.pathsep.join([classes,kclasses,stdlib]),'io.github.jichuo1.dexmeguviz.UseGraphKotlinTestKt',str(root/'tests/fixtures/generated/use_relations/two-invokes.dex')])]
summary=[]
for name,cmd in commands:
 p=subprocess.run(cmd,cwd=root,capture_output=True,timeout=120)
 (out/(name+'.stdout')).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
 summary.append({'name':name,'argv':cmd,'returncode':p.returncode,'stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(p.stderr).hexdigest()})
 if p.returncode or b'WARNING in native method' in p.stdout+p.stderr or b'JNI DETECTED ERROR' in p.stdout+p.stderr:raise SystemExit(name+' failed; see logs')
assert before=={str(p):sha(p) for p in paths}
(out/'summary.json').write_text(json.dumps({'outcome':'passed','source_before_after':before,'fixture_sha256':{x:sha(root/'tests/fixtures/generated'/x) for x in fixed},'compiler_manifest_sha256':sha(manifest),'commands':summary,'scope':'raw-byte oracle and Kotlin Windows JVM bridge only; no Android or ART'},indent=2)+'\n',encoding='utf-8')
print('PASS fixed raw DEX byte oracle and Kotlin v9 JVM bridge')

