"""Deterministically exercise JNI Job races using a test-only instrumented copy.

The source is copied to a new C workspace directory and three checked anchors
are instrumented. The user's source and the shipped Android AAR are untouched.
This tests the selected code paths, not general JVM OOM or device behavior.
"""
from pathlib import Path
import argparse,glob,hashlib,json,os,re,shutil,subprocess,sys,time,zipfile

workspace=Path(r'<LOCAL_PATH>')
p=argparse.ArgumentParser()
for flag in ('source','aar','fixture','out'):p.add_argument('--'+flag,type=Path,required=True)
a=p.parse_args();source=a.source.resolve(strict=True);aar=a.aar.resolve(strict=True);fixture=a.fixture.resolve(strict=True);out=a.out.resolve()
if not out.is_relative_to(workspace.resolve()) or out==workspace.resolve() or out.exists() or out.is_relative_to(source):raise SystemExit('output must be a new C workspace directory')
test=Path(__file__).with_name('JniJobFaultTest.java').resolve(strict=True)
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
if sha(fixture)!='dd0e9527dda007481637b6b43393a8239635e85fa006b452092dcc064c3e456f':raise SystemExit('unexpected fixed fixture')
out.mkdir();project=out/'project';project.mkdir()
inputs={}
for folder in ('src','include','cli','cmake','third_party/miniz'):
    shutil.copytree(source/folder,project/folder,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
for rel in ('CMakeLists.txt','bindings/android/tests/jni_host/CMakeLists.txt','bindings/android/dexmeguviz-android/src/main/cpp/dexmeguviz_jni.cpp'):
    target=project/rel;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source/rel,target)
for path in project.rglob('*'):
    if path.is_file():
        rel=path.relative_to(project).as_posix();digest=sha(path)
        if sha(source/rel)!=digest:raise SystemExit('source changed while copying: '+rel)
        inputs[rel]=digest
native=project/'bindings/android/dexmeguviz-android/src/main/cpp/dexmeguviz_jni.cpp'
code=native.read_text(encoding='utf-8')
support=r'''
#include <condition_variable>
#include <chrono>
namespace job_fault_test {
struct Gate { std::mutex mutex; std::condition_variable cv; bool armed=false, reached=false, released=false; };
Gate gates[3]; std::atomic<bool> fail_next{false}, fail_poll{false};
void checkpoint(int index) {
    auto& gate=gates[index]; std::unique_lock lock(gate.mutex);
    if(!gate.armed)return; gate.armed=false; gate.reached=true; gate.cv.notify_all();
    (void)gate.cv.wait_for(lock,std::chrono::seconds(20),[&]{return gate.released;});
}
}
'''
anchor='namespace {\n';assert code.count(anchor)==1;code=code.replace(anchor,support+anchor,1)
old='        std::unique_lock lock(job->consumer,std::try_to_lock);';assert code.count(old)==1
code=code.replace(old,'        job_fault_test::checkpoint(0);\n'+old,1)
old='        dmg_batch* raw=nullptr;dmg_error error{};';assert code.count(old)==1
code=code.replace(old,'        job_fault_test::checkpoint(1);\n'+old,1)
old='            copied=materialize_result(env,batch.get(),job->owner->source_set);';assert code.count(old)==1
new='            if(job_fault_test::fail_next.exchange(false)) java_exception(env,"java/lang/OutOfMemoryError","test injection");\n            else copied=materialize_result(env,batch.get(),job->owner->source_set);'
code=code.replace(old,new,1)
old='        jobject value=nullptr;if(ctor&&!env->ExceptionCheck())value=env->NewObject(cls,ctor,kind,copied);';assert code.count(old)==1
new='        jobject value=nullptr;if(job_fault_test::fail_poll.exchange(false)) java_exception(env,"java/lang/OutOfMemoryError","test injection poll");\n        else if(ctor&&!env->ExceptionCheck())value=env->NewObject(cls,ctor,kind,copied);'
code=code.replace(old,new,1)
old='        // A batch delivery may have failed while the status call was waiting.';assert code.count(old)==1
code=code.replace(old,'        job_fault_test::checkpoint(2);\n'+old,1)
code+=r'''
extern "C" JNIEXPORT void JNICALL Java_io_github_jichuo1_dexmeguviz_JniJobFaultTest_arm(JNIEnv*,jclass,jint index) {
    auto& gate=job_fault_test::gates[index];std::lock_guard lock(gate.mutex);gate.armed=true;gate.reached=false;gate.released=false;
}
extern "C" JNIEXPORT jboolean JNICALL Java_io_github_jichuo1_dexmeguviz_JniJobFaultTest_awaitGate(JNIEnv*,jclass,jint index,jint timeout) {
    auto& gate=job_fault_test::gates[index];std::unique_lock lock(gate.mutex);
    return gate.cv.wait_for(lock,std::chrono::milliseconds(timeout),[&]{return gate.reached;})?JNI_TRUE:JNI_FALSE;
}
extern "C" JNIEXPORT void JNICALL Java_io_github_jichuo1_dexmeguviz_JniJobFaultTest_release(JNIEnv*,jclass,jint index) {
    auto& gate=job_fault_test::gates[index];std::lock_guard lock(gate.mutex);gate.released=true;gate.cv.notify_all();
}
extern "C" JNIEXPORT void JNICALL Java_io_github_jichuo1_dexmeguviz_JniJobFaultTest_failNextMaterialization(JNIEnv*,jclass) {
    job_fault_test::fail_next.store(true);
}
extern "C" JNIEXPORT void JNICALL Java_io_github_jichuo1_dexmeguviz_JniJobFaultTest_failNextPoll(JNIEnv*,jclass) {
    job_fault_test::fail_poll.store(true);
}
'''
native.write_text(code,encoding='utf-8')
jar=out/'classes.jar'
with zipfile.ZipFile(aar) as archive:
    jar_data=archive.read('classes.jar');jar.write_bytes(jar_data)
jar_hash=hashlib.sha256(jar_data).hexdigest();assert sha(jar)==jar_hash
cmake=Path(r'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe')
jdk=Path(r'C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot');java=jdk/'bin/java.exe';javac=jdk/'bin/javac.exe'
runner=Path(__file__).resolve(strict=True);tools={str(path):sha(path) for path in (cmake,java,javac,runner)}
before={'product_inputs':inputs,'aar':sha(aar),'classes_jar':jar_hash,'fixture':sha(fixture),'test':sha(test),'instrumented_cpp':sha(native),'tools':tools}
(out/'inputs-before.json').write_text(json.dumps(before,indent=2)+'\n')
env=os.environ.copy()
for name in ('JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','CLASSPATH'):env.pop(name,None)
env['PATH']=os.pathsep.join(sorted(glob.glob(r'C:\Program Files\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64'),reverse=True)+[env.get('PATH','')]);env['PYTHONDONTWRITEBYTECODE']='1'
build=out/'build';classes=out/'classes';classes.mkdir();records=[]
commands=[('configure',[cmake,'-S',project/'bindings/android/tests/jni_host','-B',build,'-G','Visual Studio 18 2026','-DJDK_HOME='+str(jdk),'-DDMG_BUILD_TESTS=OFF','-DDMG_BUILD_FUZZERS=OFF','-DDMG_WITH_SQLITE=OFF']),
          ('build',[cmake,'--build',build,'--config','Release','--target','dexmeguviz_jni_host','--parallel','3']),
          ('javac',[javac,'--release','17','-cp',jar,'-d',classes,test]),
          ('run',[java,'-ea','-Xcheck:jni','-Xlog:class+load=info','-Djava.library.path='+str(build/'Release'),'-cp',os.pathsep.join(map(str,(classes,jar))),'io.github.jichuo1.dexmeguviz.JniJobFaultTest',fixture])]
test_classes={}
for name,command in commands:
    start=time.monotonic();result=subprocess.run([str(x) for x in command],cwd=out,env=env,capture_output=True,timeout=1200)
    (out/(name+'.stdout.log')).write_bytes(result.stdout);(out/(name+'.stderr.log')).write_bytes(result.stderr)
    records.append({'name':name,'argv':[str(x) for x in command],'exit_code':result.returncode,'seconds':round(time.monotonic()-start,2)})
    (out/'commands.json').write_text(json.dumps(records,indent=2)+'\n');print(name,result.returncode,flush=True)
    if result.returncode:raise SystemExit(result.returncode)
    if name=='javac':
        test_classes={p.relative_to(classes).as_posix():sha(p) for p in classes.rglob('*.class')}
        assert set(test_classes)=={'io/github/jichuo1/dexmeguviz/JniJobFaultTest.class'}
stdout=(out/'run.stdout.log').read_text(encoding='utf-8',errors='replace');stderr=(out/'run.stderr.log').read_text(encoding='utf-8',errors='replace')
assert 'PASS deterministic JNI job delivery failure and consumer races' in stdout
assert not re.search(r'WARNING in native method|FATAL ERROR in native method|JNI DETECTED ERROR',stdout+'\n'+stderr)
for klass,fragment in [('NativeEngine','classes.jar'),('JniJobFaultTest','classes/')]:
    matches=re.findall(r'\]\s+io\.github\.jichuo1\.dexmeguviz\.'+klass+r'\s+source:\s+(\S+)',stdout)
    assert len(matches)==1 and fragment in matches[0],(klass,matches)
for rel,digest in inputs.items():
    if sha(source/rel)!=digest:raise SystemExit('source changed during test: '+rel)
    if rel!='bindings/android/dexmeguviz-android/src/main/cpp/dexmeguviz_jni.cpp' and sha(project/rel)!=digest:raise SystemExit('copy changed: '+rel)
assert sha(aar)==before['aar'] and sha(jar)==before['classes_jar'] and sha(fixture)==before['fixture'] and sha(test)==before['test'] and sha(native)==before['instrumented_cpp']
assert {name:sha(Path(name)) for name in tools}==tools
assert {p.relative_to(classes).as_posix():sha(p) for p in classes.rglob('*.class')}==test_classes
(out/'summary.json').write_text(json.dumps({'outcome':'passed','scope':'test-only transformed JNI copy and actual AAR Java classes on Windows JVM; no device or general OOM proof','inputs':before,'test_classes':test_classes,'commands':records,'jni_sha256':sha(build/'Release/dexmeguviz.dll')},indent=2)+'\n')
print('PASS test-only deterministic failure schedules',flush=True)
