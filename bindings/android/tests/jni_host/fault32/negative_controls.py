"""Prove the deterministic race checks reject removal of each guard.

Uses a prior passed instrumented copy and its built core libraries; only the
test JNI wrapper is compiled twice in new output directories. No production
file or previously recorded result is modified.
"""
from pathlib import Path
import argparse,glob,hashlib,json,os,re,subprocess,time

p=argparse.ArgumentParser();p.add_argument('--positive',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
positive=a.positive.resolve(strict=True);fixture=a.fixture.resolve(strict=True);out=a.out.resolve();workspace=Path(r'<LOCAL_PATH>').resolve()
assert out.is_relative_to(workspace) and out!=workspace and not out.exists() and not out.is_relative_to(positive)
summary=json.loads((positive/'summary.json').read_text());assert summary['outcome']=='passed'
native=positive/'project/bindings/android/dexmeguviz-android/src/main/cpp/dexmeguviz_jni.cpp';jar=positive/'classes.jar';classes=positive/'classes';core=positive/'build/core/Release/dexmeguviz_core.lib';miniz=positive/'build/core/Release/dmg_miniz.lib'
h=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
assert h(native)==summary['inputs']['instrumented_cpp'] and h(fixture)==summary['inputs']['fixture']
assert h(jar)==summary['inputs']['classes_jar']
assert {p.relative_to(classes).as_posix():h(p) for p in classes.rglob('*.class')}==summary['test_classes']
java_test=Path(__file__).with_name('JniJobFaultTest.java');assert h(java_test)==summary['inputs']['test']
poll_line=next(i for i,line in enumerate(java_test.read_text(encoding='utf-8').splitlines(),1) if '// poll-construction-failure' in line)
inputs={str(x):h(x) for x in (native,jar,core,miniz,fixture)}
cpp=native.read_text(encoding='utf-8')
check='        if(job->delivery_failed.load(std::memory_order_acquire)){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}\n'
consumer='        // and acquisition; never advance a poisoned stream.\n'+check+'        job_fault_test::checkpoint(1);'
status='        // The status snapshot does not certify future concurrent deliveries.\n'+check+'        if(state.outcome.candidates_count>'
assert cpp.count(consumer)==1 and cpp.count(status)==1
lock_guard='        if(!lock.owns_lock()){java_exception(env,"java/lang/IllegalStateException","only one batch consumer is allowed");return nullptr;}\n'
poll_guard='            if(batch){job->delivery_failed.store(true,std::memory_order_release);dmg_job_cancel(job->job);}\n'
assert cpp.count(lock_guard)==1 and cpp.count(poll_guard)==1
variants={'consumer':(consumer,consumer.replace(check,''),'JniJobFaultTest.java:41','AssertionError: expected poisoned stream'),
          'status':(status,status.replace(check,''),'JniJobFaultTest.java:50','AssertionError: expected poisoned stream'),
          'single-consumer':(lock_guard,'','JniJobFaultTest.java:61','AssertionError: concurrent consumer accepted'),
          'poll-failure':(poll_guard,'','JniJobFaultTest.java:'+str(poll_line),'AssertionError: expected poisoned stream')}
out.mkdir();cmake=Path(r'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe');jdk=Path(r'C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot');env=os.environ.copy();env['PATH']=os.pathsep.join(sorted(glob.glob(r'C:\Program Files\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64'),reverse=True)+[env.get('PATH','')])
records=[]
for name,(old,new,expected_line,expected_error) in variants.items():
    target=out/name;target.mkdir();(target/'native.cpp').write_text(cpp.replace(old,new,1),encoding='utf-8')
    text=f'''cmake_minimum_required(VERSION 3.25)
project(JobNegative LANGUAGES CXX)
add_library(dexmeguviz SHARED native.cpp)
target_compile_features(dexmeguviz PRIVATE cxx_std_20)
target_compile_definitions(dexmeguviz PRIVATE _ITERATOR_DEBUG_LEVEL=0)
target_include_directories(dexmeguviz PRIVATE "{(positive/'project/include').as_posix()}" "{(jdk/'include').as_posix()}" "{(jdk/'include/win32').as_posix()}")
target_link_libraries(dexmeguviz PRIVATE "{core.as_posix()}" "{miniz.as_posix()}")
'''
    (target/'CMakeLists.txt').write_text(text,encoding='utf-8');build=target/'build'
    commands=[('configure',[cmake,'-S',target,'-B',build,'-G','Visual Studio 18 2026']),('build',[cmake,'--build',build,'--config','Release','--parallel','2']),
              ('run',[jdk/'bin/java.exe','-ea','-Xcheck:jni','-Djava.library.path='+str(build/'Release'),'-cp',os.pathsep.join(map(str,(classes,jar))),'io.github.jichuo1.dexmeguviz.JniJobFaultTest',fixture])]
    for label,argv in commands:
        started=time.monotonic();r=subprocess.run([str(x) for x in argv],cwd=target,env=env,capture_output=True,timeout=300)
        (target/(label+'.stdout.log')).write_bytes(r.stdout);(target/(label+'.stderr.log')).write_bytes(r.stderr)
        records.append({'variant':name,'step':label,'exit_code':r.returncode,'seconds':round(time.monotonic()-started,2)})
        if label!='run' and r.returncode:raise SystemExit(name+' '+label+' failed')
        if label=='run':
            text=(r.stdout+r.stderr).decode('utf-8','replace')
            if r.returncode==0 or expected_error not in text or expected_line not in text or re.search(r'WARNING in native method|FATAL ERROR in native method|JNI DETECTED ERROR',text):
                raise SystemExit('negative did not fail at intended assertion: '+name)
            print(name,'rejected at intended assertion',flush=True)
for path,value in inputs.items():assert h(Path(path))==value,path
assert {p.relative_to(classes).as_posix():h(p) for p in classes.rglob('*.class')}==summary['test_classes']
(out/'summary.json').write_text(json.dumps({'outcome':'passed','cases':list(variants),'inputs':inputs,'commands':records,'scope':'test-only omission of specific JNI guards; not general JVM or device verification'},indent=2)+'\n')
print('PASS deterministic guard omission controls',flush=True)
