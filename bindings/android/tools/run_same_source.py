"""Plan/build/verify one isolated Android AAR and Windows JNI source snapshot.

Default mode is plan. No downloads, deletion, fuzz, device or publication tasks.
"""
from pathlib import Path
from zipfile import ZipFile
import argparse,ctypes,hashlib,json,os,re,shutil,subprocess,sys,threading,time
from launcher_log import redact_launcher

SOURCE_DIRS=('src','include','cli','cmake','third_party/miniz','bindings/android','tests/fixtures','tests/integration','tools/evidence_verifier')
OMIT_DIRS={'.git','.gradle','.cxx','build','build-debug','build-release','CMakeFiles','__pycache__','.idea'}
OMIT_SUFFIXES={'.obj','.ilk','.pdb','.lib','.dll','.exe','.aar','.class','.pyc','.o','.a','.so','.log','.stdout','.stderr'}
MAX_LOG=32*1024*1024
def need(ok,message):
    if not ok:raise RuntimeError(message)
def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for part in iter(lambda:f.read(1024*1024),b''):h.update(part)
    return h.hexdigest()
def save(path,value):Path(path).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def under(root,relative):
    p=(root/relative).resolve();need(p.is_relative_to(root) and p!=root,'relative input escapes source root');return p
def plain_path(path):
    p=Path(path).resolve();need(not any(c in str(p) for c in '\r\n"%&|<>^'),'unsupported path characters');return p
def windows_options(value):
    if not value.strip():return []
    need(os.name=='nt','this runner currently supports Windows hosts only')
    argc=ctypes.c_int();shell=ctypes.windll.shell32;shell.CommandLineToArgvW.argtypes=[ctypes.c_wchar_p,ctypes.POINTER(ctypes.c_int)];shell.CommandLineToArgvW.restype=ctypes.POINTER(ctypes.c_wchar_p)
    pointer=shell.CommandLineToArgvW('java '+value,ctypes.byref(argc));need(bool(pointer),'invalid inherited Java options')
    try:return [pointer[i] for i in range(1,argc.value)]
    finally:ctypes.windll.kernel32.LocalFree.argtypes=[ctypes.c_void_p];ctypes.windll.kernel32.LocalFree(pointer)
def select_sources(root,overlay):
    selected={}
    for base in [root]+([overlay] if overlay else []):
        paths=[base/'CMakeLists.txt',base/'CMakePresets.json']
        for folder in SOURCE_DIRS:
            start=base/folder
            if not start.exists():continue
            for directory,dirs,files in os.walk(start,followlinks=False):
                dirs[:]=[d for d in dirs if d not in OMIT_DIRS and not (Path(directory)/d).is_symlink() and not getattr(Path(directory)/d,'is_junction',lambda:False)()]
                for name in files:paths.append(Path(directory)/name)
        for p in paths:
            if not p.is_file() or p.is_symlink() or p.name in ('local.properties','.env') or p.suffix in OMIT_SUFFIXES:continue
            rel=p.relative_to(base).as_posix()
            if p.suffix=='.jar' and rel!='bindings/android/gradle/wrapper/gradle-wrapper.jar':continue
            need(p.resolve().is_relative_to(base),'source junction escapes root')
            selected[rel]=p
    need('CMakeLists.txt' in selected and len(selected)<=20000,'source selection bound')
    need(sum(p.stat().st_size for p in selected.values())<=512*1024*1024,'source snapshot exceeds 512 MiB')
    return selected
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('root','jdk','sdk','gradle-cache','cmake','compiler-inputs','out'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('overlay','gradle-home','android-jar','r8-jar','readelf','suite','approved-plan'):p.add_argument('--'+name,type=Path)
    p.add_argument('--mode',choices=('plan','build','verify'),default='plan');p.add_argument('--generator');p.add_argument('--parallel',type=int,default=2);p.add_argument('--timeout-seconds',type=int,default=1800)
    a=p.parse_args();need(os.name=='nt','Windows host required');need(1<=a.parallel<=8 and 30<=a.timeout_seconds<=7200,'invalid execution bound')
    root=plain_path(a.root);overlay=plain_path(a.overlay) if a.overlay else None;out=plain_path(a.out);jdk=plain_path(a.jdk);sdk=plain_path(a.sdk);cache=plain_path(a.gradle_cache);cmake=plain_path(a.cmake)
    need(root.is_dir() and (overlay is None or overlay.is_dir()),'source root missing');need(not out.exists() and not out.is_relative_to(root) and not root.is_relative_to(out),'output must be new and separate from source')
    need(overlay is None or not out.is_relative_to(overlay) and not overlay.is_relative_to(out),'output overlaps overlay');need(len(str(out/'t'))<=80,'use a short output path so the Java temp path is at most 80 characters')
    release=(jdk/'release').read_text();need(re.search(r'JAVA_VERSION="17(?:\.|\")',release),'JDK 17 required')
    selected=select_sources(root,overlay);sources={rel:digest(f) for rel,f in selected.items()}
    def source(rel):need(rel in selected,'missing selected source: '+rel);return selected[rel]
    build=source('bindings/android/dexmeguviz-android/build.gradle.kts').read_text();wrapper=source('bindings/android/gradle/wrapper/gradle-wrapper.properties').read_text()
    gradle_version=re.search(r'gradle-([0-9.]+)-bin\.zip',wrapper)[1];ndk_version=re.search(r'ndkVersion\s*=\s*"([^"]+)"',build)[1];build_tools=re.search(r'buildToolsVersion\s*=\s*"([^"]+)"',build)[1]
    major=re.search(r'version\s*=\s*release\((\d+)\)',build)[1];minor=re.search(r'minorApiLevel\s*=\s*(\d+)',build)
    platform='android-'+major+('.'+minor[1] if minor else '')
    homes=[plain_path(a.gradle_home)] if a.gradle_home else sorted(cache.glob('wrapper/dists/gradle-'+gradle_version+'-bin/*/gradle-'+gradle_version))
    need(len(homes)==1 and homes[0].is_dir(),'one installed matching Gradle distribution required; supply --gradle-home')
    gradle=homes[0].resolve();launcher=gradle/'lib'/('gradle-gradle-cli-main-'+gradle_version+'.jar');need(launcher.is_file(),'matching Gradle launcher unavailable; wrapper download is never attempted')
    android=plain_path(a.android_jar) if a.android_jar else sdk/'platforms'/platform/'android.jar';r8=plain_path(a.r8_jar) if a.r8_jar else sdk/'build-tools'/build_tools/'lib/d8.jar';ndk=sdk/'ndk'/ndk_version
    readelf=plain_path(a.readelf) if a.readelf else ndk/'toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-readelf.exe'
    compiler_manifest=plain_path(a.compiler_inputs);compiler=json.loads(compiler_manifest.read_text(encoding='utf-8-sig'));need(isinstance(compiler,list) and 1<=len(compiler)<=32,'compiler manifest shape')
    for item in compiler:need(digest(Path(item['path']))==item['sha256'],'compiler input digest mismatch')
    jars=[Path(x['path']).resolve() for x in compiler];stdlib=next(x for x in jars if x.name=='kotlin-stdlib-2.4.21.jar');annotations=next(x for x in jars if x.name=='annotations-13.0.jar')
    suite_path=plain_path(a.suite) if a.suite else Path(__file__).with_name('android_suite_v1.json').resolve();suite=json.loads(suite_path.read_text());need(suite.get('schema_version')==1,'suite version')
    for item in suite['java']+suite['kotlin']:
        need(re.fullmatch(r'io\.github\.jichuo1\.dexmeguviz\.[A-Za-z0-9_$]+',item['class']) is not None,'invalid consumer class')
        for rel in [item['source'],*item['fixtures']]:source(rel)
    taskkill=Path(os.environ['SystemRoot'])/'System32/taskkill.exe'
    tools=[Path(__file__).resolve(),Path(__file__).with_name('launcher_log.py').resolve(),suite_path,Path(sys.executable),jdk/'release',jdk/'bin/java.exe',jdk/'bin/javac.exe',jdk/'lib/modules',jdk/'include/jni.h',cmake,android,r8,readelf,compiler_manifest,taskkill,*jars,*gradle.rglob('*.jar'),ndk/'source.properties',ndk/'build/cmake/android.toolchain.cmake']
    for name in ('clang.exe','clang++.exe','ld.lld.exe','llvm-ar.exe'):tools.append(readelf.parent/name)
    need(all(x.is_file() for x in tools),'a selected tool or SDK file is missing');tool_hashes={str(x.resolve()):digest(x) for x in tools}
    with ZipFile(r8) as z:need('com/android/tools/r8/R8.class' in z.namelist() and 'com/android/tools/r8/D8.class' in z.namelist(),'R8/D8 entrypoints absent')
    inherited={key:{'present':key in os.environ,'sha256':hashlib.sha256(os.environ.get(key,'').encode()).hexdigest()} for key in ('JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS','GRADLE_OPTS')}
    hidden_tokens=windows_options(os.environ.get('JAVA_OPTS',''))+windows_options(os.environ.get('GRADLE_OPTS',''))
    def display(argv):return ['<inherited-java-option>' if str(x) in hidden_tokens else str(x) for x in argv]
    snap=out/'source';project=snap/'bindings/android';java=jdk/'bin/java.exe';javac=jdk/'bin/javac.exe';tmp=out/'t';jni=out/'jni';native=jni/'build/Release';aar=project/'dexmeguviz-android/build/outputs/aar/dexmeguviz-android-release.aar';jar=jni/'classes.jar';classes=out/'host/classes';kclasses=out/'host/kotlin';report=out/'runtime-report.txt'
    pom=project/'dexmeguviz-android/build/publications/localProbe/pom-default.xml';module=pom.with_name('module.json')
    gradle_cmd=[java,'-Xmx64m','-Xms64m',*hidden_tokens,'-Dorg.gradle.appname=gradle','-jar',launcher,'--offline','--no-daemon','--console=plain','--max-workers='+str(a.parallel),'-Dorg.gradle.java.home='+str(jdk),'-g',cache,'-p',project,'--init-script',out/'resolved-inputs.gradle']
    configure=[cmake,'-S',snap/'bindings/android/tests/jni_host','-B',jni/'build','-DJDK_HOME='+str(jdk),'-DDMG_WITH_SQLITE=OFF','-DDMG_BUILD_FUZZERS=OFF']+(['-G',a.generator] if a.generator else [])
    python=[sys.executable,'-B'];steps=[]
    def step(name,phase,argv,cwd=out,marker=None):steps.append({'name':name,'phase':phase,'argv':argv,'cwd':cwd,'marker':marker,'status':'not_executed'})
    step('gradle-aar','build',gradle_cmd+[':dexmeguviz-android:assembleRelease',':dexmeguviz-android:verifyNoExternalRuntime',':dexmeguviz-android:verifyHostProvidedStdlib',':dexmeguviz-android:generatePomFileForLocalProbePublication',':dexmeguviz-android:generateMetadataFileForLocalProbePublication',':dexmeguviz-android:recordRunnerInputs'],project)
    step('gradle-runtime-report','build',gradle_cmd+[':dexmeguviz-android:dependencies','--configuration','releaseRuntimeClasspath'],project)
    step('jni-configure','build',configure);step('jni-build','build',[cmake,'--build',jni/'build','--config','Release','--target','dexmeguviz_jni_host','dmg_graph_writer_test','--parallel',str(a.parallel)])
    step('aar-audit','verify',python+[snap/'bindings/android/tools/verify_aar.py','--aar',aar,'--pom',pom,'--module',module,'--header',snap/'include/dexmeguviz/dexmeguviz.h','--readelf',readelf,'--runtime-report',report,'--expect-kotlin','--out',out/'aar-audit'])
    step('jni-writer','verify',[native/'dmg_graph_writer_test.exe'],marker='PASS')
    step('javac-consumers','verify',[javac,'--release','17','-cp',jar,'-d',classes,*[snap/x['source'] for x in suite['java']]])
    for item in suite['java']:step(item['class'].split('.')[-1],'verify',[java,'-ea','-Xcheck:jni','-Djava.io.tmpdir='+str(tmp),'-Djava.library.path='+str(native),'-cp',os.pathsep.join(map(str,[classes,jar])),item['class'],*[snap/f for f in item['fixtures']]],marker='PASS')
    step('kotlin-consumers','verify',[java,'-cp',os.pathsep.join(map(str,jars)),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-jvm-target','17','-classpath',os.pathsep.join(map(str,[jar,stdlib,annotations])) ,*[snap/x['source'] for x in suite['kotlin']],'-d',kclasses])
    for item in suite['kotlin']:step(item['class'].split('.')[-1],'verify',[java,'-ea','-Xcheck:jni','-Djava.io.tmpdir='+str(tmp),'-Djava.library.path='+str(native),'-cp',os.pathsep.join(map(str,[kclasses,jar,stdlib])),item['class'],*[snap/f for f in item['fixtures']]],marker='PASS')
    for kind in ('binder_fixture','member_binder_fixture'):step(kind,'verify',python+[snap/'bindings/android/tests'/kind/'run_host.py','--aar',aar,'--jni',native/'dexmeguviz.dll','--jdk',jdk,'--d8',r8,'--out',out/kind],marker='PASS')
    step('r8','verify',python+[snap/'bindings/android/tests/r8_host/verify_r8_host.py','--preserve-java-options','--root',snap,'--out',out/'r8','--aar',aar,'--aar-source-manifest',out/'source-manifest.json','--jni-dir',jni,'--jni-summary',out/'jni-summary.json','--compiler-manifest',compiler_manifest,'--java-home',jdk,'--r8-jar',r8,'--android-jar',android,'--unknown-dex',snap/'tests/fixtures/generated/graph-cache/unknown.dex'],marker='PASS R8')
    plan={'schema_version':1,'mode':a.mode,'source_root':str(root),'overlay':str(overlay) if overlay else None,'output':str(out),'source_files':sources,'source_origins':{rel:str(p) for rel,p in selected.items()},'tools':tool_hashes,'inherited_java_options':inherited,'steps':[dict(x,argv=display(x['argv']),cwd=str(x['cwd'])) for x in steps],'suite':suite,'exclusions':['devices/adb/ART','fuzz including previously filtered v5/equivalent variants','denied old CLI or copied substitutes','clean/delete/reset/publish/install tasks','old hard-coded JNI/core receipts','automatic-deletion and fault-instrumented historical runners'],'source_bytes':sum(x.stat().st_size for x in selected.values()),'short_java_temp':str(tmp),'network':'offline installed Gradle; no wrapper download','logs':'launcher banners redacted; inherited option values are not serialized','claims':'Selected fixed host checks only. AAR/runtime/profile completeness and device claims remain separate.'}
    if a.approved_plan:
        approved=json.loads(a.approved_plan.read_text());need(all(approved[k]==plan[k] for k in ('source_files','tools','suite','inherited_java_options')),'reviewed plan inputs changed')
    need(all(digest(selected[rel])==h for rel,h in sources.items()),'source changed while planning')
    need(all(digest(Path(path))==h for path,h in tool_hashes.items()),'tool changed while planning')
    out.mkdir(parents=True,exist_ok=False);save(out/'plan.json',plan);save(out/'source-manifest.json',sources)
    if a.mode=='plan':save(out/'summary.json',{'status':'planned_only','executed_steps':0,'plan_sha256':digest(out/'plan.json')});print('PLAN ONLY: '+str(out/'plan.json'));return
    env=os.environ.copy();env.update(JAVA_HOME=str(jdk),ANDROID_HOME=str(sdk),ANDROID_SDK_ROOT=str(sdk),GRADLE_USER_HOME=str(cache),TEMP=str(tmp),TMP=str(tmp),PYTHONDONTWRITEBYTECODE='1')
    env['JAVA_TOOL_OPTIONS']=(env.get('JAVA_TOOL_OPTIONS','')+' -Djava.io.tmpdir="'+str(tmp)+'"').strip();tmp.mkdir();(out/'logs').mkdir();jni.mkdir();classes.mkdir(parents=True);kclasses.mkdir(parents=True)
    for rel,path in selected.items():
        need(digest(path)==sources[rel],'source changed before copy: '+rel);target=under(snap,rel);target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target);need(digest(target)==sources[rel],'source copy mismatch')
    (project/'local.properties').write_text('sdk.dir='+sdk.as_posix()+'\n',encoding='utf-8')
    # Capture resolved compile/runtime plugin artifacts selected by this actual offline Gradle run.
    init="""import groovy.json.JsonOutput
gradle.projectsEvaluated {
  def p = gradle.rootProject.project(':dexmeguviz-android')
  p.tasks.register('recordRunnerInputs') {
    doLast {
      def paths = new LinkedHashSet<String>()
      [p.configurations.findByName('releaseCompileClasspath'), p.configurations.findByName('releaseRuntimeClasspath'), p.buildscript.configurations.findByName('classpath'), gradle.rootProject.buildscript.configurations.findByName('classpath')].findAll { it != null }.each { c -> c.files.each { paths.add(it.canonicalPath) } }
      new File(System.getenv('DMG_RUNNER_RESOLVED')).text = JsonOutput.toJson(paths.toList().sort())
    }
  }
}
"""
    (out/'resolved-inputs.gradle').write_text(init,encoding='utf-8');env['DMG_RUNNER_RESOLVED']=str(out/'resolved-input-paths.json')
    records=[];artifacts={};runtime_inputs={}
    def stable():
        need(all(digest(selected[rel])==h and digest(snap/rel)==h for rel,h in sources.items()),'source inputs changed')
        need(all(digest(Path(path))==h for path,h in tool_hashes.items()),'selected tools changed')
    def execute(item):
        log=out/'logs'/(item['name']+'.log');start=time.monotonic();state={'overflow':False,'error':None};process=subprocess.Popen(list(map(str,item['argv'])),cwd=item['cwd'],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT);seen=bytearray();stop_lock=threading.Lock()
        def stop_owned_tree():
            with stop_lock:
                if process.poll() is None:
                    subprocess.run([str(taskkill),'/PID',str(process.pid),'/T','/F'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
                    if process.poll() is None:process.kill()
        def pump():
            try:
                with log.open('xb') as output:
                    total=0
                    while True:
                        line=process.stdout.readline(1024*1024+1)
                        if not line:break
                        total+=len(line)
                        if len(line)>1024*1024 or total>MAX_LOG:state['overflow']=True;stop_owned_tree();break
                        clean=redact_launcher(line);output.write(clean)
                        if len(seen)<MAX_LOG:seen.extend(clean)
            except Exception as e:state['error']=type(e).__name__;stop_owned_tree()
            finally:process.stdout.close()
        reader=threading.Thread(target=pump,daemon=True);reader.start();timed_out=False
        try:process.wait(timeout=a.timeout_seconds)
        except subprocess.TimeoutExpired:timed_out=True;stop_owned_tree();process.wait(timeout=15)
        reader.join(timeout=10)
        status='failed' if process.returncode or timed_out or state['overflow'] or state['error'] or reader.is_alive() else 'passed'
        if item['marker'] and item['marker'].encode() not in seen:status='failed'
        if any(x in seen for x in (b'JNI DETECTED ERROR',b'FATAL ERROR in native method',b'WARNING in native method')):status='failed'
        records.append({'name':item['name'],'phase':item['phase'],'argv':display(item['argv']),'cwd':str(item['cwd']),'status':status,'exit_code':process.returncode,'timed_out':timed_out,'output_limit':state['overflow'],'seconds':time.monotonic()-start,'log':str(log),'log_sha256':digest(log) if log.is_file() else None});save(out/'commands.json',records);need(status=='passed','stage failed: '+item['name'])
    def current_artifacts():return {str(p):digest(p) for p in (aar,jar,native/'dexmeguviz.dll',pom,module) if p.is_file()}
    try:
        for item in steps:
            if a.mode=='build' and item['phase']=='verify':continue
            if item['name']=='r8':
                stable();save(out/'jni-summary.json',{'outcome':'passed','changed_inputs':[],'aar_sha256':digest(aar),'classes_sha256':digest(jar),'host_jni_sha256':digest(native/'dexmeguviz.dll'),'actual_after_sha256':{'candidate_files':sources,'aar_build_inputs':sources},'scope':'Current fixed JVM/Kotlin/binder checks on this AAR and JNI; not all profiles/device'})
            execute(item)
            if item['name']=='gradle-aar':
                need(aar.is_file() and pom.is_file() and module.is_file(),'new AAR/POM/module metadata missing')
                with ZipFile(aar) as z:
                    need(z.getinfo('classes.jar').file_size<=32*1024*1024,'AAR classes bound');jar.write_bytes(z.read('classes.jar'))
                paths=json.loads((out/'resolved-input-paths.json').read_text());need(len(paths)<=2048,'resolved artifact count');runtime_inputs={x:digest(Path(x)) for x in paths if Path(x).is_file()};save(out/'resolved-input-hashes.json',runtime_inputs)
            if item['name']=='gradle-runtime-report':shutil.copyfile(out/'logs/gradle-runtime-report.log',report)
            if item['name']=='jni-configure':
                configured={}
                for file in (jni/'build').rglob('*.cmake'):
                    for value in re.findall(r'set\(CMAKE_(?:C|CXX)_COMPILER\s+"([^"]+)"',file.read_text(errors='replace')):
                        path=Path(value)
                        if path.is_file():configured[str(path.resolve())]=digest(path)
                need(configured,'configured host compiler not recorded');tool_hashes.update(configured);save(out/'configured-host-tools.json',configured)
            if item['name']=='jni-build':stable();artifacts=current_artifacts();need(len(artifacts)==5,'same-source AAR/classes/JNI/POM/module artifacts missing');save(out/'artifacts-before-tests.json',artifacts)
        stable();need(artifacts==current_artifacts(),'AAR/JNI artifacts changed during verification');need(all(digest(Path(p))==h for p,h in runtime_inputs.items()),'resolved Gradle artifacts changed')
        status='built_not_tested' if a.mode=='build' else 'selected_host_checks_passed'
        summary={'status':status,'mode':a.mode,'source_sha256':digest(out/'source-manifest.json'),'plan_sha256':digest(out/'plan.json'),'artifacts':artifacts,'executed':[x['name'] for x in records],'not_executed':[x['name'] for x in steps if x['name'] not in {r['name'] for r in records}],'inherited_java_options':inherited,'output_retention':'all outputs retained; no delete or clean','coverage_limits':suite['not_covered']};save(out/'summary.json',summary);print(status+': '+str(out/'summary.json'))
    except Exception as e:
        save(out/'summary.json',{'status':'failed','failure_type':type(e).__name__,'detail':str(e),'executed':[x['name'] for x in records],'not_executed':[x['name'] for x in steps if x['name'] not in {r['name'] for r in records}],'artifacts':current_artifacts(),'output_retention':'retained; no automatic retry or deletion'});raise
if __name__=='__main__':main()
