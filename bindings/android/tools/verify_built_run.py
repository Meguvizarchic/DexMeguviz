"""Verify a pinned, fully completed run_same_source build without rebuilding it."""
from pathlib import Path
import argparse,hashlib,json,os,re,subprocess,sys,threading,time

def need(ok,message):
    if not ok:raise RuntimeError(message)
def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for part in iter(lambda:f.read(1024*1024),b''):h.update(part)
    return h.hexdigest()
def read(path):return json.loads(Path(path).read_text(encoding='utf-8-sig'))
def save(path,value):Path(path).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def redacted(data):return b''.join(b'[Java launcher environment options redacted]\n' if re.search(rb'(?:NOTE:\s*)?Picked up (?:JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS)\s*:',line,re.I) else line for line in data.splitlines(keepends=True))
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--built-run',type=Path,required=True);parser.add_argument('--expected-plan-sha256',required=True);parser.add_argument('--out',type=Path,required=True);parser.add_argument('--mode',choices=('plan','verify'),default='plan');parser.add_argument('--timeout-seconds',type=int,default=1800)
    parser.add_argument('--fixture-overrides',type=Path);parser.add_argument('--fixture-overrides-sha256')
    a=parser.parse_args();need(os.name=='nt','Windows host required');base=a.built_run.resolve(strict=True);out=a.out.resolve();need(not out.exists() and not out.is_relative_to(base) and not base.is_relative_to(out),'output must be new and disjoint from build');need(len(str(out/'t'))<=80 and 30<=a.timeout_seconds<=7200,'output path/timeout bound')
    plan_path=base/'plan.json';need(sha(plan_path)==a.expected_plan_sha256,'independent build-plan digest mismatch');plan=read(plan_path);summary=read(base/'summary.json');commands=read(base/'commands.json');sources=read(base/'source-manifest.json')
    need(summary['status']=='built_not_tested' and summary['mode']=='build' and plan['mode']=='build','only complete build-mode receipts can be continued')
    need(summary['plan_sha256']==a.expected_plan_sha256 and summary['source_sha256']==sha(base/'source-manifest.json') and sources==plan['source_files'],'build/source receipt mismatch')
    need(Path(plan['output']).resolve()==base,'build root mismatch')
    builds=[x for x in plan['steps'] if x['phase']=='build'];verify=[x for x in plan['steps'] if x['phase']=='verify'];names=[x['name'] for x in builds]
    need(names==['gradle-aar','gradle-runtime-report','jni-configure','jni-build'],'unrecognized build sequence')
    need(summary['executed']==names and summary['not_executed']==[x['name'] for x in verify] and [x['name'] for x in commands]==names,'missing or unexpected executed stage')
    for record,step in zip(commands,builds):
        need(record['status']=='passed' and record['exit_code']==0 and not record['timed_out'] and not record['output_limit'] and record['argv']==step['argv'],'build stage not verified')
        logfile=Path(record['log']).resolve();need(logfile.is_relative_to(base) and sha(logfile)==record['log_sha256'],'build log changed')
    need(sha(base/'runtime-report.txt')==next(x['log_sha256'] for x in commands if x['name']=='gradle-runtime-report'),'runtime report changed')
    original={Path(p):h for p,h in plan['tools'].items()};original.update({Path(plan['source_origins'][rel]):h for rel,h in sources.items()});original.update({base/'source'/rel:h for rel,h in sources.items()})
    for name in ('configured-host-tools.json','resolved-input-hashes.json'):
        values=read(base/name);need(isinstance(values,dict) and bool(values),'missing selected build tools: '+name);original.update({Path(p):h for p,h in values.items()})
    artifacts=summary['artifacts'];need(len(artifacts)==5 and artifacts==read(base/'artifacts-before-tests.json'),'artifact set mismatch')
    for p,h in artifacts.items():need(Path(p).resolve().is_relative_to(base),'artifact outside build');original[Path(p)]=h
    need(all(p.is_file() and sha(p)==h for p,h in original.items()),'source/tool/artifact digest changed')
    env_meta={key:{'present':key in os.environ,'sha256':hashlib.sha256(os.environ.get(key,'').encode()).hexdigest()} for key in ('JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS','GRADLE_OPTS')}
    need(env_meta==plan['inherited_java_options'],'inherited Java options changed')
    # Pin all existing build evidence, including generated configuration, without modifying it.
    evidence={p:sha(p) for p in base.glob('*.json')};evidence[base/'resolved-inputs.gradle']=sha(base/'resolved-inputs.gradle');evidence[base/'runtime-report.txt']=sha(base/'runtime-report.txt');evidence.update({Path(x['log']):x['log_sha256'] for x in commands})
    writer=base/'jni/build/Release/dmg_graph_writer_test.exe';need(writer.is_file(),'current build writer target missing');additional={writer:sha(writer),Path(__file__).resolve():sha(Path(__file__).resolve())}
    # Only validation output paths move. AAR/JNI/fixtures/tool paths remain the pinned build inputs.
    moved=('host','aar-audit','binder_fixture','member_binder_fixture','r8','jni-summary.json','t')
    def rewrite(arg):
        result=str(arg)
        for folder in moved:result=result.replace(str(base/folder),str(out/folder))
        return result
    steps=[]
    for step in verify:
        need('<inherited-java-option>' not in step['argv'],'unexpected inherited option placeholder in validation command')
        steps.append({**step,'argv':[rewrite(x) for x in step['argv']],'cwd':str(out),'status':'not_executed'})
    overrides=None
    if a.fixture_overrides:
        need(a.fixture_overrides_sha256 is not None and sha(a.fixture_overrides)==a.fixture_overrides_sha256,'independent fixture override digest mismatch')
        overrides=read(a.fixture_overrides);need(set(overrides)=={'schema_version','build_plan_sha256','changes'} and overrides['schema_version']==1 and overrides['build_plan_sha256']==a.expected_plan_sha256,'override binding/version')
        need(isinstance(overrides['changes'],list) and 1<=len(overrides['changes'])<=16,'override count')
        consumers={x['class'].split('.')[-1]:x for x in plan['suite']['java']+plan['suite']['kotlin']};seen_overrides=set()
        for change in overrides['changes']:
            need(set(change)=={'step','from_fixture','to_fixture','to_sha256','reason'},'override fields');name=change['step'];old=change['from_fixture'];new=change['to_fixture']
            need(name in consumers and old in consumers[name]['fixtures'] and new in sources and new.startswith('tests/fixtures/') and sources[new]==change['to_sha256'],'override must target an original consumer fixture and a pinned existing fixture')
            need(isinstance(change['reason'],str) and 1<=len(change['reason'])<=1024 and (name,old) not in seen_overrides,'override reason/duplicate');seen_overrides.add((name,old))
            old_path=(base/'source'/old).resolve();new_path=(base/'source'/new).resolve();need(old_path.is_relative_to(base/'source') and new_path.is_relative_to(base/'source'),'fixture path escape')
            target=next(x for x in steps if x['name']==name);need(target['argv'].count(str(old_path))==1 and target['argv'][0].endswith('java.exe') and consumers[name]['class'] in target['argv'],'fixture argument occurrence')
            target['argv']=[str(new_path) if x==str(old_path) else x for x in target['argv']]
        additional[a.fixture_overrides.resolve()]=a.fixture_overrides_sha256
    else:need(a.fixture_overrides_sha256 is None,'override digest without override file')
    need([x['name'] for x in steps][-1]=='r8','expected final R8 step')
    receipt={'schema_version':1,'mode':a.mode,'built_run':str(base),'independent_build_plan_sha256':a.expected_plan_sha256,'build_summary_sha256':sha(base/'summary.json'),'source_manifest_sha256':sha(base/'source-manifest.json'),'checked_source_tool_artifact_files':len(original),'additional_test_executables_and_runner':{str(p):h for p,h in additional.items()},'immutable_build_evidence':{str(p):h for p,h in evidence.items()},'fixture_overrides':overrides,'steps':steps,'inherited_java_options':env_meta,'scope':plan['suite']['scope'],'not_covered':plan['suite']['not_covered'],'output_retention':'all outputs retained; original build is read-only'}
    out.mkdir(parents=True,exist_ok=False);save(out/'resume-plan.json',receipt)
    if a.mode=='plan':save(out/'summary.json',{'status':'planned_only','executed_steps':0,'resume_plan_sha256':sha(out/'resume-plan.json')});print('RESUME PLAN ONLY: '+str(out/'resume-plan.json'));return
    tmp=out/'t';tmp.mkdir();(out/'logs').mkdir();(out/'host/classes').mkdir(parents=True);(out/'host/kotlin').mkdir(parents=True)
    env=os.environ.copy();env.update(TEMP=str(tmp),TMP=str(tmp),PYTHONDONTWRITEBYTECODE='1');env['JAVA_TOOL_OPTIONS']=(env.get('JAVA_TOOL_OPTIONS','')+' -Djava.io.tmpdir="'+str(tmp)+'"').strip();records=[]
    taskkill=Path(os.environ['SystemRoot'])/'System32/taskkill.exe';need(taskkill in original,'taskkill not in pinned tool list')
    def execute(step):
        start=time.monotonic();log=out/'logs'/(step['name']+'.log');proc=subprocess.Popen(step['argv'],cwd=out,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT);state={'overflow':False,'error':None};seen=bytearray();lock=threading.Lock()
        def stop():
            with lock:
                if proc.poll() is None:
                    subprocess.run([str(taskkill),'/PID',str(proc.pid),'/T','/F'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
                    if proc.poll() is None:proc.kill()
        def pump():
            try:
                with log.open('xb') as f:
                    total=0
                    while True:
                        line=proc.stdout.readline(1024*1024+1)
                        if not line:break
                        total+=len(line)
                        if len(line)>1024*1024 or total>32*1024*1024:state['overflow']=True;stop();break
                        value=redacted(line);f.write(value);seen.extend(value)
            except Exception as e:state['error']=type(e).__name__;stop()
            finally:proc.stdout.close()
        reader=threading.Thread(target=pump,daemon=True);reader.start();timeout=False
        try:proc.wait(timeout=a.timeout_seconds)
        except subprocess.TimeoutExpired:timeout=True;stop();proc.wait(timeout=15)
        reader.join(timeout=10)
        okay=proc.returncode==0 and not timeout and not state['overflow'] and state['error'] is None and not reader.is_alive()
        okay=okay and (not step['marker'] or step['marker'].encode() in seen) and not any(x in seen for x in (b'JNI DETECTED ERROR',b'FATAL ERROR in native method',b'WARNING in native method'))
        records.append({'name':step['name'],'argv':step['argv'],'status':'passed' if okay else 'failed','exit_code':proc.returncode,'seconds':time.monotonic()-start,'timed_out':timeout,'output_limit':state['overflow'],'log':str(log),'log_sha256':sha(log)});save(out/'commands.json',records);need(okay,'validation failed: '+step['name'])
    def unchanged():
        need(all(p.is_file() and sha(p)==h for p,h in {**original,**evidence,**additional}.items()),'pinned build inputs/evidence changed')
    try:
        for step in steps:
            if step['name']=='r8':
                unchanged();aar=next(Path(x) for x in artifacts if x.endswith('.aar'));jar=base/'jni/classes.jar';dll=base/'jni/build/Release/dexmeguviz.dll'
                save(out/'jni-summary.json',{'outcome':'passed','changed_inputs':[],'aar_sha256':sha(aar),'classes_sha256':sha(jar),'host_jni_sha256':sha(dll),'actual_after_sha256':{'candidate_files':sources,'aar_build_inputs':sources},'scope':'Actual current fixed host/JNI/Kotlin and binder stages passed in this resume output; not device/ART'})
            execute(step)
        unchanged();save(out/'summary.json',{'status':'selected_host_checks_passed','built_run':str(base),'resume_plan_sha256':sha(out/'resume-plan.json'),'source_manifest_sha256':sha(base/'source-manifest.json'),'artifacts':artifacts,'executed':[x['name'] for x in records],'not_executed':[],'original_build_unchanged':True,'coverage_limits':plan['suite']['not_covered']});print('PASS same-source verification continued without rebuilding: '+str(out/'summary.json'))
    except Exception as e:
        save(out/'summary.json',{'status':'failed','failure_type':type(e).__name__,'detail':str(e),'built_run':str(base),'executed':[x['name'] for x in records],'not_executed':[x['name'] for x in steps if x['name'] not in {r['name'] for r in records}],'output_retention':'retained, no retry or deletion'});raise
if __name__=='__main__':main()
