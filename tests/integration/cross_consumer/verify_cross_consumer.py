"""Compare one DEX through C, actual AAR Kotlin/JNI, CLI and an independent byte oracle."""
from pathlib import Path
from urllib.parse import unquote, urlsplit
from zipfile import ZipFile
import argparse,copy,glob,hashlib,importlib.util,json,os,re,subprocess,sys

if not __debug__:raise SystemExit('cross-consumer verification requires assertions enabled')
p=argparse.ArgumentParser()
for key in ('root','out','cli','core-lib','miniz-lib','core-summary','core-source-manifest','aar','aar-source-manifest','jni-dir','jni-summary','compiler-manifest','java-home','cmake'):
 p.add_argument('--'+key,type=Path,required=True)
a=p.parse_args();root=a.root.resolve();out=a.out.resolve();cli=a.cli.resolve();aar=a.aar.resolve();jar=a.jni_dir.resolve()/'classes.jar';dll=a.jni_dir.resolve()/'build/Release/dexmeguviz.dll';corelib=a.core_lib.resolve();minizlib=a.miniz_lib.resolve()
if out.exists():raise SystemExit('output exists')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
read=lambda p:json.loads(p.read_text(encoding='utf-8-sig'))
source_manifest=read(a.aar_source_manifest);prior=read(a.jni_summary);compiler=read(a.compiler_manifest)
assert prior['outcome']=='passed' and not prior['changed_inputs'] and sha(dll)==prior['host_jni_sha256'] and sha(jar)==prior['classes_sha256'] and sha(aar)==prior['aar_sha256']
core=read(a.core_summary);core_sources=read(a.core_source_manifest)
assert core['outcome']=='passed' and Path(core['cli_path']).resolve()==cli and sha(cli)==core['cli_sha256'] and sha(a.core_source_manifest)==core['source_before_sha256']==core['source_after_sha256'] and len(core_sources)==core['source_count']
assert corelib.parent.parent==cli.parent and minizlib.parent==corelib.parent
for rel,h in core_sources.items():assert sha(root/rel)==h,rel
with ZipFile(aar) as archive:assert hashlib.sha256(archive.read('classes.jar')).hexdigest()==sha(jar)
for rel,h in source_manifest.items():assert sha(root/rel)==h,rel
for item in compiler:assert sha(Path(item['path']))==item['sha256'],item['path']
stdlib=next(Path(x['path']) for x in compiler if x['path'].endswith('kotlin-stdlib-2.4.21.jar'));annotations=next(Path(x['path']) for x in compiler if x['path'].endswith('annotations-13.0.jar'))
fixture=root/'tests/fixtures/generated/metadata-035.dex';oracle_path=root/'tools/evidence_verifier/verify.py';test=Path(__file__).resolve().parent;cfile=test/'cross_consumer.c';ktest=test/'CrossConsumer.kt';java=a.java_home/'bin/java.exe';cmake=a.cmake.resolve();header=root/'include/dexmeguviz/dexmeguviz.h'
spec=importlib.util.spec_from_file_location('cross_oracle',oracle_path);oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
parsed=oracle.parse_dex(fixture);assert [x['name'] for x in parsed['definitions']]==['locate','second']
inputs=[Path(__file__).resolve(),cfile,ktest,oracle_path,fixture,header,cli,aar,jar,dll,corelib,minizlib,a.core_summary.resolve(),a.core_source_manifest.resolve(),a.aar_source_manifest.resolve(),a.jni_summary.resolve(),a.compiler_manifest.resolve(),java,cmake,*[Path(x['path']) for x in compiler]]
before={str(x.resolve()):sha(x) for x in inputs};out.mkdir(parents=True);(out/'inputs-before.json').write_text(json.dumps(before,indent=2)+'\n',encoding='utf-8')
env=os.environ.copy()
for name in ('JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','CLASSPATH'):env.pop(name,None)
env['PATH']=os.pathsep.join([str(dll.parent),str(cmake.parent),*sorted(glob.glob(r'C:\Program Files\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64'),reverse=True),env.get('PATH','')]);env['PYTHONDONTWRITEBYTECODE']='1';records=[]
def run(name,cmd):
 r=subprocess.run(list(map(str,cmd)),cwd=out,env=env,capture_output=True,timeout=300)
 (out/(name+'.stdout.log')).write_bytes(r.stdout);(out/(name+'.stderr.log')).write_bytes(r.stderr)
 records.append({'name':name,'exit_code':r.returncode,'argv':list(map(str,cmd)),'stdout_sha256':hashlib.sha256(r.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(r.stderr).hexdigest()});(out/'commands.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
 if r.returncode:raise SystemExit('failed '+name)
 if name=='kotlin' and any(v in r.stdout+r.stderr for v in (b'WARNING in native method',b'FATAL ERROR in native method',b'JNI DETECTED ERROR')):raise SystemExit('JNI warning')
 return r
project=out/'project';project.mkdir();(project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.25)\nproject(cross LANGUAGES C CXX)\nadd_executable(cross "${CROSS_SOURCE}")\nset_target_properties(cross PROPERTIES LINKER_LANGUAGE CXX)\ntarget_compile_definitions(cross PRIVATE _ITERATOR_DEBUG_LEVEL=0)\ntarget_include_directories(cross PRIVATE "${CROSS_INCLUDE}")\ntarget_link_libraries(cross PRIVATE "${CROSS_CORE}" "${CROSS_MINIZ}")\n',encoding='utf-8')
run('configure',[cmake,'-S',project,'-B',out/'build','-G','Visual Studio 18 2026','-DCROSS_SOURCE='+str(cfile),'-DCROSS_INCLUDE='+str(root/'include'),'-DCROSS_CORE='+str(corelib),'-DCROSS_MINIZ='+str(minizlib)])
run('build',[cmake,'--build',out/'build','--config','Debug','--target','cross','--parallel','2']);consumer=out/'build/Debug/cross.exe'
classes=out/'classes';run('kotlinc',[java,'-cp',os.pathsep.join(x['path'] for x in compiler),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-jvm-target','17','-classpath',os.pathsep.join(map(str,(stdlib,annotations,jar))),ktest,'-d',classes])
klasslog=out/'class-load.log';k=run('kotlin',[java,'-ea','-Xcheck:jni','-Xlog:class+load=info:file='+str(klasslog),'-Djava.library.path='+str(dll.parent),'-cp',os.pathsep.join(map(str,(classes,jar,stdlib))),'io.github.jichuo1.dexmeguviz.CrossConsumerKt',fixture])
logs=klasslog.read_text(encoding='utf-8',errors='replace')
for name in ('NativeEngine','NativeEngine$Snapshot','NativeEngine$QueryResult','NativeEngine$MethodCandidate','MethodQuery','MethodPredicate','QueryExecution'):
 matches=re.findall(r'\]\s+io\.github\.jichuo1\.dexmeguviz\.'+re.escape(name)+r'\s+source:\s+(\S+)',logs)
 assert len(matches)==1,(name,matches)
 u=urlsplit(matches[0]);path=unquote(u.path);path=path[1:] if re.match(r'^/[A-Za-z]:/',path) else path
 assert u.scheme=='file' and Path(path).resolve()==jar.resolve(),(name,matches)
cases={};rows={}
for line in k.stdout.decode('utf-8').splitlines():
 parts=line.split('\t')
 if parts[0]=='CASE':
  assert len(parts)==12;name=parts[1];assert name not in cases
  cases[name]={'qid':parts[2],'sha':parts[3],'status':list(map(int,parts[4:11])),'query':json.loads(parts[11])}
 elif parts[0]=='ROW':
  assert len(parts)==9;rows.setdefault(parts[1],[]).append((*map(int,parts[2:6]),*parts[6:]))
assert set(cases)=={'enumerate','unique-one','unique-none','unique-two','exists-one','exists-none'}
status={0:'Complete',1:'InvalidArgument',2:'CorruptInput',3:'Unsupported',4:'BudgetExceeded',5:'OutOfMemory',6:'InternalError',7:'Closed',8:'SourceMismatch',9:'Cancelled',10:'DeadlineExceeded'}
coverage={0:'Complete',1:'Partial'};decision={0:'NotApplicable',1:'Undetermined',2:'ProvenFalse',3:'ProvenTrue'};reason={0:'None',1:'NoMatch',2:'Ambiguous',3:'Witness',4:'ResultLimit',5:'SourceScopeIncomplete',6:'UnknownAttribute'}
def normalize(body):return (status_inv[body['execution_status']],coverage_inv[body['coverage']],decision_inv[body['decision']],reason_inv[body['reason']],len(body['candidates']),body['visited_methods'],body['total_methods'])
status_inv={v:k for k,v in status.items()};coverage_inv={v:k for k,v in coverage.items()};decision_inv={v:k for k,v in decision.items()};reason_inv={v:k for k,v in reason.items()}
reports={}
for name,case in cases.items():
 query=out/(name+'.query.json');query.write_text(json.dumps(case['query'],ensure_ascii=True,separators=(',',':')),encoding='ascii')
 cr=run('c-'+name,[consumer,fixture,query]); lines=cr.stdout.decode().splitlines();head=lines[0].split('\t');assert head[0]=='RESULT' and len(head)==10
 assert head[1]==case['qid'] and head[2]==case['sha']==sha(fixture) and list(map(int,head[3:]))==case['status']
 crows=[]
 for line in lines[1:]:
  fields=line.split('\t');assert fields[0]=='ROW' and len(fields)==8
  crows.append((*map(int,fields[1:5]),*fields[5:]))
 assert sorted(crows)==sorted(rows.get(name,[]))
 body=json.loads(run('cli-partial-'+name,[cli,'query',fixture,'--query',query,'--scope-incomplete','--json']).stdout)
 assert body['query_id']==case['qid'] and body['source_sha256']==sha(fixture) and list(normalize(body))==case['status']
 getrows=lambda b:sorted((x['method_index'],x['access_flags'],x['declaration_offset'],x['code_offset'],x['owner'],x['name'],x['prototype']) for x in b['candidates'])
 assert getrows(body)==sorted(crows)
 partial=oracle.verify_result(fixture,body,case['query'])
 complete_body=json.loads(run('cli-complete-'+name,[cli,'query',fixture,'--query',query,'--json']).stdout)
 assert complete_body['query_id']==case['qid'] and complete_body['coverage']=='Complete'
 complete=oracle.verify_result(fixture,complete_body,case['query'])
 reports[name]={'partial':partial,'complete':complete,'partial_decision':body['decision'],'complete_decision':complete_body['decision']}
 if name=='unique-one':
  corrupted=copy.deepcopy(body);corrupted['candidates'][0]['access_flags']^=1
  try:oracle.verify_result(fixture,corrupted,case['query']);raise AssertionError('forged flags accepted')
  except ValueError:pass
 if name=='unique-none':
  corrupted=copy.deepcopy(body);corrupted['decision']='ProvenFalse';corrupted['reason']='NoMatch'
  try:oracle.verify_result(fixture,corrupted,case['query']);raise AssertionError('partial absence accepted')
  except ValueError:pass
assert reports['unique-one']['partial_decision']=='Undetermined' and reports['unique-one']['complete_decision']=='ProvenTrue'
assert reports['unique-none']['partial_decision']=='Undetermined' and reports['unique-none']['complete_decision']=='ProvenFalse'
assert reports['unique-two']['partial_decision']=='ProvenFalse' and reports['exists-none']['partial_decision']=='Undetermined' and reports['exists-none']['complete_decision']=='ProvenFalse'
after={str(x.resolve()):sha(x) for x in inputs};assert before==after
outputs={str(p.resolve()):sha(p) for p in [consumer,klasslog,*classes.rglob('*.class')]}
(out/'summary.json').write_text(json.dumps({'outcome':'passed','scope':'C/Kotlin/CLI method-v1 on one fixed raw DEX and independent Python byte oracle; no Android/ART or full QueryIR','inputs_before':before,'inputs_after':after,'outputs_sha256':outputs,'aar_sha256':sha(aar),'classes_sha256':sha(jar),'host_jni_sha256':sha(dll),'cases':reports,'forged_controls':['flags','partial-absence'],'commands':records},indent=2)+'\n',encoding='utf-8')
print('PASS six C/Kotlin/CLI cases with independent byte oracle')
