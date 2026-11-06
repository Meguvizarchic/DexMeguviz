"""Cross-check multi-DEX APK occurrences across C, Kotlin, CLI and independent bytes."""
from pathlib import Path
from urllib.parse import unquote,urlsplit
from zipfile import ZipFile
import argparse,copy,glob,hashlib,importlib.util,json,os,re,subprocess,sys
if not __debug__:raise SystemExit('multi-source verification requires assertions enabled')
p=argparse.ArgumentParser()
for key in ('root','out','cli','core-lib','miniz-lib','core-summary','core-source-manifest','core-bindings','aar','aar-source-manifest','jni-dir','jni-summary','compiler-manifest','java-home','cmake'):
 p.add_argument('--'+key,type=Path,required=True)
a=p.parse_args();root=a.root.resolve();out=a.out.resolve();cli=a.cli.resolve();aar=a.aar.resolve();jar=a.jni_dir.resolve()/'classes.jar';dll=a.jni_dir.resolve()/'build/Release/dexmeguviz.dll';corelib=a.core_lib.resolve();minizlib=a.miniz_lib.resolve()
if out.exists():raise SystemExit('output exists')
sha=lambda x:hashlib.sha256(x.read_bytes()).hexdigest()
read=lambda x:json.loads(x.read_text(encoding='utf-8-sig'))
source_manifest=read(a.aar_source_manifest);prior=read(a.jni_summary);compiler=read(a.compiler_manifest);core=read(a.core_summary);core_sources=read(a.core_source_manifest)
assert prior['outcome']=='passed' and not prior['changed_inputs'] and sha(dll)==prior['host_jni_sha256'] and sha(jar)==prior['classes_sha256'] and sha(aar)==prior['aar_sha256']
actual_inputs=prior['actual_after_sha256'];tracked_sources=set()
assert actual_inputs['aar']==sha(aar) and actual_inputs['classes.jar']==sha(jar) and actual_inputs['host-jni-dll']==sha(dll) and actual_inputs['aar-source-manifest']==sha(a.aar_source_manifest)
for key in ('candidate_files','aar_build_inputs'):
 assert actual_inputs[key],key
 for rel,h in actual_inputs[key].items():assert sha(root/rel)==h,(key,rel);tracked_sources.add(root/rel)
assert core['outcome']=='passed' and Path(core['cli_path']).resolve()==cli and sha(cli)==core['cli_sha256'] and sha(a.core_source_manifest)==core['source_before_sha256']==core['source_after_sha256'] and len(core_sources)==core['source_count']
assert corelib.parent.parent==cli.parent and minizlib.parent==corelib.parent
bindings=read(a.core_bindings);assert bindings['outcome']=='passed' and sha(a.core_summary)==bindings['core_summary'] and sha(a.core_source_manifest)==bindings['source_before']==bindings['source_after']
for name,path in (('cli',cli),('core_lib',corelib),('miniz_lib',minizlib)):
 item=bindings['artifacts'][name];assert Path(item['path']).resolve()==path and sha(path)==item['sha256'],name
for path,h in bindings['logs'].items():assert sha(Path(path))==h,path
for rel,h in core_sources.items():assert sha(root/rel)==h,rel
with ZipFile(aar) as z:assert hashlib.sha256(z.read('classes.jar')).hexdigest()==sha(jar)
for rel,h in source_manifest.items():assert sha(root/rel)==h,rel
for x in compiler:assert sha(Path(x['path']))==x['sha256'],x['path']
stdlib=next(Path(x['path']) for x in compiler if x['path'].endswith('kotlin-stdlib-2.4.21.jar'));annotations=next(Path(x['path']) for x in compiler if x['path'].endswith('annotations-13.0.jar'))
first=root/'tests/fixtures/generated/multisource/reverse-stored.apk';other=root/'tests/fixtures/generated/multisource/resource-only.apk';deflated=root/'tests/fixtures/generated/multisource/reverse-deflate.apk';bad=root/'tests/fixtures/generated/multisource/bad-crc.apk';oracle_path=root/'tools/evidence_verifier/multisource.py';base_oracle=root/'tools/evidence_verifier/verify.py';test=Path(__file__).resolve().parent;cfile=test/'apk_cross.c';ktest=test/'ApkCross.kt';java=a.java_home/'bin/java.exe';cmake=a.cmake.resolve();header=root/'include/dexmeguviz/dexmeguviz.h'
spec=importlib.util.spec_from_file_location('multi_oracle',oracle_path);oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
datasets={'stored-resource':([first,other],[False,True]),'deflate-repeat':([deflated,deflated],[False,False])}
inputs=[Path(__file__).resolve(),cfile,ktest,oracle_path,base_oracle,first,other,deflated,bad,header,cli,aar,jar,dll,corelib,minizlib,a.core_summary.resolve(),a.core_source_manifest.resolve(),a.core_bindings.resolve(),a.aar_source_manifest.resolve(),a.jni_summary.resolve(),a.compiler_manifest.resolve(),java,cmake,*[Path(x['path']) for x in compiler],*[Path(x) for x in bindings['logs']],*sorted(tracked_sources)]
before={str(x.resolve()):sha(x) for x in inputs};out.mkdir(parents=True);(out/'inputs-before.json').write_text(json.dumps(before,indent=2)+'\n',encoding='utf-8')
env=os.environ.copy()
for n in ('JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','CLASSPATH'):env.pop(n,None)
env['PATH']=os.pathsep.join([str(dll.parent),str(cmake.parent),*sorted(glob.glob(r'C:\Program Files\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64'),reverse=True),env.get('PATH','')]);env['PYTHONDONTWRITEBYTECODE']='1';records=[]
def run(name,cmd,expected=0):
 r=subprocess.run(list(map(str,cmd)),cwd=out,env=env,capture_output=True,timeout=300);(out/(name+'.stdout.log')).write_bytes(r.stdout);(out/(name+'.stderr.log')).write_bytes(r.stderr)
 records.append({'name':name,'exit_code':r.returncode,'argv':list(map(str,cmd)),'stdout_sha256':hashlib.sha256(r.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(r.stderr).hexdigest()});(out/'commands.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
 if r.returncode!=expected:raise SystemExit('failed '+name)
 if name=='kotlin' and any(v in r.stdout+r.stderr for v in (b'WARNING in native method',b'FATAL ERROR in native method',b'JNI DETECTED ERROR')):raise SystemExit('JNI warning')
 return r
project=out/'project';project.mkdir();(project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.25)\nproject(cross LANGUAGES C CXX)\nadd_executable(cross "${CROSS_SOURCE}")\nset_target_properties(cross PROPERTIES LINKER_LANGUAGE CXX)\ntarget_compile_definitions(cross PRIVATE _ITERATOR_DEBUG_LEVEL=0)\ntarget_include_directories(cross PRIVATE "${CROSS_INCLUDE}")\ntarget_link_libraries(cross PRIVATE "${CROSS_CORE}" "${CROSS_MINIZ}")\n',encoding='utf-8')
run('configure',[cmake,'-S',project,'-B',out/'build','-G','Visual Studio 18 2026','-DCROSS_SOURCE='+str(cfile),'-DCROSS_INCLUDE='+str(root/'include'),'-DCROSS_CORE='+str(corelib),'-DCROSS_MINIZ='+str(minizlib)])
run('build',[cmake,'--build',out/'build','--config','Debug','--target','cross','--parallel','2']);consumer=out/'build/Debug/cross.exe'
classes=out/'classes';run('kotlinc',[java,'-cp',os.pathsep.join(x['path'] for x in compiler),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-jvm-target','17','-classpath',os.pathsep.join(map(str,(stdlib,annotations,jar))),ktest,'-d',classes])
klasslog=out/'class-load.log';k=run('kotlin',[java,'-ea','-Xcheck:jni','-Xlog:class+load=info:file='+str(klasslog),'-Djava.library.path='+str(dll.parent),'-cp',os.pathsep.join(map(str,(classes,jar,stdlib))),'io.github.jichuo1.dexmeguviz.ApkCrossKt',first,other,deflated,bad])
logs=klasslog.read_text(encoding='utf-8',errors='replace')
for name in ('NativeEngine','NativeEngine$SourceSetSnapshot','NativeEngine$SourceSetInfo','NativeEngine$RawDexSourceInfo','NativeEngine$QueryResult','NativeEngine$MethodCandidate','MethodQuery','MethodPredicate','QueryExecution'):
 matches=re.findall(r'\]\s+io\.github\.jichuo1\.dexmeguviz\.'+re.escape(name)+r'\s+source:\s+(\S+)',logs);assert len(matches)==1,(name,matches)
 u=urlsplit(matches[0]);path=unquote(u.path);path=path[1:] if re.match(r'^/[A-Za-z]:/',path) else path
 assert u.scheme=='file' and Path(path).resolve()==jar.resolve(),(name,matches)
cases={};rows={};sources={};rejected=[]
for line in k.stdout.decode().splitlines():
 f=line.split('\t')
 if f[0]=='SOURCE':
  assert len(f)==12;sources.setdefault(f[1],[]).append((f[2],int(f[3]),int(f[4]),*f[5:11],int(f[11])))
 elif f[0]=='CASE':
  assert len(f)==13;key=(f[1],f[2]);assert key not in cases;cases[key]={'qid':f[3],'snapshot':f[4],'status':list(map(int,f[5:12])),'query':json.loads(f[12])}
 elif f[0]=='ROW':
  assert len(f)==14;rows.setdefault((f[1],f[2]),[]).append((*map(int,f[3:9]),*f[9:]))
 elif f[0]=='REJECT':assert f==['REJECT','bad-crc','2'];rejected.append('kotlin')
names={'enumerate','unique-locate','unique-absent','exists-locate','exists-absent'}
assert set(cases)=={(d,n) for d in datasets for n in names} and set(sources)==set(datasets)
models={};expected_android={}
for label,(paths,allow) in datasets.items():
 desc=[{'path':str(path),'kind':'apk','allow_no_dex':allow[i]} for i,path in enumerate(paths)]
 model=oracle.load_source_set(desc,root,False,root);models[label]=(desc,model)
 input_rows=[];expected=[];source_rows=[]
 for i,item in enumerate(model['inputs']):
  slot=('base','other')[i];input_rows.append({'slot_key':slot,'role':'apk','format':'Apk','allow_no_dex':allow[i],'content_id':item['content_id']})
 for item in model['sources']:
  i=item['input_index'];slot=('base','other')[i];occ=oracle.occurrence_id('android-jni',slot,'apk',item['entry_name'],item['content_id'])
  source_rows.append({'occurrence_id':occ})
  expected.append((item['source_index'],i,slot,item['source_sha256'],item['content_id'],occ,item['logical_dex_id'],item['entry_name'],item['central_index']))
 sid=oracle.snapshot_id('android-jni',False,input_rows,source_rows);expected_android[label]=(sid,expected)
 assert sources[label]==[(sid,*x) for x in expected]
 if label=='stored-resource':assert len(expected)==3 and model['inputs'][1]['source_count']==0
 else:
  assert len(expected)==6
  for i in range(3):assert expected[i][4]==expected[i+3][4] and expected[i][5]!=expected[i+3][5]
status={'Complete':0};coverage={'Complete':0,'Partial':1};decision={'NotApplicable':0,'Undetermined':1,'ProvenFalse':2,'ProvenTrue':3};reason={'None':0,'NoMatch':1,'Ambiguous':2,'Witness':3,'ResultLimit':4,'SourceScopeIncomplete':5,'UnknownAttribute':6}
reports={};forged=[]
for (dataset,name),case in cases.items():
 paths,allow=datasets[dataset];q=out/(dataset+'-'+name+'.query.json');q.write_text(json.dumps(case['query'],ensure_ascii=True,separators=(',',':')),encoding='ascii')
 lines=run('c-'+dataset+'-'+name,[consumer,*paths,'resource' if allow[1] else 'code',q]).stdout.decode().splitlines();head=lines[0].split('\t');assert len(head)==10 and head[0]=='RESULT'
 assert head[1]==case['qid'] and head[2]==case['snapshot']==expected_android[dataset][0] and list(map(int,head[3:]))==case['status']
 c_sources=[];c_rows=[]
 for line in lines[1:]:
  f=line.split('\t')
  if f[0]=='SOURCE':assert len(f)==10;c_sources.append((int(f[1]),int(f[2]),*f[3:9],int(f[9])))
  elif f[0]=='ROW':assert len(f)==12;c_rows.append((*map(int,f[1:7]),*f[7:]))
  else:raise AssertionError('unexpected C output')
 assert c_sources==expected_android[dataset][1] and sorted(c_rows)==sorted(rows.get((dataset,name),[]))
 for complete in (False,True):
  cmd=[cli,'query',paths[0],'--resource-source' if allow[1] else '--source',paths[1],'--query',q,'--json']
  if not complete:cmd.append('--scope-incomplete')
  body=json.loads(run('cli-'+('complete' if complete else 'partial')+'-'+dataset+'-'+name,cmd).stdout)
  desc,_=models[dataset];model=oracle.load_source_set(desc,root,complete,root)
  proof=oracle.verify_source_set_result(model,body,case['query']);assert body['query_id']==case['qid']
  if not complete:
   actual=[(x['source_index'],x['input_index'],x['method_index'],x['access_flags'],x['declaration_offset'],x['code_offset'],x['owner'],x['name'],x['prototype']) for x in body['candidates']]
   assert sorted(actual)==sorted(x[:9] for x in c_rows)
   normalized=[status[body['execution_status']],coverage[body['coverage']],decision[body['decision']],reason[body['reason']],len(body['candidates']),body['visited_methods'],body['total_methods']]
   assert normalized==case['status']
   if dataset=='deflate-repeat' and name=='enumerate':
    fake=copy.deepcopy(body);fake['candidates'][1]=copy.deepcopy(fake['candidates'][0])
    try:oracle.verify_source_set_result(model,fake,case['query']);raise AssertionError('duplicate accepted')
    except ValueError:forged.append('duplicate-occurrence')
    fake=copy.deepcopy(body);fake['sources'][0],fake['sources'][1]=fake['sources'][1],fake['sources'][0]
    try:oracle.verify_source_set_result(model,fake,case['query']);raise AssertionError('source swap accepted')
    except ValueError:forged.append('source-swap')
  reports[dataset+'/'+name+('/complete' if complete else '/partial')]={'oracle':proof,'decision':body['decision']}
assert reports['stored-resource/unique-locate/partial']['decision']=='ProvenFalse'
assert reports['deflate-repeat/unique-absent/partial']['decision']=='Undetermined' and reports['deflate-repeat/unique-absent/complete']['decision']=='ProvenFalse'
assert set(forged)=={'duplicate-occurrence','source-swap'}
query=out/'stored-resource-enumerate.query.json'
assert run('c-bad-crc',[consumer,first,bad,'bad',query]).stdout.strip()==b'REJECT\tbad-crc\t2';rejected.append('c')
bad_result=json.loads(run('cli-bad-crc',[cli,'query',first,'--source',bad,'--query',query,'--scope-incomplete','--json'],expected=2).stdout)
assert bad_result['execution_status']=='CorruptInput' and bad_result['candidates']==[];rejected.append('cli')
try:oracle.load_source_set([{'path':str(first),'kind':'apk'},{'path':str(bad),'kind':'apk'}],root,False,root);raise AssertionError('oracle accepted bad CRC')
except oracle.SourceError as error:assert error.status=='CorruptInput';rejected.append('oracle')
assert set(rejected)=={'c','kotlin','cli','oracle'}
after={str(x.resolve()):sha(x) for x in inputs};assert before==after
queries=sorted(out.glob('*.query.json'));assert len(queries)==10
outputs={str(x.resolve()):sha(x) for x in [consumer,klasslog,*classes.rglob('*.class'),*queries]}
(out/'summary.json').write_text(json.dumps({'outcome':'passed','scope':'two fixed stored/deflated APK SourceSets, C/Kotlin/CLI plus independent ZIP/DEX byte identity oracle; no ART or full P2-08',
 'inputs_before':before,'inputs_after':after,'outputs_sha256':outputs,'aar_sha256':sha(aar),'classes_sha256':sha(jar),'host_jni_sha256':sha(dll),'cases':reports,'forged_controls':forged,'bad_crc_rejections':rejected,'commands':records},indent=2)+'\n',encoding='utf-8')
print('PASS ten APK C/Kotlin/CLI cases with independent archive and identity oracle')
