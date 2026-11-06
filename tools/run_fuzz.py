from pathlib import Path
import hashlib,json,os,shutil,struct,subprocess,time
root=Path(__file__).resolve().parents[1]
targets=['dex','code','archive','query','relational','use_scan']
cmake=Path(r'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe')
runtime=Path(r'C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64')
env=os.environ.copy();env['PATH']=str(runtime)+os.pathsep+env.get('PATH','')
build=root/'build/host-fuzz';evidence=root/'docs/evidence/fuzz'/('run-'+str(time.time_ns()));evidence.mkdir(parents=True)
commands=[]

def relational_fixture_inputs():
 result=[]
 for slot,name in [('left','tests/fixtures/generated/definition_catalog/definitions.dex'),('right','tests/fixtures/generated/method_facts/method-uses.dex')]:
  path=root/name;data=path.read_bytes()
  if not path.resolve().is_relative_to(root.resolve()) or len(data)>65536 or len(data)<112 or data[:4]!=b'dex\n':raise SystemExit('Unexpected relational fixture: '+name)
  counts={key:struct.unpack_from('<I',data,at)[0] for key,at in [('strings',56),('types',64),('field_refs',80),('method_refs',88),('class_defs',96)]}
  result.append({'slot':slot,'path':name,'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'dex_version':data[4:7].decode('ascii'),'header_counts':counts})
 return result


def use_scan_fixture_inputs():
 expected={
  'tests/fixtures/generated/method_facts/method-uses.dex':'8262d2b338e54a7965111b4cec1ef9e628ada9795ad2f6a555d717a2ba9546bc',
  'tests/fixtures/generated/method_facts/invoke-domains-038.dex':'ecf85d163c87d58f065335f0d932442be48b91b5efa3858e319a1c1cdf7313b0',
  'tests/fixtures/generated/use_relations/two-invokes.dex':'04656bbfe03c8b04e6f77d29b8cae8e7e06f18a038f85300658f8c691435648b',
  'tests/fixtures/generated/use_relations/field-read-write.dex':'7558a8945c3a87f727de782d885c687539d839e460497f6d2e86c2a7c7f46e8d',
  'tests/fixtures/generated/use_relations/string-normal-jumbo.dex':'65373dc14bb0b19b3fb4ae8fd236e83befbfee4b69b74e3a8d4a8b7db2637c04',
  'tests/fixtures/generated/use_relations/valid-then-corrupt.dex':'4e0661d233cfc3eaf32aff66e615a1cacba822e768c3c3b4559f0f0abfc2c2be',
 }
 result=[]
 for name,expected_hash in expected.items():
  path=root/name
  if not path.resolve().is_relative_to(root.resolve()) or not path.is_file():raise SystemExit('Missing use scan fixture: '+name)
  data=path.read_bytes();actual=hashlib.sha256(data).hexdigest()
  if actual!=expected_hash or len(data)>65536 or len(data)<112 or data[:4]!=b'dex\n':raise SystemExit('Use scan fixture identity mismatch: '+name)
  result.append({'path':name,'sha256':actual,'bytes':len(data),'dex_version':data[4:7].decode('ascii')})
 return result

def relational_seed_values():
 def scan(relation,where=None,slot=None):
  value={'op':'scan','relation':relation}
  if where is not None:value['where']=where
  if slot is not None:value['scope']={'slots':[slot]}
  return value
 def label(value,name):return {'op':'label','input':value,'label':name}
 def union(*values,semantics='bag',identity='tuple'):return {'op':'union','inputs':list(values),'semantics':semantics,'identity':identity}
 def query(value,**options):return {'schema_version':1,'relation':value,**options}
 uses=scan('method_defs',{'name':'uses'},'right');quiet=scan('method_defs',{'name':'quiet'},'right')
 fields=scan('field_defs',slot='left');unknown=scan('field_refs',{'flags_contains':8},'left')
 external=scan('field_refs',{'has_local_definition':False},'left');a=label(uses,'A');b=label(uses,'B')
 roles=union(a,b)
 seeds={
  'filter-body':query({'op':'filter','input':scan('method_defs',slot='right'),'where':{'name':'uses','using_strings':{'all':['used-string']},'invokes':{'all':[{'name':'sink'}]}}}),
  'scan-unknown':query(unknown),
  'filter-eliminates-unknown':query({'op':'filter','input':unknown,'where':{'name':'shared'}}),
  'filter-false':query({'op':'filter','input':unknown,'where':False}),
  'union-bag':query(union(uses,uses)),
  'union-set':query(union(uses,uses,semantics='set')),
  'union-true-over-unknown':query(union(unknown,external,semantics='set',identity='entity')),
  'distinct-entity':query({'op':'distinct','input':roles,'identity':'entity'}),
  'distinct-tuple':query({'op':'distinct','input':roles,'identity':'tuple'}),
  'label':query(a),
  'group-shared':query({'op':'group_by_owner','inputs':[a,b],'min':1,'max':1,'required_roles':['A','B'],'role_policy':'shared'}),
  'group-distinct':query({'op':'group_by_owner','inputs':[a,label(quiet,'A'),b],'min':2,'max':2,'required_roles':['A','B'],'role_policy':'distinct'}),
  'group-mixed-member-kinds':query({'op':'group_by_owner','inputs':[label(scan('method_defs',slot='left'),'M'),label(scan('field_defs',{'owner':'Lcatalog/Child;'},'left'),'F')],'min':2,'max':2,'required_roles':['M','F'],'role_policy':'distinct'}),
  'group-late-upper-bound':query({'op':'group_by_owner','inputs':[fields],'min':1,'max':1},max_results=1),
  'filter-group-owner':query({'op':'filter','input':{'op':'group_by_owner','inputs':[fields]},'where':{'descriptor':'Lcatalog/Base;'}}),
  'unique-entity':query(roles,intent='unique',unique_by='entity',max_results=1),
  'unique-tuple':query(roles,intent='unique',unique_by='tuple',max_results=2),
  'root-tuple-set':query(roles,semantics='set'),
  'top-n-late-branch':query(union(quiet,uses),intent='top_n',max_results=1,order_by=[{'field':'name','direction':'desc'}]),
  'intermediate-cap':query(fields,intent='exists',max_results=1,max_intermediate_rows=2),
  'work-cap':query(union(uses,quiet),max_work=1),
  'missing-scope':query(scan('field_refs',slot='absent')),
  'empty-scope':query(fields,scope={'slots':[]}),
  'projection':query(fields,projection=['identity','type','evidence']),
  'utf16-string':query(scan('string_values',{'value':{'op':'contains','u16':[0,55296]}})),
  'join-same-entity':query({'op':'join','left':uses,'right':uses,'on':'same_entity'}),
  'join-local-definition':query({'op':'join','left':fields,'right':scan('field_refs',slot='left'),'on':'local_definition'}),
  'join-local-owner':query({'op':'join','left':fields,'right':scan('class_defs',slot='left'),'on':'local_owner'}),
  'join-symbol-cross-source':query({'op':'join','left':scan('method_defs',slot='left'),'right':scan('method_refs',slot='right'),'on':'symbol'}),
  'join-bag-multiplicity':query({'op':'join','left':union(uses,uses),'right':union(uses,uses,uses),'on':'same_entity'}),
  'join-tuple-sides':query({'op':'distinct','identity':'tuple','input':{'op':'join','left':union(a,uses),'right':union(a,uses),'on':'same_entity'}}),
  'semi-unknown':query({'op':'semi_join','left':external,'right':unknown,'on':'same_entity'}),
  'semi-true-dominates':query({'op':'semi_join','left':external,'right':union(unknown,external),'on':'same_entity'}),
  'semi-owner-group':query({'op':'semi_join','left':scan('method_defs',slot='left'),'right':{'op':'group_by_owner','inputs':[label(scan('method_defs',slot='left'),'M'),label(scan('field_defs',{'owner':'Lcatalog/Child;'},'left'),'F')],'min':2,'max':2,'required_roles':['M','F'],'role_policy':'distinct'},'on':'local_owner'}),
  'nested-semi-proof':query({'op':'semi_join','left':{'op':'semi_join','left':uses,'right':uses,'on':'same_entity'},'right':uses,'on':'same_entity'}),
  'use-caller':query({'op':'join','left':uses,'right':label(scan('invoke_sites',slot='right'),'I'),'on':'caller'}),
  'use-caller-reversed':query({'op':'join','left':scan('invoke_sites',slot='right'),'right':uses,'on':'caller'}),
  'use-target-method':query({'op':'join','left':scan('invoke_sites',slot='right'),'right':scan('method_refs',slot='right'),'on':'target_ref'}),
  'use-target-field':query({'op':'join','left':scan('field_uses',slot='right'),'right':scan('field_refs',slot='right'),'on':'target_ref'}),
  'use-target-string':query({'op':'join','left':scan('string_values',slot='right'),'right':scan('string_uses',slot='right'),'on':'target_ref'}),
  'use-semi-proof':query({'op':'semi_join','left':uses,'right':label(scan('invoke_sites',slot='right'),'I'),'on':'caller'}),
  'use-distinct-pc':query({'op':'distinct','identity':'entity','input':union(scan('invoke_sites',slot='right'),scan('invoke_sites',slot='right'))}),
 }
 for relation in ['string_uses','invoke_sites','field_uses']:
  seeds['scan-'+relation]=query(scan(relation,slot='right'))
 for relation in ['method_defs','class_defs','field_defs','method_refs','field_refs','string_values','type_refs']:
  seeds['scan-'+relation]=query(scan(relation))
 return seeds

fixtures=relational_fixture_inputs()
use_fixtures=use_scan_fixture_inputs()

def save_seeds(seeds):
 manifest={'schema_version':2,'targets':seeds,'relational_fixture_inputs':fixtures,'use_scan_fixture_inputs':use_fixtures,
           'relational_scope':'Execute scan/filter/union/distinct/label/group_by_owner/join/semi_join expressions through C API on two project-original fixtures; resource and accessor invariants, not an independent semantic oracle or BoundedExpand coverage'}
 (evidence/'seed-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
def run(name,args,timeout=240):
 start=time.monotonic()
 try:p=subprocess.run(list(map(str,args)),cwd=root,env=env,capture_output=True,timeout=timeout)
 except subprocess.TimeoutExpired as failure:
  (evidence/(name+'.stdout.log')).write_bytes(failure.stdout or b'');(evidence/(name+'.stderr.log')).write_bytes(failure.stderr or b'')
  commands.append({'name':name,'argv':list(map(str,args)),'exit_code':None,'timed_out':True,'timeout_seconds':timeout,'elapsed_seconds':time.monotonic()-start,'stdout':name+'.stdout.log','stderr':name+'.stderr.log'})
  (evidence/'commands.json').write_text(json.dumps(commands,indent=2)+'\n',encoding='utf-8')
  raise SystemExit(name+' timed out after '+str(timeout)+' seconds; partial output was saved')
 (evidence/(name+'.stdout.log')).write_bytes(p.stdout);(evidence/(name+'.stderr.log')).write_bytes(p.stderr)
 commands.append({'name':name,'argv':list(map(str,args)),'exit_code':p.returncode,'elapsed_seconds':time.monotonic()-start,'stdout':name+'.stdout.log','stderr':name+'.stderr.log'})
 (evidence/'commands.json').write_text(json.dumps(commands,indent=2)+'\n',encoding='utf-8')
 print((p.stdout+p.stderr).decode('utf-8',errors='replace')[-8000:],flush=True)
 if p.returncode:raise SystemExit(p.returncode)
run('configure',[cmake,'-S',root,'-B',build,'-DDMG_BUILD_FUZZERS=ON','-DDMG_ENABLE_ASAN=ON'])
run('build',[cmake,'--build',build,'--config','RelWithDebInfo','--parallel','4','--target',*['dmg_fuzz_'+kind for kind in targets]])
if relational_fixture_inputs()!=fixtures:raise SystemExit('Relational fixture changed during configure/build; rerun with stable source inputs')
if use_scan_fixture_inputs()!=use_fixtures:raise SystemExit('Use scan fixture changed during configure/build; rerun with stable source inputs')
(evidence/'relational-fixtures.json').write_text(json.dumps(fixtures,indent=2)+'\n',encoding='utf-8')
(evidence/'use-scan-fixtures.json').write_text(json.dumps(use_fixtures,indent=2)+'\n',encoding='utf-8')
corpus_root=build/('corpus-'+str(time.time_ns()));seeds={}
for kind in targets:
 corpus=corpus_root/kind;corpus.mkdir(parents=True);artifacts=corpus/'artifacts';artifacts.mkdir()
 files=[]
 if kind=='dex':files=[*list((root/'tests/fixtures/generated').glob('*.dex')),*list((root/'tests/fixtures/generated/extended').glob('*.dex')),*list((root/'tests/fixtures/generated/method_facts').glob('*.dex')),*list((root/'tests/fixtures/generated/definition_catalog').glob('*.dex'))]
 elif kind=='archive':files=list((root/'tests/fixtures/generated/archive').glob('*.apk'))+list((root/'tests/fixtures/generated/archive').glob('*.zip'))
 elif kind=='use_scan':files=[root/item['path'] for item in use_fixtures]
 for p in files:
  data=p.read_bytes()
  if kind=='use_scan':
   expected=next(item['sha256'] for item in use_fixtures if root/item['path']==p)
   if hashlib.sha256(data).hexdigest()!=expected:raise SystemExit('Use scan fixture changed before corpus copy: '+str(p))
  if len(data)<=65536:(corpus/hashlib.sha256(data).hexdigest()).write_bytes(data)
 if kind=='code':
  for i,words in enumerate([[0x000e],[0x001a,0,0x106e,0,0,0x000e],[0x002b,4,0,0x000e,0x0100,1,0,0,3,0]]):
   data=struct.pack('<HHHHII',16,0,5,0,0,len(words))+struct.pack('<'+'H'*len(words),*words)
   (corpus/f'seed-{i}').write_bytes(data)
 if kind=='query':
  values=[{'schema_version':1,'relation':'method_defs'},
          {'schema_version':1,'relation':'method_defs','where':{'all':[{'name':'uses'},{'using_strings':{'all':['used-string']}}]},'intent':'unique'},
          {'schema_version':1,'relation':'method_defs','where':{'invokes':{'all':[{'name':'sink','parameters':['I']}]},'declares_fields':{'where':{'type':'I'},'min':1}},'intent':'top_n','max_results':2,'order_by':[{'field':'name'}]}]
  values += [{'schema_version':1,'relation':kind} for kind in ['class_defs','field_defs','method_refs','field_refs','string_values','type_refs']]
  values += [{'schema_version':1,'relation':'field_refs','where':{'any':[{'has_local_definition':False},{'not':{'flags_any':8}}]},'order_by':[{'field':'flags'}]},
             {'schema_version':1,'relation':'string_values','where':{'value':{'op':'contains','u16':[0,55296]}}}]
  for i,value in enumerate(values):(corpus/f'seed-{i}.json').write_text(json.dumps(value),encoding='utf-8')
 if kind=='relational':
  for name,value in relational_seed_values().items():(corpus/(name+'.json')).write_text(json.dumps(value),encoding='utf-8')
 seeds[kind]={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in corpus.iterdir() if p.is_file()}
 save_seeds(seeds)
 exe=build/'RelWithDebInfo'/('dmg_fuzz_'+kind+'.exe')
 run('fuzz-'+kind,[exe,corpus,'-runs=10000','-seed=20261026','-max_len=65536','-timeout=10','-rss_limit_mb=2048','-malloc_limit_mb=512','-artifact_prefix='+str(artifacts)+os.sep])
save_seeds(seeds)
summary={'all_passed':True,'configuration':'RelWithDebInfo; MSVC dynamic release CRT and iterator level 0','runs_per_target':10000,'seed':20261026,'targets':list(seeds),'evidence':str(evidence.relative_to(root)),'corpus':str(corpus_root),'relational_fixture_inputs':fixtures,'use_scan_fixture_inputs':use_fixtures,'scope':'MSVC experimental libFuzzer with AddressSanitizer; bounded generated DEX, code_item and ZIP inputs, QueryIR compilation, current relational operators including Join/SemiJoin, and single-source use scan on project-original fixtures; not an independent semantic oracle, complete event or relational IR/BoundedExpand, Android runtime, exhaustive correctness, device or performance evidence'}
(evidence/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
print(json.dumps(summary))
