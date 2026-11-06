"""Fixed source-occurrence candidate and incomplete-scope controls for dexdiff."""
import argparse,copy,hashlib,importlib.util,json,subprocess,sys
from pathlib import Path
if not __debug__:raise SystemExit('test requires assertions enabled')
p=argparse.ArgumentParser()
for name in ('tool','exe','root','out'):p.add_argument('--'+name,type=Path,required=True)
p.add_argument('--original',type=Path,help='optional independently retained old-tool output for byte comparison')
a=p.parse_args();root=a.root.resolve();exe=a.exe.resolve();tool=a.tool.resolve();out=a.out.resolve();original=a.original.resolve() if a.original else None
if out.exists():raise SystemExit('output exists')
fixture=root/'tests/fixtures/generated/graph';oracle_path=root/'tests/integration/raw_graph_oracle.py';entity_oracle_path=root/'tests/integration/entity_query_test.py';catalog=root/'tests/fixtures/generated/definition_catalog/definitions.dex';A=fixture/'amb-a.dex';B=fixture/'amb-b1.dex';C=fixture/'amb-b2.dex'
spec=importlib.util.spec_from_file_location('independent_graph_oracle',oracle_path);oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
assert tuple(oracle.parse(A)['calls'][0]['symbol'])==('Lamb/B;','b','()V')
assert tuple(oracle.parse(B)['definition'])==tuple(oracle.parse(C)['definition'])==('Lamb/B;','b','()V')
sha=lambda x:hashlib.sha256(x.read_bytes()).hexdigest()
inputs=[Path(__file__).resolve(),Path(sys.executable).resolve(),tool,exe,A,B,C,oracle_path,entity_oracle_path,catalog]+([original] if original else []);before={str(x):sha(x) for x in inputs}
out.mkdir(parents=True);records=[]
def run(name,args,success=True):
 cmd=[sys.executable,'-B',str(tool),'--exe',str(exe),*map(str,args),'--workdir',str(out/(name+'-work'))]
 r=subprocess.run(cmd,capture_output=True,timeout=300);(out/(name+'.stdout.json')).write_bytes(r.stdout);(out/(name+'.stderr.log')).write_bytes(r.stderr)
 assert (r.returncode==0)==success,(name,r.returncode,r.stderr)
 if not success:assert not r.stdout
 records.append({'name':name,'argv':cmd,'exit_code':r.returncode,'stdout_sha256':hashlib.sha256(r.stdout).hexdigest()})
 return json.loads(r.stdout) if success else r

def method(value):
 rows=[x for x in value['symbols'] if x['symbol']==['method','Lamb/B;','b','()V']];assert len(rows)==1;return rows[0]
def ref(side,source):
 rows=[x for x in side['references'] if x['source_index']==source];assert len(rows)==1;return rows[0]
def evidence(row,local,other,lower):
 value=row['static_candidates'];assert value=={'local_definition':'observed' if local else 'not_observed',
  'other_source_definition_count':other,'other_source_state':'none_observed' if other==0 else 'one_observed' if other==1 else 'multiple_observed',
  'candidate_count_is_lower_bound':lower,'runtime_resolution':'not_evaluated'}
default=run('default-unchanged',['--before',A,'--after',A,B,'--before-complete','--after-complete'])
if original:assert (out/'default-unchanged.stdout.json').read_bytes()==original.read_bytes()
first=run('new-split',['--before',A,'--after',A,B,'--before-complete','--after-complete','--reference-candidates'])
# The feature projection is purely additive; default is the same result with added fields removed.
projection=copy.deepcopy(first);projection.pop('reference_candidate_model')
for entry0 in projection['symbols']:
 entry0.pop('reference_candidate_summary')
 for side0 in ('before','after'):
  for row0 in entry0[side0]['references']:row0.pop('static_candidates')
assert projection==default
entry=method(first);evidence(ref(entry['before'],0),False,0,False);evidence(ref(entry['after'],0),False,1,False);evidence(ref(entry['after'],1),True,0,False)
assert entry['reference_candidate_summary']['bucket_counts_changed'] and not entry['reference_candidate_summary']['scope_claim_changed']
delta=first['reference_candidate_model']['source_occurrences'];assert not delta['only_before'] and len(delta['only_after'])==1 and len(delta['present_in_both'])==1
assert delta['only_after'][0]['source_index']==1 and delta['only_after'][0]['source_sha256']==sha(B)
assert ref(entry['before'],0)['occurrence_id']==ref(entry['after'],0)['occurrence_id']
second=run('two-definitions',['--before',A,B,'--after',A,B,C,'--reference-candidates'])
entry=method(second);evidence(ref(entry['before'],0),False,1,True);evidence(ref(entry['after'],0),False,2,True);evidence(ref(entry['after'],1),True,1,True);evidence(ref(entry['after'],2),True,1,True)
assert entry['after']['definition_count']==2 and entry['after']['definitions'][0]['occurrence_id']!=entry['after']['definitions'][1]['occurrence_id']
partial=run('partial-no-candidate',['--before',A,'--after',A,'--reference-candidates'])
entry=method(partial);evidence(ref(entry['before'],0),False,0,True);assert not entry['before']['scope_complete']
# Class and field references are checked against an existing independent byte oracle.
spec=importlib.util.spec_from_file_location('entity_oracle',entity_oracle_path);entity_oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(entity_oracle)
raw=entity_oracle.raw_entities(catalog,root)
cat=run('class-field-oracle',['--before',catalog,'--after',catalog,'--before-complete','--after-complete','--reference-candidates'])
for relation,kind in (('type_refs','class'),('field_refs','field')):
 for row in raw[relation]:
  symbol=['class',row['type_descriptor']] if kind=='class' else ['field',row['owner'],row['name'],row['type_descriptor']]
  entries=[x for x in cat['symbols'] if x['symbol']==symbol];assert len(entries)==1
  refs=[x for x in entries[0]['before']['references'] if x['source_index']==0 and x['reference_index']==row['reference_index']];assert len(refs)==1
  evidence(refs[0],row['has_local_definition'],0,False)
error=run('bounded-failure',['--before',A,'--after',A,B,'--reference-candidates','--max-results','1'],False)
assert error.returncode==2 and b'BudgetExceeded' in error.stderr
# A caller supplying contradictory local metadata must not get a fabricated candidate mapping.
spec=importlib.util.spec_from_file_location('candidate_diff',tool);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
invalid={'scope_complete':True,'definitions':[{'source_index':0,'reference_index':0,'definition_offset':7}],
 'references':[{'source_index':0,'reference_index':0,'definition_offset':None,'has_local_definition':False}]}
try:module.annotate_reference_candidates(invalid)
except module.DiffError:pass
else:raise AssertionError('contradictory local definition accepted')
after={str(x):sha(x) for x in inputs};assert before==after
(out/'summary.json').write_text(json.dumps({'outcome':'passed','scope':'synthetic static fixture, not ART or ClassLoader','inputs_before':before,'inputs_after':after,'records':records},indent=2)+'\n',encoding='utf-8')
print('PASS static cross-source reference evidence, exact occurrence delta and fail-closed controls')
