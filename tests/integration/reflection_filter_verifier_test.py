"""Independent reflection filter-chain acceptance and forged witness rejection."""
import argparse, copy, hashlib, importlib.util, json, subprocess, tempfile
from pathlib import Path
p=argparse.ArgumentParser()
for name in ('root','exe','verifier','out'):p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args(); root=a.root.resolve(); exe=a.exe.resolve(); module=a.verifier.resolve(); out=a.out.resolve()
out.mkdir(parents=True,exist_ok=False)
fixture=root/'tests/fixtures/generated/definition_catalog/definitions.dex'
paths=[Path(__file__).resolve(),exe,fixture,module,root/'tests/integration/relational_test.py',root/'tests/integration/entity_query_test.py',root/'tools/evidence_verifier/verify.py',root/'tools/evidence_verifier/multisource.py']
sha=lambda x:hashlib.sha256(x.read_bytes()).hexdigest()
before={str(x):sha(x) for x in paths}
assert sha(fixture)=='e1059582b6c893690880403d00f6b5be8dfceb7be282793e2117bdf15b14e77a'
spec=importlib.util.spec_from_file_location('chain34',module); v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
flags=lambda target,mode,value:{target:{'domain':'reflection','mode':mode,'value':value}}
wrap=lambda child,where:{'op':'filter','input':child,'where':where}
caps=['reflection_flags_static','reflection_relational']
records=[];reject=[]
with tempfile.TemporaryDirectory(prefix='filter34-',dir=out) as temp:
 def run(name,relation):
  q={'schema_version':1,'relation':relation,'intent':'enumerate','required_capabilities':caps}
  path=Path(temp)/(name+'.json');path.write_text(json.dumps(q),encoding='utf-8')
  call=subprocess.run([str(exe),'query',str(fixture),'--query',str(path),'--json'],capture_output=True,timeout=40)
  if call.returncode:raise AssertionError((name,call.returncode,call.stdout,call.stderr))
  result=json.loads(call.stdout);report=v.verify(root,fixture,q,result)
  records.append({'name':name,'output_sha256':hashlib.sha256(call.stdout).hexdigest(),'known':report['known_rows'],'unknown':report['unknown_rows'],'query_id':report['query_id']})
  return q,result,report
 for relation in v.RELATIONS:
  for mode,mask in [('contains',1),('exact',9),('any',0),('contains',0)]:
   scan={'op':'scan','relation':relation}
   q,r,report=run(relation+'-one-'+mode+'-'+str(mask),wrap(scan,flags('flags',mode,mask)))
   if relation=='field_refs' and mode=='contains' and mask==1:
    sample=(q,r)
    assert report['query_id']=='query:v14:c2a7da50e9769ed0516c1628f0d41e48b700460bfe9e0e29a4e58021a30b74c0'
    assert (report['known_rows'],report['unknown_rows'])==(3,1)
 for relation in ('method_defs','field_defs','method_refs','field_refs'):
  for first,second in [(('flags','contains',1),('owner_flags','contains',1)),(('owner_flags','contains',0),('flags','exact',9)),(('flags','any',0),('owner_flags','contains',0))]:
   scan={'op':'scan','relation':relation}
   q,r,report=run(relation+'-two-'+str(len(records)),wrap(wrap(scan,flags(*first)),flags(*second)))
   if relation=='field_refs' and first==('flags','contains',1) and second==('owner_flags','contains',1):
    assert report['query_id']=='query:v14:448aa20d1fc9674ae1b858e11af746725d39708f8e7cc77d5893ce8190608496'
    assert (report['known_rows'],report['unknown_rows'])==(1,3)
    sample_two=(q,r)
 scan={'op':'scan','relation':'field_refs','where':flags('flags','contains',1)}
 q,r,report=run('scan-reflection-plus-filter',wrap(scan,flags('owner_flags','contains',1)))
 assert (report['known_rows'],report['unknown_rows'])==(1,3)
 scan={'op':'scan','relation':'field_refs'}
 for n in range(1,9):
  scan=wrap(scan,flags('flags','contains',0))
  q,r,report=run('depth-'+str(n),scan)
  assert (report['known_rows'],report['unknown_rows'])==(3,1)
# Strictly check node IDs, witness count/order, graph stats and three-valued profiles.
q,r=sample_two
mutations=[
 ('filter-unknown',lambda x:x['relation_profile']['operators'][1].__setitem__('unknown_rows',0)),
 ('scan-complete',lambda x:x['relation_profile']['operators'][0].__setitem__('complete',False)),
 ('filter-input',lambda x:x['relation_profile']['operators'][2].__setitem__('input_rows',0)),
 ('filter-output-bool',lambda x:x['relation_profile']['operators'][2].__setitem__('output_rows',True)),
 ('filter-operator-id',lambda x:x['relation_profile']['operators'][1].__setitem__('node_id',0)),
 ('filter-profile-order',lambda x:x['relation_profile']['operators'].reverse()),
 ('missing-scan-witness',lambda x:x['candidates'][0]['evidence'].pop(0)),
 ('missing-filter-witness',lambda x:x['candidates'][0]['evidence'].pop()),
 ('wrong-witness-order',lambda x:x['candidates'][0]['evidence'].reverse()),
 ('false-filter-witness',lambda x:x['candidates'][0]['evidence'][2].__setitem__('matched',False)),
 ('unknown-filter-witness',lambda x:x['candidates'][0]['evidence'][1].__setitem__('matched',None)),
 ('wrong-filter-node',lambda x:x['candidates'][0]['evidence'][1].__setitem__('node_id',1)),
 ('wrong-filter-operator',lambda x:x['candidates'][0]['evidence'][1].__setitem__('operator_node',0)),
 ('wrong-witness-entity',lambda x:x['candidates'][0]['evidence'][1]['entity'].__setitem__('local_index',0)),
 ('extra-witness',lambda x:x['candidates'][0]['evidence'].append(copy.deepcopy(x['candidates'][0]['evidence'][0]))),
 ('invented-proof',lambda x:x['relation_profile'].__setitem__('extra_proof',{'verified':True})),
 ('lost-unknown',lambda x:x.__setitem__('unknown_rows',0)),
 ('incorrect-coverage',lambda x:x.__setitem__('coverage','Complete')),
 ('query-id',lambda x:x.__setitem__('query_id','query:v14:'+'0'*64)),
 ('node-count',lambda x:x['query'].__setitem__('node_count',2)),
 ('top-dex-version-float',lambda x:x.__setitem__('dex_version',float(x['dex_version']))),
]
for name,change in mutations:
 forged=copy.deepcopy(r);change(forged)
 try:v.verify(root,fixture,q,forged)
 except (AssertionError,v.InvalidEvidence,KeyError,TypeError,ValueError):reject.append(name)
 else:raise AssertionError('accepted forged '+name)
q,r=sample
bad=[]
def unsupported(name,query):
 try:v.verify(root,fixture,query,r)
 except (v.Unsupported,TypeError):bad.append(name)
 else:raise AssertionError('accepted unsupported '+name)
for label,mut in [
 ('join',lambda x:x['relation'].__setitem__('op','join')),
 ('multiple-sources',lambda x:x.__setitem__('scope',{'slots':['a','b']})),
 ('unordered-boolean',lambda x:x['relation'].__setitem__('where',{'all':[flags('flags','contains',1)]})),
 ('input-filter-extra',lambda x:x['relation']['input'].__setitem__('invented',1)),
 ('flags-bool',lambda x:x['relation']['where']['flags'].__setitem__('value',True)),
 ('max-results-bool',lambda x:x.__setitem__('max_results',True)),
 ('unknown-capability',lambda x:x['required_capabilities'].append('numeric_literals')),
]:
 broken=copy.deepcopy(q);mut(broken);unsupported(label,broken)
extra=copy.deepcopy(q);node=extra['relation']
for i in range(8):node=wrap(node,flags('flags','contains',0))
extra['relation']=node;unsupported('depth-nine',extra)
after={str(x):sha(x) for x in paths};assert before==after
(out/'summary.json').write_text(json.dumps({'outcome':'passed','scope':'fixed DEX; scan and 1-8 filter chain only; static metadata, no ART/join/group','records':records,'rejected':reject,'unsupported':bad,'input_sha256_before':before,'input_sha256_after':after},indent=2)+'\n',encoding='utf-8')
print('PASS',len(records),'filter queries;',len(reject),'forged evidence;',len(bad),'unsupported rejected')

