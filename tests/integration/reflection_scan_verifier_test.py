"""Fixed v14 scan verifier controls, including forged evidence and unsupported queries."""
import argparse, copy, hashlib, importlib.util, json, subprocess, tempfile
from pathlib import Path

parser=argparse.ArgumentParser()
for name in ('root','exe','verifier','out'):parser.add_argument('--'+name,type=Path,required=True)
args=parser.parse_args();root=args.root.resolve();exe=args.exe.resolve();module=args.verifier.resolve();base=args.out.resolve()
base.mkdir(parents=True,exist_ok=False)
fixture=root/'tests/fixtures/generated/definition_catalog/definitions.dex'
spec=importlib.util.spec_from_file_location('reflection_scan_v14',module); verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
paths=[Path(__file__).resolve(),exe,fixture,module,root/'tests/integration/relational_test.py',root/'tests/integration/entity_query_test.py',root/'tools/evidence_verifier/verify.py',root/'tools/evidence_verifier/multisource.py']
before={str(p):sha(p) for p in paths}; records=[]; rejected=[]
caps=['reflection_flags_static','reflection_relational']
with tempfile.TemporaryDirectory(prefix='v14-scan33-',dir=base) as tmp:
 for relation in verifier.RELATIONS:
  for target in ('flags','owner_flags'):
   if target=='owner_flags' and relation in ('class_defs','type_refs'):continue
   for mode,value in [('contains',1),('exact',9),('any',0),('contains',0)]:
    name=f'{relation}-{target}-{mode}-{value}';q={'schema_version':1,'relation':{'op':'scan','relation':relation,'where':{target:{'domain':'reflection','mode':mode,'value':value}}},'intent':'enumerate','required_capabilities':caps}; qpath=Path(tmp)/(name+'.json');qpath.write_text(json.dumps(q),encoding='utf-8')
    p=subprocess.run([str(exe),'query',str(fixture),'--query',str(qpath),'--json'],capture_output=True,timeout=40)
    if p.returncode!=0:raise RuntimeError((name,p.returncode,p.stderr,p.stdout))
    result=json.loads(p.stdout); report=verifier.verify(root,fixture,q,result)
    records.append({'name':name,'output_sha256':hashlib.sha256(p.stdout).hexdigest(),'known':report['known_rows'],'unknown':report['unknown_rows']})
    if name=='field_refs-flags-contains-1': sample=(q,result)
q,result=sample
mutations=[('candidate-source',lambda x:x['candidates'][0].__setitem__('source_index',1)),('candidate-offset',lambda x:x['candidates'][0].__setitem__('record_offset',0)),('candidate-flag',lambda x:x['candidates'][0].__setitem__('access_flags',0)),('witness-truth',lambda x:x['candidates'][0]['evidence'][0].__setitem__('matched',False)),('witness-truth-int',lambda x:x['candidates'][0]['evidence'][0].__setitem__('matched',1)),('source-index-bool',lambda x:x['candidates'][0].__setitem__('source_index',False)),('candidate-flag-bool',lambda x:x['candidates'][0].__setitem__('access_flags',True)),('profile-complete-int',lambda x:x['relation_profile']['operators'][0].__setitem__('complete',0)),('witness-node',lambda x:x['candidates'][0]['evidence'][0].__setitem__('node_id',2)),('witness-operator',lambda x:x['candidates'][0]['evidence'][0].__setitem__('operator_node',5)),('witness-entity',lambda x:x['candidates'][0]['evidence'][0]['entity'].__setitem__('local_index',1)),('witness-missing',lambda x:x['candidates'][0].__setitem__('evidence',[])),('forged-link',lambda x:x['candidates'][0].__setitem__('links',[{'key':'symbol'}])),('forged-proof-binding',lambda x:x['candidates'][0].__setitem__('proof_bindings',[{'operator_node':1}])),('duplicate-row',lambda x:x['candidates'].__setitem__(1,copy.deepcopy(x['candidates'][0]))),('unknown-count',lambda x:x.__setitem__('unknown_rows',0)),('false-complete',lambda x:x.__setitem__('coverage','Complete')),('query-id',lambda x:x.__setitem__('query_id','query:v14:'+'0'*64)),('operator-count',lambda x:x['relation_profile']['operators'][0].__setitem__('total_rows',0)),('source-digest',lambda x:x['sources'][0].__setitem__('source_sha256','0'*64)),('source-meta-index-bool',lambda x:x['sources'][0].__setitem__('source_index',False)),('unknown-count-bool',lambda x:x.__setitem__('unknown_rows',True)),('schema-bool',lambda x:x.__setitem__('schema_version',True)),('scope-source-bool',lambda x:x['query_scope'].__setitem__('sources',[False])),('query-projection',lambda x:x['query'].__setitem__('projection_mask',0)),('query-capabilities',lambda x:x['query'].__setitem__('required_capabilities',0)),('scope-explicit',lambda x:x['query_scope'].__setitem__('explicit',True)),('local-relation',lambda x:x['sources'][0]['local_scope'].__setitem__('relation','method_defs')),('validation-metadata',lambda x:x['validation'].__setitem__('metadata_subset_checked',False)),('validation-instruction',lambda x:x['validation'].__setitem__('instruction_stream','Complete')),('profile-matches',lambda x:x['query_profile'].__setitem__('matches_seen',777)),('top-source-bytes',lambda x:x.__setitem__('source_bytes',0)),('candidate-fake-prototype',lambda x:x['candidates'][0].__setitem__('prototype','()V')),('unknown-top-field',lambda x:x.__setitem__('invented',1)),('unknown-source-field',lambda x:x['sources'][0].__setitem__('invented',1)),('unknown-query-field',lambda x:x['query'].__setitem__('invented',1)),('unknown-graph-proof',lambda x:x['relation_profile'].__setitem__('extra_proof',{'verified':True})),('unknown-profile-field',lambda x:x['query_profile'].__setitem__('invented',1)),('unknown-validation-field',lambda x:x['validation'].__setitem__('invented',1))]
mutations.append(('top-dex-version-float',lambda x:x.__setitem__('dex_version',float(x['dex_version']))))
for name,mutate in mutations:
 fake=copy.deepcopy(result);mutate(fake)
 try:verifier.verify(root,fixture,q,fake)
 except (AssertionError,verifier.InvalidEvidence,KeyError,ValueError):rejected.append(name)
 else:raise AssertionError('accepted forged '+name)
for name,change in [('graph',lambda x:x['relation'].__setitem__('op','filter')),('top-n',lambda x:x.__setitem__('intent','top_n')),('scope',lambda x:x.__setitem__('scope',{'slots':[]})),('extra-predicate',lambda x:x['relation']['where'].__setitem__('name','x')),('extra-capability',lambda x:x['required_capabilities'].append('numeric_literals'))]:
 bad=copy.deepcopy(q);change(bad)
 try:verifier.verify(root,fixture,bad,result)
 except verifier.Unsupported:rejected.append('unsupported-'+name)
 else:raise AssertionError('accepted unsupported '+name)
after={str(p):sha(p) for p in paths};assert before==after
(base/'summary.json').write_text(json.dumps({'outcome':'passed','scope':'fixed fixture single-scan only; no ART or general graph proof','records':records,'rejected':rejected,'input_sha256_before':before,'input_sha256_after':after},indent=2)+'\n',encoding='utf-8')
print('PASS',len(records),'scan cases;',len(rejected),'forged or unsupported rejected')








