"""Prove v13/v14 requests compile on the selected core before JNI rejection."""
import argparse,hashlib,json,subprocess,tempfile
from pathlib import Path

p=argparse.ArgumentParser()
for name in ('cli','fixture','out'):p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args()
assert not a.out.exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
before={str(p):sha(p) for p in (a.cli,a.fixture)}
assert before[str(a.fixture)]=='e1059582b6c893690880403d00f6b5be8dfceb7be282793e2117bdf15b14e77a'
flag={'domain':'reflection','mode':'contains','value':1}
tests={
 'v13':{'schema_version':1,'relation':'class_defs','where':{'flags':flag},'required_capabilities':['reflection_flags_static']},
 'v14':{'schema_version':1,'relation':{'op':'scan','relation':'field_refs','where':{'flags':flag}},'intent':'enumerate',
        'required_capabilities':['reflection_flags_static','reflection_relational']}}
records=[]
with tempfile.TemporaryDirectory(prefix='dmg-entity-advanced-') as temp:
 for name,query in tests.items():
  path=Path(temp)/(name+'.json');path.write_text(json.dumps(query),encoding='utf-8')
  run=subprocess.run([str(a.cli.resolve()),'query',str(a.fixture.resolve()),'--query',str(path),'--json'],capture_output=True,text=True,encoding='utf-8',timeout=60)
  result=json.loads(run.stdout)
  assert run.returncode==0 and result['execution_status']=='Complete' and result['query_id'].startswith('query:'+name+':'),(name,run.returncode,result)
  if name=='v14':assert result['query_id']=='query:v14:f522ae279f590b3030bf24859db7c29278106408a709323bdd699b4ac221a69f'
  records.append({'name':name,'query_id':result['query_id'],'profile':result['profile'],'coverage':result['coverage'],'exit_code':run.returncode})
assert before=={str(p):sha(p) for p in (a.cli,a.fixture)}
a.out.parent.mkdir(parents=True,exist_ok=True)
with a.out.open('x',encoding='utf-8') as stream:
 json.dump({'outcome':'passed','scope':'v13/v14 core compile control before separately tested JNI refusal; no device','inputs':before,'records':records},stream,indent=2);stream.write('\n')
print('PASS native core compiles v13/v14 controls')
