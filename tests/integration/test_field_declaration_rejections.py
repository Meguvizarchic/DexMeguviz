"""Compile boundaries and failure atomicity for the field declaration profile."""
import argparse,copy,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--old',type=Path,required=True);p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
paths=[a.fixtures/x for x in ('child.dex','parent.dex','object.dex')];slots=['input:'+str(i)+':'+str(x) for i,x in enumerate(paths)]
base={'schema_version':1,'required_capabilities':['field_declaration_static'],'scope':{'slots':slots},'relation':{'op':'scan','relation':'field_uses','where':{'target_field_declaration':{'scope':'inherited'}}}}
def run(name,q,exe=None):
 f=a.out/(name+'.json');f.write_text(json.dumps(q),encoding='utf-8');cmd=[str(exe or a.exe),'query',str(paths[0]),'--source',str(paths[1]),'--source',str(paths[2]),'--query',str(f),'--json'];r=subprocess.run(cmd,capture_output=True,text=True);(a.out/(name+'.out')).write_text(r.stdout,encoding='utf-8');(a.out/(name+'.err')).write_text(r.stderr,encoding='utf-8');return r
bad=[]
q=copy.deepcopy(base);q.pop('scope');bad.append(('no-scope',q))
q=copy.deepcopy(base);q['scope']['slots']=[];bad.append(('empty-scope',q))
q=copy.deepcopy(base);q['scope']['slots']=['missing-slot'];bad.append(('missing-slot',q))
q=copy.deepcopy(base);q.pop('required_capabilities');bad.append(('no-capability',q))
q=copy.deepcopy(base);q['relation']['relation']='invoke_sites';bad.append(('wrong-relation',q))
q=copy.deepcopy(base);q['relation']['where']={'any':[q['relation']['where'],True]};bad.append(('predicate-under-any',q))
q=copy.deepcopy(base);q['relation']['where']={'not':q['relation']['where']};bad.append(('predicate-under-not',q))
q=copy.deepcopy(base);q['required_capabilities'].append('use_streaming');bad.append(('mixed-streaming',q))
q=copy.deepcopy(base);q['relation']={'op':'filter','input':q['relation'],'where':True};bad.append(('unsupported-graph',q))
q=copy.deepcopy(base);q['max_work']=1;bad.append(('work-budget',q))
q=copy.deepcopy(base);q['max_intermediate_rows']=1;bad.append(('rows-budget',q))
for name,q in bad:
 r=run(name,q);assert r.returncode!=0,(name,r.stdout,r.stderr)
 if r.stdout.strip().startswith('{'):
  failure=json.loads(r.stdout);assert failure.get('execution_status')!='Ok' and failure.get('candidates',[])==[],(name,failure)
legacy={'schema_version':1,'relation':{'op':'scan','relation':'field_uses','where':{'opcode':{'min':82,'max':109}}},'intent':'enumerate'}
a1=run('old-profile-current',legacy);a2=run('old-profile-baseline',legacy,a.old);assert a1.returncode==a2.returncode==0
x,y=json.loads(a1.stdout),json.loads(a2.stdout);assert x['query_id']==y['query_id'] and x['profile']==y['profile']=='dex-query-use-v4'
assert [(z['source_index'],z['dex_pc'],z['opcode'],z['target_index']) for z in x['candidates']]==[(z['source_index'],z['dex_pc'],z['opcode'],z['target_index']) for z in y['candidates']]
print('PASS Q08 rejection boundaries, budget failures and v4 compatibility')
