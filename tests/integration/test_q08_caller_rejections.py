"""Unsupported graph boundaries and resource failures for caller/v19."""
from pathlib import Path
import argparse,copy,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
paths=[a.fixtures/x for x in ('caller-a.dex','caller-b.dex','child.dex','parent.dex','object.dex')];slots=['input:'+str(i)+':'+str(x) for i,x in enumerate(paths)];where={'target_field_declaration':{'scope':'inherited'}}
base={'schema_version':1,'required_capabilities':['field_declaration_static'],'scope':{'slots':slots},'relation':{'op':'join','on':'caller','left':{'op':'scan','relation':'method_defs'},'right':{'op':'scan','relation':'field_uses','where':where}}}
bad=[]
q=copy.deepcopy(base);q.pop('scope');bad.append(('no-scope',q))
q=copy.deepcopy(base);q['scope']['slots']=[];bad.append(('empty-scope',q))
q=copy.deepcopy(base);q['scope']['slots']=['not-present'];bad.append(('missing-slot',q))
q=copy.deepcopy(base);q.pop('required_capabilities');bad.append(('no-capability',q))
q=copy.deepcopy(base);q['relation']['left'],q['relation']['right']=q['relation']['right'],q['relation']['left'];bad.append(('reverse',q))
q=copy.deepcopy(base);q['relation']['on']='target_ref';bad.append(('wrong-key',q))
q=copy.deepcopy(base);q['relation']['left']['scope']={'slots':[slots[0]]};bad.append(('local-left-scope',q))
q=copy.deepcopy(base);q['relation']['right']['scope']={'slots':[slots[0]]};bad.append(('local-right-scope',q))
q=copy.deepcopy(base);q['relation']['left']['where']={'field_access':{'any':[{'name':'value'}]}};bad.append(('left-body-predicate',q))
q=copy.deepcopy(base);q['relation']['right']['where']={'not':where};bad.append(('negate-declaration',q))
q=copy.deepcopy(base);q['relation']['right']['where']={'any':[where,True]};bad.append(('optional-declaration',q))
q=copy.deepcopy(base);q['relation']={'op':'distinct','input':q['relation']};bad.append(('extra-root',q))
q=copy.deepcopy(base);q['required_capabilities'].append('use_streaming');bad.append(('streaming-mix',q))
q=copy.deepcopy(base);q['max_work']=1;bad.append(('work-budget',q))
q=copy.deepcopy(base);q['max_intermediate_rows']=1;bad.append(('rows-budget',q))
for name,q in bad:
 f=a.out/(name+'.json');f.write_text(json.dumps(q),encoding='utf-8');cmd=[str(a.exe),'query',str(paths[0])]
 for x in paths[1:]:cmd+=['--source',str(x)]
 cmd+=['--query',str(f),'--json'];r=subprocess.run(cmd,capture_output=True,text=True);(a.out/(name+'.out')).write_text(r.stdout,encoding='utf-8');(a.out/(name+'.err')).write_text(r.stderr,encoding='utf-8');assert r.returncode!=0,(name,r.stdout,r.stderr)
 if r.stdout.strip().startswith('{'):
  value=json.loads(r.stdout);assert value.get('execution_status')!='Complete' and value.get('candidates',[])==[],(name,value)
print('PASS Q08 caller graph rejects unsupported shapes and resource failures')
