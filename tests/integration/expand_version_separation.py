"""Draft-only canonical domain and unsupported combination checks."""
import argparse,json,subprocess,tempfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True);a=p.parse_args()
expand={'op':'bounded_expand','input':{'op':'scan','relation':'method_defs'},'min_depth':0,'max_depth':0}
numeric={'numeric_bits':{'width':32,'bits':'ffffffff','kind':'constant'}}
inherited={'declares_fields':{'scope':'inherited','where':{'name':'x'},'min':1}}
cases=[
 {'relation':expand,'required_capabilities':['inherited_fields']},
 {'relation':expand,'required_capabilities':['numeric_literals']},
 {'relation':{**expand,'input':{'op':'scan','relation':'method_defs','where':numeric}}},
 {'relation':'method_defs','where':inherited,'required_capabilities':['bounded_expand']},
 {'relation':'method_defs','where':numeric,'required_capabilities':['bounded_expand']},
 {'relation':'method_defs','required_capabilities':['bounded_expand','inherited_fields']},
 {'relation':'method_defs','required_capabilities':['bounded_expand','numeric_literals']},
]
advanced=('inherited_fields','numeric_literals','interface_fields','use_streaming','composite',
          'interface_resolved','unique_one_stream','reflection_flags_static',
          'reflection_relational','reflection_method_uses')
for capability in advanced:
 cases.append({'relation':expand,'required_capabilities':[capability]})
 cases.append({'relation':'method_defs','required_capabilities':['bounded_expand',capability]})
for scope in ('inherited','inherited_interfaces','inherited_interfaces_resolved'):
 predicate={'declares_fields':{'scope':scope,'where':{'name':'x'},'min':1}}
 for leaf in ('walk_where','emit_where'):
  cases.append({'relation':{**expand,leaf:predicate}})
 cases.append({'relation':{**expand,'input':{'op':'scan','relation':'method_defs','where':predicate}}})
for leaf in ('walk_where','emit_where'):
 cases.append({'relation':{**expand,leaf:numeric}})
 reflection={'flags':{'domain':'reflection','value':1}}
 cases.append({'relation':{**expand,leaf:reflection},'required_capabilities':['reflection_flags_static','reflection_relational']})
with tempfile.TemporaryDirectory(prefix='dmg-expand-version-') as tmp:
 def run(i,q):
  f=Path(tmp)/(str(i)+'.json');f.write_text(json.dumps({'schema_version':1,**q}),encoding='utf-8')
  r=subprocess.run([str(a.exe),'query',str(a.fixture),'--query',str(f),'--json'],capture_output=True,text=True,encoding='utf-8',timeout=30)
  return r.returncode,json.loads(r.stdout)
 for i,q in enumerate(cases):
  rc,actual=run(i,q);assert rc==2 and actual['execution_status']=='Unsupported' and not actual['candidates'],(i,actual)
  assert actual.get('message')!='unknown required capability',(i,actual)
 rc,required=run('capability',{'relation':'method_defs','required_capabilities':['bounded_expand']})
 assert rc==0 and required['query_id'].startswith('query:v5:') and required['profile']=='dex-query-expand-v5',required
 rc,normal=run('normal',{'relation':'method_defs'})
 assert rc==0 and normal['query_id'].startswith('query:v1:') and normal['profile']=='dex-query-method-v1',normal
print('PASS draft v5 capability identity and',len(cases),'v6-v15 mixed rejection cases')
