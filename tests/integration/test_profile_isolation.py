"""Composite profile and incompatible superclass/interface controls."""
import argparse,itertools,json,subprocess,tempfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True);a=p.parse_args()
v6={'declares_fields':{'scope':'inherited','where':{'name':'x'},'min':1}}
v7={'numeric_bits':{'width':32,'bits':'ffffffff','kind':'constant'}}
v8={'declares_fields':{'scope':'inherited_interfaces','where':{'name':'x'},'min':1}}
v11={'declares_fields':{'scope':'inherited_interfaces_resolved','where':{'name':'x'},'min':1}}
cap=['inherited_fields','numeric_literals','interface_fields','use_streaming']
use={'op':'scan','relation':'invoke_sites'}
cases=[];rejected=[]
for left,right in itertools.combinations(cap[:3],2):
 (rejected if {left,right}=={'inherited_fields','interface_fields'} else cases).append({'relation':'method_defs','where':True,'required_capabilities':[left,right]})
for other in cap[:3]:
 cases.append({'relation':use,'required_capabilities':['use_streaming',other]})
for predicate in (v6,v7,v8):
 method={'op':'scan','relation':'method_defs','where':predicate}
 relation={'op':'join','left':method,'right':use,'on':'caller'}
 cases.append({'relation':relation,'required_capabilities':['use_streaming']})
for predicate,other in ((v6,'interface_fields'),(v7,'interface_fields'),(v8,'inherited_fields'),(v8,'numeric_literals')):
 (rejected if (predicate,other) in ((v6,'interface_fields'),(v8,'inherited_fields')) else cases).append({'relation':'method_defs','where':predicate,'required_capabilities':[other]})
for other in ('inherited_fields','numeric_literals','interface_fields','composite'):
 rejected.append({'relation':'method_defs','where':v11,'required_capabilities':[other]})
rejected.append({'relation':use,'required_capabilities':['interface_resolved','use_streaming']})
for predicate in (v6,v7,v8):
 rejected.append({'relation':'method_defs','where':predicate,'required_capabilities':['interface_resolved']})
with tempfile.TemporaryDirectory(prefix='dmg-profile-isolation-') as tmp:
 def run(label,q):
  path=Path(tmp)/(label+'.json');path.write_text(json.dumps({'schema_version':1,**q}),encoding='utf-8')
  r=subprocess.run([str(a.exe),'query',str(a.fixture),'--query',str(path),'--json'],capture_output=True,text=True,encoding='utf-8',timeout=30)
  return r.returncode,json.loads(r.stdout)
 for i,q in enumerate(cases):
  code,result=run(str(i),q)
  assert code==0 and result['profile']=='dex-query-composite-v10' and result['query_id'].startswith('query:v10:'),(i,result)
 for i,q in enumerate(rejected):
  code,result=run('reject-'+str(i),q)
  assert code==2 and result['execution_status']=='Unsupported' and not result['candidates'],(i,result)
 for name,q,profile,domain in [
  ('v6',{'relation':'method_defs','required_capabilities':['inherited_fields']},'dex-query-inherited-v6','query:v6:'),
  ('v7',{'relation':'method_defs','required_capabilities':['numeric_literals']},'dex-query-numeric-v7','query:v7:'),
  ('v8',{'relation':'method_defs','required_capabilities':['interface_fields']},'dex-query-interface-v8','query:v8:'),
  ('v11',{'relation':'method_defs','required_capabilities':['interface_resolved']},'dex-query-interface-resolved-v11','query:v11:'),
  ('v9',{'relation':use,'required_capabilities':['use_streaming']},'dex-query-use-stream-v9','query:v9:')]:
  code,result=run(name,q);assert code==0 and result['profile']==profile and result['query_id'].startswith(domain),(name,result)
print('PASS composite v10 combinations and superclass/interface isolation')
