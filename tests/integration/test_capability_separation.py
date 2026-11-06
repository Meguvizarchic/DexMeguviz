"""v6/v7 capabilities use an independent v10 identity."""
import argparse,json,subprocess,tempfile
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True);a=p.parse_args()
inherited={'declares_fields':{'scope':'inherited','where':{'name':'parentOnly'},'min':1}}
numeric={'numeric_bits':{'width':32,'bits':'ffffffff','kind':'constant'}}
cases=[
 {'where':{'all':[inherited,numeric]}},
 {'where':{'any':[True,{'all':[numeric,inherited]}]}},
 {'where':inherited,'required_capabilities':['numeric_literals']},
 {'where':numeric,'required_capabilities':['inherited_fields']},
 {'where':True,'required_capabilities':['numeric_literals','inherited_fields']},
 {'where':True,'required_capabilities':['inherited_fields','numeric_literals']},
]
with tempfile.TemporaryDirectory(prefix='dmg-mixed-capabilities-') as temp:
 ids=[]
 for i,case in enumerate(cases):
  query={'schema_version':1,'relation':'method_defs',**case}
  path=Path(temp)/f'{i}.json';path.write_text(json.dumps(query),encoding='utf-8')
  run=subprocess.run([str(a.exe),'query',str(a.fixture),'--query',str(path),'--json'],capture_output=True,text=True,encoding='utf-8',timeout=30)
  assert run.returncode==0,(i,run.returncode,run.stdout,run.stderr)
  result=json.loads(run.stdout)
  assert result['profile']=='dex-query-composite-v10' and result['query_id'].startswith('query:v10:') and result['query']['required_capabilities']&262144,(i,result)
  ids.append(result['query_id'])
 assert ids[4]==ids[5]
print('PASS v6/v7 predicate and explicit capability mixes use canonical v10 identity')
