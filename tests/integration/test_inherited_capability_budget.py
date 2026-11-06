"""A capability declaration alone must not perform inheritance preparation."""
import argparse,json,subprocess,tempfile
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True);a=p.parse_args()
with tempfile.TemporaryDirectory(prefix='dmg-inherited-capability-') as tmp:
 def run(name,cap,work=None,where=True):
  q={'schema_version':1,'relation':'method_defs','where':where,'intent':'enumerate'}
  if cap:q['required_capabilities']=['inherited_fields']
  if work is not None:q['max_work']=work
  path=Path(tmp)/(name+'.json');path.write_text(json.dumps(q),encoding='utf-8')
  r=subprocess.run([str(a.exe),'query',str(a.fixture),'--source',str(a.fixture),'--query',str(path),'--json'],capture_output=True,text=True,encoding='utf-8',timeout=30)
  return r.returncode,json.loads(r.stdout)
 rc,base=run('base',False);assert rc==0 and base['execution_status']=='Complete'
 work=base['query_profile']['work_units'];assert work>1
 rc,cap=run('cap',True,work);rc0,original=run('base-same',False,work)
 assert rc==rc0==0 and cap['execution_status']==original['execution_status']=='Complete'
 assert cap['profile']=='dex-query-inherited-v6' and cap['query_profile']['work_units']==original['query_profile']['work_units']==work
 assert len(cap['candidates'])==len(original['candidates']) and cap['coverage']==original['coverage']
 rc1,low=run('low',False,work-1);rc2,lowcap=run('low-cap',True,work-1)
 assert rc1==rc2==3 and low['execution_status']==lowcap['execution_status']=='BudgetExceeded'
 inherited={'declares_fields':{'scope':'inherited','where':{'name':'unused'},'min':1}}
 for kind,deciding,other in [('any',True,False),('all',False,False)]:
  rc,baseline=run(kind+'-base',False,where={kind:[deciding,other]});assert rc==0
  budget=baseline['query_profile']['work_units']
  rc,short=run(kind+'-short',False,budget,where={kind:[deciding,inherited]})
  assert rc==0 and short['execution_status']=='Complete'
  assert short['query_profile']['work_units']==budget and short['candidates']==baseline['candidates']
  assert short['profile']=='dex-query-inherited-v6' and short['query_id'].startswith('query:v6:')
print('PASS capability-only query preserves old work-budget behavior across two sources')
