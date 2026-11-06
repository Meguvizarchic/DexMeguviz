"""Deterministic independent raw DEX comparisons for the isolated target_symbol prototype."""
from pathlib import Path
from collections import Counter
import argparse,copy,hashlib,importlib.util,json,subprocess

def main():
 a=argparse.ArgumentParser();a.add_argument('--exe',type=Path,required=True);a.add_argument('--root',type=Path,required=True);a.add_argument('--output',type=Path,required=True);x=a.parse_args()
 x.output.mkdir(parents=True,exist_ok=False); fixtures=x.root/'tests/fixtures/generated/graph'; oracle_path=x.root/'tests/integration/raw_graph_oracle.py'
 spec=importlib.util.spec_from_file_location('graph_oracle',oracle_path);oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
 sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest(); exe_hash=sha(x.exe); records=[];rejected=[]
 def run(name,entries,reverse=False,incomplete=False,intent='enumerate',where=None,cap=True,advanced=False):
  parsed=oracle.dataset(fixtures,entries); edges=oracle.edges(parsed); bylabel={name:i for i,(name,_) in enumerate(entries)}
  left={'op':'scan','relation':'invoke_sites'};right={'op':'scan','relation':'method_defs'}
  if where:left['where']=where
  if reverse:left,right=right,left
  query={'schema_version':1,'relation':{'op':'join','left':left,'right':right,'on':'target_symbol'},'max_results':100,'intent':intent}
  if cap:query['required_capabilities']=['use_target_symbol']+(['use_streaming'] if advanced else [])
  q=x.output/(name+'.query.json');q.write_text(json.dumps(query),encoding='utf-8')
  cmd=[str(x.exe),'query',str(fixtures/entries[0][1]),'--query',str(q),'--json']
  for _,filename in entries[1:]:cmd.extend(['--source',str(fixtures/filename)])
  if incomplete:cmd.append('--scope-incomplete')
  p=subprocess.run(cmd,capture_output=True,timeout=60);(x.output/(name+'.stdout.json')).write_bytes(p.stdout);(x.output/(name+'.stderr.log')).write_bytes(p.stderr)
  value=json.loads(p.stdout);expected_exit=2 if not cap or advanced else 0
  assert p.returncode==expected_exit,(name,p.returncode,p.stderr.decode('utf-8','replace'),value)
  if expected_exit:
   assert value['execution_status']=='Unsupported';records.append({'name':name,'exit_code':p.returncode});return value
  assert value['profile']=='dex-query-use-target-symbol-v16' and value['query_id'].startswith('query:v16:')
  if where:edges=[e for e in edges if parsed[bylabel[e['caller']]]['definition'][0]==where['caller_owner']]
  expected=Counter((bylabel[e['caller']],e['pc'],e['method_ref'],bylabel[e['target']],e['opcode'],tuple(e['symbol'])) for e in edges)
  if intent=='exists' and expected: expected=None
  def verify(v):
   assert v['coverage']==('Partial' if incomplete else 'Complete')
   actual=[]
   for row in v['candidates']:
    assert len(row['links'])==1 and row['links'][0]['key']=='target_symbol'
    link=row['links'][0];event=link['right'] if reverse else link['left'];target=link['left'] if reverse else link['right']
    assert event['relation']=='invoke_sites' and target['relation']=='method_defs' and event['local_index']==target['local_index']==0
    bindings=row['bindings']; eb=next(b for b in bindings if b['relation']=='invoke_sites');tb=next(b for b in bindings if b['relation']=='method_defs')
    assert eb['source_index']==event['source_index'] and eb['dex_pc']==event['dex_pc'] and tb['source_index']==target['source_index']
    assert eb['target_domain']=='method_ref' and tb['prototype']==parsed[target['source_index']]['definition'][2]
    actual.append((event['source_index'],event['dex_pc'],eb['target_index'],target['source_index'],eb['opcode'],(tb['owner'],tb['name'],tb['prototype'])))
   if expected is not None:assert Counter(actual)==expected,(name,actual,expected)
   elif actual:assert Counter(actual)<=Counter((bylabel[e['caller']],e['pc'],e['method_ref'],bylabel[e['target']],e['opcode'],tuple(e['symbol'])) for e in edges)
   return actual
  actual=verify(value)
  if name=='forward':
   for label,change in [('wrong-pc',lambda z:z['candidates'][0]['links'][0]['left'].__setitem__('dex_pc',99)),('wrong-target',lambda z:z['candidates'][0]['links'][0]['right'].__setitem__('source_index',5)),('wrong-symbol',lambda z:z['candidates'][0]['bindings'][1].__setitem__('name','forged')),('missing-row',lambda z:z['candidates'].pop())]:
    bad=copy.deepcopy(value);change(bad)
    try:verify(bad)
    except (AssertionError,KeyError,IndexError,StopIteration):rejected.append(label)
    else:raise AssertionError('forgery accepted '+label)
  records.append({'name':name,'count':len(actual),'exit_code':p.returncode,'sha256':sha(x.output/(name+'.stdout.json')),'decision':value['decision']});return value
 entries=[('a','amb-a.dex'),('b1','amb-b1.dex'),('b2','amb-b2.dex'),('c1','amb-c1.dex'),('c2','amb-c2.dex'),('overload','amb-overload.dex')]
 assert len(run('forward',entries)['candidates'])==6
 assert len(run('reverse',entries,reverse=True)['candidates'])==6
 repeat=entries[:2]+[('b1-copy','amb-b1.dex')]+entries[2:];assert len(run('repeated',repeat)['candidates'])==9
 assert run('partial-positive',entries,incomplete=True,intent='exists')['decision']=='ProvenTrue'
 assert run('partial-negative',entries,incomplete=True,intent='exists',where={'caller_owner':'Lnone/X;'})['decision']=='Undetermined'
 assert run('complete-negative',entries,intent='exists',where={'caller_owner':'Lnone/X;'})['decision']=='ProvenFalse'
 run('capability-required',entries,cap=False);run('advanced-rejected',entries,advanced=True)
 parsed=oracle.dataset(fixtures,entries);edges=oracle.edges(parsed);label={v[0]:i for i,v in enumerate(entries)}
 legal={(label[e['caller']],e['pc'],label[e['target']]) for e in edges}
 for name,reverse,incomplete,missing in [('semi-forward',False,False,False),('semi-reverse',True,False,False),('semi-incomplete',False,True,True),('semi-absent',False,False,True)]:
  left={'op':'scan','relation':'method_defs' if reverse else 'invoke_sites'};right={'op':'scan','relation':'invoke_sites' if reverse else 'method_defs'}
  if missing:right['where']={'name':'missing'}
  query={'schema_version':1,'required_capabilities':['use_target_symbol'],'relation':{'op':'semi_join','left':left,'right':right,'on':'target_symbol'},'max_results':100,'intent':'exists' if missing else 'enumerate'}
  qp=x.output/(name+'.query.json');qp.write_text(json.dumps(query),encoding='utf-8');cmd=[str(x.exe),'query',str(fixtures/entries[0][1]),'--query',str(qp),'--json']
  for _,filename in entries[1:]:cmd.extend(['--source',str(fixtures/filename)])
  if incomplete:cmd.append('--scope-incomplete')
  p=subprocess.run(cmd,capture_output=True,timeout=60);(x.output/(name+'.stdout.json')).write_bytes(p.stdout);(x.output/(name+'.stderr.log')).write_bytes(p.stderr);v=json.loads(p.stdout)
  assert p.returncode==0 and v['profile']=='dex-query-use-target-symbol-v16' and v['coverage']==('Partial' if incomplete else 'Complete')
  if missing:
   assert not v['candidates'] and v['decision']==('Undetermined' if incomplete else 'ProvenFalse')
   assert v['unknown_rows']==(4 if incomplete else 0)
  else:
   actual=set()
   for row in v['candidates']:
    assert len(row['links'])==1 and row['links'][0]['key']=='target_symbol' and len(row['proof_bindings'])>=1
    link=row['links'][0];event=link['right'] if reverse else link['left'];definition=link['left'] if reverse else link['right'];edge=(event['source_index'],event['dex_pc'],definition['source_index']);assert edge in legal
    actual.add(definition['source_index'] if reverse else (event['source_index'],event['dex_pc']))
   expected={e[2] if reverse else (e[0],e[1]) for e in legal};assert actual==expected and len(v['candidates'])==len(expected)
  records.append({'name':name,'count':len(v['candidates']),'exit_code':p.returncode,'sha256':sha(x.output/(name+'.stdout.json')),'decision':v['decision']})
 assert sha(x.exe)==exe_hash
 result={'passed':len(records),'failed':0,'records':records,'forgeries_rejected':rejected,'exe_sha256':exe_hash,'oracle_sha256':sha(oracle_path),'fixture_sha256':{n:sha(fixtures/n) for _,n in entries},'scope':'fixed invoke graph fixtures only; not field/string, ART, runtime binding or full v16 acceptance'}
 (x.output/'summary.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps({'passed':len(records),'forgeries_rejected':len(rejected)}))
if __name__=='__main__':main()
