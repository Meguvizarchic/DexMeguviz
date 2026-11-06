"""Independent v12 identity bytes and old/new static CLI comparison."""
import argparse,hashlib,json,struct,subprocess
from pathlib import Path

p=argparse.ArgumentParser()
for name in ('old-exe','new-exe','root','out'):p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
u32=lambda n:struct.pack('<I',n)
u64=lambda n:struct.pack('<Q',n)
frame=lambda b:u64(len(b))+b
# Independently encoded canonical bytes for default Unique/1 root invoke scan.
predicate=b''.join(u32(n) for n in (0,0,0,0,0xffffffff,0))
caps=4674+131072+1048576
top=b''.join(u32(n) for n in (8,2,1))+u64(100000000)+b''.join(u32(n) for n in (7,1,0,caps,0,100000,0,0))
node=b''.join(u32(n) for n in (0,8,1))+frame(predicate)+b''.join(u32(n) for n in (0,1,0xffffffff,1,0,0,0,0,0,0))
canonical=b'DexMeguviz:QueryIR:unique-one-v12'+top+node
assert len(canonical)==169
expected='query:v12:'+hashlib.sha256(canonical).hexdigest()
assert expected=='query:v12:89ced6aa2081ad2dc50dab1daa56558a04e26c9bdb8c4de56dc2522fcb2f2366'
root=a.root.resolve();fixture=root/'tests/fixtures/generated/use-stream-v9/two-methods.dex'
assert hashlib.sha256(fixture.read_bytes()).hexdigest()=='cb9020777da008d67b856862068a7a23fd6483b599a18ead5f01a3b94ecde00b'
interfaces=root/'tests/fixtures/generated/interface-v11'
scan={'op':'scan','relation':'invoke_sites'}
base={'schema_version':1,'relation':scan,'intent':'unique','max_results':1}
v11={'schema_version':1,'relation':'class_defs','intent':'unique','max_results':1,'where':{'all':[{'descriptor':'Lifx/Left;'},{'declares_fields':{'scope':'inherited_interfaces_resolved','where':{'name':'diamond'},'min':1,'max':1}}]}}
v11_paths=[interfaces/'left.dex',interfaces/'top.dex',interfaces/'root.dex']
cases=[
 ('v9','v9',{**base,'required_capabilities':['use_streaming']},[fixture]),
 ('v9-string','v9',{**base,'required_capabilities':['use_streaming','string_uses']},[fixture]),
 ('v9-field','v9',{**base,'required_capabilities':['use_streaming','field_uses']},[fixture]),
 ('v10','v10',{**base,'required_capabilities':['use_streaming','numeric_literals']},[fixture]),
 ('v10-string','v10',{**base,'required_capabilities':['use_streaming','numeric_literals','string_uses']},[fixture]),
 ('v11','v11',v11,v11_paths),
 ('v11-field','v11',{**v11,'required_capabilities':['field_uses']},v11_paths)]
records=[]
def call(label,exe,document,paths):
 q=a.out/(label+'.json');q.write_text(json.dumps(document,sort_keys=True),encoding='utf-8')
 command=[str(exe.resolve()),'query',str(paths[0])]
 for path in paths[1:]:command+=['--source',str(path)]
 result=subprocess.run(command+['--query',str(q.resolve()),'--json'],capture_output=True,text=True,encoding='utf-8',timeout=60)
 (a.out/(label+'.stdout.json')).write_text(result.stdout,encoding='utf-8');(a.out/(label+'.stderr.log')).write_text(result.stderr,encoding='utf-8')
 return result.returncode,json.loads(result.stdout)
def semantic(x):
 return {k:v for k,v in x.items() if k not in ('budgets','memory','elapsed_ms')}
for name,version,document,paths in cases:
 old_status,old=call(name+'-old',a.old_exe,document,paths)
 new_status,new=call(name+'-new',a.new_exe,document,paths)
 if old_status!=new_status or semantic(old)!=semantic(new):raise SystemExit('old profile changed: '+name)
 assert old['query_id'].startswith('query:'+version+':')
 records.append({'case':name,'old_exit':old_status,'new_exit':new_status,'query_id':old['query_id']})
v12={**base,'required_capabilities':['unique_one_stream']}
old_status,old=call('v12-old',a.old_exe,v12,[fixture]);new_status,new=call('v12-new',a.new_exe,v12,[fixture])
assert old_status==2 and old['execution_status']=='Unsupported'
assert new_status==3 and new['profile']=='dex-query-unique-one-v12' and new['query_id']==expected and new['reason']=='ResultLimit'
alias={**base,'required_capabilities':['unique_one_stream','use_streaming']}
alias_status,alias_result=call('v12-alias',a.new_exe,alias,[fixture])
assert alias_status==new_status and alias_result['query_id']==expected
records.append({'case':'v12','old_exit':old_status,'new_exit':new_status,'query_id':expected,'canonical_bytes':len(canonical),'caps':caps})
summary={'old_exe_sha256':hashlib.sha256(a.old_exe.read_bytes()).hexdigest(),'new_exe_sha256':hashlib.sha256(a.new_exe.read_bytes()).hexdigest(),
         'fixture_sha256':hashlib.sha256(fixture.read_bytes()).hexdigest(),'records':records,'scope':'fixed static inputs only; no ART or runtime proof'}
(a.out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
print('PASS v12 independently encoded identity, alias and old v9/v10/v11 CLI comparison')
