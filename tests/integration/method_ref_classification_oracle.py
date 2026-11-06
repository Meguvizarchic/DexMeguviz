"""Independent byte and CLI check; outputs retained, no temporary cleanup."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,struct,subprocess,sys
if not __debug__:raise SystemExit('assertions required')
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--exe',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();root=a.root.resolve();exe=a.exe.resolve();out=a.out.resolve();assert not out.exists();out.mkdir(parents=True);sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
oracle_path=root/'tools/evidence_verifier/verify.py';spec=importlib.util.spec_from_file_location('independent_oracle',oracle_path);oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
fixture=root/'tests/fixtures/generated/method-ref-classification';left=fixture/'reference.dex';right=fixture/'definition-with-return.dex';facts=root/'tests/fixtures/generated/method_facts/method-uses.dex';inputs=[Path(__file__),exe,oracle_path,left,right,facts];before={str(p):sha(p) for p in inputs};a0=oracle.parse_dex(left.read_bytes());b0=oracle.parse_dex(right.read_bytes());symbol=('Lsample/Target;','sink','()V')
def rows(data):return [x for x in data['references'] if (x['owner'],x['name'],x['prototype'])==symbol]
assert len(rows(a0))==len(rows(b0))==1 and not [x for x in a0['definitions'] if (x['owner'],x['name'],x['prototype'])==symbol]
local=[x for x in b0['definitions'] if (x['owner'],x['name'],x['prototype'])==symbol];assert len(local)==1 and local[0]['code_offset']>0
raw=right.read_bytes();assert struct.unpack_from('<I',raw,local[0]['code_offset']+12)[0]==1 and struct.unpack_from('<H',raw,local[0]['code_offset']+16)[0]==0x000e
q={'schema_version':1,'relation':'method_refs','where':{'name':'sink'},'intent':'enumerate','max_work':1000000};qpath=out/'query.json';qpath.write_text(json.dumps(q,separators=(',',':')))
command=[str(exe),'query',str(left),'--source',str(left),'--source',str(right),'--scope-incomplete','--query',str(qpath),'--json'];p=subprocess.run(command,capture_output=True,timeout=120);(out/'stdout.json').write_bytes(p.stdout);(out/'stderr.log').write_bytes(p.stderr);assert p.returncode==0,(p.returncode,p.stderr);j=json.loads(p.stdout);assert j['execution_status']=='Complete' and j['scope_complete'] is False
result=j['candidates'];assert len(result)==3 and [x['source_index'] for x in result]==[0,1,2] and len({x['occurrence_id'] for x in result})==3
for row,defined in zip(result,(False,False,True)):
 assert (row['owner'],row['name'],row['prototype'])==symbol and row['has_local_definition'] is defined and row['code_offset'] is None
 if defined:assert row['definition_offset']==local[0]['declaration_offset'] and row['access_flags']==local[0]['access_flags']
 else:assert row['definition_offset'] is None and row['access_flags'] is None
assert all(sha(p)==v for p,v in before.items());outputs={str(p):sha(p) for p in out.rglob('*') if p.is_file()};(out/'summary.json').write_text(json.dumps({'outcome':'passed','scope':'one generated source pair, duplicate occurrence, CLI byte oracle; no ART or runtime','inputs_before':before,'inputs_after':before,'outputs_sha256':outputs,'argv':command,'exit':p.returncode},indent=2)+'\n');print('PASS independent source-local method ref byte oracle')
