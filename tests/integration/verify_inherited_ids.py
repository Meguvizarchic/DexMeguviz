"""Independent canonical-byte oracle for v6 field and explicit-capability IDs."""
import argparse,hashlib,json,struct,subprocess,tempfile
from pathlib import Path
u32=lambda x:struct.pack('<I',x)
u64=lambda x:struct.pack('<Q',x)
prefix=b'DexMeguviz:QueryIR:inherited-v6'
def canonical(relation,projection,caps,node):
 return prefix+u32(relation)+u32(0)+u32(4096)+u64(100000000)+u32(projection)+u32(0)+u32(0)+u32(caps)+u32(0)+u32(0)+node
yes=u32(0)+u32(0)+u32(0)+u32(0)+u32(0xffffffff)+u32(0)
name='parentOnly';literal=name.encode('utf-16le')
leaf=u32(29)+u32(0)+u32(0)+u32(1)+u32(1)
leaf+=u32(0)+(u32(1)+u32(0)+u32(0)+u64(len(name))+literal)+u32(0)+u32(0)+u32(0)+u32(0)
expected={
 'capability':'query:v6:'+hashlib.sha256(canonical(0,7,16387,yes)).hexdigest(),
 'predicate':'query:v6:'+hashlib.sha256(canonical(1,8,16642,leaf)).hexdigest(),
}
assert expected['capability']=='query:v6:00a1c25cfd045cd1c58711dc39732399196a7f14b424d75d95fa0ba46d4f5462'
assert expected['predicate']=='query:v6:67701be9556cca4a50af2e817770089c411266b6da0d5b7a8a837ce218171a1e'
p=argparse.ArgumentParser();p.add_argument('--exe',required=True,type=Path);p.add_argument('--fixture',required=True,type=Path);a=p.parse_args()
cases={
 'capability':{'schema_version':1,'relation':'method_defs','required_capabilities':['inherited_fields']},
 'predicate':{'schema_version':1,'relation':'class_defs','where':{'declares_fields':{'scope':'inherited','where':{'name':name},'min':1,'max':1}}},
}
with tempfile.TemporaryDirectory(prefix='dmg-v6-queryid-') as tmp:
 for label,q in cases.items():
  qfile=Path(tmp)/(label+'.json');qfile.write_text(json.dumps(q),encoding='utf-8')
  run=subprocess.run([str(a.exe),'query',str(a.fixture),'--query',str(qfile),'--json'],capture_output=True,text=True,encoding='utf-8',timeout=30)
  assert run.returncode==0,(run.returncode,run.stderr);value=json.loads(run.stdout)
  assert value['profile']=='dex-query-inherited-v6' and value['query_id']==expected[label],(label,value.get('query_id'),expected[label])
 print(json.dumps(expected,sort_keys=True))
print('PASS independently encoded v6 QueryIDs and explicit-capability profile')
