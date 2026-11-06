"""Independent use/inherited join oracle and source-scope negative control."""
import argparse,hashlib,json,struct,subprocess,sys,tempfile,zlib
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--root',type=Path,required=True);a=p.parse_args()
source=a.root/'tests/fixtures/generated/inherited-use/local-target.dex';parent=a.root/'tests/fixtures/generated/inherited/root.dex'
original=a.root/'tests/fixtures/generated/use_relations/two-invokes.dex';generator=a.root/'tests/fixtures/generators/generate_inherited_use.py'
data=source.read_bytes();assert hashlib.sha256(data).hexdigest()=='ef33098510d9768bd17f2ace28d77138235b499d1f5f84907f814c1a6fe0d7fb'
assert data[12:32]==hashlib.sha1(data[32:]).digest() and struct.unpack_from('<I',data,8)[0]==zlib.adler32(data[12:])&0xffffffff
for pc in (0,3):
 assert struct.unpack_from('<H',data,416+16+pc*2)[0]&255==0x71
 assert struct.unpack_from('<H',data,416+16+(pc+1)*2)[0]==3
slot0=f'input:0:{source}';slot1=f'input:1:{parent}'
inherited={'declares_fields':{'scope':'inherited','where':{'name':'unseen'},'min':0,'max':0}}
def scan(relation,scope,where=None):
 result={'op':'scan','relation':relation,'scope':{'slots':scope}}
 if where is not None:result['where']=where
 return result
use=scan('invoke_sites',[slot0]);method=scan('method_defs',[slot0,slot1],{'all':[{'name':'uses'},inherited]})
ref=scan('method_refs',[slot0,slot1],{'all':[{'name':'uses'},inherited]})
def join(left,right,key):return {'op':'join','on':key,'left':left,'right':right}
with tempfile.TemporaryDirectory(prefix='dmg-inherited-use-') as temp:
 rebuilt=Path(temp)/'rebuilt.dex';r=subprocess.run([sys.executable,str(generator),'--input',str(original),'--output',str(rebuilt)],capture_output=True,text=True,timeout=30)
 assert r.returncode==0 and rebuilt.read_bytes()==data
 def run(name,relation):
  q={'schema_version':1,'relation':relation,'intent':'enumerate'};path=Path(temp)/(name+'.json');path.write_text(json.dumps(q),encoding='utf-8')
  proc=subprocess.run([str(a.exe),'query',str(source),'--source',str(parent),'--query',str(path),'--json'],capture_output=True,text=True,encoding='utf-8',timeout=30)
  assert proc.returncode==0,(name,proc.returncode,proc.stderr,proc.stdout);return json.loads(proc.stdout)
 def verify(value,root_kind):
  assert value['profile']=='dex-query-inherited-v6' and value['query_id'].startswith('query:v6:')
  assert value['coverage']=='Complete' and value['execution_status']=='Complete' and len(value['candidates'])==2
  pcs=[]
  for row in value['candidates']:
   assert row['source_index']==0 and row['source_sha256']==hashlib.sha256(data).hexdigest()
   if root_kind=='use':pcs.append(row['dex_pc'])
   proofs=[w for w in row['evidence'] if w['kind']=='inherited'];assert proofs
   paths=[w['inherited'] for w in proofs if w['inherited']['item']==1]
   assert [(x['source_index'],x['local_index']) for x in paths]==[(0,0),(1,0)]
   assert all(w['matched'] is True and w['operator_node'] is not None for w in proofs)
   links=row['links'];assert len(links)==1 and links[0]['key'] in ('caller','target_ref')
  if root_kind=='use':assert pcs==[0,3]
 for name,expr,root_kind in [('method-caller',join(method,use,'caller'),'method'),('use-caller',join(use,method,'caller'),'use'),('target-ref',join(use,ref,'target_ref'),'use')]:verify(run(name,expr),root_kind)
 restricted=scan('method_refs',[slot0],{'all':[{'name':'uses'},inherited]})
 partial=run('isolated-target',join(use,restricted,'target_ref'))
 assert partial['coverage']=='Partial' and partial['unknown_rows']==2 and not partial['candidates']
print('PASS v6 inherited with v4 caller/target_ref, typed use identities and source-scope isolation')
