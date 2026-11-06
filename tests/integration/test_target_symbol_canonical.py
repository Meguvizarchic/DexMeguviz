"""Independent manual canonical bytes for the fixed v16 target-symbol join."""
from pathlib import Path
import argparse,copy,hashlib,json,struct,subprocess

def main():
 a=argparse.ArgumentParser();a.add_argument('--exe',type=Path,required=True);a.add_argument('--fixture',type=Path,required=True);a.add_argument('--out',type=Path,required=True);x=a.parse_args();x.out.mkdir(parents=True,exist_ok=False)
 u32=lambda n:struct.pack('<I',n);u64=lambda n:struct.pack('<Q',n);frame=lambda b:u64(len(b))+b
 predicate=b''.join(map(u32,(0,0,0,0,0xffffffff,0)))
 def scan(kind):return b''.join(map(u32,(0,kind,1)))+frame(predicate)+b''.join(map(u32,(0,1,0xffffffff,1,0,0,0,0,0,0)))
 relation=b''.join(map(u32,(6,8,0,0,1,0xffffffff,1,0,0,0,6,0,0,2)))+frame(scan(8))+frame(scan(0))
 top=b''.join(map(u32,(8,0,100)))+u64(100000000)+b''.join(map(u32,(7,1,0,16783939,0,100000,0,0)))
 canonical=b'DexMeguviz:QueryIR:use-target-symbol-v16'+top+relation;fixed='0aee5b0afac2e06ce0c7de2596dc52ecad4dcc1a84502d1ab9bb387abd73494e'
 assert len(canonical)==332 and hashlib.sha256(canonical).hexdigest()==fixed;(x.out/'canonical.bin').write_bytes(canonical)
 q={'schema_version':1,'required_capabilities':['use_target_symbol'],'relation':{'op':'join','on':'target_symbol','left':{'op':'scan','relation':'invoke_sites'},'right':{'op':'scan','relation':'method_defs'}},'max_results':100};records=[]
 def run(name,query):
  p=x.out/(name+'.query.json');p.write_text(json.dumps(query),encoding='utf-8');r=subprocess.run([str(x.exe),'query',str(x.fixture),'--query',str(p),'--json'],capture_output=True,timeout=60);(x.out/(name+'.stdout.json')).write_bytes(r.stdout);(x.out/(name+'.stderr.log')).write_bytes(r.stderr);assert r.returncode==0,(name,r.stderr);v=json.loads(r.stdout);records.append({'name':name,'query_id':v['query_id']});return v['query_id']
 base=run('base',q);assert base=='query:v16:'+fixed
 order={'max_results':100,'relation':q['relation'],'required_capabilities':['use_target_symbol'],'schema_version':1};assert run('field-order',order)==base
 swapped=copy.deepcopy(q);swapped['relation']['left'],swapped['relation']['right']=swapped['relation']['right'],swapped['relation']['left'];assert run('swapped-inputs',swapped)!=base
 limit=copy.deepcopy(q);limit['max_results']=101;assert run('different-limit',limit)!=base
 semi=copy.deepcopy(q);semi['relation']['op']='semi_join';assert run('different-operator',semi)!=base
 (x.out/'summary.json').write_text(json.dumps({'passed':len(records),'canonical_bytes':len(canonical),'canonical_sha256':fixed,'records':records,'scope':'one explicitly encoded target-symbol shape and three identity mutations'},indent=2)+'\n',encoding='utf-8');print(json.dumps({'passed':len(records)}))
if __name__=='__main__':main()
