"""Raw DEX oracle and CLI differential for the opt-in use-stream-v9 profile."""
import argparse,hashlib,json,struct,subprocess,sys,tempfile,zlib
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--root',type=Path,required=True);a=p.parse_args()
fixtures=a.root/'tests/fixtures/generated/use-stream-v9';manifest=json.loads((fixtures/'manifest.json').read_text(encoding='utf-8'))
def u32(b,p):return struct.unpack_from('<I',b,p)[0]
def leb(b,p):
 value=0
 for i in range(5):
  x=b[p];p+=1;value|=(x&127)<<(7*i)
  if x<128:return value,p
 raise ValueError('invalid ULEB')
def raw_methods(b):
 strings=[]
 for i in range(u32(b,56)):
  size,at=leb(b,u32(b,u32(b,60)+4*i));end=b.index(0,at);v=b[at:end];assert len(v)==size;strings.append(v.decode('ascii'))
 method_names=[strings[u32(b,u32(b,92)+8*i+4)] for i in range(u32(b,88))]
 class_at=u32(b,100);cursor=u32(b,class_at+24);counts=[]
 for _ in range(4):n,cursor=leb(b,cursor);counts.append(n)
 for n in counts[:2]:
  for _ in range(n):_,cursor=leb(b,cursor);_,cursor=leb(b,cursor)
 result=[]
 for n in counts[2:]:
  ref=0
  for _ in range(n):
   delta,cursor=leb(b,cursor);ref+=delta;_,cursor=leb(b,cursor);code,cursor=leb(b,cursor)
   result.append((len(result),ref,method_names[ref],code))
 return result
for item in manifest['files']:
 b=(fixtures/item['path']).read_bytes();assert hashlib.sha256(b).hexdigest()==item['sha256'];assert b[:8]==b'dex\n035\0' and u32(b,32)==len(b)
 assert b[12:32]==hashlib.sha1(b[32:]).digest() and u32(b,8)==zlib.adler32(b[12:])&0xffffffff
 defs=raw_methods(b);assert defs[1:3]==[(1,2,'quiet',396),(2,3,'uses',420)]
 assert struct.unpack_from('<4H',b,396+16)==(0x71,4,0,0x0e)
 words=struct.unpack_from('<8H',b,420+16);assert words[:5]==(0x1a,10,0x71,4,0) and words[5]==(0x73 if item['corrupt'] else 0x60)
with tempfile.TemporaryDirectory(prefix='dmg-use-v9-') as temp:
 tmp=Path(temp);rebuilt=tmp/'rebuilt';gen=a.root/'tests/fixtures/generators/use_stream_v9.py';source=a.root/'tests/fixtures/generated/method_facts/method-uses.dex';expected=source.parent/'expected.json'
 run=subprocess.run([sys.executable,str(gen),'--source',str(source),'--expected',str(expected),'--output',str(rebuilt)],capture_output=True,timeout=30);assert run.returncode==0,run.stderr
 for item in manifest['files']:
  assert (rebuilt/item['path']).read_bytes()==(fixtures/item['path']).read_bytes()
 assert (rebuilt/'manifest.json').read_bytes()==(fixtures/'manifest.json').read_bytes()
 def query(label,stream,fixture='two-methods.dex',extra=None,args=()):
  q={'schema_version':1,'relation':{'op':'scan','relation':'invoke_sites'},'intent':'unique','max_results':100}
  if stream:q['required_capabilities']=['use_streaming']
  if extra:q.update(extra)
  path=tmp/(label+'.json');path.write_text(json.dumps(q),encoding='utf-8')
  r=subprocess.run([str(a.exe),'query',str(fixtures/fixture),'--query',str(path),'--json',*args],capture_output=True,text=True,encoding='utf-8',timeout=30)
  return r.returncode,json.loads(r.stdout)
 r4,v4=query('legacy',False);r9,v9=query('stream',True);assert r4==r9==0
 assert v4['profile']=='dex-query-use-v4' and v4['query_id'].startswith('query:v4:')
 assert v9['profile']=='dex-query-use-stream-v9' and v9['query_id'].startswith('query:v9:') and v9['query_id']!=v4['query_id']
 assert v4['execution_status']==v9['execution_status']=='Complete' and v9['decision']=='ProvenFalse' and v9['reason']=='Ambiguous'
 assert v4['candidates']==v9['candidates'] and len(v9['candidates'])==2
 for row,(ordinal,pc,code) in zip(v9['candidates'],[(1,0,396),(2,2,420)]):
  assert (row['source_index'],row['caller_ordinal'],row['dex_pc'],row['opcode'],row['target_index'],row['code_offset'])==(0,ordinal,pc,0x71,4,code)
  assert any(w['kind']=='invoke' and w['dex_pc']==pc and w['reference_index']==4 for w in row['evidence'])
 rc,broken=query('corrupt',True,'later-corrupt.dex');assert rc==2 and broken['execution_status']=='CorruptInput' and broken['candidates']==[]
 rc,incomplete=query('partial',True,args=('--scope-incomplete',));assert rc==0 and incomplete['coverage']=='Partial' and incomplete['reason']=='Ambiguous'
print('PASS independent v9 raw bytecode and fixture regeneration, v4/v9 complete results, corruption and scope')
