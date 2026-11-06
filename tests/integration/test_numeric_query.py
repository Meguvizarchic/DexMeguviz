"""Independent fixed-byte oracle for the numeric v7 query slice."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess,tempfile,zlib

p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--root',type=Path,required=True);a=p.parse_args()
b=a.fixture.read_bytes();assert hashlib.sha256(b).hexdigest()=='45493d9c18a659507a1929467be3420bba23e408f906641d253da59d73c92699'
assert b[12:32]==hashlib.sha1(b[32:]).digest() and struct.unpack_from('<I',b,8)[0]==zlib.adler32(b[12:])&0xffffffff
expected=json.loads((a.root/'tests/fixtures/generated/method_facts/expected.json').read_text(encoding='utf-8'))
off=expected['uses']['code_offset'];assert struct.unpack_from('<8H',b,off+16)==(0xf012,0x0016,0xfffe,0x0015,0x8000,0x001a,10,0x000e)
def uleb(pos):
 value=0
 for shift in range(0,35,7):
  part=b[pos];pos+=1;value|=(part&127)<<shift
  if part<128:return value,pos
 raise AssertionError('invalid ULEB')
u32=lambda pos:struct.unpack_from('<I',b,pos)[0]
method_ordinals=[]
for c in range(u32(96)):
 pos=u32(u32(100)+32*c+24)
 if not pos:continue
 counts=[]
 for _ in range(4):n,pos=uleb(pos);counts.append(n)
 for count in counts[:2]:
  for _ in range(count):_,pos=uleb(pos);_,pos=uleb(pos)
 for count in counts[2:]:
  method_index=0
  for _ in range(count):
   delta,pos=uleb(pos);method_index+=delta;_,pos=uleb(pos);code,pos=uleb(pos);method_ordinals.append((method_index,code))
assert len(method_ordinals)==4
uses_ordinal=method_ordinals.index((expected['uses']['method_index'],off))
words=struct.unpack_from('<8H',b,off+16)
def literal_at(pc):
 if pc not in (0,1,3):raise AssertionError('not an authored literal boundary')
 word=words[pc];op=word&255
 if op==0x12:
  value=(word>>12)&15;value=value-16 if value&8 else value
  return op,32,f'{value&0xffffffff:08x}','constant'
 if op==0x16:
  value=words[pc+1];value=value-65536 if value&0x8000 else value
  return op,64,f'{value&0xffffffffffffffff:016x}','constant'
 if op==0x15:return op,32,f'{words[pc+1]<<16:08x}','constant'
 raise AssertionError('unexpected opcode')
def verify_witness(w):
 op,width,bits,kind=literal_at(w['dex_pc'])
 assert (w['opcode'],w['width_bits'],w['bits'],w['literal_kind'])==(op,width,bits,kind)
 assert w['matched'] and w['entity']=={'relation':'method_defs','source_index':0,'local_index':uses_ordinal}

with tempfile.TemporaryDirectory(prefix='dmg-numeric-query-') as tmp:
 def run(name,where,*,relation='method_defs',code=0,extra=None,extra_args=()):
  q={'schema_version':1,'relation':relation,'where':where,'intent':'enumerate'}
  if extra:q.update(extra)
  path=Path(tmp)/(name+'.json');path.write_text(json.dumps(q),encoding='utf-8')
  r=subprocess.run([str(a.exe),'query',str(a.fixture),'--query',str(path),'--json',*map(str,extra_args)],capture_output=True,timeout=30)
  assert r.returncode==code,(name,r.returncode,r.stdout,r.stderr)
  return json.loads(r.stdout)
 def number(width,bits,kind):return {'numeric_bits':{'width':width,'bits':bits,'kind':kind}}
 def check(result,pc,width,bits,kind):
  assert result['profile']=='dex-query-numeric-v7' and result['query_id'].startswith('query:v7:')
  assert result['execution_status']=='Complete' and result['coverage']=='Complete' and len(result['candidates'])==1
  row=result['candidates'][0];assert row['name']=='uses' and row['source_index']==0
  witnesses=[x for x in row['evidence'] if x['kind']=='numeric_literal'];assert len(witnesses)==1
  w=witnesses[0];assert (w['dex_pc'],w['width_bits'],w['bits'],w['literal_kind'])==(pc,width,bits,kind)
  verify_witness(w)
  for key,bad in [('bits','0'*len(bits)),('width_bits',64 if width==32 else 32),('dex_pc',2),('opcode',255),('entity',{'relation':'method_defs','source_index':1,'local_index':uses_ordinal})]:
   fake=dict(w);fake[key]=bad
   try:verify_witness(fake)
   except AssertionError:pass
   else:raise AssertionError('forged numeric witness accepted: '+key)
 def where(width,bits,kind):return {'all':[{'name':'uses'},number(width,bits,kind)]}
 v=run('32',where(32,'ffffffff','constant'));check(v,0,32,'ffffffff','constant')
 upper=run('32-upper',where(32,'FFFFFFFF','constant'));assert upper['query_id']==v['query_id']
 check(run('64',where(64,'fffffffffffffffe','either')),1,64,'fffffffffffffffe','constant')
 check(run('high16',where(32,'80000000','constant')),3,32,'80000000','constant')
 first=number(32,'ffffffff','constant');second=number(64,'fffffffffffffffe','constant')
 two=run('canonical-two',{'all':[first,second,{'name':'uses'}]});swapped=run('canonical-swapped',{'all':[{'name':'uses'},second,first]})
 assert two['query_id']==swapped['query_id'] and two['query_id']!=v['query_id'] and len(two['candidates'])==1
 assert len([x for x in two['candidates'][0]['evidence'] if x['kind']=='numeric_literal'])==2
 for name,w in [('width',where(64,'00000000ffffffff','constant')),('kind',where(32,'ffffffff','arithmetic_operand')),('not',{'all':[{'name':'uses'},{'not':number(32,'ffffffff','constant')}]})]:
  r=run('absent-'+name,w);assert r['candidates']==[] and r['coverage']=='Complete'
 rel={'op':'scan','relation':'method_defs','where':where(64,'fffffffffffffffe','constant')}
 r=run('relation',True,relation=rel);check(r,1,64,'fffffffffffffffe','constant')
 mixed={'op':'join','on':'caller','left':rel,'right':{'op':'scan','relation':'string_uses'}}
 r=run('numeric-use-join',True,relation=mixed);check(r,1,64,'fffffffffffffffe','constant')
 assert any(x['kind']=='string_use' for x in r['candidates'][0]['evidence'])
 same_method=run('mixed-demand',{'all':[where(32,'ffffffff','constant'),{'using_strings':{'all':['used-string']}}]})
 check(same_method,0,32,'ffffffff','constant');assert same_method['query']['demand_mask']==9 and same_method['query_profile']['methods_decoded']==1
 short_circuit=run('short-circuit',{'all':[{'name':'not-present'},number(32,'ffffffff','constant')]})
 assert short_circuit['candidates']==[] and short_circuit['query_profile']['methods_decoded']==0
 partial=run('incomplete-unique',where(32,'ffffffff','constant'),extra={'intent':'unique'},extra_args=['--scope-incomplete'])
 assert partial['coverage']=='Partial' and partial['decision']=='Undetermined' and len(partial['candidates'])==1
 repeated=run('repeated-source',where(32,'ffffffff','constant'),extra_args=['--source',a.fixture])
 assert len(repeated['candidates'])==2 and repeated['candidates'][0]['occurrence_id']!=repeated['candidates'][1]['occurrence_id']
 for source,row in enumerate(repeated['candidates']):
  witness=next(x for x in row['evidence'] if x['kind']=='numeric_literal');assert row['source_index']==source and witness['entity']['source_index']==source
 no_body=run('no-body',{'not':number(32,'ffffffff','constant')})
 assert {x['name'] for x in no_body['candidates']}=={'abstractMethod','nativeMethod','quiet'}
 for row in no_body['candidates']:
  if row['name']!='quiet':assert any(x['kind']=='no_body' and x['matched'] is False for x in row['evidence'])
 for name,w in [('short',number(32,'ffff','constant')),('prefix',number(32,'0xffffffff','constant')),('bad-width',number(16,'ffff','constant')),('bad-kind',number(32,'ffffffff','unknown'))]:run('invalid-'+name,w,code=2)
 wrong_relation=run('wrong-relation',number(32,'ffffffff','constant'),relation='field_refs',code=2)
 limit=run('budget',where(32,'ffffffff','constant'),code=3,extra={'max_work':1});assert limit['execution_status']=='BudgetExceeded'
 explicit=run('capability',{'name':'uses'},extra={'required_capabilities':['numeric_literals']});assert explicit['query_id'].startswith('query:v7:') and explicit['query']['demand_mask']==0
 old=run('old',{'name':'uses'});assert old['profile']=='dex-query-method-v1' and old['query_id']=='query:v1:21162950c31e9ed71e2a6695975b41f8a952f73a1f68c2154dad0d44e93253d7'
 assert old['query_profile']['methods_decoded']==0
 old_v2=run('old-v2',True,relation='field_refs');assert old_v2['query_id']=='query:v2:00343cb03929a3c9fa8419f18b2935e00839b43d0a1aff5a855c77f5c1ce5fa1'
 old_v3=run('old-v3',True,relation={'op':'scan','relation':'method_defs','where':{'name':'uses'}});assert old_v3['query_id']=='query:v3:0edd37816e5d38c403cdaa3b53984fcc48f7b5c0274532e52b26f9ee2985ffe6'
 old_use=run('old-use',True,relation={'op':'scan','relation':'string_uses'});assert old_use['query_id']=='query:v4:79778a74d977783706c17d78bbf8658fcb118e606d4b7f6ce239da1598bafda6'
 print('PASS numeric v7: independent raw bytes and forged witness rejection, canonical case, wrong width/kind, no-body, budget, relation/use join and fixed v1-v4 IDs')
