"""Fixed byte and CLI controls for explicit v15; no ART or loader equivalence."""
import argparse,hashlib,json,struct,subprocess,tempfile,zlib
from pathlib import Path

if not __debug__:raise SystemExit('v15 test requires assertions enabled')

p=argparse.ArgumentParser();p.add_argument('--exe',required=True,type=Path);p.add_argument('--fixture',required=True,type=Path);p.add_argument('--consumer',required=True,type=Path);a=p.parse_args()
exe=a.exe.resolve();data=a.fixture.read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(data)=='8262d2b338e54a7965111b4cec1ef9e628ada9795ad2f6a555d717a2ba9546bc'
u16=lambda at:struct.unpack_from('<H',data,at)[0]
u32=lambda at:struct.unpack_from('<I',data,at)[0]
assert data[:8]==b'dex\n035\0' and data[12:32]==hashlib.sha1(data[32:]).digest() and u32(8)==zlib.adler32(data[12:])&0xffffffff
def leb(pos):
 value=0
 for i in range(5):
  b=data[pos+i];assert i<4 or b<=15
  value|=(b&127)<<(7*i)
  if b<128:return value,pos+i+1
 raise AssertionError('invalid leb')
strings=[]
for i in range(u32(56)):
 at=u32(u32(60)+4*i);n,pos=leb(at);end=data.index(0,pos);raw=data[pos:end];assert len(raw)==n and all(0<x<128 for x in raw);strings.append(raw.decode('ascii'))
names=[strings[u32(u32(92)+8*i+4)] for i in range(u32(88))]
assert names==['abstractMethod','nativeMethod','quiet','uses','sink']
cursor=u32(u32(100)+24);sizes=[]
for i in range(4):n,cursor=leb(cursor);sizes.append(n)
assert sizes==[1,0,3,1]
for i in range(sum(sizes[:2])):
 _,cursor=leb(cursor);_,cursor=leb(cursor)
methods=[];idx=0;flag_offset=None
for i in range(sizes[2]):
 delta,cursor=leb(cursor);idx+=delta;at=cursor;flags,cursor=leb(cursor);code,cursor=leb(cursor)
 methods.append((names[idx],flags,code))
 if names[idx]=='uses':flag_offset=at
assert methods==[('nativeMethod',0x109,0),('quiet',9,396),('uses',9,416)] and flag_offset is not None
assert list(struct.unpack_from('<8H',data,432))==[0x001a,strings.index('used-string'),0x0071,4,0,0x0060,0,0x000e]
root=Path(tempfile.mkdtemp(prefix='dmg-reflection-method-uses-v15-'))
def variant(name,changes):
 b=bytearray(data)
 for at,value in changes:b[at]=value
 b[12:32]=hashlib.sha1(b[32:]).digest();struct.pack_into('<I',b,8,zlib.adler32(b[12:])&0xffffffff)
 path=root/(name+'.dex');path.write_bytes(b);return path
original=root/'original.dex';original.write_bytes(data)
unknown=variant('unknown',[(flag_offset,0x0b)]) # conflicting public/private visibility
broken=variant('bad-body',[(432,0x3e)]) # unsupported instruction after otherwise valid metadata
job=subprocess.run([str(a.consumer.resolve()),str(unknown),'unknown'],capture_output=True,timeout=30)
(root/'c-unknown.stdout.log').write_bytes(job.stdout);(root/'c-unknown.stderr.log').write_bytes(job.stderr)
assert job.returncode==0 and b'PASS v15 C ABI sync and Job terminal status' in job.stdout,(job.returncode,job.stdout,job.stderr)
flag={'flags':{'domain':'reflection','mode':'contains','value':8}}
uses={'using_strings':{'all':[{'op':'exact','value':'used-string'}]}}
missing={'using_strings':{'all':[{'op':'exact','value':'not-in-pool'}]}}
inv={'invokes':{'all':[{'name':'sink','param_count':0}]}}
field={'field_access':{'all':[{'name':'counter','access':'read'}]}}
caps=['reflection_flags_static','reflection_method_uses']
base={'schema_version':1,'relation':'method_defs','where':{'all':[{'name':'uses'},flag,uses]},'intent':'enumerate','max_results':100,'required_capabilities':caps}
records=[]
def call(name,query,source=original,expected=0,extra=()):
 path=root/(name+'.query.json');path.write_text(json.dumps(query,ensure_ascii=True),encoding='utf-8')
 cmd=[str(exe),'query',str(source),'--query',str(path),'--json',*extra]
 r=subprocess.run(cmd,capture_output=True,timeout=30);(root/(name+'.stdout.json')).write_bytes(r.stdout);(root/(name+'.stderr.log')).write_bytes(r.stderr)
 assert r.returncode==expected,(name,r.returncode,r.stdout,r.stderr)
 v=json.loads(r.stdout);records.append(name);return v
def q(where,**kw):return {**base,'where':where,**kw}
def where(*values):return {'all':[{'name':'uses'},*values]}
ok=call('all-three',q(where(flag,uses,inv,field)))
assert ok['profile']=='dex-query-reflection-method-uses-v15' and ok['query_id'].startswith('query:v15:') and ok['coverage']=='Complete' and [x['name'] for x in ok['candidates']]==['uses']
evidence=ok['candidates'][0]['evidence'];assert {x['kind'] for x in evidence}>={'string_use','invoke','field_use'}
assert {(x['kind'],x['dex_pc']) for x in evidence if x['kind'] in ('string_use','invoke','field_use')}=={('string_use',0),('invoke',2),('field_use',5)}
op=call('reordered',q(where(field,inv,uses,flag)));assert op['query_id']==ok['query_id']
for name,body in [('string',uses),('invoke',inv),('field',field)]:
 v=call(name,q(where(flag,body)));assert [x['name'] for x in v['candidates']]==['uses'] and v['coverage']=='Complete'
v=call('unknown-true',q(where(flag,uses),intent='unique'),unknown)
assert (v['coverage'],v['decision'],v['reason'],v['query_profile']['unknown_rows'])==('Partial','Undetermined','UnknownAttribute',1)
v=call('unknown-false',q(where(flag,missing),intent='unique'),unknown)
assert (v['coverage'],v['decision'],v['query_profile']['unknown_rows'])==('Complete','ProvenFalse',0)
v=call('unknown-or-true',q(where({'any':[flag,uses]})),unknown)
assert v['coverage']=='Complete' and [x['name'] for x in v['candidates']]==['uses']
v=call('unknown-not',q(where({'not':flag},uses),intent='unique'),unknown)
assert v['coverage']=='Partial' and v['query_profile']['unknown_rows']==1 and v['decision']=='Undetermined'
v=call('short-circuit',q(where({'flags':{'domain':'reflection','value':2}},uses),intent='unique'),broken)
assert v['execution_status']=='Complete' and v['decision']=='ProvenFalse' and not v['candidates']
bad=[('missing-new',q(where(flag,uses),required_capabilities=['reflection_flags_static'])),
 ('missing-reflection',q(where(flag,uses),required_capabilities=['reflection_method_uses'])),
 ('missing-body',q(where(flag))),('missing-flag',q(where(uses))),
 ('relation-object',q(where(flag,uses),relation={'op':'scan','relation':'method_defs'})),
 ('order',q(where(flag,uses),order_by=[{'field':'name'}])),
 ('graph-cap',q(where(flag,uses),required_capabilities=caps+['reflection_relational'])),
 ('advanced-cap',q(where(flag,uses),required_capabilities=caps+['numeric_literals'])),
 ('uses-cap',q(where(flag,uses),required_capabilities=caps+['use_relations'])),
 ('stream-cap',q(where(flag,uses),required_capabilities=caps+['use_streaming']))]
for name,query in bad:
 v=call(name,query,expected=2);assert v['execution_status']=='Unsupported',(name,v)
v=call('budget',q(where(flag,uses),max_work=1),expected=3);assert v['execution_status']=='BudgetExceeded'
old=call('old-v13',q(where(flag),required_capabilities=['reflection_flags_static']));assert old['query_id'].startswith('query:v13:')
old=call('old-v1',q(where(uses),required_capabilities=[]));assert old['query_id'].startswith('query:v1:')
print('PASS',len(records),'v15 cases; evidence directory:',root)
