"""Regenerate the field fixture and independently inspect field-ref order."""
import argparse,hashlib,json,struct,subprocess,sys,tempfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);a=p.parse_args();r=a.root
base=r/'tests/fixtures/generated/q09-stream';b=(base/'definitions.dex').read_bytes()
assert hashlib.sha256(b).hexdigest()=='6419a7b0b6f792efbd43fc53d8d991d7b5b2b1fad971de0f9a47509e124d9413'
u32=lambda p:struct.unpack_from('<I',b,p)[0]
strings=[]
for i in range(u32(56)):
 pos=u32(u32(60)+4*i)
 while b[pos]&128:pos+=1
 pos+=1;end=b.index(0,pos);strings.append(b[pos:end].decode('ascii'))
types=[strings[u32(u32(68)+4*i)] for i in range(u32(64))]
fields=[]
for i in range(u32(80)):
 owner,typ,name=struct.unpack_from('<HHI',b,u32(84)+8*i);fields.append((types[owner],strings[name],types[typ]))
assert fields[0]==('Lacatalog/External;','externalField','I')
assert fields[1][0]=='Lcatalog/Base;' and fields[2][0]=='Lcatalog/Base;'
def read_uleb(data,pos):
 value=0
 for i in range(5):
  x=data[pos];pos+=1;value|=(x&127)<<(7*i)
  if not (x&128):return value,pos
 raise ValueError('bad uleb')
def definitions(data):
 size,offset=struct.unpack_from('<II',data,96)
 result={};positions={}
 for ci in range(size):
  class_data=struct.unpack_from('<I',data,offset+32*ci+24)[0]
  if not class_data:continue
  counts=[];pos=class_data
  for _ in range(4):n,pos=read_uleb(data,pos);counts.append(n)
  for count in counts[:2]:
   field_index=0
   for _ in range(count):
    delta,pos=read_uleb(data,pos);field_index+=delta;flag_pos=pos;flags,pos=read_uleb(data,pos)
    assert field_index not in result
    result[field_index]=flags;positions[field_index]=flag_pos
  for count in counts[2:]:
   for _ in range(count):
    _,pos=read_uleb(data,pos);_,pos=read_uleb(data,pos);_,pos=read_uleb(data,pos)
 return result,positions
def check_definitions(data):
 found,_=definitions(data)
 assert found=={1:1,2:9,3:1}
 assert 0 not in found and all(found[i]&1 for i in (1,2))
check_definitions(b)
_,positions=definitions(b);forged=bytearray(b);forged[positions[1]]=0
try:check_definitions(forged)
except AssertionError:pass
else:raise AssertionError('forged access flags passed oracle')
expected=json.loads((base/'expected.json').read_text(encoding='utf-8'))
assert expected['external_field_ref_index']==0
with tempfile.TemporaryDirectory(prefix='dmg-q09-stream-') as tmp:
 subprocess.run([sys.executable,str(r/'tests/fixtures/generators/generate_q09_stream.py'),'--output',tmp],check=True,timeout=30)
 for f in base.iterdir():
  if f.is_file():assert (Path(tmp)/f.name).read_bytes()==f.read_bytes()
print('PASS q09 stream fixture independent field order and regeneration')
