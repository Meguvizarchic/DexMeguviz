"""Independently parse project-original DEX edge fixtures and reject forged flags."""
import argparse,hashlib,json,struct,zlib
from pathlib import Path
EXPECTED={
 'child-private.dex':('Lfixture/EdgeChild;','Lfixture/EdgeBase;',[('shared','I',2)],[]),
 'child-clear.dex':('Lfixture/EdgeChild;','Lfixture/EdgeBase;',[],[]),
 'child-interface.dex':('Lfixture/EdgeChild;','Lfixture/EdgeBase;',[],['Lfixture/EdgeInterface;']),
 'base-collision.dex':('Lfixture/EdgeBase;','Ljava/lang/Object;',[('shared','I',1),('shared','J',1)],[]),
}
def uleb(b,p):
 out=0
 for i in range(5):
  x=b[p];p+=1;out|=(x&127)<<(7*i)
  if not x&128:return out,p
 raise ValueError('uleb overflow')
def parse(b,check_integrity=True):
 assert b[:8]==b'dex\n035\0' and struct.unpack_from('<I',b,32)[0]==len(b)
 if check_integrity:
  assert b[12:32]==hashlib.sha1(b[32:]).digest() and struct.unpack_from('<I',b,8)[0]==zlib.adler32(b[12:])&0xffffffff
 u32=lambda p:struct.unpack_from('<I',b,p)[0]
 strings=[]
 for i in range(u32(56)):
  off=u32(u32(60)+4*i);n,off=uleb(b,off);end=b.index(0,off);text=b[off:end].decode('ascii');assert len(text)==n;strings.append(text)
 types=[strings[u32(u32(68)+4*i)] for i in range(u32(64))]
 refs=[]
 for i in range(u32(80)):
  owner,typ,name=struct.unpack_from('<HHI',b,u32(84)+8*i);refs.append((types[owner],types[typ],strings[name]))
 class_off=u32(100);owner,_,parent,iface,_,_,data,_=struct.unpack_from('<8I',b,class_off)
 interfaces=[] if not iface else [types[struct.unpack_from('<H',b,iface+4+2*i)[0]] for i in range(u32(iface))]
 fields=[];flag_positions=[]
 if data:
  p=data;counts=[]
  for _ in range(4):n,p=uleb(b,p);counts.append(n)
  assert counts[0]==counts[2]==counts[3]==0
  index=0
  for _ in range(counts[1]):
   d,p=uleb(b,p);index+=d;flag_positions.append(p);flag,p=uleb(b,p);declaring,typ,name=refs[index];assert declaring==types[owner];fields.append((name,typ,flag))
 return (types[owner],types[parent],fields,interfaces),flag_positions
def main():
 p=argparse.ArgumentParser();p.add_argument('fixtures',type=Path);a=p.parse_args()
 manifest=json.loads((a.fixtures/'manifest.json').read_text(encoding='utf-8'));assert set(manifest)==set(EXPECTED)
 for name,wanted in EXPECTED.items():
  raw=(a.fixtures/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==manifest[name]['sha256'];actual,positions=parse(raw);assert actual==wanted
  if positions:
   forged=bytearray(raw);forged[positions[0]]^=1;assert parse(forged,False)[0]!=wanted
 print('PASS edge byte oracle: private hiding, same-name distinct types and interface')
if __name__=='__main__':main()
