"""Fixed DEX byte oracle for ordinary-flow CFG; not ART or path feasibility."""
import argparse,hashlib,struct,subprocess,zlib
from pathlib import Path
if not __debug__:raise SystemExit('CFG oracle requires assertions enabled')
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--exe',type=Path,required=True);a=p.parse_args()
branch=a.root/'tests/fixtures/generated/branch-facts/branch-facts.dex';switch=a.root/'tests/fixtures/generated/switch-facts/switch-facts.dex'
def image(path,expected):
 b=path.read_bytes();assert hashlib.sha256(b).hexdigest()==expected and b[:8]==b'dex\n035\0'
 assert struct.unpack_from('<I',b,32)[0]==len(b) and b[12:32]==hashlib.sha1(b[32:]).digest() and struct.unpack_from('<I',b,8)[0]==zlib.adler32(b[12:])&0xffffffff
 return b
b=image(branch,'87c9340db46e00cad9573951d6e39ccdb1514993adc6d10626e22890e41f5cf1')
s=image(switch,'c99e0594c79d5309533b4071286d6cf4b8a6a9edd01c70376546ff04a7ec3d38')
base=244+16;u16=lambda data,pc:struct.unpack_from('<H',data,base+2*pc)[0]
expected_branch=[(0,2,0x28),(2,5,0x29),(5,9,0x2a),(9,12,0x32),(12,9,0x38),(14,14,0x2a),(17,14,0x3b)]
for pc,dest,op in expected_branch:
 word=u16(b,pc);assert word&255==op
 if op==0x28:off=struct.unpack('b',bytes([word>>8]))[0]
 elif op==0x29 or 0x32<=op<=0x3d:off=struct.unpack_from('<h',b,base+2*(pc+1))[0]
 else:off=struct.unpack_from('<i',b,base+2*(pc+1))[0]
 assert pc+off==dest
assert u16(s,0)&255==0x2b and u16(s,3)&255==0x2c
assert 0+struct.unpack_from('<i',s,base+2)[0]==8 and 3+struct.unpack_from('<i',s,base+8)[0]==16
assert [struct.unpack_from('<i',s,base+2*x)[0] for x in (10,12,14)]==[-1,6,6]
assert [struct.unpack_from('<i',s,base+2*x)[0] for x in (18,20,22,24)]==[-2147483648,2147483647,3,3]
r=subprocess.run([str(a.exe),str(branch),str(switch)],capture_output=True,text=True,encoding='utf-8',timeout=90,check=True)
assert 'PASS bounded CFG' in r.stdout
graphs={};blocks={'branch':[],'switch':[]};edges={'branch':[],'switch':[]}
for line in r.stdout.splitlines():
 v=line.split()
 if not v:continue
 if v[0]=='GRAPH':graphs[v[1]]=(int(v[2]),int(v[3]))
 if v[0]=='BLOCK':blocks[v[1]].append((int(v[2]),int(v[3]),int(v[4]),v[5],int(v[6])))
 if v[0]=='EDGE':edges[v[1]].append((int(v[2]),int(v[3]),v[4],int(v[5]),int(v[6]),int(v[7])))
assert graphs=={'branch':(26,1),'switch':(26,1)}
assert blocks['branch']==[(0,1,0,'jump',1),(1,2,1,'return',0),(2,4,2,'jump',1),(4,5,4,'return',0),(5,8,5,'jump',1),(8,9,8,'return',0),(9,11,9,'conditional',1),(11,12,11,'return',1),(12,14,12,'conditional',1),(14,17,14,'jump',1),(17,19,17,'conditional',0)]+[(pc,pc+1,pc,'return',0) for pc in range(19,26)]
assert edges['branch']==[(0,2,'branch',0,0,-1),(2,5,'branch',0,0,-1),(5,9,'branch',0,0,-1),(9,12,'taken',0,0,-1),(9,11,'not_taken',0,0,-1),(12,9,'taken',0,0,-1),(12,14,'not_taken',0,0,-1),(14,14,'branch',0,0,-1),(17,14,'taken',0,0,-1),(17,19,'not_taken',0,0,-1)]
assert blocks['switch']==[(0,3,0,'switch',1),(3,6,3,'switch',1),(6,7,6,'return',1),(7,8,7,'ordinary',0)]
assert edges['switch']==[(0,6,'case',-1,0,8),(0,6,'case',0,1,8),(0,3,'default',0,0,-1),(3,6,'case',-2147483648,0,16),(3,6,'case',2147483647,1,16),(3,6,'default',0,0,-1),(7,-1,'payload',0,0,-1)]
print('PASS independent DEX branch, payload and CFG structural graph oracle')
