"""Generate the fixed reflection-Unknown variant of the method-facts DEX."""
from pathlib import Path
import hashlib,struct,sys,zlib
if not __debug__:raise SystemExit('assertions required')
root=Path(__file__).resolve().parents[3];src=root/'tests/fixtures/generated/method_facts/method-uses.dex';out=root/'tests/fixtures/generated/graph-cache/unknown.dex';data=bytearray(src.read_bytes())
assert hashlib.sha256(data).hexdigest()=='8262d2b338e54a7965111b4cec1ef9e628ada9795ad2f6a555d717a2ba9546bc'
def u32(at):return struct.unpack_from('<I',data,at)[0]
def leb(pos):
 value=0
 for i in range(5):
  b=data[pos+i];assert i<4 or b<=15;value|=(b&127)<<(7*i)
  if b<128:return value,pos+i+1
 raise ValueError('invalid ULEB')
strings=[]
for i in range(u32(56)):
 at=u32(u32(60)+4*i);n,pos=leb(at);end=data.index(0,pos);raw=data[pos:end];assert len(raw)==n and all(0<x<128 for x in raw);strings.append(raw.decode('ascii'))
names=[strings[u32(u32(92)+8*i+4)] for i in range(u32(88))];cursor=u32(u32(100)+24);sizes=[]
for i in range(4):n,cursor=leb(cursor);sizes.append(n)
assert sizes==[1,0,3,1]
for i in range(sum(sizes[:2])):_,cursor=leb(cursor);_,cursor=leb(cursor)
idx=0;flag_at=None
for i in range(sizes[2]):
 delta,cursor=leb(cursor);idx+=delta;at=cursor;flags,cursor=leb(cursor);code,cursor=leb(cursor)
 if names[idx]=='uses':assert flags==9 and code==416;flag_at=at
assert flag_at is not None;data[flag_at]=0x0b;data[12:32]=hashlib.sha1(data[32:]).digest();struct.pack_into('<I',data,8,zlib.adler32(data[12:])&0xffffffff)
assert hashlib.sha256(data).hexdigest()=='2330fc94aa2f2602536fb46e8834111f9fc930d79d8ca72042b26bd8ef0e1b2c';out.parent.mkdir(parents=True,exist_ok=True)
if out.exists():assert out.read_bytes()==data
else:out.write_bytes(data)
print('PASS graph cache Unknown fixture')
