"""Independently decode branch bytes and compare fixed native observations."""
import argparse,hashlib,json,struct,subprocess,sys,tempfile,zlib
from pathlib import Path
EXPECTED='87c9340db46e00cad9573951d6e39ccdb1514993adc6d10626e22890e41f5cf1'
def leb(data,pos):
 value=0
 for shift in range(0,35,7):
  b=data[pos];pos+=1;value|=(b&127)<<shift
  if b<128:return value,pos
 raise ValueError('invalid leb')
def main():
 if not __debug__:raise RuntimeError('branch oracle requires assertions enabled')
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--exe',type=Path,required=True);a=p.parse_args()
 folder=a.root/'tests/fixtures/generated/branch-facts';file=folder/'branch-facts.dex';b=file.read_bytes()
 assert hashlib.sha256(b).hexdigest()==EXPECTED and b[:8]==b'dex\n035\0'
 u16=lambda at:struct.unpack_from('<H',b,at)[0];u32=lambda at:struct.unpack_from('<I',b,at)[0]
 assert u32(32)==len(b) and b[12:32]==hashlib.sha1(b[32:]).digest() and u32(8)==zlib.adler32(b[12:])&0xffffffff
 c=u32(u32(100)+24);counts=[]
 for _ in range(4):v,c=leb(b,c);counts.append(v)
 assert counts==[0,0,1,0]
 method,c=leb(b,c);flags,c=leb(b,c);code,c=leb(b,c)
 assert (method,flags,code)==(0,9,244) and u32(code+12)==26
 base=code+16; rows=[]
 for pc in (0,2,5,9,12,14,17):
  word=u16(base+2*pc);op=word&255
  if op==0x28:offset=struct.unpack('b',bytes([word>>8]))[0]
  elif op==0x29 or 0x32<=op<=0x3d:offset=struct.unpack_from('<h',b,base+2*(pc+1))[0]
  else:assert op==0x2a;offset=struct.unpack_from('<i',b,base+2*(pc+1))[0]
  target=pc+offset;assert 0<=target<26
  rows.append([pc,target,op,'conditional' if op>=0x32 else 'unconditional'])
 fixed=json.loads((folder/'expected.json').read_text(encoding='utf-8'));assert fixed['sha256']==EXPECTED and fixed['cases']==rows
 r=subprocess.run([str(a.exe),str(file)],capture_output=True,text=True,encoding='utf-8',timeout=90,check=True)
 actual=[]
 for line in r.stdout.splitlines():
  if line.startswith('BRANCH '):
   _,pc,target,op,kind=line.split();actual.append([int(pc),int(target),int(op),kind])
 assert actual==rows and 'PASS checked branch facts' in r.stdout
 with tempfile.TemporaryDirectory(prefix='dmg-branch-facts-') as temp:
  out=Path(temp)/'rebuilt';subprocess.run([sys.executable,'-B',str(a.root/'tests/fixtures/generators/branch_facts.py'),'--output',str(out)],check=True,timeout=30)
  assert (out/file.name).read_bytes()==b and json.loads((out/'expected.json').read_text(encoding='utf-8'))==fixed
 print('PASS independent DEX bytes and native branch evidence')
if __name__=='__main__':main()
