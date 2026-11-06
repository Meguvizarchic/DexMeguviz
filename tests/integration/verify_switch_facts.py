"""Independently decode fixed switch operands and compare native observations."""
import argparse,hashlib,json,struct,subprocess,sys,tempfile,zlib
from pathlib import Path
EXPECTED='c99e0594c79d5309533b4071286d6cf4b8a6a9edd01c70376546ff04a7ec3d38'
def leb(data,pos):
 value=0
 for shift in range(0,35,7):
  byte=data[pos];pos+=1;value|=(byte&127)<<shift
  if byte<128:return value,pos
 raise ValueError('invalid leb')
def main():
 if not __debug__:raise RuntimeError('switch oracle requires assertions enabled')
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--exe',type=Path,required=True);a=p.parse_args()
 folder=a.root/'tests/fixtures/generated/switch-facts';file=folder/'switch-facts.dex';b=file.read_bytes()
 assert hashlib.sha256(b).hexdigest()==EXPECTED and b[:8]==b'dex\n035\0'
 u16=lambda at:struct.unpack_from('<H',b,at)[0]
 u32=lambda at:struct.unpack_from('<I',b,at)[0]
 assert u32(32)==len(b) and b[12:32]==hashlib.sha1(b[32:]).digest() and u32(8)==zlib.adler32(b[12:])&0xffffffff
 class_data=u32(u32(100)+24);c=class_data;counts=[]
 for _ in range(4): v,c=leb(b,c);counts.append(v)
 assert counts==[0,0,1,0]
 method,c=leb(b,c);flags,c=leb(b,c);code,c=leb(b,c)
 assert (method,flags,code)==(0,9,244) and u32(code+12)==26
 base=code+16;rows=[]
 for pc,expected_kind in ((0,0x2b),(3,0x2c)):
  assert u16(base+pc*2)==expected_kind
  payload=pc+struct.unpack_from('<i',b,base+(pc+1)*2)[0]
  assert payload%2==0 and u16(base+payload*2)==(0x0100 if pc==0 else 0x0200)
  count=u16(base+(payload+1)*2)
  for i in range(count):
   key=(struct.unpack_from('<i',b,base+(payload+2)*2)[0]+i if pc==0 else struct.unpack_from('<i',b,base+(payload+2+i*2)*2)[0])
   target_base=payload+(4 if pc==0 else 2+count*2)
   target=pc+struct.unpack_from('<i',b,base+(target_base+i*2)*2)[0]
   assert u16(base+target*2)==0x000e
   rows.append([pc,payload,key,target])
 fixed=json.loads((folder/'expected.json').read_text(encoding='utf-8'));assert fixed['sha256']==EXPECTED and fixed['cases']==rows
 result=subprocess.run([str(a.exe),str(file)],capture_output=True,text=True,encoding='utf-8',timeout=90,check=True)
 actual=[[int(v) for v in line.split()[1:]] for line in result.stdout.splitlines() if line.startswith('CASE ')]
 assert actual==rows and 'PASS checked switch cases' in result.stdout
 with tempfile.TemporaryDirectory(prefix='dmg-switch-facts-') as temp:
  out=Path(temp)/'rebuilt';subprocess.run([sys.executable,'-B',str(a.root/'tests/fixtures/generators/switch_facts.py'),'--output',str(out)],check=True,timeout=30)
  assert (out/file.name).read_bytes()==b and json.loads((out/'expected.json').read_text(encoding='utf-8'))==fixed
 print('PASS independent DEX bytes and native switch evidence')
if __name__=='__main__':main()
