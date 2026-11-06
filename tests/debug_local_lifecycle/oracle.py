from pathlib import Path
import argparse,hashlib,importlib.util,struct,subprocess,zlib
if not __debug__:raise SystemExit('assertions required; Python optimization is unsupported')
p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--generator',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
spec=importlib.util.spec_from_file_location('fixture',a.generator);f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
original=a.fixture.read_bytes();assert hashlib.sha256(original).hexdigest()==f.SHA
stream=bytes.fromhex('01 00 03 00 01 01 04 00 00 00 01 01 01 05 00 06 00 01 01 05 00 00');image=f.build(original,[stream],None,0)
struct.pack_into('<HH',image,f.CODE_B+16,0x0013,1);struct.pack_into('<H',image,f.CODE_B+24,2);image[f.CODE_B+31]=0;image[f.CODE_B+32]=0
image[12:32]=hashlib.sha1(image[32:]).digest();struct.pack_into('<I',image,8,zlib.adler32(image[12:])&0xffffffff)
def uleb(at):
 v=0
 for n in range(5):
  byte=image[at];at+=1;v|=(byte&127)<<(7*n)
  if byte<128:return v,at
 raise ValueError('bad leb')
offset=struct.unpack_from('<I',image,f.CODE_B+8)[0];assert offset==717
line,pos=uleb(offset);params,pos=uleb(pos);assert (line,params)==(1,0)
events=[];pc=0
while True:
 at=pos;op=image[pos];pos+=1
 if op==0:break
 if op==1:advance,pos=uleb(pos);pc+=advance;continue
 assert op in (3,4,5,6);reg,pos=uleb(pos);name=typ=sig=0
 if op in (3,4):
  name,pos=uleb(pos);typ,pos=uleb(pos)
  if op==4:sig,pos=uleb(pos)
 events.append((op,pc,reg,name,typ,sig,at))
assert events==[(3,0,0,1,1,0,719),(4,0,0,0,0,1,723),(5,1,0,0,0,0,730),(6,1,0,0,0,0,732),(5,2,0,0,0,0,736)] and bytes(image[offset:pos])==stream
with a.out.open('xb') as file:file.write(image)
r=subprocess.run([str(a.exe.resolve()),str(a.out.resolve())],capture_output=True,text=True,timeout=60);assert r.returncode==0,(r.returncode,r.stdout,r.stderr)
actual=[tuple(map(int,line.split()[1:])) for line in r.stdout.splitlines() if line.startswith('transition ')]
expected=[(0,0,0,0,1,1,1,1,0,719),(1,0,0,1,1,1,0,0,1,723),(2,1,0,1,2,1,0,0,1,730),(3,1,0,2,1,1,0,0,1,732),(2,2,0,1,2,1,0,0,1,736)]
assert actual==expected,(actual,expected)
print('PASS independent byte and transition oracle',hashlib.sha256(image).hexdigest(),len(actual))
