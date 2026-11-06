"""Fixed DEX local-event stream with a separate byte-level oracle."""
import argparse, hashlib, importlib.util, struct, subprocess, tempfile, zlib
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--exe',required=True,type=Path);p.add_argument('--fixture',required=True,type=Path);p.add_argument('--generator',required=True,type=Path)
a=p.parse_args()
spec=importlib.util.spec_from_file_location('fixture',a.generator); f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
original=a.fixture.read_bytes()
if hashlib.sha256(original).hexdigest()!=f.SHA:raise RuntimeError('fixture hash differs')
stream=bytes.fromhex('01 00 03 00 01 01 04 00 00 00 01 01 01 05 00 06 00 01 01 05 00 00')
image=f.build(original,[stream],None,0)
struct.pack_into('<HH',image,f.CODE_B+16,0x0013,1)
struct.pack_into('<H',image,f.CODE_B+24,2);image[f.CODE_B+31]=0;image[f.CODE_B+32]=0
image[12:32]=hashlib.sha1(image[32:]).digest();struct.pack_into('<I',image,8,zlib.adler32(image[12:])&0xffffffff)
# Oracle independently traverses raw code/debug operands, never the C++ parser.
def uleb(at):
 value=0
 for n in range(5):
  byte=image[at];at+=1;value|=(byte&127)<<(7*n)
  if byte<128:return value,at
 raise ValueError('invalid LEB')
offset=struct.unpack_from('<I',image,f.CODE_B+8)[0]
if offset!=717 or struct.unpack_from('<H',image,f.CODE_B)[0]!=1 or struct.unpack_from('<I',image,f.CODE_B+12)[0]!=2:raise RuntimeError('unexpected code layout')
line,pos=uleb(offset);params,pos=uleb(pos)
if (line,params)!=(1,0):raise RuntimeError('unexpected debug header')
events=[];pc=0
while True:
 at=pos;op=image[pos];pos+=1
 if op==0:break
 if op==1:
  advance,pos=uleb(pos);pc+=advance;continue
 if op not in (3,4,5,6):raise RuntimeError('unexpected fixture opcode')
 reg,pos=uleb(pos);name=typ=sig=0
 if op in (3,4):
  name,pos=uleb(pos);typ,pos=uleb(pos)
  if op==4:sig,pos=uleb(pos)
 events.append((op,pc,reg,name,typ,sig,at))
expected=[(3,0,0,1,1,0,719),(4,0,0,0,0,1,723),(5,1,0,0,0,0,730),(6,1,0,0,0,0,732),(5,2,0,0,0,0,736)]
if events!=expected or bytes(image[offset:pos])!=stream:raise RuntimeError('fixture byte oracle mismatch')
with tempfile.TemporaryDirectory(prefix='dmg-debug-locals-') as tmp:
 path=Path(tmp)/'locals.dex';path.write_bytes(image)
 run=subprocess.run([str(a.exe.resolve()),str(path)],capture_output=True,text=True,timeout=60)
 if run.returncode or 'PASS debug local events and limits' not in run.stdout:raise RuntimeError((run.returncode,run.stdout,run.stderr))
 print('fixture_sha256',hashlib.sha256(image).hexdigest(),'oracle events',len(events),run.stdout.strip())
