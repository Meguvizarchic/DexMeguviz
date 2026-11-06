"""Independently inspect fixed DEX catch bytes and compare the opt-in CFG."""
import argparse,hashlib,json,struct,subprocess,zlib
from pathlib import Path
if not __debug__:raise SystemExit('exception CFG oracle requires assertions enabled')
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--exe',type=Path,required=True);a=p.parse_args()
fixture=a.root/'tests/fixtures/generated/extended/shared-items.dex';manifest=a.root/'tests/fixtures/generated/extended/manifest.json'
data=fixture.read_bytes();info=json.loads(manifest.read_text(encoding='utf-8'));layout=info['layout']
expected=next(x['sha256'] for x in info['entries'] if x['path']=='shared-items.dex')
assert hashlib.sha256(data).hexdigest()==expected and data[:8]==b'dex\n035\0'
assert struct.unpack_from('<I',data,32)[0]==len(data) and data[12:32]==hashlib.sha1(data[32:]).digest()
assert struct.unpack_from('<I',data,8)[0]==zlib.adler32(data[12:])&0xffffffff
code=layout['code_b'];start=layout['try_at'];handlers=layout['handlers_at']
assert struct.unpack_from('<H',data,code+6)[0]==1 and struct.unpack_from('<I',data,code+12)[0]==2
begin,length,offset=struct.unpack_from('<IHH',data,start);assert (begin,length,offset)==(0,1,1)
def uleb(pos):
 value=0
 for i in range(5):
  b=data[pos+i];value|=(b&127)<<(7*i)
  if b<128:return value,pos+i+1
 raise AssertionError('invalid ULEB')
count,pos=uleb(handlers);assert count==1 and pos-handlers==offset and data[pos]==0x7f
kind,pos=uleb(pos+1);typed,pos=uleb(pos);catchall,pos=uleb(pos)
assert typed==catchall==1 and kind<struct.unpack_from('<I',data,64)[0]
r=subprocess.run([str(a.exe),str(fixture)],capture_output=True,text=True,encoding='utf-8',timeout=90,check=True)
observed=[tuple(map(int,line.split()[1:])) for line in r.stdout.splitlines() if line.startswith('CATCH ')]
assert observed==[(0,typed,kind,0),(0,catchall,0xffffffff,1)],observed
assert 'PASS bounded conservative exception CFG' in r.stdout
print('PASS independent fixed DEX try and handler bytes against conservative CFG')
