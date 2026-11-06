"""Independent fixed DEX byte check for opt-in opaque invoke use-def."""
import argparse,hashlib,json,struct,subprocess,zlib
from pathlib import Path
if not __debug__:raise SystemExit('invoke dataflow oracle requires assertions enabled')
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--exe',type=Path,required=True);a=p.parse_args()
fixture=a.root/'tests/fixtures/generated/dataflow-invoke-v1/dataflow-invoke.dex';info=json.loads((fixture.parent/'expected.json').read_text(encoding='utf-8'));data=fixture.read_bytes()
assert hashlib.sha256(data).hexdigest()==info['sha256'] and data[:8]==b'dex\n035\0'
assert struct.unpack_from('<I',data,32)[0]==len(data) and data[12:32]==hashlib.sha1(data[32:]).digest()
assert struct.unpack_from('<I',data,8)[0]==zlib.adler32(data[12:])&0xffffffff
code=info['code_offset'];assert struct.unpack_from('<HHH',data,code)==(2,0,1) and struct.unpack_from('<I',data,code+12)[0]==8
words=struct.unpack_from('<8H',data,code+16);assert words==(0x7012,0x1071,4,0,0x010a,0x10b0,0x000f,0x000e)
assert words[1]>>12==1 and words[3]&15==0 and words[2]<struct.unpack_from('<I',data,88)[0]
join=a.root/'tests/fixtures/generated/dataflow-v1/dataflow-join.dex'
r=subprocess.run([str(a.exe),str(join),str(fixture)],capture_output=True,text=True,encoding='utf-8',timeout=90,check=True)
observed=[list(map(int,line.split()[1:])) for line in r.stdout.splitlines() if line.startswith('INVOKE_USE ')]
expected=[[x[0],x[1],x[2],int(x[3]),x[4],x[5]] for x in info['uses']]
assert observed==expected,(observed,expected)
assert 'PASS bounded int32 dataflow' in r.stdout
print('PASS independent invoke code bytes and conservative return use-def')
