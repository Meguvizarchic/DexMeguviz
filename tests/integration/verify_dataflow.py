"""Independent fixed DEX byte check for the structural dataflow join."""
import argparse,hashlib,json,struct,subprocess,zlib
from pathlib import Path
if not __debug__:raise SystemExit('dataflow oracle requires assertions enabled')
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--exe',type=Path,required=True);a=p.parse_args()
fixture=a.root/'tests/fixtures/generated/dataflow-v1/dataflow-join.dex';expected=json.loads((fixture.parent/'expected.json').read_text(encoding='utf-8'));data=fixture.read_bytes()
assert hashlib.sha256(data).hexdigest()==expected['sha256'] and data[:8]==b'dex\n035\0'
assert struct.unpack_from('<I',data,32)[0]==len(data) and data[12:32]==hashlib.sha1(data[32:]).digest()
assert struct.unpack_from('<I',data,8)[0]==zlib.adler32(data[12:])&0xffffffff
code=expected['code_offset'];assert struct.unpack_from('<H',data,code)[0]==2 and struct.unpack_from('<I',data,code+12)[0]==26
words=struct.unpack_from('<26H',data,code+16)
assert words[:7]==(0x1012,0x0138,4,0x1012,0x0228,0x1012,0x000f)
assert 1+struct.unpack('<h',struct.pack('<H',words[2]))[0]==5 and 4+struct.unpack('b',bytes([words[4]>>8]))[0]==6
assert words[0]>>12==words[3]>>12==words[5]>>12==1
r=subprocess.run([str(a.exe),str(fixture)],capture_output=True,text=True,encoding='utf-8',timeout=90,check=True)
observed=[list(map(int,line.split()[1:])) for line in r.stdout.splitlines() if line.startswith('USE ')]
expected_uses=[[x[0],x[1],x[2],int(x[3]),x[4],x[5]] for x in expected['uses']]
assert observed==expected_uses,(observed,expected_uses)
assert 'PASS bounded int32 dataflow' in r.stdout
print('PASS independent DEX branch/constant bytes and structural join')
