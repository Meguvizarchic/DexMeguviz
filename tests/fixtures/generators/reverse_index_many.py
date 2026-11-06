"""Deterministic structural DEX: 1024 calls to one method reference.

--verify reads only; --output exclusively creates a new file. No cleanup.
"""
from pathlib import Path
import argparse,hashlib,struct,zlib
from reverse_fixture_base import build
EXPECTED='a207b35cf995e4c5c35e0482823c5fca33232558e3ffd4cd6cb6ff6332c4175f'
target=('Lfixture/Target;','sink','V',[])
data=build('Lfixture/Caller;','uses','V',[],targets=[target]*1024,static=True)
assert hashlib.sha256(data).hexdigest()==EXPECTED and data[:8]==b'dex\n035\0'
assert data[12:32]==hashlib.sha1(data[32:]).digest() and struct.unpack_from('<I',data,8)[0]==zlib.adler32(data[12:])&0xffffffff
code=284;assert struct.unpack_from('<I',data,code+12)[0]==3073
for i in range(1024):
    op,index,regs=struct.unpack_from('<3H',data,code+16+6*i)
    assert op==0x0071 and index==1 and regs==0
assert struct.unpack_from('<H',data,code+16+6*1024)[0]==0x000e
p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group(required=True);g.add_argument('--verify',type=Path);g.add_argument('--output',type=Path);a=p.parse_args()
if a.verify:assert a.verify.read_bytes()==data
else:
    with a.output.open('xb') as f:f.write(data)
print('PASS reverse 1024-call fixture',EXPECTED)
