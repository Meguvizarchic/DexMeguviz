"""Derive a checked use fixture with two calls to the locally-owned method."""
import argparse,hashlib,struct,zlib
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
data=bytearray(a.input.read_bytes())
assert hashlib.sha256(data).hexdigest()=='04656bbfe03c8b04e6f77d29b8cae8e7e06f18a038f85300658f8c691435648b'
code=416
for pc in (0,3):
 assert struct.unpack_from('<H',data,code+16+pc*2)[0]&255==0x71
 assert struct.unpack_from('<H',data,code+16+(pc+1)*2)[0]==4
 struct.pack_into('<H',data,code+16+(pc+1)*2,3)
data[12:32]=hashlib.sha1(data[32:]).digest();struct.pack_into('<I',data,8,zlib.adler32(data[12:])&0xffffffff)
if a.output.exists():raise FileExistsError(a.output)
a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(data)
print(hashlib.sha256(data).hexdigest())
