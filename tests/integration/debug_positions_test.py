"""Construct a DEX from a pinned independent fixture and check emitted PCs."""
import argparse, hashlib, importlib.util, struct, subprocess, tempfile, zlib
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--exe',required=True,type=Path)
p.add_argument('--fixture',required=True,type=Path)
p.add_argument('--generator',required=True,type=Path)
a=p.parse_args()
spec=importlib.util.spec_from_file_location('fixture',a.generator)
f=importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
original=a.fixture.read_bytes()
assert hashlib.sha256(original).hexdigest()==f.SHA
image=f.build(original,[bytes.fromhex('01 00 0e 1d 1d 00')],None,0)
assert struct.unpack_from('<I',image,f.CODE_B+12)[0]==2
struct.pack_into('<HH',image,f.CODE_B+16,0x0013,1)
# Keep try end and both handler targets on decoded instruction boundaries.
struct.pack_into('<H',image,f.CODE_B+24,2)
image[f.CODE_B+31]=0; image[f.CODE_B+32]=0
image[12:32]=hashlib.sha1(image[32:]).digest()
struct.pack_into('<I',image,8,zlib.adler32(image[12:])&0xffffffff)
with tempfile.TemporaryDirectory(prefix='dmg-debug-position-') as tmp:
    path=Path(tmp)/'position.dex'; path.write_bytes(image)
    run=subprocess.run([str(a.exe.resolve()),str(path)],capture_output=True,text=True,timeout=60)
    assert run.returncode==0,(run.returncode,run.stdout,run.stderr)
    print('fixture_sha256',hashlib.sha256(image).hexdigest(),run.stdout.strip())

