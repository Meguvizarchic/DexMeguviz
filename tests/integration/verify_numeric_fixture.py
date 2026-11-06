"""Check numeric fixture raw bytes and deterministic regeneration."""
import argparse,hashlib,json,struct,subprocess,sys,tempfile,zlib
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);a=p.parse_args();r=a.root
fixture=r/'tests/fixtures/generated/numeric/numeric.dex'
expected=json.loads((fixture.parent/'expected.json').read_text(encoding='utf-8'))
source=r/'tests/fixtures/generated/method_facts/method-uses.dex'
source_expected=r/'tests/fixtures/generated/method_facts/expected.json'
generator=r/'tests/fixtures/generators/numeric_facts.py'
b=fixture.read_bytes();assert hashlib.sha256(b).hexdigest()==expected['sha256']
assert hashlib.sha256(source.read_bytes()).hexdigest()==expected['source_sha256']
assert b[:8]==b'dex\n035\0' and struct.unpack_from('<I',b,32)[0]==len(b)
assert b[12:32]==hashlib.sha1(b[32:]).digest()
assert struct.unpack_from('<I',b,8)[0]==zlib.adler32(b[12:])&0xffffffff
off=json.loads(source_expected.read_text(encoding='utf-8'))['uses']['code_offset']
assert struct.unpack_from('<I',b,off+12)[0]==8
assert list(struct.unpack_from('<8H',b,off+16))==expected['code_units']
with tempfile.TemporaryDirectory(prefix='dmg-numeric-fixture-') as tmp:
 out=Path(tmp)/'numeric.dex'
 subprocess.run([sys.executable,str(generator),'--input',str(source),'--expected',str(source_expected),'--output',str(out)],check=True,timeout=30)
 assert out.read_bytes()==b
print('PASS independently checked numeric fixture bytes and reproducibility')
