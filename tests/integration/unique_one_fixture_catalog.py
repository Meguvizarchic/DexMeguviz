"""Rebuild the isolated v12 UTF-16 suite and verify catalog attribution."""
import hashlib,json,subprocess,sys,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[2];fixtures=root/'tests/fixtures';catalog=json.loads((fixtures/'catalog.json').read_text(encoding='utf-8'))
suites={x['id']:x for x in catalog['suites']};suite=suites['unique-one-v12'];old=suites['use-relations']
h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
generator=fixtures/suite['generator'];assert h(generator)==suite['generator_sha256']
manifest=fixtures/'generated/unique-one-v12/manifest.json';assert h(manifest)==suite['oracle_files']['generated/unique-one-v12/manifest.json']
entries=suite['files'];assert len(entries)==1 and entries[0]['path']=='generated/unique-one-v12/string-utf16-v12.dex'
path=fixtures/entries[0]['path'];assert len(path.read_bytes())==entries[0]['bytes'] and h(path)==entries[0]['sha256']
assert {p.relative_to(fixtures).as_posix() for p in (fixtures/'generated/use_relations').glob('*.dex')}=={x['path'] for x in old['files']}
assert all('unique-one-v12' not in x['path'] for x in old['files'])
out=Path(tempfile.mkdtemp(prefix='dmg-unique-one-v12-'))/'rebuilt'
source=fixtures/'generated/use_relations/string-normal-jumbo.dex'
subprocess.run([sys.executable,str(generator),'--source',str(source),'--output',str(out)],check=True)
assert (out/path.name).read_bytes()==path.read_bytes() and (out/'manifest.json').read_bytes()==manifest.read_bytes()
print('PASS v12 suite reproducible, exact old glob, correct catalog ownership; rebuild retained at',out)
