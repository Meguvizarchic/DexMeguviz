"""Generate static multi-definition interface fixtures; no runtime claim."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
import generate_interface_v8 as g

parser = argparse.ArgumentParser()
parser.add_argument('--output', required=True, type=Path)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=False)
items = dict(g.SPECS)
items['left-alt.dex'] = (g.LEFT, g.OBJ, 0x601, [('classSame','I',g.F), ('override','I',g.F)], [g.TOP])
items['top-alt.dex'] = (g.TOP, g.OBJ, 0x601, [('hidden','I',g.F), ('override','I',g.F)], [])
source = Path(g.__file__)
manifest = {'generator_sha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'records': {}}
for name, record in items.items():
    data = g.build(*record)
    (args.output / name).write_bytes(data)
    manifest['records'][name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data), 'spec': record}
(args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
