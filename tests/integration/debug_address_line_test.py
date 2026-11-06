"""Bounded debug-state diagnostics using a pinned, independently generated DEX."""
import argparse
import hashlib
import importlib.util
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser()
for name in ('exe', 'default-exe', 'fixture', 'generator'):
    parser.add_argument('--' + name, required=True, type=Path)
args = parser.parse_args()
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('fixture', args.generator)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
original = args.fixture.read_bytes()
assert hashlib.sha256(original).hexdigest() == fixture.SHA
assert struct.unpack_from('<I', original, fixture.CODE_A + 12)[0] == 1
assert struct.unpack_from('<I', original, fixture.CODE_B + 12)[0] == 2

def single(stream, target='b'):
    # A has two parameters and one code unit; B has zero and two code units.
    params = b'\x02\x00\x00' if target == 'a' else b'\x00'
    image = fixture.build(original, [b'\x0a' + params + stream + b'\x00'],
                          0 if target == 'a' else None, 0 if target == 'b' else None,
                          'static-wide' if target == 'a' else 'original')
    return image

cases = [
    ('zero-advance', single(b'\x01\x00\x0e'), True, None),
    ('advance-within', single(b'\x01\x01\x0e'), True, None),
    ('advance-end-inclusive', single(b'\x01\x02'), True, None),
    ('advance-past-end', single(b'\x01\x03'), False, 'debug address exceeds code instruction count'),
    ('special-at-end-inclusive', single(b'\x28'), True, None), # (0x28-10)/15 == 2
    ('special-past-end', single(b'\x37'), False, 'debug address exceeds code instruction count'),
    ('mixed-advance-at-end', single(b'\x01\x01\x19'), True, None),
    ('mixed-advance-past-end', single(b'\x01\x02\x19'), False, 'debug address exceeds code instruction count'),
    ('large-uleb-cumulative', single(bytes.fromhex('01 ff ff ff ff 0f 01 ff ff ff ff 0f')),
     False, 'debug address exceeds code instruction count'),
    ('same-stream-shorter-code', single(b'\x01\x02', 'a'), False, 'debug address exceeds code instruction count'),
    ('line-reaches-one', single(b'\x02\x77'), True, None), # signed LEB -9: 10 -> 1
    ('line-below-one', single(b'\x02\x76'), False, 'debug line is less than one'),
    ('special-line-below-one', single(b'\x02\x7a\x0a'), False, 'debug line is less than one'),
    ('line-recovery-still-invalid', single(b'\x02\x76\x02\x02'), False, 'debug line is less than one'),
    ('associated-line-start-zero', fixture.build(original, [bytes.fromhex('00 00 00')], None, 0),
     False, 'debug line is less than one'),
    ('associated-line-zero-then-recovery', fixture.build(original, [bytes.fromhex('00 00 02 01 00')], None, 0),
     False, 'debug line is less than one'),
    ('orphan-invalid-line', fixture.build(original, [bytes.fromhex('00 00 00')]), True, None),
    ('orphan-invalid-address', fixture.build(original, [bytes.fromhex('01 00 01 7f 00')]), True, None),
    ('shared-short-and-long-code', fixture.build(original, [bytes.fromhex('0a 02 00 00 01 02 00')], 0, 0,
                                                'static-wide'), False, 'debug address exceeds code instruction count'),
]
records = []
with tempfile.TemporaryDirectory(prefix='dmg-debug-address-') as temp:
    for name, data, valid, detail in cases:
        path = Path(temp) / (name + '.dex')
        path.write_bytes(data)
        def run(exe):
            return subprocess.run([str(exe.resolve()), 'inspect', str(path), '--json'], capture_output=True,
                                  text=True, encoding='utf-8', timeout=30)
        checked, default = run(args.exe), run(args.default_exe)
        expected = 0 if valid else 2
        assert checked.returncode == expected, (name, checked.returncode, checked.stdout, checked.stderr)
        if detail: assert detail in checked.stderr, (name, checked.stderr)
        assert default.returncode == 0 and json.loads(default.stdout)['execution_status'] == 'Complete', (name, default.stderr)
        records.append({'case': name, 'sha256': hashlib.sha256(data).hexdigest(), 'checked_exit': checked.returncode,
                        'diagnostic': checked.stderr.strip(), 'default_exit': default.returncode})
print(json.dumps({'scope': 'fixed authored DEX cases; no full debug/ART verification', 'cases': records}, indent=2))
