"""Create the pinned wide-parameter fixture for the explicit checker failure test."""
import argparse
import hashlib
import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--exe', required=True, type=Path)
parser.add_argument('--fixture', required=True, type=Path)
parser.add_argument('--generator', required=True, type=Path)
args = parser.parse_args()
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('debug_association_fixture', args.generator)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
original = args.fixture.read_bytes()
assert hashlib.sha256(original).hexdigest() == module.SHA
data = module.build(original, [bytes.fromhex('01 02 00 00 03 02 00 00 00')], 0, None, 'static-wide')
with tempfile.TemporaryDirectory(prefix='dmg-debug-association-oom-') as directory:
    path = Path(directory) / 'wide-debug.dex'
    path.write_bytes(data)
    result = subprocess.run([str(args.exe.resolve()), str(path)], capture_output=True, text=True, timeout=60)
    print(result.stdout, end='')
    if result.returncode:
        print(result.stderr, end='')
        raise SystemExit(result.returncode)
