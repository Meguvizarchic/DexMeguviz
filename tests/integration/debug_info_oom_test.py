"""Produce the pinned authored debug-info fixture and exercise PMR failure cleanup."""
import argparse
import hashlib
import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--exe', type=Path, required=True)
parser.add_argument('--fixture', type=Path, required=True)
parser.add_argument('--generator', type=Path, required=True)
args = parser.parse_args()

spec = importlib.util.spec_from_file_location('debug_fixture', args.generator)
module = importlib.util.module_from_spec(spec)
sys.dont_write_bytecode = True
spec.loader.exec_module(module)
original = args.fixture.read_bytes()
assert hashlib.sha256(original).hexdigest() == module.SHA
data = module.build(original)
module.checksum(data)
digest = hashlib.sha256(data).hexdigest()
with tempfile.TemporaryDirectory(prefix='dmg-debug-info-oom-') as directory:
    path = Path(directory) / 'debug.dex'
    path.write_bytes(data)
    result = subprocess.run([str(args.exe.resolve()), str(path), digest], capture_output=True, text=True, timeout=60)
    print(result.stdout, end='')
    if result.returncode:
        print(result.stderr, end='')
        raise SystemExit(result.returncode)
