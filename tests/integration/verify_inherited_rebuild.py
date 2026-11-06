"""Regenerate all project-original hierarchy fixtures and compare bytes."""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile

p=argparse.ArgumentParser()
p.add_argument('--generator',type=Path,required=True)
p.add_argument('--oracle',type=Path,required=True)
p.add_argument('--fixtures',type=Path,required=True)
a=p.parse_args()
with tempfile.TemporaryDirectory(prefix='dex-inherited-') as tmp:
    output=Path(tmp)/'fixtures'
    subprocess.run([sys.executable,str(a.generator),'--output',str(output)],check=True,timeout=30)
    expected={p.name for p in a.fixtures.iterdir() if p.is_file()}
    actual={p.name for p in output.iterdir() if p.is_file()}
    assert actual==expected
    for name in expected:assert (output/name).read_bytes()==(a.fixtures/name).read_bytes(),name
    subprocess.run([sys.executable,str(a.oracle),str(output)],check=True,timeout=30)
print('PASS inherited fixture byte reproduction and independent oracle')
