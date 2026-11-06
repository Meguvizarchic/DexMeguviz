"""Ensure optimized Python cannot turn the fixed oracle into a false pass."""
import argparse, subprocess, sys
from pathlib import Path
p=argparse.ArgumentParser()
for name in ('oracle','exe','fixtures'):p.add_argument('--'+name,required=True,type=Path)
a=p.parse_args()
for name,command in [
 ('oracle',[sys.executable,'-B','-O',str(a.oracle),'--exe',str(a.exe),'--fixtures',str(a.fixtures)]),
]:
    result=subprocess.run(command,capture_output=True,timeout=30)
    if result.returncode==0 or b'Python optimization disables required checks' not in result.stderr or b'PASS' in result.stdout:
        raise RuntimeError(f'{name} accepted optimized Python or had wrong failure: {result.returncode}, {result.stdout!r}, {result.stderr!r}')
print('PASS optimized Python explicitly rejected by oracle')
