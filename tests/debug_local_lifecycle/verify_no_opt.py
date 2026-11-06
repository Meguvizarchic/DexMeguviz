import subprocess,sys
from pathlib import Path
if not __debug__:raise SystemExit('assertions required')
p=Path(__file__).with_name('oracle.py')
r=subprocess.run([sys.executable,'-B','-O',str(p)],capture_output=True,text=True,timeout=30)
if r.returncode!=1 or 'assertions required; Python optimization is unsupported' not in r.stderr:raise RuntimeError((r.returncode,r.stdout,r.stderr))
print('PASS Python optimized mode refused')
