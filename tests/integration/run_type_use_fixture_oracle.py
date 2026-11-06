"""Run type-use oracle in a new retained result directory; never removes files."""
import argparse,hashlib,json,os,subprocess,sys,tempfile
from pathlib import Path
p=argparse.ArgumentParser()
for name in ('exe','fixture','expected','oracle','output-root'):p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args();exe=a.exe.resolve();fixture=a.fixture.resolve();expected=a.expected.resolve();oracle=a.oracle.resolve();python=Path(sys.executable).resolve();script=Path(__file__).resolve();root=a.output_root.resolve();root.mkdir(parents=True,exist_ok=True);out=Path(tempfile.mkdtemp(prefix='type-use-',dir=root))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs=[python,exe,fixture,expected,oracle,script];before={str(p):sha(p) for p in inputs};argv=[str(python),'-I',str(oracle),str(exe),str(fixture),str(expected),str(out/'oracle')];env=os.environ.copy()
for k in ('PYTHONPATH','PYTHONHOME'):env.pop(k,None)
r=subprocess.run(argv,capture_output=True,env=env,timeout=300);(out/'stdout.log').write_bytes(r.stdout);(out/'stderr.log').write_bytes(r.stderr);after={str(p):sha(p) for p in inputs};files={str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file()};receipt={'status':'passed' if r.returncode==0 and before==after else 'failed','argv':argv,'exit_code':r.returncode,'inputs_before':before,'inputs_after':after,'outputs_sha256':files,'scope':'fixed D8 fixture; no ART/device'};(out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print('receipt:',out/'receipt.json');print(r.stdout.decode('utf8','replace'));sys.stderr.write(r.stderr.decode('utf8','replace'))
if receipt['status']!='passed':raise SystemExit(1)
