"""Confirm targeted controls were accepted by the immediately previous audit."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path

p=argparse.ArgumentParser()
for name in ('prior','abi-controls','elf-controls','header','readelf','runtime-report','out'):p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
paths=sorted(a.abi_controls.glob('minor-*.aar'))+sorted(a.elf_controls.glob('*.aar'))
if len(paths)!=14:raise SystemExit('expected 8 minor and 6 ELF controls')
records=[]
for i,path in enumerate(paths):
 command=[sys.executable,'-B',str(a.prior),'--aar',str(path),'--header',str(a.header),'--readelf',str(a.readelf),'--runtime-report',str(a.runtime_report),'--out',str(a.out/('case-'+str(i)))]
 proc=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=90)
 (a.out/(str(i)+'.stdout.log')).write_text(proc.stdout,encoding='utf-8');(a.out/(str(i)+'.stderr.log')).write_text(proc.stderr,encoding='utf-8')
 records.append({'case':path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'exit_code':proc.returncode})
 if proc.returncode:raise SystemExit('previous audit unexpectedly rejected '+path.name+': '+proc.stderr)
(a.out/'records.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
print('PASS',len(records),'minor/ELF binary controls accepted by immediately previous audit')
