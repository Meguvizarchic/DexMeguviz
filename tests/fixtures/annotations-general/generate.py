"""Rebuild self-authored annotation DEX in a new directory; no cleanup."""
from pathlib import Path
import argparse,subprocess,hashlib,json
p=argparse.ArgumentParser();p.add_argument('--javac',type=Path,required=True);p.add_argument('--java',type=Path,required=True);p.add_argument('--d8-jar',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
for item in (a.javac,a.java,a.d8_jar):
 if not item.is_file():raise SystemExit('required installed tool not found')
if a.out.exists():raise SystemExit('output must not exist')
a.out.mkdir();classes=a.out/'classes';dex=a.out/'dex';classes.mkdir();dex.mkdir();source=Path(__file__).with_name('Annotated.java')
commands=[[str(a.javac),'--release','8','-encoding','UTF-8','-g','-d',str(classes),str(source)],[str(a.java),'-cp',str(a.d8_jar),'com.android.tools.r8.D8','--min-api','27','--no-desugaring','--output',str(dex)]]
for i,cmd in enumerate(commands):
 if i==1:cmd.extend(str(x) for x in sorted(classes.rglob('*.class')))
 r=subprocess.run(cmd,capture_output=True,timeout=120);(a.out/(str(i)+'.stdout')).write_bytes(r.stdout);(a.out/(str(i)+'.stderr')).write_bytes(r.stderr)
 if r.returncode:raise SystemExit(r.returncode)
p=dex/'classes.dex';print(hashlib.sha256(p.read_bytes()).hexdigest())
