"""Rebuild the self-authored many-class DEX in a new directory; no cleanup."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess
p=argparse.ArgumentParser();p.add_argument('--jdk',type=Path,required=True);p.add_argument('--d8-jar',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
r=Path(__file__).resolve().parent;j=a.jdk.resolve()/'bin/java.exe';javac=a.jdk.resolve()/'bin/javac.exe';d8=a.d8_jar.resolve();o=a.out.resolve()
if o.exists():raise SystemExit('output exists')
for x in (j,javac,d8,r/'Many.java',r/'expected.json'):
 if not x.is_file():raise SystemExit('missing input: '+str(x))
h=lambda x:hashlib.sha256(x.read_bytes()).hexdigest();inputs=[Path(__file__).resolve(),j,javac,d8,r/'Many.java',r/'expected.json'];before={str(x):h(x) for x in inputs};e=json.loads((r/'expected.json').read_text());o.mkdir();classes=o/'classes';dex=o/'dex';tmp=o/'tmp';classes.mkdir();dex.mkdir();tmp.mkdir();env=os.environ.copy();env.update(TEMP=str(tmp),TMP=str(tmp));commands=[[javac,'--release','8','-encoding','UTF-8','-g:none','-d',classes,r/'Many.java'],[j,'-Djava.io.tmpdir='+str(tmp),'-cp',d8,'com.android.tools.r8.D8','--min-api','27','--no-desugaring','--output',dex]]
for i,cmd in enumerate(commands):
 if i==1:cmd.extend(sorted(classes.rglob('*.class')))
 q=subprocess.run([str(x) for x in cmd],env=env,capture_output=True,timeout=120);(o/(str(i)+'.log')).write_bytes(q.stdout+q.stderr)
 if q.returncode:raise SystemExit('fixture command failed')
if h(dex/'classes.dex')!=e['dex_sha256'] or before!={str(x):h(x) for x in inputs}:raise SystemExit('fixture or inputs differ')
(o/'receipt.json').write_text(json.dumps({'status':'passed','inputs':before,'dex_sha256':h(dex/'classes.dex')},indent=2)+'\n');print('PASS reproducible method batch fixture')
