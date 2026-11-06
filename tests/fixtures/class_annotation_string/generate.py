"""Rebuild two self-authored annotation DEX fixtures in a new directory; no cleanup."""
from pathlib import Path
import argparse, hashlib, json, os, subprocess
p=argparse.ArgumentParser();p.add_argument('--jdk',type=Path,required=True);p.add_argument('--d8-jar',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
root=Path(__file__).resolve().parent;jdk=a.jdk.resolve();java=jdk/'bin/java.exe';javac=jdk/'bin/javac.exe';d8=a.d8_jar.resolve();out=a.out.resolve()
if out.exists():raise SystemExit('output exists')
for item in (java,javac,d8,root/'a/Fixtures.java',root/'b/Fixtures.java',root/'expected.json'):
 if not item.is_file():raise SystemExit('missing input: '+str(item))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs=[Path(__file__).resolve(),java,javac,d8,root/'a/Fixtures.java',root/'b/Fixtures.java',root/'expected.json'];before={str(p):sha(p) for p in inputs};expected=json.loads((root/'expected.json').read_text(encoding='utf8'));out.mkdir();tmp=out/'tmp';tmp.mkdir();env=os.environ.copy();env.update(TEMP=str(tmp),TMP=str(tmp));results=[]
for variant in ('a','b'):
 classes=out/(variant+'-classes');dex=out/(variant+'-dex');classes.mkdir();dex.mkdir();source=root/variant/'Fixtures.java'
 commands=[[javac,'--release','8','-encoding','UTF-8','-g:none','-d',classes,source],[java,'-Djava.io.tmpdir='+str(tmp),'-cp',d8,'com.android.tools.r8.D8','--min-api','27','--no-desugaring','--output',dex]]
 for index,cmd in enumerate(commands):
  if index==1:cmd.extend(sorted(classes.rglob('*.class')))
  result=subprocess.run([str(x) for x in cmd],env=env,capture_output=True,timeout=120);(out/(variant+'-'+str(index)+'.log')).write_bytes(result.stdout+result.stderr)
  if result.returncode:raise SystemExit('fixture command failed: '+variant+' '+str(index))
 digest=sha(dex/'classes.dex');results.append({'variant':variant,'sha256':digest,'matches_expected':digest==expected[variant]['dex_sha256']})
if any(not row['matches_expected'] for row in results):raise SystemExit('DEX output differs from pinned fixture')
after={str(p):sha(p) for p in inputs}
if before!=after:raise SystemExit('fixture input changed')
(out/'receipt.json').write_text(json.dumps({'status':'passed','inputs':before,'results':results,'scope':'self-authored build-time fixtures; no ART/device'},indent=2)+'\n',encoding='utf8')
print('PASS reproducible class annotation string fixtures')
