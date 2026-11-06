"""Generate the fixed, project-authored D8 same-method fixture without cleanup."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--expected-sha256');p.add_argument('--source',type=Path,required=True);p.add_argument('--java',type=Path,required=True);p.add_argument('--d8',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();source=a.source.resolve();java=a.java.resolve();javac=java.with_name('javac.exe' if java.name.endswith('.exe') else 'javac');d8=a.d8.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);classes=out/'classes';classes.mkdir();dex=out/'dex';dex.mkdir();temp=out/'temp';temp.mkdir();env=os.environ.copy();env.update(TEMP=str(temp),TMP=str(temp),TMPDIR=str(temp));
for k in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):env.pop(k,None)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
inputs=[Path(__file__).resolve(),source,java,javac,d8];before={str(p):sha(p) for p in inputs};records=[]
def run(name,argv):
 argv=list(map(str,argv));r=subprocess.run(argv,env=env,cwd=out,capture_output=True,timeout=300);(out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr);records.append({'name':name,'argv':argv,'exit_code':r.returncode,'stdout_sha256':sha(out/(name+'.stdout')),'stderr_sha256':sha(out/(name+'.stderr'))});
 if r.returncode:raise SystemExit('failed '+name)
run('javac',[javac,'--release','8','-g:none','-d',classes,source]);classfiles=sorted(classes.rglob('*.class'));assert classfiles
run('d8',[java,'-cp',d8,'com.android.tools.r8.D8','--min-api','27','--no-desugaring','--output',dex,*classfiles]);after={str(p):sha(p) for p in inputs};assert before==after
digest=sha(dex/'classes.dex');
if a.expected_sha256 and digest!=a.expected_sha256:raise SystemExit('fixture digest mismatch: '+digest)
result={'status':'passed','scope':'self-authored Java fixture, D8 bytes; not Android runtime','inputs_before':before,'inputs_after':after,'commands':records,'dex_sha256':sha(dex/'classes.dex'),'classes':{str(p.relative_to(classes)):sha(p) for p in classfiles}}
(out/'summary.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8');print(json.dumps(result))
