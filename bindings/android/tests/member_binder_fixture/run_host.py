"""Build and run self-authored member-binder fixtures without deleting existing outputs."""
import argparse,hashlib,json,os,subprocess,zipfile
from pathlib import Path
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from launcher_log import redact_launcher

def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
 p=argparse.ArgumentParser();p.add_argument('--aar',type=Path,required=True);p.add_argument('--jni',type=Path,required=True);p.add_argument('--jdk',type=Path,required=True);p.add_argument('--d8',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();here=Path(__file__).resolve().parent;out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
 for name in ('fixture-original','fixture','dex','static-fixture','static-dex','tests','tmp'):(out/name).mkdir()
 java=a.jdk/'bin/java.exe';javac=a.jdk/'bin/javac.exe';fixture=sorted((here/'fixture').glob('*.java'));static_fixture=sorted((here/'static_fixture/fixture').glob('*.java'));tests=[here.parent/'jni_host/RuntimeMemberBinderTest.java',here.parent/'jni_host/MemberBinderSecurityTest.java'];inputs=[Path(__file__).resolve(),a.aar.resolve(),a.jni.resolve(),java.resolve(),javac.resolve(),a.d8.resolve(),*fixture,*static_fixture,*tests];before={str(x):digest(x) for x in inputs};env=os.environ.copy();env['TEMP']=env['TMP']=str(out/'tmp');records=[]
 def run(name,args):
  cmd=list(map(str,args));x=subprocess.run(cmd,cwd=out,env=env,capture_output=True,timeout=300);(out/(name+'.stdout.log')).write_bytes(redact_launcher(x.stdout));(out/(name+'.stderr.log')).write_bytes(redact_launcher(x.stderr));records.append({'name':name,'argv':cmd,'exit_code':x.returncode});(out/'commands.json').write_text(json.dumps(records,indent=2)+'\n');
  if x.returncode:raise RuntimeError(name+' failed')
  return x.stdout
 run('fixture-javac',[javac,'--release','8','-g:none','-d',out/'fixture-original',*fixture]);classes=[]
 for f in sorted((out/'fixture-original').rglob('*.class')):
  data=f.read_bytes()
  if f.name=='TwinFields.class':
   old=b'\x01\x00\x04yyyy';new=b'\x01\x00\x04xxxx';assert data.count(old)==1;data=data.replace(old,new)
  target=out/'fixture'/f.relative_to(out/'fixture-original');target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data);classes.append(target)
 run('fixture-d8',[java,'-Djava.io.tmpdir='+str(out/'tmp'),'-cp',a.d8,'com.android.tools.r8.D8','--min-api','27','--no-desugaring','--output',out/'dex',*classes])
 run('static-javac',[javac,'--release','8','-g:none','-d',out/'static-fixture',*static_fixture]);static_classes=sorted((out/'static-fixture').rglob('*.class'));run('static-d8',[java,'-Djava.io.tmpdir='+str(out/'tmp'),'-cp',a.d8,'com.android.tools.r8.D8','--min-api','27','--no-desugaring','--output',out/'static-dex',*static_classes]);jar=out/'aar-classes.jar'
 with zipfile.ZipFile(a.aar) as z:jar.write_bytes(z.read('classes.jar'))
 run('test-javac',[javac,'--release','17','-cp',jar,'-d',out/'tests',*tests]);runtime=[jar,a.jni.resolve(),*sorted((out/'tests').rglob('*.class')),*classes,*static_classes,out/'dex/classes.dex',out/'static-dex/classes.dex'];runtime_before={str(x):digest(x) for x in runtime};cp=str(out/'tests')+os.pathsep+str(jar)
 for name in ('RuntimeMemberBinderTest','MemberBinderSecurityTest'):
  args=[java,'-Xcheck:jni','-Djava.io.tmpdir='+str(out/'tmp'),'-Djava.library.path='+str(a.jni.resolve().parent),'-cp',cp,'io.github.jichuo1.dexmeguviz.'+name,out/'fixture']
  if name=='RuntimeMemberBinderTest':args.extend([out/'dex/classes.dex',out/'static-fixture',out/'static-dex/classes.dex'])
  x=run(name,args)
  if b'PASS' not in x:raise RuntimeError(name+' missing PASS')
 if before!={str(x):digest(x) for x in inputs} or runtime_before!={str(x):digest(x) for x in runtime}:raise RuntimeError('test input changed')
 outputs={str(x):digest(x) for x in out.rglob('*') if x.is_file()};(out/'summary.json').write_text(json.dumps({'outcome':'passed','inputs_before':before,'inputs_after':before,'runtime_before':runtime_before,'runtime_after':runtime_before,'outputs':outputs,'commands':records,'scope':'self-authored Windows JVM/JNI fixture, no ART/device'},indent=2)+'\n');print('PASS reproducible member binder host fixtures')
if __name__=='__main__':main()
