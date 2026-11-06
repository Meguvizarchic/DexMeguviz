"""Checks an isolated manually compiled JAR and a host-provided Kotlin runtime."""
import argparse,hashlib,subprocess,zipfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--jar',required=True,type=Path);p.add_argument('--stdlib',required=True,type=Path);p.add_argument('--consumer',required=True,type=Path);p.add_argument('--java',required=True,type=Path);a=p.parse_args()
assert hashlib.sha256(a.stdlib.read_bytes()).hexdigest()=='bd8250210584cb659847dce9cda660f8e9906e5def7fbebcea93dc6dcb6a88a3'
classes={'GraphQueryExecution','Coverage','Decision','DecisionReason','ExecutionStatus','MethodPredicate$Companion','MethodPredicate','MethodQuery','MethodTextField','QueryExecution','QueryIntent','QuerySummary','RawDexFlags','RawFlagOperation','SourceIdentity','TextOperation','EntityPredicate$Companion','EntityPredicate','EntityQuery','EntityRelation','EntityTextField'}
with zipfile.ZipFile(a.jar) as z:
 names=z.namelist();actual={n for n in names if n.endswith('.class')}
 assert actual=={'io/github/jichuo1/dexmeguviz/'+name+'.class' for name in classes | {'NativeEngine','NativeEngine$Snapshot','NativeEngine$SnapshotInfo','NativeEngine$NativeFailure','NativeEngine$MethodCandidate','NativeEngine$QueryResult','NativeEngine$SourceSetSnapshot','NativeEngine$SourceSetInfo','NativeEngine$RawDexSourceInfo','NativeEngine$InputInfo','NativeEngine$Job','NativeEngine$JobPoll','NativeEngine$JobStatus','NativeEngine$EntityCandidate','NativeEngine$EntityResult','NativeEngine$EntityJob','NativeEngine$EntityJobPoll','NativeEngine$EntityJobStatus','NativeEngine$GraphJob','NativeEngine$GraphJobPoll','NativeEngine$GraphJobStatus','GraphResult','GraphResult$Binding','GraphResult$Entity','GraphResult$Input','GraphResult$Link','GraphResult$Operator','GraphResult$Profile','GraphResult$Reader','GraphResult$Row','GraphResult$Source','GraphResult$Witness'}}
 assert not any(n.startswith('kotlin/') or n.endswith('.jar') for n in names)
 for name in actual:
  code=z.read(name);assert code[:4]==b'\xca\xfe\xba\xbe' and int.from_bytes(code[6:8],'big')==61
import os
def run(paths):return subprocess.run([str(a.java),'-cp',os.pathsep.join(map(str,paths)),'HostProbe'],capture_output=True,text=True,timeout=30)
ok=run([a.consumer,a.jar,a.stdlib]);assert ok.returncode==0 and 'PASS plain JVM host' in ok.stdout,(ok.returncode,ok.stderr)
missing=run([a.consumer,a.jar]);assert missing.returncode!=0 and 'NoClassDefFoundError: kotlin/' in missing.stderr
print('PASS isolated JAR contents and explicit host stdlib, expected failure without host runtime')
