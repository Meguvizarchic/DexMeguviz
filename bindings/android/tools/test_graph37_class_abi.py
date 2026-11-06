from pathlib import Path
import hashlib,json,struct,sys
import argparse
p=argparse.ArgumentParser();p.add_argument('--classes',required=True,type=Path);p.add_argument('--out',required=True,type=Path);args=p.parse_args()
out=args.out
if out.exists():raise SystemExit('evidence exists')
out.mkdir(parents=True)
sys.path.insert(0,str(Path(__file__).resolve().parent))
from jni_classfile import ADVANCED_CLASSES,METHOD_CALLS_CLASSES,parse,verify_classfiles,ClassError
from verify_aar import check_kotlin_class
prefix='io/github/jichuo1/dexmeguviz/'
javapath=args.classes/prefix
java={prefix+n+'.class':(javapath/(n+'.class')).read_bytes() for n in ['GraphResult', 'GraphResult$Binding', 'GraphResult$Entity', 'GraphResult$Input', 'GraphResult$Link', 'GraphResult$Operator', 'GraphResult$Profile', 'GraphResult$Reader', 'GraphResult$Row', 'GraphResult$Source', 'GraphResult$Witness', 'NativeEngine', 'NativeEngine$EntityCandidate', 'NativeEngine$EntityJob', 'NativeEngine$EntityJobPoll', 'NativeEngine$EntityJobStatus', 'NativeEngine$EntityResult', 'NativeEngine$GraphJob', 'NativeEngine$GraphJobPoll', 'NativeEngine$GraphJobStatus', 'NativeEngine$InputInfo', 'NativeEngine$Job', 'NativeEngine$JobPoll', 'NativeEngine$JobStatus', 'NativeEngine$MethodCandidate', 'NativeEngine$NativeFailure', 'NativeEngine$QueryResult', 'NativeEngine$RawDexSourceInfo', 'NativeEngine$Snapshot', 'NativeEngine$SnapshotInfo', 'NativeEngine$SourceSetInfo', 'NativeEngine$SourceSetSnapshot', 'UseGraphResult', 'UseGraphResult$Binding', 'UseGraphResult$Entity', 'UseGraphResult$Identity', 'UseGraphResult$Input', 'UseGraphResult$Link', 'UseGraphResult$Operator', 'UseGraphResult$Profile', 'UseGraphResult$Reader', 'UseGraphResult$Row', 'UseGraphResult$Source', 'UseGraphResult$Use', 'UseGraphResult$Value', 'UseGraphResult$Witness']}
java.update({prefix+n+'.class':(javapath/(n+'.class')).read_bytes() for n in ['NativeEngine$ExpandJob', 'NativeEngine$ExpandJobPoll', 'ExpandResult', 'ExpandResult$Reader', 'ExpandResult$Profile', 'ExpandResult$Operator', 'ExpandResult$Input', 'ExpandResult$Source', 'ExpandResult$Entity', 'ExpandResult$Use', 'ExpandResult$Value', 'ExpandResult$Identity', 'ExpandResult$Binding', 'ExpandResult$Link', 'ExpandResult$ExpandProfile', 'ExpandResult$Witness', 'ExpandResult$Hop', 'ExpandResult$Evidence', 'ExpandResult$Path', 'ExpandResult$Row', 'ExpandResult$RowEvidence', 'ExpandResult$Frontier']})
java.update({prefix+n+'.class':(javapath/(n+'.class')).read_bytes() for n in ['GraphResult$ClassAnnotationFlags','NativeEngine$MethodTypeJob','NativeEngine$MethodTypeJobPoll','MethodTypeResult','MethodTypeResult$Reader','MethodTypeResult$Row','MethodTypeResult$Witness']+['NativeEngine$UseGraphJob','NativeEngine$UseGraphJobPoll','NativeEngine$UseGraphJobStatus']})
java.update({prefix+n+'.class':(javapath/(n+'.class')).read_bytes() for n in ADVANCED_CLASSES+METHOD_CALLS_CLASSES})
parsed=verify_classfiles(java)
records=[]
def neg(label,fn):
 try: fn()
 except (ValueError,ClassError): records.append(label);return
 raise AssertionError('accepted mutant '+label)
for cls,name in [('NativeEngine','nativeQueryUseGraph'),('NativeEngine$Snapshot','queryUseGraph'),('NativeEngine$SourceSetSnapshot','queryUseGraph'),('NativeEngine','nativeQueryReflectionMethodUses'),('NativeEngine','nativeStartReflectionMethodUsesJob'),('NativeEngine$Snapshot','queryReflectionMethodUses'),('NativeEngine$Snapshot','startReflectionMethodUsesJob'),('NativeEngine$SourceSetSnapshot','queryReflectionMethodUses'),('NativeEngine$SourceSetSnapshot','startReflectionMethodUsesJob')]:
 key=prefix+cls+'.class'; original=java[key];m=next(m for m in parse(original)['methods'] if m['name']==name.encode())
 for field in ('name','descriptor','access'):
  b=bytearray(original)
  if field=='access':struct.pack_into('>H',b,m['access_offset'],m['access']^1)
  else:
   val=m[field];at=m[field+'_offset'];b[at:at+len(val)]=val[:-1]+b'X'
  mutated=dict(java);mutated[key]=bytes(b)
  neg(cls+' '+name+' '+field,lambda:verify_classfiles(mutated))
for cls,field in [('UseGraphResult$Use','dexPc'),('UseGraphResult$Identity','dexPc'),('UseGraphResult$Witness','extraProto'),('UseGraphResult$Value','use'),('UseGraphResult$Source','occurrenceId')]:
 key=prefix+cls+'.class';b=bytearray(java[key]);m=next(f for f in parse(b)['fields'] if f['name']==field.encode());struct.pack_into('>H',b,m['access_offset'],m['access']^1)
 mutated=dict(java);mutated[key]=bytes(b);neg(cls+' '+field,lambda:verify_classfiles(mutated))
kt=javapath
extra=javapath
names=['GraphExpression', 'GraphExpression$Companion', 'GraphExpression$Companion$WhenMappings', 'GraphIdentity', 'GraphJoinKey', 'GraphPredicate', 'GraphPredicate$Companion', 'GraphQuery', 'GraphRolePolicy', 'GraphSetSemantics', 'ReflectionFlags', 'TypedGraphQueryExecution', 'UseGraphQueryExecution', 'ReflectionMethodUsesExecution']
names+=['StaticTextMatch','InvokeReferenceKind','FieldUseAccess','InvokeTarget','FieldTarget','ReflectionMethodPredicate','ReflectionMethodPredicate$Companion','ReflectionMethodUsesQuery','ReflectionMethodUsesQueryKt','TypedReflectionMethodUsesExecution']
for name in names:
 p=kt/(name+'.class')
 c=parse(p.read_bytes());check_kotlin_class(c,name)
for cls,name in [('GraphExpression$Companion','join'),('GraphPredicate$Companion','reflectionFlags'),('GraphQuery','toQueryIrJson'),('TypedGraphQueryExecution','execute'),('TypedGraphQueryExecution','startJob'),('UseGraphQueryExecution','execute'),('ReflectionMethodUsesExecution','execute'),('ReflectionMethodUsesExecution','startJob')]:
 p=(extra if cls=='UseGraphQueryExecution' else kt)/(cls+'.class');raw=p.read_bytes();ms=[m for m in parse(raw)['methods'] if m['name']==name.encode()]
 for index,m in enumerate(ms):
  for field in ('name','descriptor','access'):
   b=bytearray(raw)
   if field=='access':struct.pack_into('>H',b,m['access_offset'],m['access']^1)
   else:
    val=m[field];at=m[field+'_offset'];b[at:at+len(val)]=val[:-1]+b'X'
   neg(cls+' '+name+' '+str(index)+' '+field,lambda:check_kotlin_class(parse(b),cls))
for cls in ('GraphIdentity','GraphJoinKey','GraphRolePolicy','GraphSetSemantics'):
 b=bytearray((kt/(cls+'.class')).read_bytes());m=next(f for f in parse(b)['fields'] if f['access'] & 0x4000);struct.pack_into('>H',b,m['access_offset'],m['access']^1);neg(cls+' enum',lambda:check_kotlin_class(parse(b),cls))
b=bytearray((kt/'ReflectionMethodUsesExecution.class').read_bytes());m=next(f for f in parse(b)['fields'] if f['name']==b'INSTANCE');struct.pack_into('>H',b,m['access_offset'],m['access']^1);neg('ReflectionMethodUsesExecution INSTANCE',lambda:check_kotlin_class(parse(b),'ReflectionMethodUsesExecution'))
targets=[('StaticTextMatch','getValue'),('InvokeTarget','getReferenceKind'),('FieldTarget','getAccess'),
 ('ReflectionMethodPredicate$Companion','metadata'),('ReflectionMethodPredicate$Companion','reflectionFlags'),('ReflectionMethodPredicate$Companion','reflectionOwnerFlags'),
 ('ReflectionMethodPredicate$Companion','stringsAll'),('ReflectionMethodPredicate$Companion','stringsAny'),('ReflectionMethodPredicate$Companion','invokesAll'),('ReflectionMethodPredicate$Companion','invokesAny'),
 ('ReflectionMethodPredicate$Companion','fieldsAll'),('ReflectionMethodPredicate$Companion','fieldsAny'),('ReflectionMethodPredicate$Companion','not'),('ReflectionMethodPredicate$Companion','all'),('ReflectionMethodPredicate$Companion','any'),
 ('ReflectionMethodUsesQuery','toQueryIrJson'),('TypedReflectionMethodUsesExecution','execute'),('TypedReflectionMethodUsesExecution','startJob'),('ReflectionMethodUsesQueryKt','boundedJoin')]
for cls,name in targets:
 raw=(kt/(cls+'.class')).read_bytes();methods=[m for m in parse(raw)['methods'] if m['name']==name.encode()]
 if not methods:raise AssertionError('missing mutation target '+cls+' '+name)
 for index,m in enumerate(methods):
  for field in ('name','descriptor','access'):
   b=bytearray(raw)
   if field=='access':struct.pack_into('>H',b,m['access_offset'],m['access']^1)
   else:
    val=m[field];at=m[field+'_offset'];b[at:at+len(val)]=val[:-1]+b'X'
   neg(cls+' '+name+' '+str(index)+' '+field,lambda:check_kotlin_class(parse(b),cls))
for cls in ('StaticTextMatch','InvokeTarget','FieldTarget','ReflectionMethodUsesQuery'):
 raw=(kt/(cls+'.class')).read_bytes();m=next(m for m in parse(raw)['methods'] if m['name']==b'<init>' and m['access']==1 and m['descriptor']!=b'()V')
 for field in ('name','descriptor','access'):
  b=bytearray(raw)
  if field=='access':struct.pack_into('>H',b,m['access_offset'],m['access']^1)
  else:
   val=m[field];at=m[field+'_offset'];b[at:at+len(val)]=val[:-1]+b'X'
  neg(cls+' constructor '+field,lambda:check_kotlin_class(parse(b),cls))
for cls in ('InvokeReferenceKind','FieldUseAccess'):
 b=bytearray((kt/(cls+'.class')).read_bytes());m=next(f for f in parse(b)['fields'] if f['access'] & 0x4000);struct.pack_into('>H',b,m['access_offset'],m['access']^1);neg(cls+' enum',lambda:check_kotlin_class(parse(b),cls))
for cls,field in [('ReflectionMethodPredicate','Companion'),('TypedReflectionMethodUsesExecution','INSTANCE')]:
 b=bytearray((kt/(cls+'.class')).read_bytes());m=next(f for f in parse(b)['fields'] if f['name']==field.encode());struct.pack_into('>H',b,m['access_offset'],m['access']^1);neg(cls+' '+field,lambda:check_kotlin_class(parse(b),cls))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
result={'outcome':'passed','scope':'real Java/Kotlin classfiles and targeted mutations; no Android or ART','java_classes':len(java),'new_kotlin_classes':len(names),'mutation_count':len(records),'mutations':records,'inputs':{str(p):sha(p) for p in [javapath/(n+'.class') for n in ['GraphResult', 'GraphResult$Binding', 'GraphResult$Entity', 'GraphResult$Input', 'GraphResult$Link', 'GraphResult$Operator', 'GraphResult$Profile', 'GraphResult$Reader', 'GraphResult$Row', 'GraphResult$Source', 'GraphResult$Witness', 'NativeEngine', 'NativeEngine$EntityCandidate', 'NativeEngine$EntityJob', 'NativeEngine$EntityJobPoll', 'NativeEngine$EntityJobStatus', 'NativeEngine$EntityResult', 'NativeEngine$GraphJob', 'NativeEngine$GraphJobPoll', 'NativeEngine$GraphJobStatus', 'NativeEngine$InputInfo', 'NativeEngine$Job', 'NativeEngine$JobPoll', 'NativeEngine$JobStatus', 'NativeEngine$MethodCandidate', 'NativeEngine$NativeFailure', 'NativeEngine$QueryResult', 'NativeEngine$RawDexSourceInfo', 'NativeEngine$Snapshot', 'NativeEngine$SnapshotInfo', 'NativeEngine$SourceSetInfo', 'NativeEngine$SourceSetSnapshot', 'UseGraphResult', 'UseGraphResult$Binding', 'UseGraphResult$Entity', 'UseGraphResult$Identity', 'UseGraphResult$Input', 'UseGraphResult$Link', 'UseGraphResult$Operator', 'UseGraphResult$Profile', 'UseGraphResult$Reader', 'UseGraphResult$Row', 'UseGraphResult$Source', 'UseGraphResult$Use', 'UseGraphResult$Value', 'UseGraphResult$Witness']+names]+[Path(__file__).resolve(),Path(__file__).with_name('jni_classfile.py'),Path(__file__).with_name('verify_aar.py')]}}
(out/'summary.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print('PASS',len(java),'Java classes',len(names),'Kotlin classes',len(records),'mutations')
