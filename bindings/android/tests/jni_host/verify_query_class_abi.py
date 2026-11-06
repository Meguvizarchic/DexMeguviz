"""Reject mutated JNI query signatures and constructors in Java classfiles."""
import argparse,struct,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from jni_classfile import ClassError,parse,verify_classfiles

p=argparse.ArgumentParser();p.add_argument('--classes',required=True,type=Path);a=p.parse_args()
prefix='io/github/jichuo1/dexmeguviz/'
names=['NativeEngine','NativeEngine$Snapshot','NativeEngine$SnapshotInfo','NativeEngine$NativeFailure','NativeEngine$MethodCandidate','NativeEngine$QueryResult','NativeEngine$SourceSetSnapshot','NativeEngine$SourceSetInfo','NativeEngine$RawDexSourceInfo','NativeEngine$InputInfo','NativeEngine$Job','NativeEngine$JobPoll','NativeEngine$JobStatus','NativeEngine$EntityCandidate','NativeEngine$EntityResult','NativeEngine$EntityJob','NativeEngine$EntityJobPoll','NativeEngine$EntityJobStatus','NativeEngine$GraphJob','NativeEngine$GraphJobPoll','NativeEngine$GraphJobStatus','GraphResult','GraphResult$Binding','GraphResult$Entity','GraphResult$Input','GraphResult$Link','GraphResult$Operator','GraphResult$Profile','GraphResult$Reader','GraphResult$Row','GraphResult$Source','GraphResult$Witness']
names += ['NativeEngine$ExpandJob', 'NativeEngine$ExpandJobPoll', 'ExpandResult', 'ExpandResult$Reader', 'ExpandResult$Profile', 'ExpandResult$Operator', 'ExpandResult$Input', 'ExpandResult$Source', 'ExpandResult$Entity', 'ExpandResult$Use', 'ExpandResult$Value', 'ExpandResult$Identity', 'ExpandResult$Binding', 'ExpandResult$Link', 'ExpandResult$ExpandProfile', 'ExpandResult$Witness', 'ExpandResult$Hop', 'ExpandResult$Evidence', 'ExpandResult$Path', 'ExpandResult$Row', 'ExpandResult$RowEvidence', 'ExpandResult$Frontier']
names += ['UseGraphResult', 'UseGraphResult$Binding', 'UseGraphResult$Entity', 'UseGraphResult$Identity', 'UseGraphResult$Input', 'UseGraphResult$Link', 'UseGraphResult$Operator', 'UseGraphResult$Profile', 'UseGraphResult$Reader', 'UseGraphResult$Row', 'UseGraphResult$Source', 'UseGraphResult$Use', 'UseGraphResult$Value', 'UseGraphResult$Witness']
names += ['NativeEngine$UseGraphJob','NativeEngine$UseGraphJobPoll','NativeEngine$UseGraphJobStatus']
names += ['GraphResult$ClassAnnotationFlags','NativeEngine$MethodTypeJob','NativeEngine$MethodTypeJobPoll','MethodTypeResult','MethodTypeResult$Reader','MethodTypeResult$Row','MethodTypeResult$Witness']
original={prefix+n+'.class':(a.classes/(prefix+n+'.class')).read_bytes() for n in names}
verify_classfiles(original)
targets=[('NativeEngine','nativeQueryUseGraphScopedV4',None),('NativeEngine$Snapshot','queryUseGraphScopedV4',None),('NativeEngine$SourceSetSnapshot','queryUseGraphScopedV4',None),('NativeEngine','nativeStartEntityJob',None),('NativeEngine','nativeEntityJobNext',None),('NativeEngine$EntityJob','<init>',None),('NativeEngine$EntityJobPoll','<init>',None),('NativeEngine','nativeQueryMethods',None),('NativeEngine','nativeOpenRawDexSet',None),('NativeEngine','nativeOpenSources',None),('NativeEngine','nativeSourceSetInfo',None),('NativeEngine','nativeQuerySourceSetMethods',None),('NativeEngine$MethodCandidate','<init>',b'(JJJJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V'),('NativeEngine$MethodCandidate','<init>',b'(JJJJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;IILjava/lang/String;Ljava/lang/String;)V'),('NativeEngine$QueryResult','<init>',None),('NativeEngine$SourceSetSnapshot','<init>',None),('NativeEngine$SourceSetInfo','<init>',b'(Ljava/lang/String;Z[Lio/github/jichuo1/dexmeguviz/NativeEngine$RawDexSourceInfo;)V'),('NativeEngine$SourceSetInfo','<init>',b'(Ljava/lang/String;Z[Lio/github/jichuo1/dexmeguviz/NativeEngine$RawDexSourceInfo;[Lio/github/jichuo1/dexmeguviz/NativeEngine$InputInfo;)V'),('NativeEngine$RawDexSourceInfo','<init>',b'(IIJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V'),('NativeEngine$RawDexSourceInfo','<init>',b'(IIJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V'),('NativeEngine$InputInfo','<init>',None)]
targets += [('NativeEngine','nativeOpenApkPaths',None),('NativeEngine','nativeOpenApkFdSources',None),('NativeEngine','openApkFdSources',None)]
targets += [('NativeEngine','nativeStartUseGraphJob',None),('NativeEngine','nativeUseGraphJobNext',None),('NativeEngine','nativeUseGraphJobStatus',None),('NativeEngine$Snapshot','startUseGraphJob',None),('NativeEngine$SourceSetSnapshot','startUseGraphJob',None),('NativeEngine$UseGraphJob','<init>',None),('NativeEngine$UseGraphJobPoll','<init>',None),('NativeEngine$UseGraphJobStatus','<init>',None),('UseGraphResult','decode',None)]
targets += [('NativeEngine','nativeQueryMethodType',None),('NativeEngine','nativeStartMethodTypeJob',None),('NativeEngine','nativeMethodTypeJobNext',None),('NativeEngine$Snapshot','queryMethodType',None),('NativeEngine$SourceSetSnapshot','startMethodTypeJob',None),('NativeEngine$MethodTypeJob','<init>',None),('NativeEngine$MethodTypeJobPoll','<init>',None),('MethodTypeResult','decode',None)]
for klass,method,descriptor in targets:
 for mode in ('name','descriptor','access'):
  key=prefix+klass+'.class';modified=bytearray(original[key]);entry=next(m for m in parse(modified)['methods'] if m['name']==method.encode() and (descriptor is None or m['descriptor']==descriptor))
  if mode=='name':
   at=entry['name_offset'];name=entry['name'];changed=name[:-2]+b'x>' if name==b'<init>' else name[:-1]+b'X';modified[at:at+len(name)]=changed
  elif mode=='descriptor':
   at=entry['descriptor_offset'];desc=entry['descriptor'];changed=desc.replace(b'J',b'I',1) if b'J' in desc else desc.replace(b'Z',b'I',1) if b'Z' in desc else desc.replace(b'I',b'J',1) if b'I' in desc else desc.replace(b'[B',b'[I',1);assert changed!=desc;modified[at:at+len(desc)]=changed
  else:struct.pack_into('>H',modified,entry['access_offset'],entry['access']^0x0003)
  forged=dict(original);forged[key]=bytes(modified)
  try:verify_classfiles(forged)
  except ClassError:continue
  raise AssertionError('mutation accepted: '+klass+' '+mode)
print('PASS JNI query name, descriptor and access forgery controls')

