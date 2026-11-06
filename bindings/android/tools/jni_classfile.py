"""Bounded fixed-profile JNI and selected public Java ABI classfile checks."""
import struct

class ClassError(ValueError): pass
METHOD_CALLS_CLASSES=['MethodCallsResult','MethodCallsResult$Reader','MethodCallsResult$Row']
METHOD_PARAMETERS_CLASSES=['MethodParametersResult','MethodParametersResult$Parameter','MethodParametersResult$Reader']
METHOD_FACTS_CLASSES=['MethodFactsResult','MethodFactsResult$Reader','MethodFactsResult$StringUse','MethodFactsResult$FieldUse','MethodFactsResult$NumberUse','MethodFactsResult$Invoke','MethodFactsResult$TypeUse','MethodFactsResult$Instruction']
SCOPED_METHOD_CLASSES=['ScopedMethodQuery','ScopedMethodQuery$Scope','ScopedMethodQuery$Result','ScopedMethodQuery$Job']
SOURCE_EXPORT_CLASSES=['DexSourceExport','DexStreamExport']
OPCODE_CLASSES=['OpcodeQuery']
METHOD_BATCH_CLASSES=['MethodBatchQuery','MethodBatchQuery$Result','MethodBatchQuery$Profile','MethodBatchQuery$Failure']
SCOPED_METHOD_BATCH_CLASSES=['ScopedMethodBatchQuery','ScopedMethodBatchQuery$Result','ScopedMethodBatchQuery$Scope']
CLASS_ANNOTATION_QUERY_CLASSES=['ClassAnnotationQuery']
SCOPED_CLASS_ANNOTATION_CLASSES=['ScopedClassAnnotationQuery','ScopedClassAnnotationQuery$Scope','ScopedClassAnnotationQuery$Result','ScopedClassAnnotationQuery$Job']
CLASS_ANNOTATION_STRING_CLASSES=['ClassAnnotationStringQuery','ScopedClassAnnotationStringQuery','ScopedClassAnnotationStringQuery$Scope','ScopedClassAnnotationStringQuery$Result','ScopedClassAnnotationStringQuery$Job']
SCOPED_OPCODE_CLASSES=['ScopedOpcodeQuery','ScopedOpcodeQuery$Scope','ScopedOpcodeQuery$Result']
ANNOTATION_CLASSES=['Annotations','Annotations$Target','Annotations$Limits','AnnotationResult','AnnotationResult$Reader','AnnotationResult$Item','AnnotationResult$Element']
ADVANCED_CLASSES=['NativeEngine$AdvancedJob', 'NativeEngine$AdvancedJobPoll', 'AdvancedResult', 'AdvancedResult$Reader', 'AdvancedResult$Profile', 'AdvancedResult$Operator', 'AdvancedResult$Input', 'AdvancedResult$Source', 'AdvancedResult$Entity', 'AdvancedResult$Binding', 'AdvancedResult$Link', 'AdvancedResult$Witness', 'AdvancedResult$Inherited', 'AdvancedResult$Numeric', 'AdvancedResult$InterfaceGraph', 'AdvancedResult$Row']
class Reader:
 def __init__(self,data):self.data=bytes(data);self.pos=0
 def take(self,n):
  if n<0 or n>len(self.data)-self.pos:raise ClassError('truncated classfile')
  out=self.data[self.pos:self.pos+n];self.pos+=n;return out
 def u1(self):return self.take(1)[0]
 def u2(self):return struct.unpack('>H',self.take(2))[0]
 def u4(self):return struct.unpack('>I',self.take(4))[0]

def parse(data):
 r=Reader(data)
 if r.u4()!=0xcafebabe:raise ClassError('bad classfile magic')
 minor,major=r.u2(),r.u2()
 if major!=61 or minor!=0:raise ClassError('class is not non-preview Java 17 version 61.0')
 count=r.u2();cp=[None]*count;i=1
 while i<count:
  tag=r.u1()
  if tag==1:
   size=r.u2();at=r.pos;cp[i]=(tag,r.take(size),at)
  elif tag==3:cp[i]=(tag,r.u4())
  elif tag==4:r.take(4);cp[i]=(tag,)
  elif tag in (5,6):
   r.take(8);cp[i]=(tag,);i+=1
   if i>=count:raise ClassError('invalid wide constant')
  elif tag in (7,8,16,19,20):cp[i]=(tag,r.u2())
  elif tag in (9,10,11,12,17,18):r.take(4);cp[i]=(tag,)
  elif tag==15:r.take(3);cp[i]=(tag,)
  else:raise ClassError('unknown constant pool tag')
  i+=1
 def item(index,tag):
  if not 0<index<count or cp[index] is None or cp[index][0]!=tag:raise ClassError('bad constant pool reference')
  return cp[index]
 def utf(index):return item(index,1)[1]
 def attrs():
  result=[]
  for _ in range(r.u2()):
   offset=r.pos;name=utf(r.u2());r.take(r.u4());result.append((name,offset))
  return result
 flags=r.u2();this=r.u2();super_offset=r.pos;super_index=r.u2();name=utf(item(this,7)[1])
 superclass=utf(item(super_index,7)[1]) if super_index else None
 for _ in range(r.u2()):item(r.u2(),7)
 fields=[]
 for _ in range(r.u2()):
  offset=r.pos;access=r.u2();name_index=r.u2();descriptor_index=r.u2()
  attributes=attrs()
  fields.append({'name':utf(name_index),'descriptor':utf(descriptor_index),'access':access,'access_offset':offset,'name_index_offset':offset+2,'descriptor_index_offset':offset+4,'attributes':attributes})
 methods=[]
 for _ in range(r.u2()):
  offset=r.pos;access=r.u2();name_index=r.u2();descriptor_index=r.u2()
  attributes=attrs()
  methods.append({'name':utf(name_index),'descriptor':utf(descriptor_index),'access':access,'access_offset':offset,'name_index_offset':offset+2,'descriptor_index_offset':offset+4,'name_offset':item(name_index,1)[2],'descriptor_offset':item(descriptor_index,1)[2],'attributes':attributes})
 attrs()
 if r.pos!=len(data):raise ClassError('trailing classfile bytes')
 utf_indexes={entry[1]:index for index,entry in enumerate(cp) if entry and entry[0]==1}
 return {'name':name,'superclass':superclass,'super_offset':super_offset,'flags':flags,'fields':fields,'methods':methods,'minor':minor,'major':major,'utf_indexes':utf_indexes,'constant_pool':cp,'data':r.data}

def require_method(clazz,name,descriptor,access):
 selected=[m for m in clazz['methods'] if m['name']==name]
 if len(selected)!=1 or selected[0]['descriptor']!=descriptor or selected[0]['access']!=access:
  raise ClassError('unexpected method name, descriptor, overload or access: '+name.decode('ascii'))
 return selected[0]

def require_field(clazz,name,descriptor,access):
 selected=[f for f in clazz['fields'] if f['name']==name]
 if len(selected)!=1 or selected[0]['descriptor']!=descriptor or selected[0]['access']!=access:
  raise ClassError('unexpected public field name, descriptor, duplicate or access: '+name.decode('ascii'))
 return selected[0]

def verify_classfiles(entries):
 prefix='io/github/jichuo1/dexmeguviz/'
 names=['NativeEngine','NativeEngine$Snapshot','NativeEngine$SnapshotInfo','NativeEngine$NativeFailure','NativeEngine$MethodCandidate','NativeEngine$QueryResult','NativeEngine$SourceSetSnapshot','NativeEngine$SourceSetInfo','NativeEngine$RawDexSourceInfo','NativeEngine$InputInfo','NativeEngine$Job','NativeEngine$JobPoll','NativeEngine$JobStatus','NativeEngine$EntityCandidate','NativeEngine$EntityResult','NativeEngine$EntityJob','NativeEngine$EntityJobPoll','NativeEngine$EntityJobStatus','NativeEngine$GraphJob','NativeEngine$GraphJobPoll','NativeEngine$GraphJobStatus','GraphResult','GraphResult$Binding','GraphResult$Entity','GraphResult$Input','GraphResult$Link','GraphResult$Operator','GraphResult$Profile','GraphResult$Reader','GraphResult$Row','GraphResult$Source','GraphResult$Witness','GraphResult$ClassAnnotationFlags']
 names += ['NativeEngine$MethodStream']
 names += ['UseGraphResult', 'UseGraphResult$Binding', 'UseGraphResult$Entity', 'UseGraphResult$Identity', 'UseGraphResult$Input', 'UseGraphResult$Link', 'UseGraphResult$Operator', 'UseGraphResult$Profile', 'UseGraphResult$Reader', 'UseGraphResult$Row', 'UseGraphResult$Source', 'UseGraphResult$Use', 'UseGraphResult$Value', 'UseGraphResult$Witness']
 names += ['NativeEngine$UseGraphJob','NativeEngine$UseGraphJobPoll','NativeEngine$UseGraphJobStatus']
 names += ['NativeEngine$MethodTypeJob','NativeEngine$MethodTypeJobPoll','MethodTypeResult','MethodTypeResult$Reader','MethodTypeResult$Row','MethodTypeResult$Witness']
 names += ['NativeEngine$ExpandJob', 'NativeEngine$ExpandJobPoll', 'ExpandResult', 'ExpandResult$Reader', 'ExpandResult$Profile', 'ExpandResult$Operator', 'ExpandResult$Input', 'ExpandResult$Source', 'ExpandResult$Entity', 'ExpandResult$Use', 'ExpandResult$Value', 'ExpandResult$Identity', 'ExpandResult$Binding', 'ExpandResult$Link', 'ExpandResult$ExpandProfile', 'ExpandResult$Witness', 'ExpandResult$Hop', 'ExpandResult$Evidence', 'ExpandResult$Path', 'ExpandResult$Row', 'ExpandResult$RowEvidence', 'ExpandResult$Frontier']
 names += ADVANCED_CLASSES+METHOD_CALLS_CLASSES+METHOD_FACTS_CLASSES+METHOD_PARAMETERS_CLASSES+SCOPED_METHOD_CLASSES+ANNOTATION_CLASSES+SOURCE_EXPORT_CLASSES+OPCODE_CLASSES+SCOPED_OPCODE_CLASSES+CLASS_ANNOTATION_QUERY_CLASSES+SCOPED_CLASS_ANNOTATION_CLASSES+CLASS_ANNOTATION_STRING_CLASSES+METHOD_BATCH_CLASSES+SCOPED_METHOD_BATCH_CLASSES
 parsed={name:parse(entries[prefix+name+'.class']) for name in names}
 parents={'NativeEngine':b'java/lang/Object','NativeEngine$Snapshot':b'java/lang/Object',
          'NativeEngine$SnapshotInfo':b'java/lang/Object','NativeEngine$NativeFailure':b'java/lang/RuntimeException',
          'NativeEngine$MethodCandidate':b'java/lang/Object','NativeEngine$QueryResult':b'java/lang/Object',
          'NativeEngine$SourceSetSnapshot':b'java/lang/Object','NativeEngine$SourceSetInfo':b'java/lang/Object','NativeEngine$RawDexSourceInfo':b'java/lang/Object','NativeEngine$InputInfo':b'java/lang/Object',
          'NativeEngine$Job':b'java/lang/Object','NativeEngine$JobPoll':b'java/lang/Object','NativeEngine$JobStatus':b'java/lang/Object',
          'NativeEngine$EntityCandidate':b'java/lang/Object','NativeEngine$EntityResult':b'java/lang/Object',
          'NativeEngine$EntityJob':b'java/lang/Object','NativeEngine$EntityJobPoll':b'java/lang/Object','NativeEngine$EntityJobStatus':b'java/lang/Object','NativeEngine$GraphJob':b'java/lang/Object','NativeEngine$GraphJobPoll':b'java/lang/Object','NativeEngine$GraphJobStatus':b'java/lang/Object','GraphResult':b'java/lang/Object','GraphResult$Binding':b'java/lang/Object','GraphResult$Entity':b'java/lang/Object','GraphResult$Input':b'java/lang/Object','GraphResult$Link':b'java/lang/Object','GraphResult$Operator':b'java/lang/Object','GraphResult$Profile':b'java/lang/Object','GraphResult$Reader':b'java/lang/Object','GraphResult$Row':b'java/lang/Object','GraphResult$Source':b'java/lang/Object','GraphResult$Witness':b'java/lang/Object','GraphResult$ClassAnnotationFlags':b'java/lang/Object'}
 parents['NativeEngine$MethodStream']=b'java/lang/Object'
 parents.update({name:b'java/lang/Object' for name in ['UseGraphResult', 'UseGraphResult$Binding', 'UseGraphResult$Entity', 'UseGraphResult$Identity', 'UseGraphResult$Input', 'UseGraphResult$Link', 'UseGraphResult$Operator', 'UseGraphResult$Profile', 'UseGraphResult$Reader', 'UseGraphResult$Row', 'UseGraphResult$Source', 'UseGraphResult$Use', 'UseGraphResult$Value', 'UseGraphResult$Witness']})
 parents.update({name:b'java/lang/Object' for name in ['NativeEngine$UseGraphJob','NativeEngine$UseGraphJobPoll','NativeEngine$UseGraphJobStatus']})
 parents.update({name:b'java/lang/Object' for name in ['NativeEngine$MethodTypeJob','NativeEngine$MethodTypeJobPoll','MethodTypeResult','MethodTypeResult$Reader','MethodTypeResult$Row','MethodTypeResult$Witness']})
 parents.update({name:b'java/lang/Object' for name in ['NativeEngine$ExpandJob', 'NativeEngine$ExpandJobPoll', 'ExpandResult', 'ExpandResult$Reader', 'ExpandResult$Profile', 'ExpandResult$Operator', 'ExpandResult$Input', 'ExpandResult$Source', 'ExpandResult$Entity', 'ExpandResult$Use', 'ExpandResult$Value', 'ExpandResult$Identity', 'ExpandResult$Binding', 'ExpandResult$Link', 'ExpandResult$ExpandProfile', 'ExpandResult$Witness', 'ExpandResult$Hop', 'ExpandResult$Evidence', 'ExpandResult$Path', 'ExpandResult$Row', 'ExpandResult$RowEvidence', 'ExpandResult$Frontier']})
 parents.update({name:b'java/lang/Object' for name in ADVANCED_CLASSES+METHOD_CALLS_CLASSES+METHOD_FACTS_CLASSES+METHOD_PARAMETERS_CLASSES+SCOPED_METHOD_CLASSES+ANNOTATION_CLASSES+SOURCE_EXPORT_CLASSES+OPCODE_CLASSES+SCOPED_OPCODE_CLASSES+CLASS_ANNOTATION_QUERY_CLASSES+SCOPED_CLASS_ANNOTATION_CLASSES+CLASS_ANNOTATION_STRING_CLASSES})
 parents.update({name:b'java/lang/Object' for name in METHOD_BATCH_CLASSES if name!='MethodBatchQuery$Failure'})
 parents['MethodBatchQuery$Failure']=b'java/lang/RuntimeException'
 parents.update({name:b'java/lang/Object' for name in SCOPED_METHOD_BATCH_CLASSES})
 for name,clazz in parsed.items():
  if clazz['name']!=(prefix+name).encode('ascii') or clazz['flags']!=(0x0030 if name in ('GraphResult$Reader','UseGraphResult$Reader','MethodTypeResult$Reader','ExpandResult$Reader','AdvancedResult$Reader','MethodCallsResult$Reader','MethodFactsResult$Reader','MethodParametersResult$Reader','AnnotationResult$Reader') else 0x0031):raise ClassError('unexpected JNI class identity/access: '+name)
  if clazz['superclass']!=parents[name]:raise ClassError('unexpected JNI class superclass: '+name)
 engine=parsed['NativeEngine']
 specs={b'abiVersion':(b'()I',0x0109),b'capabilities':(b'()Ljava/lang/String;',0x0109),
  b'nativeOpenRawDex':(b'([BLjava/lang/String;)J',0x010a),
  b'nativeOpenRawDexWithLimits':(b'([BLjava/lang/String;JJ)J',0x010a),
  b'nativeCreateMethodStream':(b'([[BJJ)J',0x010a),
  b'nativeOpenMethodStreamDex':(b'(J[BLjava/lang/String;)J',0x010a),
  b'nativeMethodStreamQuery':(b'(JJI)Lio/github/jichuo1/dexmeguviz/NativeEngine$QueryResult;',0x010a),
  b'nativeMethodStreamQueryBatch':(b'(JJ[IJJ)Lio/github/jichuo1/dexmeguviz/MethodBatchQuery$Result;',0x010a),
  b'nativeCloseMethodStream':(b'(J)V',0x010a),
  b'nativeSnapshotInfo':(b'(J)Lio/github/jichuo1/dexmeguviz/NativeEngine$SnapshotInfo;',0x010a),
  b'nativeClose':(b'(J)V',0x010a),
  b'nativeQueryMethods':(b'(J[B)Lio/github/jichuo1/dexmeguviz/NativeEngine$QueryResult;',0x010a),
  b'nativeOpenRawDexSet':(b'([[B[Ljava/lang/String;)J',0x010a),
  b'nativeOpenApkFdSources':(b'([I[J[J[Ljava/lang/String;[Z[Ljava/lang/String;[J[Ljava/lang/Object;)J',0x010a),
  b'nativeOpenApkPaths':(b'([[B[Ljava/lang/String;[Z[Ljava/lang/String;[J)J',0x010a),
  b'nativeOpenSources':(b'([[B[Ljava/lang/String;[I[Z)J',0x010a),
  b'nativeSourceSetInfo':(b'(J)Lio/github/jichuo1/dexmeguviz/NativeEngine$SourceSetInfo;',0x010a),
  b'nativeQuerySourceSetMethods':(b'(J[B)Lio/github/jichuo1/dexmeguviz/NativeEngine$QueryResult;',0x010a),
  b'nativeQueryExpand':(b'(J[BZ)[B',0x010a),
  b'nativeStartExpandJob':(b'(J[BZIIJ)J',0x010a),
  b'nativeExpandJobNext':(b'(JI)Lio/github/jichuo1/dexmeguviz/NativeEngine$ExpandJobPoll;',0x010a),
  b'nativeExpandJobStatus':(b'(JI)[B',0x010a),
  b'nativeInspectMethodCalls':(b'(JIJZIJJ)[B',0x010a),
  b'nativeInspectMethodFacts':(b'(JIJZIIJJ)[B',0x010a),
  b'nativeInspectMethodParameters':(b'(JIJZIIJJ)[B',0x010a),
  b'nativeQueryAdvanced':(b'(J[BZ)[B',0x010a),
  b'nativeStartAdvancedJob':(b'(J[BZIIJ)J',0x010a),
  b'nativeAdvancedJobNext':(b'(JI)Lio/github/jichuo1/dexmeguviz/NativeEngine$AdvancedJobPoll;',0x010a),
  b'nativeQueryMethodType':(b'(J[BZ)[B',0x010a),
  b'nativeStartMethodTypeJob':(b'(J[BZIIJ)J',0x010a),
  b'nativeMethodTypeJobNext':(b'(JI)Lio/github/jichuo1/dexmeguviz/NativeEngine$MethodTypeJobPoll;',0x010a),
  b'nativeQueryTypeUseGraph':(b'(J[BZ)[B',0x010a),
  b'nativeQueryInheritedUseGraph':(b'(J[BZ)[B',0x010a),
  b'nativeQueryInterfaceUseGraph':(b'(J[BZ)[B',0x010a),
  b'nativeStartInterfaceUseGraphJob':(b'(J[BZIIJ)J',0x010a),
  b'nativeStartInheritedUseGraphJob':(b'(J[BZIIJ)J',0x010a),
  b'nativeStartTypeUseGraphJob':(b'(J[BZIIJ)J',0x010a),
  b'nativeQueryClassAnnotationGraph':(b'(J[BZ)[B',0x010a),
  b'nativeQueryGraph':(b'(J[BZ)[B',0x010a),
  b'nativeQueryUseGraph':(b'(J[BZ)[B',0x010a),
  b'nativeQueryUseGraphScopedV4':(b'(J[BZ)[B',0x010a),
  b'nativeQueryFieldDeclarationGraph':(b'(J[BZ)[B',0x010a),
  b'nativeQueryCallerFieldRelationGraph':(b'(J[BZ)[[B',0x010a),
  b'nativeStartGraphJob':(b'(J[BZIIJ)J',0x010a),
  b'nativeGraphJobNext':(b'(JI)Lio/github/jichuo1/dexmeguviz/NativeEngine$GraphJobPoll;',0x010a),
  b'nativeStartUseGraphJob':(b'(J[BZIIJ)J',0x010a),
  b'nativeUseGraphJobNext':(b'(JI)Lio/github/jichuo1/dexmeguviz/NativeEngine$UseGraphJobPoll;',0x010a),
  b'nativeUseGraphJobStatus':(b'(JI)Lio/github/jichuo1/dexmeguviz/NativeEngine$UseGraphJobStatus;',0x010a),
  b'nativeQueryEntities':(b'(J[BZ)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityResult;',0x010a),
  b'nativeQueryReflectionMethodUses':(b'(J[BZ)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityResult;',0x010a),
  b'nativeStartReflectionMethodUsesJob':(b'(J[BZIIJ)J',0x010a),
  b'nativeStartMethodJob':(b'(J[BZIIJ)J',0x010a),
  b'nativeStartOpcodeJob':(b'(J[BZIIJ)J',0x010a),
  b'nativeStartEntityJob':(b'(J[BZIIJ)J',0x010a),
  b'nativeStartClassAnnotationJob':(b'(J[BZIIJ)J',0x010a),
  b'nativeStartClassAnnotationStringJob':(b'(J[BZIIJ)J',0x010a),
  b'nativeEntityJobNext':(b'(JI)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJobPoll;',0x010a),
  b'nativeJobNext':(b'(JI)Lio/github/jichuo1/dexmeguviz/NativeEngine$JobPoll;',0x010a),
  b'nativeJobStatus':(b'(JI)Lio/github/jichuo1/dexmeguviz/NativeEngine$JobStatus;',0x010a),
  b'nativeJobCancel':(b'(J)V',0x010a),b'nativeJobClose':(b'(J)V',0x010a)}
 for name,(descriptor,flags) in specs.items():
  method=require_method(engine,name,descriptor,flags)
  if any(attr[0]==b'Code' for attr in method['attributes']):raise ClassError('native JNI method has Code attribute')
 if {m['name'] for m in engine['methods'] if m['access']&0x100}!=set(specs):raise ClassError('unexpected native method set')
 for cls,descriptor in [('NativeEngine$MethodStream',b'(J)V'),('NativeEngine$SnapshotInfo',b'(IIIIIIJZLjava/lang/String;Ljava/lang/String;)V'),
                        ('NativeEngine$Snapshot',b'(J)V'),
                        ('NativeEngine$NativeFailure',b'(IJLjava/lang/String;)V'),
                        ('NativeEngine$QueryResult',b'(IIIIIIIJLjava/lang/String;Ljava/lang/String;[Lio/github/jichuo1/dexmeguviz/NativeEngine$MethodCandidate;)V'),
                        ('NativeEngine$SourceSetSnapshot',b'(J)V'),
                        ('NativeEngine$InputInfo',b'(IIIZZJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V'),
                        ('NativeEngine$Job',b'(J)V'),
                        ('NativeEngine$JobPoll',b'(ILio/github/jichuo1/dexmeguviz/NativeEngine$QueryResult;)V'),
                        ('NativeEngine$JobStatus',b'(IZIIIIIIIJJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V'),
                        ('NativeEngine$EntityCandidate',b'(IIIJJJZJZJZJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V'),
                        ('NativeEngine$EntityResult',b'(IIIIIIIIJLjava/lang/String;Ljava/lang/String;[Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityCandidate;)V'),
                        ('NativeEngine$EntityJob',b'(J)V'),
                        ('NativeEngine$EntityJobPoll',b'(ILio/github/jichuo1/dexmeguviz/NativeEngine$EntityResult;)V'),
                        ('NativeEngine$EntityJobStatus',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$JobStatus;)V'),
                        ('NativeEngine$GraphJob',b'(J)V'),
                        ('NativeEngine$GraphJobPoll',b'(ILio/github/jichuo1/dexmeguviz/GraphResult;)V'),
                        ('NativeEngine$GraphJobStatus',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$JobStatus;)V'),
                        ('NativeEngine$ExpandJob',b'(J)V'),
                        ('NativeEngine$ExpandJobPoll',b'(ILio/github/jichuo1/dexmeguviz/ExpandResult;)V'),
                        ('NativeEngine$AdvancedJob',b'(J)V'),
                        ('NativeEngine$AdvancedJobPoll',b'(ILio/github/jichuo1/dexmeguviz/AdvancedResult;)V'),
                        ('NativeEngine$MethodTypeJob',b'(J)V'),
                        ('NativeEngine$MethodTypeJobPoll',b'(ILio/github/jichuo1/dexmeguviz/MethodTypeResult;)V'),
                        ('NativeEngine$UseGraphJob',b'(J)V'),
                        ('NativeEngine$UseGraphJobPoll',b'(ILio/github/jichuo1/dexmeguviz/UseGraphResult;)V'),
                        ('NativeEngine$UseGraphJobStatus',b'([JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V')]:
  ctor=require_method(parsed[cls],b'<init>',descriptor,0x0002)
  if sum(attr[0]==b'Code' for attr in ctor['attributes'])!=1:raise ClassError('JNI constructor must have one Code attribute')
 old=b'(JJJJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V'
 new=b'(JJJJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;IILjava/lang/String;Ljava/lang/String;)V'
 constructors=[m for m in parsed['NativeEngine$MethodCandidate']['methods'] if m['name']==b'<init>']
 if len(constructors)!=2 or {m['descriptor'] for m in constructors}!={old,new} or any(m['access']!=0x0002 or sum(a[0]==b'Code' for a in m['attributes'])!=1 for m in constructors):
  raise ClassError('unexpected MethodCandidate constructor overloads')
 for cls,descriptors in {
  'NativeEngine$SourceSetInfo':{b'(Ljava/lang/String;Z[Lio/github/jichuo1/dexmeguviz/NativeEngine$RawDexSourceInfo;)V',b'(Ljava/lang/String;Z[Lio/github/jichuo1/dexmeguviz/NativeEngine$RawDexSourceInfo;[Lio/github/jichuo1/dexmeguviz/NativeEngine$InputInfo;)V'},
  'NativeEngine$RawDexSourceInfo':{b'(IIJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V',b'(IIJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V'}}.items():
  ctors=[m for m in parsed[cls]['methods'] if m['name']==b'<init>']
  if len(ctors)!=len(descriptors) or {m['descriptor'] for m in ctors}!=descriptors or any(m['access']!=0x0002 or sum(a[0]==b'Code' for a in m['attributes'])!=1 for m in ctors):raise ClassError('unexpected constructor overloads: '+cls)
 # Fixed public multi-source surface, not a general Java ABI verifier.
 require_method(parsed['NativeEngine'],b'openMethodStream',b'([[BJJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$MethodStream;',0x0009)
 for name,descriptor in [(b'openRawDex',b'([BLjava/lang/String;)Lio/github/jichuo1/dexmeguviz/NativeEngine$Snapshot;'),
                         (b'queryMethods',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$Snapshot;I)Lio/github/jichuo1/dexmeguviz/NativeEngine$QueryResult;'),
                         (b'queryMethodsBatch',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$Snapshot;[IJJ)Lio/github/jichuo1/dexmeguviz/MethodBatchQuery$Result;'),
                         (b'close',b'()V')]:
  require_method(parsed['NativeEngine$MethodStream'],name,descriptor,0x0021)
 public_methods={
  'NativeEngine': [(b'openRawDexWithLimits',b'([BLjava/lang/String;JJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$Snapshot;',0x0009),(b'openApkFdSources',b'([I[J[J[Ljava/lang/String;[Z[Ljava/lang/String;Lio/github/jichuo1/dexmeguviz/ApkFdLimits;)Lio/github/jichuo1/dexmeguviz/NativeEngine$SourceSetSnapshot;',0x0009),(b'openRawDexSet',b'([[B[Ljava/lang/String;)Lio/github/jichuo1/dexmeguviz/NativeEngine$SourceSetSnapshot;',0x0009),(b'openSources',b'([[B[Ljava/lang/String;[I[Z)Lio/github/jichuo1/dexmeguviz/NativeEngine$SourceSetSnapshot;',0x0009)],
  'NativeEngine$Snapshot': [(b'queryReflectionMethodUses',b'([B)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityResult;',0x0021),(b'startReflectionMethodUsesJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJob;',0x0021),(b'queryUseGraph',b'([B)Lio/github/jichuo1/dexmeguviz/UseGraphResult;',0x0021),(b'queryInheritedUseGraph',b'([B)Lio/github/jichuo1/dexmeguviz/UseGraphResult;',0x0021),(b'queryInterfaceUseGraph',b'([B)Lio/github/jichuo1/dexmeguviz/UseGraphResult;',0x0021),(b'startInterfaceUseGraphJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$UseGraphJob;',0x0021),(b'startInheritedUseGraphJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$UseGraphJob;',0x0021),(b'queryUseGraphScopedV4',b'([B)Lio/github/jichuo1/dexmeguviz/UseGraphResult;',0x0021),(b'startMethodJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$Job;',0x0021),(b'startOpcodeJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$Job;',0x0021),
    (b'queryGraph',b'([B)Lio/github/jichuo1/dexmeguviz/GraphResult;',0x0021),
    (b'startGraphJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$GraphJob;',0x0021),
    (b'queryEntities',b'([B)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityResult;',0x0021),
    (b'startEntityJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJob;',0x0021),(b'startClassAnnotationJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJob;',0x0021),(b'startClassAnnotationStringJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJob;',0x0021)],
  'NativeEngine$SourceSetSnapshot': [(b'queryReflectionMethodUses',b'([B)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityResult;',0x0021),(b'startReflectionMethodUsesJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJob;',0x0021),(b'queryUseGraph',b'([B)Lio/github/jichuo1/dexmeguviz/UseGraphResult;',0x0021),(b'queryInheritedUseGraph',b'([B)Lio/github/jichuo1/dexmeguviz/UseGraphResult;',0x0021),(b'queryInterfaceUseGraph',b'([B)Lio/github/jichuo1/dexmeguviz/UseGraphResult;',0x0021),(b'startInterfaceUseGraphJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$UseGraphJob;',0x0021),(b'startInheritedUseGraphJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$UseGraphJob;',0x0021),(b'queryUseGraphScopedV4',b'([B)Lio/github/jichuo1/dexmeguviz/UseGraphResult;',0x0021),(b'info',b'()Lio/github/jichuo1/dexmeguviz/NativeEngine$SourceSetInfo;',0x0021),
    (b'queryMethods',b'([B)Lio/github/jichuo1/dexmeguviz/NativeEngine$QueryResult;',0x0021),(b'close',b'()V',0x0021),
    (b'startMethodJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$Job;',0x0021),(b'startOpcodeJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$Job;',0x0021),
    (b'queryGraph',b'([B)Lio/github/jichuo1/dexmeguviz/GraphResult;',0x0021),
    (b'startGraphJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$GraphJob;',0x0021),
    (b'queryEntities',b'([B)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityResult;',0x0021),
    (b'startEntityJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJob;',0x0021),(b'startClassAnnotationJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJob;',0x0021),(b'startClassAnnotationStringJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJob;',0x0021)],
  'NativeEngine$EntityResult':[(b'candidateCount',b'()I',0x0001),
    (b'candidate',b'(I)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityCandidate;',0x0001)],
  'NativeEngine$EntityJob':[(b'next',b'(I)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJobPoll;',0x0001),
    (b'status',b'()Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJobStatus;',0x0001),
    (b'waitFor',b'(I)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJobStatus;',0x0001),
    (b'cancel',b'()V',0x0001),(b'close',b'()V',0x0001)],
  'NativeEngine$GraphJob':[(b'next',b'(I)Lio/github/jichuo1/dexmeguviz/NativeEngine$GraphJobPoll;',0x0001),
    (b'status',b'()Lio/github/jichuo1/dexmeguviz/NativeEngine$GraphJobStatus;',0x0001),
    (b'waitFor',b'(I)Lio/github/jichuo1/dexmeguviz/NativeEngine$GraphJobStatus;',0x0001),
    (b'cancel',b'()V',0x0001),(b'close',b'()V',0x0001)],
  'NativeEngine$Job':[(b'next',b'(I)Lio/github/jichuo1/dexmeguviz/NativeEngine$JobPoll;',0x0001),
    (b'status',b'()Lio/github/jichuo1/dexmeguviz/NativeEngine$JobStatus;',0x0001),
    (b'waitFor',b'(I)Lio/github/jichuo1/dexmeguviz/NativeEngine$JobStatus;',0x0001),
    (b'cancel',b'()V',0x0001),(b'close',b'()V',0x0001)],
  'NativeEngine$SourceSetInfo': [(b'sourceCount',b'()I',0x0001),(b'source',b'(I)Lio/github/jichuo1/dexmeguviz/NativeEngine$RawDexSourceInfo;',0x0001),(b'inputCount',b'()I',0x0001),(b'input',b'(I)Lio/github/jichuo1/dexmeguviz/NativeEngine$InputInfo;',0x0001)]}
 for cls in ('NativeEngine$Snapshot','NativeEngine$SourceSetSnapshot'):
  public_methods[cls].append((b'queryClassAnnotationGraph',b'([B)Lio/github/jichuo1/dexmeguviz/GraphResult;',0x0021))
  public_methods[cls].append((b'queryMethodType',b'([B)Lio/github/jichuo1/dexmeguviz/MethodTypeResult;',0x0021))
  public_methods[cls].append((b'queryAdvanced',b'([B)Lio/github/jichuo1/dexmeguviz/AdvancedResult;',0x0021))
  public_methods[cls].append((b'startMethodTypeJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$MethodTypeJob;',0x0021))
  public_methods[cls].append((b'startAdvancedJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$AdvancedJob;',0x0021))
  public_methods[cls].append((b'queryTypeUseGraph',b'([B)Lio/github/jichuo1/dexmeguviz/UseGraphResult;',0x0021))
  public_methods[cls].append((b'startTypeUseGraphJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$UseGraphJob;',0x0021))
  public_methods[cls].append((b'startUseGraphJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$UseGraphJob;',0x0021))
 public_methods['NativeEngine$MethodTypeJob']=[(b'next',b'(I)Lio/github/jichuo1/dexmeguviz/NativeEngine$MethodTypeJobPoll;',1),(b'status',b'()Lio/github/jichuo1/dexmeguviz/NativeEngine$JobStatus;',1),(b'waitFor',b'(I)Lio/github/jichuo1/dexmeguviz/NativeEngine$JobStatus;',1),(b'cancel',b'()V',1),(b'close',b'()V',1)]
 for cls in ('NativeEngine$Snapshot','NativeEngine$SourceSetSnapshot'):
  first='I' if cls.endswith('SourceSetSnapshot') else ''
  public_methods[cls].extend([(b'inspectMethodCalls',('('+first+'J)Lio/github/jichuo1/dexmeguviz/MethodCallsResult;').encode('ascii'),0x0021),(b'inspectMethodCalls',('('+first+'JIJJ)Lio/github/jichuo1/dexmeguviz/MethodCallsResult;').encode('ascii'),0x0021)])
 public_methods['NativeEngine$AdvancedJob']=[(b'next',b'(I)Lio/github/jichuo1/dexmeguviz/NativeEngine$AdvancedJobPoll;',1),(b'status',b'()Lio/github/jichuo1/dexmeguviz/NativeEngine$JobStatus;',1),(b'waitFor',b'(I)Lio/github/jichuo1/dexmeguviz/NativeEngine$JobStatus;',1),(b'cancel',b'()V',1),(b'close',b'()V',1)]
 public_methods['NativeEngine$UseGraphJob']=[(b'next',b'(I)Lio/github/jichuo1/dexmeguviz/NativeEngine$UseGraphJobPoll;',1),(b'status',b'()Lio/github/jichuo1/dexmeguviz/NativeEngine$UseGraphJobStatus;',1),(b'waitFor',b'(I)Lio/github/jichuo1/dexmeguviz/NativeEngine$UseGraphJobStatus;',1),(b'cancel',b'()V',1),(b'close',b'()V',1)]
 for cls in ('NativeEngine$Snapshot','NativeEngine$SourceSetSnapshot'):
  public_methods[cls] += [(b'queryExpand',b'([B)Lio/github/jichuo1/dexmeguviz/ExpandResult;',33),(b'startExpandJob',b'([BIIJ)Lio/github/jichuo1/dexmeguviz/NativeEngine$ExpandJob;',33)]
 public_methods['NativeEngine$ExpandJob']=[(b'next',b'(I)Lio/github/jichuo1/dexmeguviz/NativeEngine$ExpandJobPoll;',1),(b'status',b'()Lio/github/jichuo1/dexmeguviz/ExpandResult;',1),(b'waitFor',b'(I)Lio/github/jichuo1/dexmeguviz/ExpandResult;',1),(b'cancel',b'()V',1),(b'close',b'()V',1)]
 public_methods['NativeEngine$Snapshot'] += [(b'inspectMethodFacts',b'(JIIJJ)Lio/github/jichuo1/dexmeguviz/MethodFactsResult;',33)]
 for cls in ('NativeEngine$Snapshot','NativeEngine$SourceSetSnapshot'):
  first='I' if cls.endswith('SourceSetSnapshot') else ''
  public_methods[cls].extend([(b'inspectMethodParameters',('('+first+'J)Lio/github/jichuo1/dexmeguviz/MethodParametersResult;').encode('ascii'),33),(b'inspectMethodParameters',('('+first+'JIIJJ)Lio/github/jichuo1/dexmeguviz/MethodParametersResult;').encode('ascii'),33)])
 public_methods['NativeEngine$SourceSetSnapshot'] += [(b'inspectMethodFacts',b'(IJIIJJ)Lio/github/jichuo1/dexmeguviz/MethodFactsResult;',33)]
 # Exact JNI entrypoints and private constructors for the explicit scope wrapper.
 scope=parsed['ScopedMethodQuery'];result_desc=b'Lio/github/jichuo1/dexmeguviz/ScopedMethodQuery$Result;';job_desc=b'Lio/github/jichuo1/dexmeguviz/ScopedMethodQuery$Job;'
 for name,descriptor in [(b'nativeExecute',b'(Ljava/lang/Object;Z[B)'+result_desc),(b'nativeStart',b'(Ljava/lang/Object;Z[BIIJ)'+job_desc)]:require_method(scope,name,descriptor,0x010a)
 for cls,descriptor in [('ScopedMethodQuery$Result',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$QueryResult;[Ljava/lang/String;[I)V'),('ScopedMethodQuery$Job',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$Job;[Ljava/lang/String;[I)V')]:require_method(parsed[cls],b'<init>',descriptor,2)
 require_method(parsed['ScopedMethodQuery$Scope'],b'<init>',b'([Ljava/lang/String;[I)V',2)
 for name,suffix,returned in [(b'execute',b'[B',result_desc),(b'start',b'[BIIJ',job_desc)]:
  expected={(b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$'+kind+b';'+suffix+b')'+returned,9) for kind in (b'Snapshot',b'SourceSetSnapshot')}
  actual={(m['descriptor'],m['access']) for m in scope['methods'] if m['name']==name}
  if actual!=expected:raise ClassError('unexpected ScopedMethodQuery overloads')
 for cls,field,descriptor in [('ScopedMethodQuery$Result',b'query',b'Lio/github/jichuo1/dexmeguviz/NativeEngine$QueryResult;'),('ScopedMethodQuery$Result',b'scope',b'Lio/github/jichuo1/dexmeguviz/ScopedMethodQuery$Scope;'),('ScopedMethodQuery$Job',b'scope',b'Lio/github/jichuo1/dexmeguviz/ScopedMethodQuery$Scope;')]:require_field(parsed[cls],field,descriptor,17)
 for name,descriptor in [(b'inputSlotCount',b'()I'),(b'inputSlot',b'(I)Ljava/lang/String;'),(b'sourceCount',b'()I'),(b'sourceIndex',b'(I)I')]:require_method(parsed['ScopedMethodQuery$Scope'],name,descriptor,1)
 for name,descriptor in [(b'next',b'(I)Lio/github/jichuo1/dexmeguviz/NativeEngine$JobPoll;'),(b'status',b'()Lio/github/jichuo1/dexmeguviz/NativeEngine$JobStatus;'),(b'waitFor',b'(I)Lio/github/jichuo1/dexmeguviz/NativeEngine$JobStatus;'),(b'cancel',b'()V'),(b'close',b'()V')]:require_method(parsed['ScopedMethodQuery$Job'],name,descriptor,1)
 for field,descriptor in [(b'provenance',b'Ljava/lang/String;'),(b'snapshotScopeComplete',b'Z'),(b'sourceScopeAuthenticated',b'Z')]:require_field(parsed['ScopedMethodQuery$Scope'],field,descriptor,17)
 batch=parsed['MethodBatchQuery'];batch_prefix=b'io/github/jichuo1/dexmeguviz/';batch_result=b'L'+batch_prefix+b'MethodBatchQuery$Result;'
 require_method(batch,b'<init>',b'()V',2)
 require_method(batch,b'nativeExecute',b'(Ljava/lang/Object;Z[[BJJ)'+batch_result,0x010a)
 batch_overloads={(b'(L'+batch_prefix+b'NativeEngine$'+kind+b';[[BJJ)'+batch_result,9) for kind in (b'Snapshot',b'SourceSetSnapshot')}
 methods=[m for m in batch['methods'] if m['name']==b'execute']
 if len(methods)!=2 or {(m['descriptor'],m['access']) for m in methods}!=batch_overloads or any(sum(a[0]==b'Code' for a in m['attributes'])!=1 for m in methods):raise ClassError('unexpected MethodBatchQuery execute overloads')
 require_method(parsed['MethodBatchQuery$Result'],b'<init>',b'([L'+batch_prefix+b'NativeEngine$QueryResult;L'+batch_prefix+b'MethodBatchQuery$Profile;)V',2)
 require_method(parsed['MethodBatchQuery$Result'],b'size',b'()I',1)
 require_method(parsed['MethodBatchQuery$Result'],b'get',b'(I)L'+batch_prefix+b'NativeEngine$QueryResult;',1)
 require_field(parsed['MethodBatchQuery$Result'],b'profile',b'L'+batch_prefix+b'MethodBatchQuery$Profile;',17)
 require_method(parsed['MethodBatchQuery$Profile'],b'<init>',b'(JJJJJJJZ)V',2)
 for field in (b'physicalCollects',b'cacheHits',b'cacheBuilds',b'traceOverflows',b'cacheRejections',b'replayFailures',b'cacheWorkCharged'):require_field(parsed['MethodBatchQuery$Profile'],field,b'J',17)
 require_field(parsed['MethodBatchQuery$Profile'],b'arenaBudgetUnavailable',b'Z',17)
 require_method(parsed['MethodBatchQuery$Failure'],b'<init>',b'(IIJLjava/lang/String;)V',2)
 for field in (b'status',b'failureIndex'):require_field(parsed['MethodBatchQuery$Failure'],field,b'I',17)
 require_field(parsed['MethodBatchQuery$Failure'],b'errorOffset',b'J',17)
 scoped_batch=parsed['ScopedMethodBatchQuery'];sb_prefix=b'io/github/jichuo1/dexmeguviz/';sb_result=b'L'+sb_prefix+b'ScopedMethodBatchQuery$Result;'
 require_method(scoped_batch,b'<init>',b'()V',2)
 require_method(scoped_batch,b'nativeExecute',b'(Ljava/lang/Object;Z[[BJJ)'+sb_result,0x010a)
 sb_overloads={(b'(L'+sb_prefix+b'NativeEngine$'+kind+b';[[BJJ)'+sb_result,9) for kind in (b'Snapshot',b'SourceSetSnapshot')}
 methods=[m for m in scoped_batch['methods'] if m['name']==b'execute']
 if len(methods)!=2 or {(m['descriptor'],m['access']) for m in methods}!=sb_overloads or any(sum(a[0]==b'Code' for a in m['attributes'])!=1 for m in methods):raise ClassError('unexpected ScopedMethodBatchQuery overloads')
 require_method(parsed['ScopedMethodBatchQuery$Result'],b'<init>',b'([L'+sb_prefix+b'NativeEngine$QueryResult;L'+sb_prefix+b'MethodBatchQuery$Profile;[Ljava/lang/String;[I)V',2)
 require_method(parsed['ScopedMethodBatchQuery$Scope'],b'<init>',b'([Ljava/lang/String;[I)V',2)
 require_method(parsed['ScopedMethodBatchQuery$Result'],b'size',b'()I',1)
 require_method(parsed['ScopedMethodBatchQuery$Result'],b'get',b'(I)L'+sb_prefix+b'NativeEngine$QueryResult;',1)
 require_field(parsed['ScopedMethodBatchQuery$Result'],b'profile',b'L'+sb_prefix+b'MethodBatchQuery$Profile;',17)
 require_field(parsed['ScopedMethodBatchQuery$Result'],b'scope',b'L'+sb_prefix+b'ScopedMethodBatchQuery$Scope;',17)
 for name,descriptor in [(b'inputSlotCount',b'()I'),(b'inputSlot',b'(I)Ljava/lang/String;'),(b'sourceCount',b'()I'),(b'sourceIndex',b'(I)I')]:require_method(parsed['ScopedMethodBatchQuery$Scope'],name,descriptor,1)
 for field,descriptor in [(b'provenance',b'Ljava/lang/String;'),(b'snapshotScopeComplete',b'Z'),(b'sourceScopeAuthenticated',b'Z')]:require_field(parsed['ScopedMethodBatchQuery$Scope'],field,descriptor,17)
 opcode=parsed['OpcodeQuery'];opcode_prefix=b'io/github/jichuo1/dexmeguviz/'
 require_method(opcode,b'<init>',b'()V',2)
 require_method(opcode,b'nativeExecute',b'(Ljava/lang/Object;Z[B)L'+opcode_prefix+b'NativeEngine$QueryResult;',0x010a)
 opcode_overloads={(b'(L'+opcode_prefix+b'NativeEngine$Snapshot;[B)L'+opcode_prefix+b'NativeEngine$QueryResult;',9),(b'(L'+opcode_prefix+b'NativeEngine$SourceSetSnapshot;[B)L'+opcode_prefix+b'NativeEngine$QueryResult;',9)}
 methods=[m for m in opcode['methods'] if m['name']==b'execute']
 if len(methods)!=2 or {(m['descriptor'],m['access']) for m in methods}!=opcode_overloads or any(sum(a[0]==b'Code' for a in m['attributes'])!=1 for m in methods):raise ClassError('unexpected OpcodeQuery execute overloads')
 opcode_jobs={(b'(L'+opcode_prefix+b'NativeEngine$'+kind+b';[BIIJ)L'+opcode_prefix+b'NativeEngine$Job;',9) for kind in (b'Snapshot',b'SourceSetSnapshot')}
 methods=[m for m in opcode['methods'] if m['name']==b'startJob']
 if len(methods)!=2 or {(m['descriptor'],m['access']) for m in methods}!=opcode_jobs or any(sum(a[0]==b'Code' for a in m['attributes'])!=1 for m in methods):raise ClassError('unexpected OpcodeQuery startJob overloads')
 annotation_query=parsed['ClassAnnotationQuery'];annotation_prefix=b'io/github/jichuo1/dexmeguviz/'
 require_method(annotation_query,b'<init>',b'()V',2)
 require_method(annotation_query,b'nativeExecute',b'(Ljava/lang/Object;Z[B)L'+annotation_prefix+b'NativeEngine$EntityResult;',0x010a)
 annotation_overloads={(b'(L'+annotation_prefix+b'NativeEngine$'+kind+b';[B)L'+annotation_prefix+b'NativeEngine$EntityResult;',9) for kind in (b'Snapshot',b'SourceSetSnapshot')}
 methods=[m for m in annotation_query['methods'] if m['name']==b'execute']
 if len(methods)!=2 or {(m['descriptor'],m['access']) for m in methods}!=annotation_overloads or any(sum(a[0]==b'Code' for a in m['attributes'])!=1 for m in methods):raise ClassError('unexpected ClassAnnotationQuery overloads')
 annotation_jobs={(b'(L'+annotation_prefix+b'NativeEngine$'+kind+b';[BIIJ)L'+annotation_prefix+b'NativeEngine$EntityJob;',9) for kind in (b'Snapshot',b'SourceSetSnapshot')}
 methods=[m for m in annotation_query['methods'] if m['name']==b'startJob']
 if len(methods)!=2 or {(m['descriptor'],m['access']) for m in methods}!=annotation_jobs or any(sum(a[0]==b'Code' for a in m['attributes'])!=1 for m in methods):raise ClassError('unexpected ClassAnnotationQuery startJob overloads')
 scoped_class_annotation=parsed['ScopedClassAnnotationQuery'];scoped_class_result=b'Lio/github/jichuo1/dexmeguviz/ScopedClassAnnotationQuery$Result;'
 require_method(scoped_class_annotation,b'<init>',b'()V',2)
 require_method(scoped_class_annotation,b'nativeExecute',b'(Ljava/lang/Object;Z[B)'+scoped_class_result,0x010a)
 require_method(parsed['ScopedClassAnnotationQuery$Result'],b'<init>',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityResult;[Ljava/lang/String;[I)V',2)
 require_method(parsed['ScopedClassAnnotationQuery$Scope'],b'<init>',b'([Ljava/lang/String;[I)V',2)
 scoped_class_overloads={(b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$'+kind+b';[B)'+scoped_class_result,9) for kind in (b'Snapshot',b'SourceSetSnapshot')}
 methods=[m for m in scoped_class_annotation['methods'] if m['name']==b'execute']
 if len(methods)!=2 or {(m['descriptor'],m['access']) for m in methods}!=scoped_class_overloads or any(sum(a[0]==b'Code' for a in m['attributes'])!=1 for m in methods):raise ClassError('unexpected ScopedClassAnnotationQuery overloads')
 for cls,field,descriptor in [('ScopedClassAnnotationQuery$Result',b'query',b'Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityResult;'),('ScopedClassAnnotationQuery$Result',b'scope',b'Lio/github/jichuo1/dexmeguviz/ScopedClassAnnotationQuery$Scope;')]:require_field(parsed[cls],field,descriptor,17)
 for name,descriptor in [(b'inputSlotCount',b'()I'),(b'inputSlot',b'(I)Ljava/lang/String;'),(b'sourceCount',b'()I'),(b'sourceIndex',b'(I)I')]:require_method(parsed['ScopedClassAnnotationQuery$Scope'],name,descriptor,1)
 for field,descriptor in [(b'provenance',b'Ljava/lang/String;'),(b'snapshotScopeComplete',b'Z'),(b'sourceScopeAuthenticated',b'Z')]:require_field(parsed['ScopedClassAnnotationQuery$Scope'],field,descriptor,17)
 annotation_query=parsed['ClassAnnotationStringQuery'];annotation_prefix=b'io/github/jichuo1/dexmeguviz/'
 require_method(annotation_query,b'<init>',b'()V',2)
 require_method(annotation_query,b'nativeExecute',b'(Ljava/lang/Object;Z[B)L'+annotation_prefix+b'NativeEngine$EntityResult;',0x010a)
 annotation_overloads={(b'(L'+annotation_prefix+b'NativeEngine$'+kind+b';[B)L'+annotation_prefix+b'NativeEngine$EntityResult;',9) for kind in (b'Snapshot',b'SourceSetSnapshot')}
 methods=[m for m in annotation_query['methods'] if m['name']==b'execute']
 if len(methods)!=2 or {(m['descriptor'],m['access']) for m in methods}!=annotation_overloads or any(sum(a[0]==b'Code' for a in m['attributes'])!=1 for m in methods):raise ClassError('unexpected ClassAnnotationStringQuery overloads')
 annotation_jobs={(b'(L'+annotation_prefix+b'NativeEngine$'+kind+b';[BIIJ)L'+annotation_prefix+b'NativeEngine$EntityJob;',9) for kind in (b'Snapshot',b'SourceSetSnapshot')}
 methods=[m for m in annotation_query['methods'] if m['name']==b'startJob']
 if len(methods)!=2 or {(m['descriptor'],m['access']) for m in methods}!=annotation_jobs or any(sum(a[0]==b'Code' for a in m['attributes'])!=1 for m in methods):raise ClassError('unexpected ClassAnnotationStringQuery startJob overloads')
 scoped_class_annotation=parsed['ScopedClassAnnotationStringQuery'];scoped_class_result=b'Lio/github/jichuo1/dexmeguviz/ScopedClassAnnotationStringQuery$Result;'
 require_method(scoped_class_annotation,b'<init>',b'()V',2)
 require_method(scoped_class_annotation,b'nativeExecute',b'(Ljava/lang/Object;Z[B)'+scoped_class_result,0x010a)
 require_method(parsed['ScopedClassAnnotationStringQuery$Result'],b'<init>',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityResult;[Ljava/lang/String;[I)V',2)
 require_method(parsed['ScopedClassAnnotationStringQuery$Scope'],b'<init>',b'([Ljava/lang/String;[I)V',2)
 scoped_class_overloads={(b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$'+kind+b';[B)'+scoped_class_result,9) for kind in (b'Snapshot',b'SourceSetSnapshot')}
 methods=[m for m in scoped_class_annotation['methods'] if m['name']==b'execute']
 if len(methods)!=2 or {(m['descriptor'],m['access']) for m in methods}!=scoped_class_overloads or any(sum(a[0]==b'Code' for a in m['attributes'])!=1 for m in methods):raise ClassError('unexpected ScopedClassAnnotationStringQuery overloads')
 for cls,field,descriptor in [('ScopedClassAnnotationStringQuery$Result',b'query',b'Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityResult;'),('ScopedClassAnnotationStringQuery$Result',b'scope',b'Lio/github/jichuo1/dexmeguviz/ScopedClassAnnotationStringQuery$Scope;')]:require_field(parsed[cls],field,descriptor,17)
 for name,descriptor in [(b'inputSlotCount',b'()I'),(b'inputSlot',b'(I)Ljava/lang/String;'),(b'sourceCount',b'()I'),(b'sourceIndex',b'(I)I')]:require_method(parsed['ScopedClassAnnotationStringQuery$Scope'],name,descriptor,1)
 for field,descriptor in [(b'provenance',b'Ljava/lang/String;'),(b'snapshotScopeComplete',b'Z'),(b'sourceScopeAuthenticated',b'Z')]:require_field(parsed['ScopedClassAnnotationStringQuery$Scope'],field,descriptor,17)
 for class_name in ('ScopedClassAnnotationQuery','ScopedClassAnnotationStringQuery'):
  bridge=parsed[class_name];job_type=b'Lio/github/jichuo1/dexmeguviz/'+class_name.encode()+b'$Job;'
  require_method(bridge,b'nativeStart',b'(Ljava/lang/Object;Z[BIIJ)'+job_type,0x010a)
  require_method(parsed[class_name+'$Job'],b'<init>',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJob;[Ljava/lang/String;[I)V',2)
  wanted={(b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$'+kind+b';[BIIJ)'+job_type,9) for kind in (b'Snapshot',b'SourceSetSnapshot')}
  methods=[m for m in bridge['methods'] if m['name']==b'start']
  if len(methods)!=2 or {(m['descriptor'],m['access']) for m in methods}!=wanted or any(sum(a[0]==b'Code' for a in m['attributes'])!=1 for m in methods):raise ClassError('unexpected scoped annotation start overloads')
  require_field(parsed[class_name+'$Job'],b'scope',b'Lio/github/jichuo1/dexmeguviz/'+class_name.encode()+b'$Scope;',17)
  for name,descriptor in [(b'next',b'(I)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJobPoll;'),(b'status',b'()Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJobStatus;'),(b'waitFor',b'(I)Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJobStatus;'),(b'cancel',b'()V'),(b'close',b'()V')]:require_method(parsed[class_name+'$Job'],name,descriptor,1)
 scoped_opcode=parsed['ScopedOpcodeQuery']; scoped_opcode_result=b'Lio/github/jichuo1/dexmeguviz/ScopedOpcodeQuery$Result;'
 require_method(scoped_opcode,b'<init>',b'()V',2)
 require_method(scoped_opcode,b'nativeExecute',b'(Ljava/lang/Object;Z[B)'+scoped_opcode_result,0x010a)
 require_method(parsed['ScopedOpcodeQuery$Result'],b'<init>',b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$QueryResult;[Ljava/lang/String;[I)V',2)
 require_method(parsed['ScopedOpcodeQuery$Scope'],b'<init>',b'([Ljava/lang/String;[I)V',2)
 scoped_opcode_overloads={(b'(Lio/github/jichuo1/dexmeguviz/NativeEngine$'+kind+b';[B)'+scoped_opcode_result,9) for kind in (b'Snapshot',b'SourceSetSnapshot')}
 methods=[m for m in scoped_opcode['methods'] if m['name']==b'execute']
 if len(methods)!=2 or {(m['descriptor'],m['access']) for m in methods}!=scoped_opcode_overloads or any(sum(a[0]==b'Code' for a in m['attributes'])!=1 for m in methods):raise ClassError('unexpected ScopedOpcodeQuery overloads')
 for cls,field,descriptor in [('ScopedOpcodeQuery$Result',b'query',b'Lio/github/jichuo1/dexmeguviz/NativeEngine$QueryResult;'),('ScopedOpcodeQuery$Result',b'scope',b'Lio/github/jichuo1/dexmeguviz/ScopedOpcodeQuery$Scope;')]:require_field(parsed[cls],field,descriptor,17)
 for name,descriptor in [(b'inputSlotCount',b'()I'),(b'inputSlot',b'(I)Ljava/lang/String;'),(b'sourceCount',b'()I'),(b'sourceIndex',b'(I)I')]:require_method(parsed['ScopedOpcodeQuery$Scope'],name,descriptor,1)
 for field,descriptor in [(b'provenance',b'Ljava/lang/String;'),(b'snapshotScopeComplete',b'Z'),(b'sourceScopeAuthenticated',b'Z')]:require_field(parsed['ScopedOpcodeQuery$Scope'],field,descriptor,17)
 source_export=parsed['DexSourceExport'];sp=b'io/github/jichuo1/dexmeguviz/'
 require_method(source_export,b'nativeBytes',b'(Ljava/lang/Object;ZIJ)[B',0x010a)
 require_method(source_export,b'nativeSymbol',b'(Ljava/lang/Object;ZIIJI)[C',0x010a)
 require_method(source_export,b'nativeMemberIndices',b'(Ljava/lang/Object;ZIIJ)[J',0x010a)
 for name in (b'stringAt',b'typeAt',b'prototypeAt'):
  expected={(b'(L'+sp+b'NativeEngine$Snapshot;JI)Ljava/lang/String;',9),(b'(L'+sp+b'NativeEngine$SourceSetSnapshot;IJI)Ljava/lang/String;',9)}
  methods=[m for m in source_export['methods'] if m['name']==name]
  if len(methods)!=len(expected) or {(m['descriptor'],m['access']) for m in methods}!=expected:raise ClassError('unexpected source symbol overloads: '+name.decode('ascii'))
  if any(sum(a[0]==b'Code' for a in m['attributes'])!=1 for m in methods):raise ClassError('source symbol overload requires Code')
 for name in (b'fieldRefAt',b'methodRefAt'):
  expected={(b'(L'+sp+b'NativeEngine$Snapshot;J)[J',9),(b'(L'+sp+b'NativeEngine$SourceSetSnapshot;IJ)[J',9)}
  methods=[m for m in source_export['methods'] if m['name']==name]
  if len(methods)!=len(expected) or {(m['descriptor'],m['access']) for m in methods}!=expected:raise ClassError('unexpected member reference overloads: '+name.decode('ascii'))
  if any(sum(a[0]==b'Code' for a in m['attributes'])!=1 for m in methods):raise ClassError('member reference overload requires Code')
 stream=parsed['DexStreamExport']
 require_method(stream,b'<init>',b'()V',2)
 require_method(stream,b'nativeRead',b'(Ljava/lang/Object;ZIJ[BIJ)I',0x010a)
 stream_overloads={(b'(L'+sp+b'NativeEngine$Snapshot;Ljava/io/OutputStream;JI)J',9),(b'(L'+sp+b'NativeEngine$SourceSetSnapshot;ILjava/io/OutputStream;JI)J',9)}
 methods=[m for m in stream['methods'] if m['name']==b'writeTo']
 if len(methods)!=2 or {(m['descriptor'],m['access']) for m in methods}!=stream_overloads or any(sum(a[0]==b'Code' for a in m['attributes'])!=1 for m in methods):raise ClassError('unexpected stream export overloads')
 method=require_method(stream,b'writeAll',b'(L'+sp+b'NativeEngine$SourceSetSnapshot;[Ljava/io/OutputStream;JJI)[J',9)
 if sum(a[0]==b'Code' for a in method['attributes'])!=1:raise ClassError('stream export writeAll requires Code')
 for desc in (b'(L'+sp+b'NativeEngine$Snapshot;J)[B',b'(L'+sp+b'NativeEngine$SourceSetSnapshot;IJ)[B'):
  matches=[m for m in source_export['methods'] if m['name']==b'copy' and m['descriptor']==desc]
  if len(matches)!=1 or matches[0]['access']!=9:raise ClassError('source export copy ABI')
 annotation=parsed['Annotations'];prefix_b=b'io/github/jichuo1/dexmeguviz/'
 require_method(annotation,b'nativeCollect',b'(Ljava/lang/Object;ZIIJJIJJJ)[B',0x010a)
 for name,desc in [(b'collect',b'(L'+prefix_b+b'NativeEngine$Snapshot;L'+prefix_b+b'Annotations$Target;L'+prefix_b+b'Annotations$Limits;)L'+prefix_b+b'AnnotationResult;'),(b'collect',b'(L'+prefix_b+b'NativeEngine$SourceSetSnapshot;IL'+prefix_b+b'Annotations$Target;L'+prefix_b+b'Annotations$Limits;)L'+prefix_b+b'AnnotationResult;')]:
  methods=[m for m in annotation['methods'] if m['name']==name and m['descriptor']==desc]
  if len(methods)!=1 or methods[0]['access']!=9:raise ClassError('annotation collect ABI')
 for name,descriptor in [(b'classType',b'(J)L'+prefix_b+b'Annotations$Target;'),(b'field',b'(J)L'+prefix_b+b'Annotations$Target;'),(b'method',b'(J)L'+prefix_b+b'Annotations$Target;'),(b'parameter',b'(JJ)L'+prefix_b+b'Annotations$Target;')]:require_method(parsed['Annotations$Target'],name,descriptor,9)
 for name,descriptor in [(b'kind',b'I'),(b'referenceIndex',b'J'),(b'parameterIndex',b'J')]:require_field(parsed['Annotations$Target'],name,descriptor,17)
 require_method(parsed['Annotations$Limits'],b'<init>',b'(IJJJ)V',1)
 for name,descriptor in [(b'maxRecords',b'I'),(b'maxWork',b'J'),(b'maxEncodedBytes',b'J'),(b'deadlineAfterMs',b'J')]:require_field(parsed['Annotations$Limits'],name,descriptor,17)
 for cls,fields in {'AnnotationResult':{'J':'sourceIndex inputIndex targetRef parameterIndex workUnits archiveEntryIndex sourceBytes','I':'targetKind','Z':'crcVerified headerConsistencyVerified expectedDigestVerified','Ljava/lang/String;':'snapshotId slot role sourceSha256 contentId occurrenceId logicalDexId archiveSha256 archiveEntryName'},'AnnotationResult$Item':{'J':'visibility typeIndex itemOffset encodedOffset','Ljava/lang/String;':'descriptor'},'AnnotationResult$Element':{'J':'nameIndex valueKind valueArg valueOffset','Ljava/lang/String;':'name'}}.items():
  for descriptor,names in fields.items():
   for name in names.split():require_field(parsed[cls],name.encode('ascii'),descriptor.encode('ascii'),17)
 for cls,name,descriptor,access in [('AnnotationResult',b'decode',b'([B)L'+prefix_b+b'AnnotationResult;',8),('AnnotationResult',b'itemCount',b'()I',1),('AnnotationResult',b'item',b'(I)L'+prefix_b+b'AnnotationResult$Item;',1),('AnnotationResult$Item',b'encodedAnnotation',b'()[B',1),('AnnotationResult$Item',b'elementCount',b'()I',1),('AnnotationResult$Item',b'element',b'(I)L'+prefix_b+b'AnnotationResult$Element;',1),('AnnotationResult$Element',b'encodedValue',b'()[B',1),('AnnotationResult$Element',b'encodedValueLength',b'()I',1)]:require_method(parsed[cls],name,descriptor,access)
 for cls,methods in public_methods.items():
  for name,descriptor,flags in methods:
   if name in (b'inspectMethodCalls',b'inspectMethodParameters'):
    actual=[m for m in parsed[cls]['methods'] if m['name']==name]
    expected=[(d,f) for n,d,f in methods if n==name]
    if sorted((m['descriptor'],m['access']) for m in actual)!=sorted(expected):raise ClassError('unexpected selected-method overload set')
    method=next(m for m in actual if m['descriptor']==descriptor)
   else:method=require_method(parsed[cls],name,descriptor,flags)
   if sum(a[0]==b'Code' for a in method['attributes'])!=1:raise ClassError('public method must have one Code attribute: '+name.decode('ascii'))
 string=b'Ljava/lang/String;'
 public_fields={
  'NativeEngine$SourceSetInfo':[(b'snapshotId',string,0x0011),(b'sourceScopeComplete',b'Z',0x0011)],
  'NativeEngine$RawDexSourceInfo':[(b'sourceIndex',b'I',0x0011),(b'inputIndex',b'I',0x0011),(b'sourceBytes',b'J',0x0011),(b'archiveEntryIndex',b'I',0x0011)]+[(name,string,0x0011) for name in (b'slot',b'sourceSha256',b'contentId',b'occurrenceId',b'logicalDexId',b'archiveEntryName')],
  'NativeEngine$InputInfo':[(name,b'I',0x0011) for name in (b'inputIndex',b'format',b'sourceCount')]+[(name,b'Z',0x0011) for name in (b'allowNoDex',b'containerMetadataChecked')]+[(b'inputBytes',b'J',0x0011)]+[(name,string,0x0011) for name in (b'slot',b'sourceSha256',b'contentId')],
  'NativeEngine$MethodCandidate':[(b'sourceIndex',b'I',0x0011),(b'inputIndex',b'I',0x0011),(b'sourceSlot',string,0x0011),(b'occurrenceId',string,0x0011)],
  'NativeEngine$JobPoll':[(b'kind',b'I',0x0011),(b'batch',b'Lio/github/jichuo1/dexmeguviz/NativeEngine$QueryResult;',0x0011)],
  'NativeEngine$JobStatus':[(name,b'I',0x0011) for name in (b'lifecycle',b'executionStatus',b'coverage',b'decision',b'reason',b'candidateCount',b'visitedMethods',b'totalMethods')]+[(b'terminal',b'Z',0x0011)]+[(name,b'J',0x0011) for name in (b'unknownRows',b'errorOffset')]+[(name,string,0x0011) for name in (b'queryId',b'snapshotId',b'errorMessage')],
  'NativeEngine$GraphJobPoll':[(b'kind',b'I',0x0011),(b'batch',b'Lio/github/jichuo1/dexmeguviz/GraphResult;',0x0011)],
  'NativeEngine$GraphJobStatus':[(name,b'I',0x0011) for name in (b'lifecycle',b'executionStatus',b'coverage',b'decision',b'reason',b'candidateCount',b'visitedRows',b'totalRows')]+[(b'terminal',b'Z',0x0011)]+[(name,b'J',0x0011) for name in (b'unknownRows',b'errorOffset')]+[(name,string,0x0011) for name in (b'queryId',b'snapshotId',b'errorMessage')],
  'NativeEngine$EntityJobPoll':[(b'kind',b'I',0x0011),(b'batch',b'Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityResult;',0x0011)],
  'NativeEngine$EntityJobStatus':[(name,b'I',0x0011) for name in (b'lifecycle',b'executionStatus',b'coverage',b'decision',b'reason',b'candidateCount',b'visitedRows',b'totalRows')]+[(b'terminal',b'Z',0x0011)]+[(name,b'J',0x0011) for name in (b'unknownRows',b'errorOffset')]+[(name,string,0x0011) for name in (b'queryId',b'snapshotId',b'errorMessage')],
  'NativeEngine$EntityCandidate':[(name,b'I',0x0011) for name in (b'relation',b'sourceIndex',b'inputIndex')]+[(name,b'J',0x0011) for name in (b'localIndex',b'referenceIndex',b'recordOffset')]+[(name,b'Ljava/lang/Long;',0x0011) for name in (b'definitionOffset',b'accessFlags',b'codeOffset')]+[(name,string,0x0011) for name in (b'owner',b'name',b'prototype',b'typeDescriptor',b'stringValue',b'sourceSlot',b'occurrenceId')],
  'NativeEngine$EntityResult':[(name,b'I',0x0011) for name in (b'relation',b'executionStatus',b'coverage',b'decision',b'reason',b'visitedRows',b'totalRows',b'projectionMask')]+[(b'unknownRows',b'J',0x0011)]+[(name,string,0x0011) for name in (b'queryId',b'snapshotId')]}
 public_fields['NativeEngine$MethodTypeJobPoll']=[(b'kind',b'I',17),(b'batch',b'Lio/github/jichuo1/dexmeguviz/MethodTypeResult;',17)]
 public_fields['NativeEngine$AdvancedJobPoll']=[(b'kind',b'I',17),(b'batch',b'Lio/github/jichuo1/dexmeguviz/AdvancedResult;',17)]
 public_fields['NativeEngine$UseGraphJobPoll']=[(b'kind',b'I',17),(b'batch',b'Lio/github/jichuo1/dexmeguviz/UseGraphResult;',17)]
 public_fields['NativeEngine$UseGraphJobStatus']=[(name,b'I',17) for name in (b'lifecycle',b'executionStatus',b'coverage',b'decision',b'reason',b'candidateCount')]+[(b'terminal',b'Z',17)]+[(name,b'J',17) for name in (b'entityVisited',b'entityTotal',b'methodVisited',b'methodTotal',b'eventsCollected',b'unknownRows',b'errorOffset')]+[(name,string,17) for name in (b'queryId',b'snapshotId',b'errorMessage')]
 public_fields['NativeEngine$ExpandJobPoll']=[(b'kind',b'I',17),(b'batch',b'Lio/github/jichuo1/dexmeguviz/ExpandResult;',17)]
 for cls,fields in public_fields.items():
  for name,descriptor,flags in fields:require_field(parsed[cls],name,descriptor,flags)
 # GraphResult.decode is also resolved by name from JNI graph Job delivery.
 graph_fields = {'GraphResult': {'I': 'relation executionStatus coverage decision reason visitedRows totalRows nodeCount requiredCapabilities demandMask projectionMask intent maxResults rootNode uniqueIdentity identityCount', 'J': 'unknownRows maxWork', 'Z': 'explicitScope', 'Ljava/lang/String;': 'queryId snapshotId', 'Lio/github/jichuo1/dexmeguviz/GraphResult$Profile;': 'profile'}, 'GraphResult$Binding': {'J': 'operatorNode', 'Ljava/lang/String;': 'label', 'Lio/github/jichuo1/dexmeguviz/GraphResult$Entity;': 'entity'}, 'GraphResult$Entity': {'I': 'relation sourceIndex', 'J': 'localIndex referenceIndex recordOffset', 'Ljava/lang/Long;': 'definitionOffset accessFlags codeOffset', 'Ljava/lang/String;': 'owner name prototype typeDescriptor stringValue'}, 'GraphResult$Input': {'I': 'inputIndex format sourceCount', 'Z': 'allowNoDex expectedDigestVerified containerMetadataChecked', 'Ljava/lang/String;': 'slot role sourceSha256 contentId', 'J': 'inputBytes'}, 'GraphResult$Link': {'J': 'nodeId key leftSource leftRelation leftLocal rightSource rightRelation rightLocal'}, 'GraphResult$Operator': {'I': 'nodeId op', 'J': 'inputRows outputRows unknownRows visitedRows totalRows', 'Z': 'complete'}, 'GraphResult$Profile': {'J': 'workUnits factRequests methodsDecoded codeUnits stringPoolLookups invokeSites fieldUses declaredFields matchesSeen sortComparisons', 'I': 'scopeSourceCount', 'Z': 'scopeComplete orderVerified'}, 'GraphResult$Row': {'Lio/github/jichuo1/dexmeguviz/GraphResult$Entity;': 'entity'}, 'GraphResult$Source': {'I': 'sourceIndex inputIndex dexVersion stringCount typeCount classCount methodRefCount methodDefCount', 'Ljava/lang/String;': 'slot role sourceSha256 contentId occurrenceId logicalDexId archiveSha256 archiveEntryName', 'J': 'archiveEntryIndex sourceBytes', 'Z': 'crcVerified headerConsistencyVerified expectedDigestVerified'}, 'GraphResult$Witness': {'J': 'kind nodeId matched dexPc opcode referenceIndex referenceKind extraProto codeUnits operatorNode sourceIndex relation localIndex'}}
 graph_fields['GraphResult$Witness']['Lio/github/jichuo1/dexmeguviz/GraphResult$ClassAnnotationFlags;']='classAnnotationFlags'
 graph_fields['GraphResult$ClassAnnotationFlags']={'J':'sourceKind directoryOffset setOffset itemOffset valueOffset rawFlags encodedFlags projectedFlags'}
 graph_methods = {'GraphResult': {'rowCount': '()I', 'row': '(I)Lio/github/jichuo1/dexmeguviz/GraphResult$Row;', 'inputCount': '()I', 'input': '(I)Lio/github/jichuo1/dexmeguviz/GraphResult$Input;', 'sourceCount': '()I', 'source': '(I)Lio/github/jichuo1/dexmeguviz/GraphResult$Source;', 'scopeSourceCount': '()I', 'scopeSource': '(I)I', 'operatorCount': '()I', 'operator': '(I)Lio/github/jichuo1/dexmeguviz/GraphResult$Operator;'}, 'GraphResult$Binding': {'path': '()[B'}, 'GraphResult$Row': {'bindingCount': '()I', 'binding': '(I)Lio/github/jichuo1/dexmeguviz/GraphResult$Binding;', 'proofBindingCount': '()I', 'proofBinding': '(I)Lio/github/jichuo1/dexmeguviz/GraphResult$Binding;', 'linkCount': '()I', 'link': '(I)Lio/github/jichuo1/dexmeguviz/GraphResult$Link;', 'witnessCount': '()I', 'witness': '(I)Lio/github/jichuo1/dexmeguviz/GraphResult$Witness;'}}
 advanced_fields={cls.replace('GraphResult','AdvancedResult'):{desc.replace('GraphResult','AdvancedResult'):fields for desc,fields in values.items()} for cls,values in graph_fields.items() if 'ClassAnnotationFlags' not in cls}
 advanced_fields['AdvancedResult']['Z']='explicitScope hasGraph'
 advanced_fields['AdvancedResult$Witness'].pop('Lio/github/jichuo1/dexmeguviz/AdvancedResult$ClassAnnotationFlags;',None)
 for cls,field in [('Inherited','inherited'),('Numeric','numeric'),('InterfaceGraph','interfaceGraph')]:advanced_fields['AdvancedResult$Witness']['Lio/github/jichuo1/dexmeguviz/AdvancedResult$'+cls+';']=field
 advanced_fields['AdvancedResult$Inherited']={'J':'itemKind pathIndex aux branchIndex detail'}
 advanced_fields['AdvancedResult$Numeric']={'J':'widthBits literalKind entityPc bits'}
 advanced_fields['AdvancedResult$InterfaceGraph']={'J':'itemKind branchIndex nodeIndex aux detail','Z':'resolved'}
 graph_fields.update(advanced_fields)
 graph_methods.update({cls.replace('GraphResult','AdvancedResult'):{name:desc.replace('GraphResult','AdvancedResult') for name,desc in values.items()} for cls,values in list(graph_methods.items())})
 method=require_method(parsed['AdvancedResult'],b'decode',b'([B)Lio/github/jichuo1/dexmeguviz/AdvancedResult;',8)
 if sum(a[0]==b'Code' for a in method['attributes'])!=1:raise ClassError('advanced decode requires Code')
 for cls,by_type in graph_fields.items():
  for descriptor,names in by_type.items():
   for name in names.split(): require_field(parsed[cls],name.encode('ascii'),descriptor.encode('ascii'),0x0011)
 for cls,methods in graph_methods.items():
  for name,descriptor in methods.items():
   method=require_method(parsed[cls],name.encode('ascii'),descriptor.encode('ascii'),0x0001)
   if sum(a[0]==b'Code' for a in method['attributes'])!=1: raise ClassError('graph public method must have one Code attribute')
 for cls in graph_fields:
  root='AdvancedResult' if cls.startswith('AdvancedResult') else 'GraphResult'
  desc=('(Lio/github/jichuo1/dexmeguviz/'+root+'$Reader;'+('Z[Lio/github/jichuo1/dexmeguviz/'+root+'$Source;' if cls.endswith('$Row') or cls.endswith('$Witness') else 'Z' if cls=='AdvancedResult$InterfaceGraph' else '')+')V').encode('ascii')
  ctor=require_method(parsed[cls],b'<init>',desc,0x0002)
  if sum(a[0]==b'Code' for a in ctor['attributes'])!=1: raise ClassError('graph constructor must have one Code attribute')
 for name,descriptor,flags in [(b'<init>',b'([B)V',0),(b'i',b'()I',0),(b'u',b'()J',0),(b'l',b'()J',0),(b'bool',b'()Z',0),(b'count',b'(I)I',0),(b'ascii',b'()Ljava/lang/String;',0),(b'text',b'()Ljava/lang/String;',0),(b'path',b'()[B',0)]:
  method=require_method(parsed['GraphResult$Reader'],name,descriptor,flags)
  if sum(a[0]==b'Code' for a in method['attributes'])!=1:raise ClassError('graph Reader method must have one Code attribute')
 method=require_method(parsed['GraphResult'],b'decode',b'([B)Lio/github/jichuo1/dexmeguviz/GraphResult;',0x0008)
 if sum(a[0]==b'Code' for a in method['attributes'])!=1:raise ClassError('graph decode must have one Code attribute')

 # Fixed public use-graph DTO surface, captured from the documented Java API.
 use_fields = {'UseGraphResult': [(b'relation', b'I', 17), (b'executionStatus', b'I', 17), (b'coverage', b'I', 17), (b'decision', b'I', 17), (b'reason', b'I', 17), (b'candidateCount', b'I', 17), (b'entityVisited', b'J', 17), (b'entityTotal', b'J', 17), (b'methodVisited', b'J', 17), (b'methodTotal', b'J', 17), (b'eventsCollected', b'J', 17), (b'unknownRows', b'J', 17), (b'maxWork', b'J', 17), (b'nodeCount', b'I', 17), (b'requiredCapabilities', b'I', 17), (b'demandMask', b'I', 17), (b'projectionMask', b'I', 17), (b'intent', b'I', 17), (b'maxResults', b'I', 17), (b'explicitScope', b'Z', 17), (b'queryId', b'Ljava/lang/String;', 17), (b'snapshotId', b'Ljava/lang/String;', 17), (b'profile', b'Lio/github/jichuo1/dexmeguviz/UseGraphResult$Profile;', 17), (b'rootNode', b'I', 17), (b'uniqueIdentity', b'I', 17), (b'identityCount', b'I', 17)], 'UseGraphResult$Binding': [(b'operatorNode', b'J', 17), (b'label', b'Ljava/lang/String;', 17), (b'value', b'Lio/github/jichuo1/dexmeguviz/UseGraphResult$Value;', 17)], 'UseGraphResult$Entity': [(b'relation', b'I', 17), (b'sourceIndex', b'I', 17), (b'localIndex', b'J', 17), (b'referenceIndex', b'J', 17), (b'recordOffset', b'J', 17), (b'definitionOffset', b'Ljava/lang/Long;', 17), (b'accessFlags', b'Ljava/lang/Long;', 17), (b'codeOffset', b'Ljava/lang/Long;', 17), (b'owner', b'Ljava/lang/String;', 17), (b'name', b'Ljava/lang/String;', 17), (b'prototype', b'Ljava/lang/String;', 17), (b'typeDescriptor', b'Ljava/lang/String;', 17), (b'stringValue', b'Ljava/lang/String;', 17)], 'UseGraphResult$Identity': [(b'relation', b'J', 17), (b'sourceIndex', b'J', 17), (b'localIndex', b'J', 17), (b'dexPc', b'J', 17)], 'UseGraphResult$Input': [(b'inputIndex', b'I', 17), (b'format', b'I', 17), (b'sourceCount', b'I', 17), (b'allowNoDex', b'Z', 17), (b'expectedDigestVerified', b'Z', 17), (b'containerMetadataChecked', b'Z', 17), (b'slot', b'Ljava/lang/String;', 17), (b'role', b'Ljava/lang/String;', 17), (b'sourceSha256', b'Ljava/lang/String;', 17), (b'contentId', b'Ljava/lang/String;', 17), (b'inputBytes', b'J', 17)], 'UseGraphResult$Link': [(b'nodeId', b'J', 17), (b'key', b'J', 17), (b'left', b'Lio/github/jichuo1/dexmeguviz/UseGraphResult$Identity;', 17), (b'right', b'Lio/github/jichuo1/dexmeguviz/UseGraphResult$Identity;', 17)], 'UseGraphResult$Operator': [(b'nodeId', b'I', 17), (b'op', b'I', 17), (b'scanDomain', b'I', 17), (b'complete', b'Z', 17), (b'inputRows', b'J', 17), (b'outputRows', b'J', 17), (b'unknownRows', b'J', 17), (b'visited', b'J', 17), (b'total', b'J', 17), (b'attemptedMethods', b'J', 17), (b'noBodyMethods', b'J', 17), (b'decodedMethods', b'J', 17), (b'eventsCollected', b'J', 17), (b'codeUnits', b'J', 17)], 'UseGraphResult$Profile': [(b'workUnits', b'J', 17), (b'factRequests', b'J', 17), (b'methodsDecoded', b'J', 17), (b'codeUnits', b'J', 17), (b'stringPoolLookups', b'J', 17), (b'invokeSites', b'J', 17), (b'fieldUses', b'J', 17), (b'declaredFields', b'J', 17), (b'matchesSeen', b'J', 17), (b'sortComparisons', b'J', 17), (b'scopeSourceCount', b'I', 17), (b'scopeComplete', b'Z', 17), (b'orderVerified', b'Z', 17)], 'UseGraphResult$Reader': [], 'UseGraphResult$Row': [(b'value', b'Lio/github/jichuo1/dexmeguviz/UseGraphResult$Value;', 17)], 'UseGraphResult$Source': [(b'sourceIndex', b'I', 17), (b'inputIndex', b'I', 17), (b'dexVersion', b'I', 17), (b'stringCount', b'I', 17), (b'typeCount', b'I', 17), (b'classCount', b'I', 17), (b'methodRefCount', b'I', 17), (b'methodDefCount', b'I', 17), (b'slot', b'Ljava/lang/String;', 17), (b'role', b'Ljava/lang/String;', 17), (b'sourceSha256', b'Ljava/lang/String;', 17), (b'contentId', b'Ljava/lang/String;', 17), (b'occurrenceId', b'Ljava/lang/String;', 17), (b'logicalDexId', b'Ljava/lang/String;', 17), (b'archiveSha256', b'Ljava/lang/String;', 17), (b'archiveEntryName', b'Ljava/lang/String;', 17), (b'archiveEntryIndex', b'J', 17), (b'sourceBytes', b'J', 17), (b'crcVerified', b'Z', 17), (b'headerConsistencyVerified', b'Z', 17), (b'expectedDigestVerified', b'Z', 17)], 'UseGraphResult$Use': [(b'relation', b'J', 17), (b'sourceIndex', b'J', 17), (b'callerOrdinal', b'J', 17), (b'callerMethodRef', b'J', 17), (b'dexPc', b'J', 17), (b'opcode', b'J', 17), (b'codeOffset', b'J', 17), (b'targetDomain', b'J', 17), (b'targetIndex', b'J', 17), (b'extraProto', b'J', 17), (b'owner', b'Ljava/lang/String;', 17), (b'name', b'Ljava/lang/String;', 17), (b'prototype', b'Ljava/lang/String;', 17)], 'UseGraphResult$Value': [(b'kind', b'I', 17), (b'entity', b'Lio/github/jichuo1/dexmeguviz/UseGraphResult$Entity;', 17), (b'use', b'Lio/github/jichuo1/dexmeguviz/UseGraphResult$Use;', 17)], 'UseGraphResult$Witness': [(b'kind', b'J', 17), (b'nodeId', b'J', 17), (b'matched', b'J', 17), (b'dexPc', b'J', 17), (b'opcode', b'J', 17), (b'referenceIndex', b'J', 17), (b'referenceKind', b'J', 17), (b'extraProto', b'J', 17), (b'codeUnits', b'J', 17), (b'operatorNode', b'J', 17), (b'entity', b'Lio/github/jichuo1/dexmeguviz/UseGraphResult$Identity;', 17)]}
 use_methods = {'UseGraphResult': [(b'rowCount', b'()I', 1), (b'row', b'(I)Lio/github/jichuo1/dexmeguviz/UseGraphResult$Row;', 1), (b'inputCount', b'()I', 1), (b'input', b'(I)Lio/github/jichuo1/dexmeguviz/UseGraphResult$Input;', 1), (b'sourceCount', b'()I', 1), (b'source', b'(I)Lio/github/jichuo1/dexmeguviz/UseGraphResult$Source;', 1), (b'scopeSourceCount', b'()I', 1), (b'scopeSource', b'(I)I', 1), (b'operatorCount', b'()I', 1), (b'operator', b'(I)Lio/github/jichuo1/dexmeguviz/UseGraphResult$Operator;', 1)], 'UseGraphResult$Binding': [(b'path', b'()[B', 1)], 'UseGraphResult$Entity': [], 'UseGraphResult$Identity': [], 'UseGraphResult$Input': [], 'UseGraphResult$Link': [], 'UseGraphResult$Operator': [], 'UseGraphResult$Profile': [], 'UseGraphResult$Reader': [], 'UseGraphResult$Row': [(b'bindingCount', b'()I', 1), (b'binding', b'(I)Lio/github/jichuo1/dexmeguviz/UseGraphResult$Binding;', 1), (b'proofBindingCount', b'()I', 1), (b'proofBinding', b'(I)Lio/github/jichuo1/dexmeguviz/UseGraphResult$Binding;', 1), (b'linkCount', b'()I', 1), (b'link', b'(I)Lio/github/jichuo1/dexmeguviz/UseGraphResult$Link;', 1), (b'witnessCount', b'()I', 1), (b'witness', b'(I)Lio/github/jichuo1/dexmeguviz/UseGraphResult$Witness;', 1)], 'UseGraphResult$Source': [], 'UseGraphResult$Use': [], 'UseGraphResult$Value': [], 'UseGraphResult$Witness': []}
 use_fields['UseGraphResult$Use'].append((b'targetDescriptor',b'Ljava/lang/String;',17))
 use_fields['UseGraphResult$Witness'].extend([(b'inheritedDetailPresent',b'Z',17)]+[(name,b'J',17) for name in (b'inheritedItem',b'inheritedPath',b'inheritedAux',b'inheritedBranch',b'inheritedDetail')])
 for cls, fields in use_fields.items():
  for name,descriptor,flags in fields: require_field(parsed[cls],name,descriptor,flags)
 for cls, methods in use_methods.items():
  for name,descriptor,flags in methods:
   method=require_method(parsed[cls],name,descriptor,flags)
   if sum(a[0]==b'Code' for a in method['attributes'])!=1: raise ClassError('use graph public method must have one Code attribute')
 method=require_method(parsed['UseGraphResult'],b'decode',b'([B)Lio/github/jichuo1/dexmeguviz/UseGraphResult;',0x0008)
 if sum(a[0]==b'Code' for a in method['attributes'])!=1:raise ClassError('use graph decode must have one Code attribute')
 calls_fields={
  'MethodCallsResult':{'J':'sourceIndex inputIndex methodOrdinal methodRef codeOffset codeUnits validationWork callerFlags callerDeclarationOffset archiveEntryIndex sourceBytes','Z':'hasBody instructionChecked crcVerified headerConsistencyVerified expectedDigestVerified','Ljava/lang/String;':'snapshotId slot role sourceSha256 contentId occurrenceId logicalDexId archiveSha256 archiveEntryName callerOwner callerName callerPrototype'},
  'MethodCallsResult$Row':{'J':'dexPc opcode targetDomain targetIndex extraProto','Ljava/lang/String;':'owner name prototype extraPrototype'}}
 for cls,types in calls_fields.items():
  for descriptor,names in types.items():
   for name in names.split():require_field(parsed[cls],name.encode('ascii'),descriptor.encode('ascii'),17)
 for name,descriptor,flags in [(b'decode',b'([B)Lio/github/jichuo1/dexmeguviz/MethodCallsResult;',8),(b'rowCount',b'()I',1),(b'row',b'(I)Lio/github/jichuo1/dexmeguviz/MethodCallsResult$Row;',1)]:
  method=require_method(parsed['MethodCallsResult'],name,descriptor,flags)
  if sum(a[0]==b'Code' for a in method['attributes'])!=1:raise ClassError('method calls method requires Code')
 facts_fields={
  'MethodFactsResult':{'J':'sourceIndex inputIndex methodOrdinal methodRef codeOffset codeUnits validationWork callerFlags callerDeclarationOffset archiveEntryIndex sourceBytes','I':'requestedMask','Z':'hasBody instructionChecked crcVerified headerConsistencyVerified expectedDigestVerified','Ljava/lang/String;':'snapshotId slot role sourceSha256 contentId occurrenceId logicalDexId archiveSha256 archiveEntryName callerOwner callerName callerPrototype'},
  'MethodFactsResult$StringUse':{'J':'dexPc opcode stringIndex','Ljava/lang/String;':'value'},
  'MethodFactsResult$FieldUse':{'J':'dexPc opcode fieldIndex','Ljava/lang/String;':'owner name typeDescriptor'},
  'MethodFactsResult$NumberUse':{'J':'dexPc opcode bits','I':'widthBits kind'},
  'MethodFactsResult$Invoke':{'J':'dexPc opcode targetDomain targetIndex extraProto','Ljava/lang/String;':'owner name prototype extraPrototype'},
  'MethodFactsResult$TypeUse':{'J':'dexPc opcode typeIndex','Ljava/lang/String;':'descriptor'},
  'MethodFactsResult$Instruction':{'J':'dexPc width opcode payloadKind'}}
 for cls,types in facts_fields.items():
  for descriptor,names in types.items():
   for name in names.split():require_field(parsed[cls],name.encode('ascii'),descriptor.encode('ascii'),17)
 for kind in ('string','field','number','invoke','type','instruction'):
  require_method(parsed['MethodFactsResult'],(kind+'Count').encode('ascii'),b'()I',1)
  row={'string':'StringUse','field':'FieldUse','number':'NumberUse','invoke':'Invoke','type':'TypeUse','instruction':'Instruction'}[kind]
  require_method(parsed['MethodFactsResult'],kind.encode('ascii'),('(I)Lio/github/jichuo1/dexmeguviz/MethodFactsResult$'+row+';').encode('ascii'),1)
 for enum_name,constants in [('Category',('STRINGS','FIELDS','NUMBERS','INVOKES','TYPES','INSTRUCTIONS')),('Availability',('NOT_REQUESTED','NO_BODY','CHECKED'))]:
  name='MethodFactsResult$'+enum_name;enum=parse(entries[prefix+name+'.class'])
  if enum['name']!=(prefix+name).encode('ascii') or enum['flags']!=0x4031 or enum['superclass']!=b'java/lang/Enum':raise ClassError('invalid method facts enum')
  for constant in constants:require_field(enum,constant.encode('ascii'),('L'+prefix+name+';').encode('ascii'),0x4019)
  if enum_name=='Category':require_field(enum,b'mask',b'I',17)
 for name,descriptor,flags in [(b'decode',b'([B)Lio/github/jichuo1/dexmeguviz/MethodFactsResult;',8),(b'requested',b'(Lio/github/jichuo1/dexmeguviz/MethodFactsResult$Category;)Z',1),(b'availability',b'(Lio/github/jichuo1/dexmeguviz/MethodFactsResult$Category;)Lio/github/jichuo1/dexmeguviz/MethodFactsResult$Availability;',1)]:
  method=require_method(parsed['MethodFactsResult'],name,descriptor,flags)
  if sum(a[0]==b'Code' for a in method['attributes'])!=1:raise ClassError('method facts method requires Code')
 parameters_fields={
  'MethodParametersResult':{'J':'sourceIndex inputIndex methodRef methodOrdinal debugOffset workUnits archiveEntryIndex sourceBytes','I':'debugState','Z':'crcVerified headerConsistencyVerified expectedDigestVerified','Ljava/lang/String;':'snapshotId slot role sourceSha256 contentId occurrenceId logicalDexId archiveSha256 archiveEntryName returnType'},
  'MethodParametersResult$Parameter':{'J':'ordinal typeIndex nameStringIndex','I':'nameState','Ljava/lang/String;':'typeDescriptor name'}}
 for cls,types in parameters_fields.items():
  for descriptor,names in types.items():
   for name in names.split():require_field(parsed[cls],name.encode('ascii'),descriptor.encode('ascii'),17)
 for name in ('DEBUG_NO_DEFINITION','DEBUG_NO_BODY','DEBUG_NOT_PRESENT','DEBUG_PRESENT','NAME_UNKNOWN','NAME_NO_INDEX','NAME_PRESENT'):require_field(parsed['MethodParametersResult'],name.encode('ascii'),b'I',25)
 for name,descriptor,flags in [(b'decode',b'([B)Lio/github/jichuo1/dexmeguviz/MethodParametersResult;',8),(b'parameterCount',b'()I',1),(b'parameter',b'(I)Lio/github/jichuo1/dexmeguviz/MethodParametersResult$Parameter;',1)]:
  method=require_method(parsed['MethodParametersResult'],name,descriptor,flags)
  if sum(a[0]==b'Code' for a in method['attributes'])!=1:raise ClassError('method parameters method requires Code')
 method_type_fields={
  'MethodTypeResult':[(n,b'I',17) for n in (b'executionStatus',b'coverage',b'decision',b'reason',b'visitedMethods',b'totalMethods',b'sourceCount')]+[(b'unknownRows',b'J',17),(b'scopeComplete',b'Z',17)]+[(n,string,17) for n in (b'queryId',b'snapshotId')],
  'MethodTypeResult$Row':[(n,b'J',17) for n in (b'sourceIndex',b'inputIndex',b'methodOrdinal',b'methodRef',b'accessFlags',b'declarationOffset',b'codeOffset',b'stringCount',b'typeCount',b'methodRefCount',b'methodDefCount')]+[(n,string,17) for n in (b'slot',b'sourceSha256',b'occurrenceId',b'owner',b'name',b'prototype')],
  'MethodTypeResult$Witness':[(n,b'J',17) for n in (b'kind',b'nodeId',b'matched',b'dexPc',b'opcode',b'referenceIndex',b'referenceKind',b'extraProto',b'codeUnits')]+[(b'targetDescriptor',string,17)]}
 for cls,fields in method_type_fields.items():
  for name,descriptor,flags in fields:require_field(parsed[cls],name,descriptor,flags)
 for cls,name,desc in [('MethodTypeResult',b'decode',b'([B)Lio/github/jichuo1/dexmeguviz/MethodTypeResult;'),('MethodTypeResult',b'rowCount',b'()I'),('MethodTypeResult',b'row',b'(I)Lio/github/jichuo1/dexmeguviz/MethodTypeResult$Row;'),('MethodTypeResult$Row',b'witnessCount',b'()I'),('MethodTypeResult$Row',b'witness',b'(I)Lio/github/jichuo1/dexmeguviz/MethodTypeResult$Witness;')]:
  method=require_method(parsed[cls],name,desc,8 if name==b'decode' else 1)
  if sum(a[0]==b'Code' for a in method['attributes'])!=1:raise ClassError('method type method needs Code')
 method=require_method(parsed['ExpandResult'],b'decode',b'([B)Lio/github/jichuo1/dexmeguviz/ExpandResult;',8)
 if sum(a[0]==b'Code' for a in method['attributes'])!=1:raise ClassError('expand decode requires Code')
 # The Java compiler inlines these public source-kind constants into callers.
 # Check their declared int ABI and exact ConstantValue, without evaluating code.
 for name,value in ((b'SOURCE_RAW_DEX',1),(b'SOURCE_APK',2)):
  field=require_field(engine,name,b'I',0x0019)
  attrs=[a for a in field['attributes'] if a[0]==b'ConstantValue']
  if len(attrs)!=1:raise ClassError('unexpected constant field value: '+name.decode('ascii'))
  at=attrs[0][1];data=engine['data'];cp=engine['constant_pool']
  if at+8>len(data) or struct.unpack_from('>I',data,at+2)[0]!=2:
   raise ClassError('unexpected constant field value: '+name.decode('ascii'))
  index=struct.unpack_from('>H',data,at+6)[0]
  if not 0<index<len(cp) or cp[index]!=(3,value):
   raise ClassError('unexpected constant field value: '+name.decode('ascii'))
 return parsed

def verify_keep(text):
 import re
 # Accept only the fixed exact unconditional rules; no modifiers or extra directives.
 cleaned='\n'.join(line.split('#',1)[0] for line in text.split('\n'))
 space=r'[ \t\r\n\f]'
 engine=re.compile(space+r'*-keep'+space+r'+class'+space+r'+io\.github\.jichuo1\.dexmeguviz\.(NativeEngine(?:\$\*)?)'+space+r'*\{'+space+r'*\*'+space+r'*;'+space+r'*\}')
 fast_engine=re.compile(engine.pattern.replace('NativeEngine','FastDexQuery'))
 scope_engine=re.compile(engine.pattern.replace('NativeEngine','ScopedMethodQuery'))
 annotation_engine=re.compile(engine.pattern.replace('NativeEngine','Annotations'))
 source_export_engine=re.compile(engine.pattern.replace('NativeEngine','DexSourceExport'))
 stream_export_engine=re.compile(engine.pattern.replace('NativeEngine','DexStreamExport'))
 opcode_engine=re.compile(engine.pattern.replace('NativeEngine','OpcodeQuery'))
 scoped_opcode_engine=re.compile(engine.pattern.replace('NativeEngine','ScopedOpcodeQuery'))
 class_annotation_engine=re.compile(engine.pattern.replace('NativeEngine','ClassAnnotationQuery'))
 scoped_class_annotation_engine=re.compile(engine.pattern.replace('NativeEngine','ScopedClassAnnotationQuery'))
 class_annotation_string_engine=re.compile(engine.pattern.replace('NativeEngine','ClassAnnotationStringQuery'))
 scoped_class_annotation_string_engine=re.compile(engine.pattern.replace('NativeEngine','ScopedClassAnnotationStringQuery'))
 method_batch_engine=re.compile(engine.pattern.replace('NativeEngine','MethodBatchQuery'))
 scoped_method_batch_engine=re.compile(engine.pattern.replace('NativeEngine','ScopedMethodBatchQuery'))
 graph=re.compile(space+r'*-keep'+space+r'+class'+space+r'+io\.github\.jichuo1\.dexmeguviz\.GraphResult'+space+r'*\{'+space+r'*static'+space+r'+io\.github\.jichuo1\.dexmeguviz\.GraphResult'+space+r'+decode'+space+r'*\('+space+r'*byte'+space+r'*\['+space+r'*\]'+space+r'*\)'+space+r'*;'+space+r'*\}')
 use=__import__('re').compile(graph.pattern.replace('GraphResult','UseGraphResult'))
 method_type=__import__('re').compile(graph.pattern.replace('GraphResult','MethodTypeResult'))
 expand=__import__('re').compile(graph.pattern.replace('GraphResult','ExpandResult'))
 advanced=__import__('re').compile(graph.pattern.replace('GraphResult','AdvancedResult'))
 method_calls=__import__('re').compile(graph.pattern.replace('GraphResult','MethodCallsResult'))
 method_parameters=__import__('re').compile(graph.pattern.replace('GraphResult','MethodParametersResult'))
 found=[];pos=0
 while pos<len(cleaned):
  if re.fullmatch(space+r'*',cleaned[pos:]):break
  m=engine.match(cleaned,pos)
  if m:found.append(m.group(1));pos=m.end();continue
  m=fast_engine.match(cleaned,pos)
  if m:found.append(m.group(1));pos=m.end();continue
  m=scope_engine.match(cleaned,pos)
  if m:found.append(m.group(1));pos=m.end();continue
  m=annotation_engine.match(cleaned,pos)
  if m:found.append(m.group(1));pos=m.end();continue
  m=source_export_engine.match(cleaned,pos)
  if m:found.append(m.group(1));pos=m.end();continue
  m=stream_export_engine.match(cleaned,pos)
  if m:found.append(m.group(1));pos=m.end();continue
  m=opcode_engine.match(cleaned,pos)
  if m:found.append(m.group(1));pos=m.end();continue
  m=scoped_opcode_engine.match(cleaned,pos)
  if m:found.append(m.group(1));pos=m.end();continue
  m=class_annotation_engine.match(cleaned,pos)
  if m:found.append(m.group(1));pos=m.end();continue
  m=scoped_class_annotation_engine.match(cleaned,pos)
  if m:found.append(m.group(1));pos=m.end();continue
  m=class_annotation_string_engine.match(cleaned,pos)
  if m:found.append(m.group(1));pos=m.end();continue
  m=scoped_class_annotation_string_engine.match(cleaned,pos)
  if m:found.append(m.group(1));pos=m.end();continue
  m=method_batch_engine.match(cleaned,pos)
  if m:found.append(m.group(1));pos=m.end();continue
  m=scoped_method_batch_engine.match(cleaned,pos)
  if m:found.append(m.group(1));pos=m.end();continue
  m=graph.match(cleaned,pos)
  if m:found.append('GraphResult.decode');pos=m.end();continue
  m=use.match(cleaned,pos)
  if m:found.append('UseGraphResult.decode');pos=m.end();continue
  m=method_type.match(cleaned,pos)
  if m:found.append('MethodTypeResult.decode');pos=m.end();continue
  m=expand.match(cleaned,pos)
  if m:found.append('ExpandResult.decode');pos=m.end();continue
  m=advanced.match(cleaned,pos)
  if m:found.append('AdvancedResult.decode');pos=m.end();continue
  m=method_calls.match(cleaned,pos)
  if m:found.append('MethodCallsResult.decode');pos=m.end();continue
  m=method_parameters.match(cleaned,pos)
  if m:found.append('MethodParametersResult.decode');pos=m.end();continue
  raise ClassError('unsupported or conditional JNI keep rules')
 if len(found)!=30 or set(found)!={'FastDexQuery','FastDexQuery$*','ScopedMethodBatchQuery','ScopedMethodBatchQuery$*','MethodBatchQuery','MethodBatchQuery$*','ClassAnnotationStringQuery','ScopedClassAnnotationStringQuery','ScopedClassAnnotationStringQuery$*','ScopedClassAnnotationQuery','ScopedClassAnnotationQuery$*','ClassAnnotationQuery','DexStreamExport','ScopedOpcodeQuery','ScopedOpcodeQuery$*','OpcodeQuery','NativeEngine','NativeEngine$*','ScopedMethodQuery','ScopedMethodQuery$*','Annotations','Annotations$*','DexSourceExport','GraphResult.decode','UseGraphResult.decode','MethodTypeResult.decode','ExpandResult.decode','AdvancedResult.decode','MethodCallsResult.decode','MethodParametersResult.decode'}:raise ClassError('missing or duplicated exact JNI keep rule')
