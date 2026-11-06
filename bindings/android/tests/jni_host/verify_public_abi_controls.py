"""Targeted ABI mutations against real compiled JNI classes; no JVM verification claim."""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from jni_classfile import ClassError, parse, verify_classfiles

parser = argparse.ArgumentParser()
parser.add_argument('--classes', required=True, type=Path)
args = parser.parse_args()
prefix = 'io/github/jichuo1/dexmeguviz/'
classes = ['NativeEngine', 'NativeEngine$Snapshot', 'NativeEngine$SnapshotInfo',
           'NativeEngine$NativeFailure', 'NativeEngine$MethodCandidate', 'NativeEngine$QueryResult',
           'NativeEngine$SourceSetSnapshot', 'NativeEngine$SourceSetInfo', 'NativeEngine$RawDexSourceInfo','NativeEngine$InputInfo','NativeEngine$Job','NativeEngine$JobPoll','NativeEngine$JobStatus','NativeEngine$EntityCandidate','NativeEngine$EntityResult','NativeEngine$EntityJob','NativeEngine$EntityJobPoll','NativeEngine$EntityJobStatus','NativeEngine$GraphJob','NativeEngine$GraphJobPoll','NativeEngine$GraphJobStatus','GraphResult','GraphResult$Binding','GraphResult$Entity','GraphResult$Input','GraphResult$Link','GraphResult$Operator','GraphResult$Profile','GraphResult$Reader','GraphResult$Row','GraphResult$Source','GraphResult$Witness']
classes += ['NativeEngine$ExpandJob', 'NativeEngine$ExpandJobPoll', 'ExpandResult', 'ExpandResult$Reader', 'ExpandResult$Profile', 'ExpandResult$Operator', 'ExpandResult$Input', 'ExpandResult$Source', 'ExpandResult$Entity', 'ExpandResult$Use', 'ExpandResult$Value', 'ExpandResult$Identity', 'ExpandResult$Binding', 'ExpandResult$Link', 'ExpandResult$ExpandProfile', 'ExpandResult$Witness', 'ExpandResult$Hop', 'ExpandResult$Evidence', 'ExpandResult$Path', 'ExpandResult$Row', 'ExpandResult$RowEvidence', 'ExpandResult$Frontier']
classes += ['UseGraphResult', 'UseGraphResult$Binding', 'UseGraphResult$Entity', 'UseGraphResult$Identity', 'UseGraphResult$Input', 'UseGraphResult$Link', 'UseGraphResult$Operator', 'UseGraphResult$Profile', 'UseGraphResult$Reader', 'UseGraphResult$Row', 'UseGraphResult$Source', 'UseGraphResult$Use', 'UseGraphResult$Value', 'UseGraphResult$Witness']
classes += ['NativeEngine$UseGraphJob','NativeEngine$UseGraphJobPoll','NativeEngine$UseGraphJobStatus','GraphResult$ClassAnnotationFlags','NativeEngine$MethodTypeJob','NativeEngine$MethodTypeJobPoll','MethodTypeResult','MethodTypeResult$Reader','MethodTypeResult$Row','MethodTypeResult$Witness']
original = {prefix + n + '.class': (args.classes / (prefix+n+'.class')).read_bytes() for n in classes}
verify_classfiles(original)
targets = [
 ('NativeEngine','methods','openRawDexSet'),
 ('NativeEngine','methods','openSources'),
 ('NativeEngine$SourceSetSnapshot','methods','info'),
 ('NativeEngine$SourceSetSnapshot','methods','queryMethods'),
 ('NativeEngine$SourceSetSnapshot','methods','close'),
 ('NativeEngine$SourceSetInfo','methods','sourceCount'),
 ('NativeEngine$SourceSetInfo','methods','source'),
 ('NativeEngine$SourceSetInfo','methods','inputCount'),
 ('NativeEngine$SourceSetInfo','methods','input'),
 ('NativeEngine$SourceSetInfo','fields','snapshotId'),
 ('NativeEngine$SourceSetInfo','fields','sourceScopeComplete'),
 *[('NativeEngine$RawDexSourceInfo','fields',n) for n in
   ('sourceIndex','inputIndex','sourceBytes','slot','sourceSha256','contentId','occurrenceId','logicalDexId','archiveEntryName','archiveEntryIndex')],
 *[('NativeEngine$InputInfo','fields',n) for n in
   ('inputIndex','format','sourceCount','allowNoDex','containerMetadataChecked','inputBytes','slot','sourceSha256','contentId')],
 *[('NativeEngine$MethodCandidate','fields',n) for n in
   ('sourceIndex','inputIndex','sourceSlot','occurrenceId')],
]
records = []
for cls,kind,name in targets:
 key=prefix+cls+'.class'; initial=original[key]; meta=parse(initial)
 matches=[member for member in meta[kind] if member['name']==name.encode('ascii')]
 if len(matches)!=1: raise AssertionError('original member not unique: '+cls+' '+name)
 member=matches[0]
 for mode in ('name','descriptor','access'):
  changed=bytearray(initial)
  if mode=='access':
   struct.pack_into('>H',changed,member['access_offset'],member['access'] ^ 0x0001)
  else:
   # Repoint only this member to an existing UTF8 entry: the replacement
   # descriptor is another syntactically valid descriptor of the same kind.
   # A shared constant is never modified, so other members stay unchanged.
   if mode=='name':
    replacement=b'Code'
   elif kind=='methods':
    replacement=next(m['descriptor'] for m in meta['methods'] if m['descriptor']!=member['descriptor'])
   else:
    replacement=next(f['descriptor'] for f in meta['fields'] if f['descriptor']!=member['descriptor'])
   other=meta['utf_indexes'][replacement]
   offset=member[mode+'_index_offset']
   if struct.unpack_from('>H',changed,offset)[0]==other:raise AssertionError('no-op mutation')
   struct.pack_into('>H',changed,offset,other)
  forged=dict(original);forged[key]=bytes(changed)
  expected=('unexpected method name, descriptor, overload or access: ' if kind=='methods'
            else 'unexpected public field name, descriptor, duplicate or access: ')+name
  try: verify_classfiles(forged)
  except ClassError as exc:
   if str(exc)!=expected:raise AssertionError((cls,name,mode,str(exc),expected)) from exc
  else: raise AssertionError('accepted mutation: '+cls+' '+name+' '+mode)
  records.append({'class':cls,'kind':kind,'member':name,'mutation':mode,
                  'original_sha256':hashlib.sha256(initial).hexdigest(),
                  'mutated_sha256':hashlib.sha256(changed).hexdigest(),'diagnostic':expected})
print(json.dumps({'positive':'accepted','scope':'fixed multi-source Java ABI only',
                  'inputs':{key:hashlib.sha256(data).hexdigest() for key,data in original.items()},
                  'checker_sha256':hashlib.sha256((Path(__file__).resolve().parents[2]/'tools'/'jni_classfile.py').read_bytes()).hexdigest(),
                  'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  'cases':len(records),'records':records},indent=2))
