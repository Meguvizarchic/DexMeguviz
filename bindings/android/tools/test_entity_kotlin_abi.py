"""Targeted Kotlin entity enum ABI mutations against an actual compiled classes.jar."""
import argparse, hashlib, json, struct, zipfile
from pathlib import Path
from jni_classfile import parse
from verify_aar import check_kotlin_class

p=argparse.ArgumentParser();p.add_argument('--jar',required=True,type=Path);p.add_argument('--out',required=True,type=Path);a=p.parse_args()
assert not a.out.exists()
prefix='io/github/jichuo1/dexmeguviz/'
members={'EntityRelation':('METHOD_DEFS','CLASS_DEFS','FIELD_DEFS','METHOD_REFS','FIELD_REFS','TYPE_REFS','STRING_VALUES'),
         'EntityTextField':('NAME','OWNER','PROTOTYPE','RETURN_TYPE','DESCRIPTOR','TYPE','VALUE','SUPERCLASS','DIRECT_INTERFACE')}
jar_hash=hashlib.sha256(a.jar.read_bytes()).hexdigest();records=[]
with zipfile.ZipFile(a.jar) as jar:
 for cls,names in members.items():
  original=jar.read(prefix+cls+'.class');meta=parse(original);check_kotlin_class(meta,cls)
  for name in names:
   selected=[f for f in meta['fields'] if f['name']==name.encode('ascii')]
   assert len(selected)==1
   member=selected[0]
   for mode in ('name','descriptor','access'):
    changed=bytearray(original)
    if mode=='access':
     struct.pack_into('>H',changed,member['access_offset'],member['access'] ^ 0x4000)
    else:
     target=b'Code' if mode=='name' else b'Ljava/lang/String;'
     index=meta['utf_indexes'][target]
     assert struct.unpack_from('>H',changed,member[mode+'_index_offset'])[0]!=index
     struct.pack_into('>H',changed,member[mode+'_index_offset'],index)
    try:check_kotlin_class(parse(changed),cls)
    except ValueError as exc:
     expected='Kotlin entity enum mismatch: '+cls
     if str(exc)!=expected:raise AssertionError((cls,name,mode,str(exc),expected)) from exc
    else:raise AssertionError(('mutated enum accepted',cls,name,mode))
    records.append({'class':cls,'member':name,'mutation':mode,'diagnostic':expected,
                    'sha256':hashlib.sha256(changed).hexdigest()})
assert hashlib.sha256(a.jar.read_bytes()).hexdigest()==jar_hash
a.out.write_text(json.dumps({'outcome':'passed','jar_sha256':jar_hash,'cases':len(records),'records':records},indent=2)+'\n',encoding='utf-8')
print('PASS',len(records),'targeted Kotlin entity enum ABI negatives')
