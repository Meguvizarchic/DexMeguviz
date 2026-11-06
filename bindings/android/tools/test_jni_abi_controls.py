"""Exercise baseline acceptance and fixed verifier rejection of forged JNI ABI."""
import argparse,hashlib,io,json,struct,subprocess,sys,warnings,zipfile
from pathlib import Path
from jni_classfile import parse

p=argparse.ArgumentParser()
for name in ('aar','header','readelf','runtime-report','out'):p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
original=a.aar.read_bytes();base=Path(__file__).resolve().parent;prefix='io/github/jichuo1/dexmeguviz/'
methods=['abiVersion','capabilities','nativeOpenRawDex','nativeSnapshotInfo','nativeClose']
cases=[('method-desc-'+n,'NativeEngine',n,'descriptor') for n in methods]
cases += [('method-flags-'+n,'NativeEngine',n,'flags') for n in methods]
cases += [('ctor-desc-'+n,n,'<init>','descriptor') for n in ['NativeEngine$SnapshotInfo','NativeEngine$NativeFailure']]
cases += [('ctor-flags-'+n,n,'<init>','flags') for n in ['NativeEngine$SnapshotInfo','NativeEngine$NativeFailure']]
cases += [('method-name-'+n,'NativeEngine',n,'name') for n in ['nativeOpenRawDex','nativeSnapshotInfo','nativeClose']]
cases += [('ctor-name-'+n,n,'<init>','name') for n in ['NativeEngine$SnapshotInfo','NativeEngine$NativeFailure']]
cases += [('super-'+n,n,'','super') for n in ['NativeEngine','NativeEngine$Snapshot','NativeEngine$SnapshotInfo','NativeEngine$NativeFailure']]
cases += [('keep-main','','','keep-main'),('keep-nested','','','keep-nested'),('duplicate-aar','','','outer'),('duplicate-classes','','','inner')]
cases += [('conditional-main','','','conditional-main'),('conditional-nested','','','conditional-nested'),('duplicate-class','','','inner-class')]
cases += [('bad-constant-pool','NativeEngine$NativeFailure','','cp-tag'),
          ('truncated-class','NativeEngine$NativeFailure','','truncate'),
          ('bad-interface-index','NativeEngine$Snapshot','','interface-index')]
cases += [('native-code-attribute','NativeEngine','nativeClose','native-code')]
cases += [('ctor-no-code-'+n,n,'<init>','ctor-no-code') for n in ['NativeEngine$SnapshotInfo','NativeEngine$NativeFailure']]
cases += [('minor-'+value+'-'+n,n,'','minor-'+value) for n in ['NativeEngine','NativeEngine$Snapshot','NativeEngine$SnapshotInfo','NativeEngine$NativeFailure'] for value in ('one','preview')]

def forge(case):
 label,klass,method,kind=case;output=io.BytesIO()
 with zipfile.ZipFile(io.BytesIO(original)) as src,zipfile.ZipFile(output,'w') as dest:
  for entry in src.infolist():
   data=src.read(entry.filename)
   if entry.filename=='proguard.txt' and (kind.startswith('keep-') or kind.startswith('conditional-')):
    text=data.decode();line='-keep class io.github.jichuo1.dexmeguviz.NativeEngine'+('$*' if kind.endswith('nested') else '')+' { *; }'
    assert line in text
    # The baseline only searches for the NativeEngine name, which remains present.
    replacement=('-if class com.example.Missing\n'+line) if kind.startswith('conditional-') else line.replace('-keep class','-keepclassmembers class')
    data=text.replace(line,replacement,1).encode()
   if entry.filename=='classes.jar' and (klass or kind in ('inner','inner-class')):
    nested=io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as old,zipfile.ZipFile(nested,'w') as new:
     for item in old.infolist():
      content=old.read(item.filename)
      if klass and item.filename==prefix+klass+'.class':
       content=bytearray(content);meta=parse(content)
       if kind=='super':
        own_index=struct.unpack_from('>H',content,meta['super_offset']-2)[0]
        struct.pack_into('>H',content,meta['super_offset'],own_index)
       elif kind=='cp-tag':content[10]=0
       elif kind=='truncate':del content[-2:]
       elif kind.startswith('minor-'):struct.pack_into('>H',content,4,1 if kind=='minor-one' else 65535)
       elif kind=='interface-index':
        assert struct.unpack_from('>H',content,meta['super_offset']+2)[0]==1
        struct.pack_into('>H',content,meta['super_offset']+4,0)
       else:
        matches=[m for m in meta['methods'] if m['name']==method.encode()];assert len(matches)==1;m=matches[0]
       if kind=='flags':struct.pack_into('>H',content,m['access_offset'],m['access']^0x0100 if klass=='NativeEngine' else m['access']^0x0003)
       elif kind=='native-code':
        at=m['access_offset']+6;assert struct.unpack_from('>H',content,at)[0]==0
        struct.pack_into('>H',content,at,1);content[at+2:at+2]=struct.pack('>HI',meta['utf_indexes'][b'Code'],0)
       elif kind=='ctor-no-code':
        attrs=[offset for name,offset in m['attributes'] if name==b'Code'];assert len(attrs)==1
        replacement=meta['utf_indexes'].get(b'LineNumberTable',meta['utf_indexes'].get(b'SourceFile'))
        assert replacement is not None;struct.pack_into('>H',content,attrs[0],replacement)
       elif kind=='name':
        at=m['name_offset'];name=m['name'];replacement=name[:-2]+b'x>' if name==b'<init>' else name[:-1]+b'X'
        assert replacement!=name and len(replacement)==len(name);content[at:at+len(name)]=replacement
       elif kind=='descriptor':
        at=m['descriptor_offset'];desc=m['descriptor'];replacement=desc.replace(b'J',b'I',1) if b'J' in desc else desc.replace(b'I',b'J',1) if b'I' in desc else desc.replace(b'String',b'Strinx',1)
        assert replacement!=desc and len(replacement)==len(desc);content[at:at+len(desc)]=replacement
       content=bytes(content)
      new.writestr(item,content)
     if kind=='inner':
      with warnings.catch_warnings():warnings.simplefilter('ignore',UserWarning);new.writestr('io/',old.read('io/'))
     if kind=='inner-class':
      with warnings.catch_warnings():warnings.simplefilter('ignore',UserWarning);new.writestr(prefix+'NativeEngine.class',old.read(prefix+'NativeEngine.class'))
    data=nested.getvalue()
   dest.writestr(entry,data)
  if kind=='outer':
   with warnings.catch_warnings():warnings.simplefilter('ignore',UserWarning);dest.writestr('classes.jar',src.read('classes.jar'))
 return output.getvalue()

records=[]
for case in cases:
 label=case[0];path=a.out/(label+'.aar');payload=forge(case);path.write_bytes(payload)
 record={'case':label,'sha256':hashlib.sha256(payload).hexdigest()}
 for suffix,verifier in [('before','verify_aar_baseline.py'),('after','verify_aar.py')]:
  out=a.out/(label+'-'+suffix);command=[sys.executable,'-B',str(base/verifier),'--aar',str(path),'--header',str(a.header),'--readelf',str(a.readelf),'--runtime-report',str(a.runtime_report),'--out',str(out)]
  proc=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',timeout=30)
  (a.out/(label+'-'+suffix+'.stdout.log')).write_text(proc.stdout,encoding='utf-8');(a.out/(label+'-'+suffix+'.stderr.log')).write_text(proc.stderr,encoding='utf-8')
  record[suffix]={'exit_code':proc.returncode,'stderr':proc.stderr.strip()}
 records.append(record)
 (a.out/'records.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
 if record['after']['exit_code']==0 or (record['before']['exit_code']==0 if label=='duplicate-class' else record['before']['exit_code']!=0):
  raise SystemExit('unexpected control outcome '+label+': '+str(record))
print('PASS',len(records),'forged AARs: fixed audit rejected all; baseline rejects duplicate-class and accepts the remaining controls')
