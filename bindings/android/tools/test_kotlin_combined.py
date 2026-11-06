"""Synthetic JNI+Kotlin packaging controls; not a real combined build."""
import argparse,copy,hashlib,io,json,struct,subprocess,sys,warnings,zipfile
from pathlib import Path
from jni_classfile import parse

p=argparse.ArgumentParser()
for name in ('jni-aar','kotlin-aar','header','readelf','runtime-report','pom','module','out'):p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
root=Path(__file__).resolve().parent;prefix='io/github/jichuo1/dexmeguviz/'
kotlin_names={'Coverage','Decision','DecisionReason','ExecutionStatus','MethodPredicate$Companion','MethodPredicate','MethodQuery','MethodTextField','QueryExecution','QueryIntent','QuerySummary','RawDexFlags','RawFlagOperation','SourceIdentity','TextOperation'}
jni=a.jni_aar.read_bytes();kotlin=a.kotlin_aar.read_bytes();pom_original=a.pom.read_bytes();module_original=json.loads(a.module.read_text(encoding='utf-8'))
with zipfile.ZipFile(io.BytesIO(kotlin)) as k:
 kotlin_jar=k.read('classes.jar')
with zipfile.ZipFile(io.BytesIO(kotlin_jar)) as jar:
 expected={prefix+n+'.class' for n in kotlin_names}
 payload={item.filename:jar.read(item) for item in jar.infolist() if item.filename in expected or item.filename.endswith('.kotlin_module')}
 if not expected.issubset(payload):raise SystemExit('Kotlin source AAR class list differs')

def build(kind='valid'):
 outer=io.BytesIO()
 with zipfile.ZipFile(io.BytesIO(jni)) as src,zipfile.ZipFile(outer,'w') as dest:
  for entry in src.infolist():
   data=src.read(entry)
   if entry.filename=='classes.jar':
    nested=io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as old,zipfile.ZipFile(nested,'w') as new:
     for item in old.infolist():
      if kind=='missing-jni' and item.filename==prefix+'NativeEngine$Snapshot.class':continue
      new.writestr(item,old.read(item))
     for name,raw in payload.items():
      if kind=='missing' and name==prefix+'MethodQuery.class':continue
      if kind=='fake' and name==prefix+'MethodQuery.class':raw=payload[prefix+'RawDexFlags.class']
      if kind=='fake-same-name' and name==prefix+'MethodQuery.class':
       parsed=parse(raw);matches=[m for m in parsed['methods'] if m['name']==b'toQueryIrJson']
       if len(matches)!=1:raise ValueError('unexpected Kotlin anchor method')
       at=matches[0]['name_offset'];raw=bytearray(raw);raw[at:at+13]=b'toQueryIrJsoX';raw=bytes(raw)
      if kind=='minor-preview' and name==prefix+'MethodQuery.class':
       raw=bytearray(raw);struct.pack_into('>H',raw,4,65535);raw=bytes(raw)
      new.writestr(name,raw)
     if kind=='embedded-kotlin':new.writestr('kotlin/Injected.class',b'fake')
     if kind=='inner-jar':new.writestr('META-INF/embedded.JAR',b'fake')
     if kind=='duplicate-class':
      with warnings.catch_warnings():warnings.simplefilter('ignore',UserWarning);new.writestr(prefix+'MethodQuery.class',payload[prefix+'MethodQuery.class'])
    data=nested.getvalue()
   dest.writestr(entry,data)
  if kind=='outer-jar':dest.writestr('extra.JAR',b'fake')
  if kind=='outer-kotlin':dest.writestr('kotlin/Injected.class',b'fake')
 return outer.getvalue()

def metadata_for(aar):
 metadata=copy.deepcopy(module_original)
 for variant in metadata['variants']:
  for record in variant['files']:
   record['size']=len(aar)
   for algorithm in ('sha256','sha512','sha1','md5'):record[algorithm]=hashlib.new(algorithm,aar).hexdigest()
 return metadata

records=[]
def run(label,aar,pom,module,expect=True,diagnostic=None,include_metadata=True):
 path=a.out/(label+'.aar');path.write_bytes(aar)
 pompath=a.out/(label+'.pom');pompath.write_bytes(pom)
 modulepath=a.out/(label+'.module');modulepath.write_bytes(module if isinstance(module,bytes) else json.dumps(module,indent=2).encode())
 command=[sys.executable,'-B',str(root/'verify_aar.py'),'--aar',str(path),'--header',str(a.header),'--readelf',str(a.readelf),'--runtime-report',str(a.runtime_report),'--out',str(a.out/(label+'-audit'))]
 if include_metadata:command.extend(['--pom',str(pompath),'--module',str(modulepath)])
 if expect:command.append('--expect-kotlin')
 result=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=90)
 (a.out/(label+'.stdout.log')).write_text(result.stdout,encoding='utf-8');(a.out/(label+'.stderr.log')).write_text(result.stderr,encoding='utf-8')
 record={'case':label,'sha256':hashlib.sha256(aar).hexdigest(),'exit':result.returncode,'stderr':result.stderr.strip(),'expected_diagnostic':diagnostic}
 records.append(record)
 if diagnostic is None:
  if result.returncode:raise SystemExit('unexpected positive failure '+repr(record))
 elif result.returncode==0 or diagnostic not in result.stderr:raise SystemExit('unexpected negative outcome '+repr(record))

hybrid=build();meta=metadata_for(hybrid)
run('synthetic-combined',hybrid,pom_original,meta)
run('missing-metadata',hybrid,pom_original,meta,True,'Kotlin audit requires both POM and module metadata',False)
run('synthetic-without-flag',hybrid,pom_original,meta,False,'unexpected class files')
run('real-kotlin-only-missing-jni',kotlin,pom_original,module_original,True,'JNI keep rule invalid')
pom_dep=pom_original.replace(b'</project>',b'<dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId><version>1</version></dependency></dependencies></project>')
run('pom-dependency',hybrid,pom_dep,meta,True,'POM has dependency or inherited parent')
pom_parent=pom_original.replace(b'</project>',b'<parent><groupId>x</groupId><artifactId>y</artifactId><version>1</version></parent></project>')
run('pom-parent',hybrid,pom_parent,meta,True,'POM has dependency or inherited parent')
for name,index,key,value,diagnostic in [
 ('module-runtime-dependency',1,'dependencies',[{'group':'x','module':'y','version':{'requires':'1'}}],'module variant has dependencies or constraints'),
 ('module-api-dependency',0,'dependencies',[{'group':'x','module':'y','version':{'requires':'1'}}],'module variant has dependencies or constraints'),
 ('module-badtype',1,'dependencies',{},'module variant has dependencies or constraints'),
 ('module-redirect',1,'available-at',{'url':'elsewhere'},'module variant redirects externally'),
 ('module-constraints',0,'dependencyConstraints',[{'group':'x','module':'y'}],'module variant has dependencies or constraints')]:
 changed=copy.deepcopy(meta);changed['variants'][index][key]=value;run(name,hybrid,pom_original,changed,True,diagnostic)
changed=copy.deepcopy(meta);changed['variants'][1]['files'][0]['sha256']='0'*64
run('module-sha-mismatch',hybrid,pom_original,changed,True,'module artifact does not match audited AAR')
changed=copy.deepcopy(meta);changed['component']['group']='wrong'
run('module-coordinate-mismatch',hybrid,pom_original,changed,True,'POM/module coordinates differ')
good_name=meta['variants'][0]['files'][0]['name']
for label,name,url in [
 ('encoded-traversal','%2e%2e%2fghost.aar','%2e%2e%2fghost.aar'),
 ('encoded-slash','ghost%2fapp.aar','ghost%2fapp.aar'),
 ('different-safe-name','ghost-1.aar','ghost-1.aar'),
 ('query-string',good_name,good_name+'?x=1'),
 ('fragment',good_name,good_name+'#part'),
 ('unicode-name','caf\u00e9-1.aar','caf\u00e9-1.aar'),
 ('double-dot-name','ghost..-1.aar','ghost..-1.aar')]:
 changed=copy.deepcopy(meta)
 for variant in changed['variants']:
  variant['files'][0]['name']=name;variant['files'][0]['url']=url
 run('module-'+label,hybrid,pom_original,changed,True,'invalid module artifact name/url')
changed=copy.deepcopy(meta);changed['variants'][0]['files'][0]['sha512']='0'*128
run('module-sha512-mismatch',hybrid,pom_original,changed,True,'module artifact sha512 mismatch')
raw=json.dumps(meta,indent=2).encode().replace(b'"formatVersion": "1.1",',b'"formatVersion": "1.1", "formatVersion": "1.1",',1)
run('module-duplicate-key',hybrid,pom_original,raw,True,'duplicate module metadata key')
for kind,diagnostic in [('fake','class path and class identity differ'),('fake-same-name','Kotlin anchor method mismatch'),('missing','unexpected class files'),('missing-jni','unexpected class files'),('embedded-kotlin','embedded Kotlin runtime or nested jar'),('inner-jar','embedded Kotlin runtime or nested jar'),('outer-jar','unexpected embedded jar'),('outer-kotlin','embedded Kotlin runtime path'),('duplicate-class','duplicate classes.jar entry name'),('minor-preview','invalid class structure')]:
 image=build(kind);run(kind,image,pom_original,metadata_for(image),True,diagnostic)
(a.out/'records.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
print('PASS',len(records),'synthetic Kotlin/JNI metadata and class controls; final combined AAR not tested')
