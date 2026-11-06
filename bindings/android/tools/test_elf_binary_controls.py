"""Mutate real AAR ELF dynamic symbol type/binding and compare audits."""
import argparse,hashlib,io,json,struct,subprocess,sys,zipfile
from pathlib import Path

p=argparse.ArgumentParser()
for name in ('aar','header','readelf','runtime-report','out'):p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
original=a.aar.read_bytes();root=Path(__file__).resolve().parent

def mutate_elf(data,symbol,change):
 b=bytearray(data)
 if b[:4]!=b'\x7fELF' or b[5]!=1:raise ValueError('expected little-endian ELF')
 bits=b[4]
 if bits==2:
  offset=struct.unpack_from('<Q',b,40)[0];width,count=struct.unpack_from('<HH',b,58);fmt='<IIQQQQIIQQ';info_offset=4
 elif bits==1:
  offset=struct.unpack_from('<I',b,32)[0];width,count=struct.unpack_from('<HH',b,46);fmt='<IIIIIIIIII';info_offset=12
 else:raise ValueError('unknown ELF class')
 sections=[struct.unpack_from(fmt,b,offset+i*width) for i in range(count)]
 candidates=[s for s in sections if s[1]==11]
 if len(candidates)!=1:raise ValueError('unexpected dynsym count')
 dyn=candidates[0];dynoff,dynsize,link,entry=dyn[4],dyn[5],dyn[6],dyn[9]
 strings=sections[link];stringoff,stringsize=strings[4],strings[5]
 found=[]
 for off in range(dynoff,dynoff+dynsize,entry):
  name=struct.unpack_from('<I',b,off)[0]
  if name>=stringsize:raise ValueError('bad dynstr index')
  start=stringoff+name;end=b.index(0,start,stringoff+stringsize)
  if bytes(b[start:end]).decode('ascii')==symbol:found.append(off)
 if len(found)!=1:raise ValueError('symbol not unique: '+symbol)
 at=found[0]+info_offset;old=b[at]
 if old!=0x12:raise ValueError('expected GLOBAL FUNC')
 b[at]=(old&0xf0)|1 if change=='object' else (2<<4)|(old&15)
 return bytes(b)

def make(abi,symbol,change):
 output=io.BytesIO();target='jni/'+abi+'/libdexmeguviz.so';changed=False
 with zipfile.ZipFile(io.BytesIO(original)) as src,zipfile.ZipFile(output,'w') as dest:
  for item in src.infolist():
   data=src.read(item)
   if item.filename==target:data=mutate_elf(data,symbol,change);changed=True
   dest.writestr(item,data)
 if not changed:raise ValueError('missing ABI')
 return output.getvalue()

cases=[]
for abi in ('arm64-v8a','armeabi-v7a'):
 for kind,symbol in [('object','dmg_snapshot_open_sources'),('object','Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeClose'),('weak','dmg_snapshot_open_sources')]:
  label=abi+'-'+kind+'-'+('jni' if symbol.startswith('Java_') else 'c')
  payload=make(abi,symbol,kind);path=a.out/(label+'.aar');path.write_bytes(payload)
  record={'case':label,'sha256':hashlib.sha256(payload).hexdigest()}
  for name,verifier in [('before','verify_aar_baseline.py'),('after','verify_aar.py')]:
   command=[sys.executable,'-B',str(root/verifier),'--aar',str(path),'--header',str(a.header),'--readelf',str(a.readelf),'--runtime-report',str(a.runtime_report),'--out',str(a.out/(label+'-'+name))]
   proc=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=90)
   (a.out/(label+'-'+name+'.stdout.log')).write_text(proc.stdout,encoding='utf-8');(a.out/(label+'-'+name+'.stderr.log')).write_text(proc.stderr,encoding='utf-8')
   record[name]={'exit':proc.returncode,'stderr':proc.stderr.strip()}
  cases.append(record)
  if record['before']['exit']!=0 or record['after']['exit']==0 or 'invalid export type, binding, visibility, section or version' not in record['after']['stderr']:
   raise SystemExit('unexpected ELF binary control result: '+repr(record))
(a.out/'records.json').write_text(json.dumps(cases,indent=2)+'\n',encoding='utf-8')
print('PASS',len(cases),'real AAR ELF type/binding controls: old accepted, new rejected')
