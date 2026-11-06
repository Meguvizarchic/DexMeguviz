from pathlib import Path
import argparse,hashlib,json,zipfile
def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for block in iter(lambda:f.read(1<<20),b''):h.update(block)
 return h.hexdigest()
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--dex',type=Path,required=True);a=p.parse_args();a.out.mkdir(exist_ok=False);data=a.dex.read_bytes();records=[]
for mode in ('debug','asan'):
 for name in ('early','late'):
  path=a.out/(mode+'-'+name+'.apk')
  with path.open('xb') as raw:
   with zipfile.ZipFile(raw,'w',compression=zipfile.ZIP_DEFLATED) as z:
    z.writestr('classes.dex',data);info=zipfile.ZipInfo('assets/padding.bin');info.compress_type=zipfile.ZIP_STORED
    with z.open(info,'w') as dst:
     block=bytes(65536)
     for _ in range(4):dst.write(block)
  records.append({'file':path.name,'bytes':path.stat().st_size,'sha256':sha(path)})
(a.out/'manifest.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf8');print(json.dumps(records))
