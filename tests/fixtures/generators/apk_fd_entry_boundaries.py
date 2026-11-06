from pathlib import Path
import argparse,hashlib,json,zipfile
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--dex',type=Path,required=True);a=p.parse_args();a.out.mkdir(exist_ok=False);data=a.dex.read_bytes();records=[]
for count in (64,65):
 path=a.out/('dex-%d.apk'%count)
 with path.open('xb') as raw:
  with zipfile.ZipFile(raw,'w',compression=zipfile.ZIP_DEFLATED) as z:
   for i in range(count,0,-1):z.writestr('classes.dex' if i==1 else 'classes%d.dex'%i,data)
 records.append({'file':path.name,'dex_count':count,'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
(a.out/'manifest.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf8');print(json.dumps(records))
