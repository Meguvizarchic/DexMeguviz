from pathlib import Path
import argparse,hashlib,json,zipfile

def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for block in iter(lambda:f.read(1<<20),b''):h.update(block)
 return h.hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--dex-a',type=Path,required=True);p.add_argument('--dex-b',type=Path,required=True);a=p.parse_args()
 a.out.mkdir(exist_ok=False);one=a.dex_a.read_bytes();two=a.dex_b.read_bytes();out=[]
 for name,megabytes in [('small.apk',0),('over16.apk',17),('over128.apk',129)]:
  path=a.out/name
  with path.open('xb') as raw:
   with zipfile.ZipFile(raw,'w',compression=zipfile.ZIP_DEFLATED) as z:
    # Deliberately reverse central-directory order; semantic order is numeric.
    z.writestr('classes2.dex',two);z.writestr('classes.dex',one)
    if megabytes:
     info=zipfile.ZipInfo('assets/padding.bin');info.compress_type=zipfile.ZIP_STORED
     with z.open(info,'w') as dest:
      block=bytes(65536)
      for _ in range(megabytes*16):dest.write(block)
  out.append({'file':name,'bytes':path.stat().st_size,'sha256':sha(path)})
 small=a.out/'small.apk';prefixed=a.out/'prefixed.bin';prefix=b'fd-range-v1!';suffix=b'fd-tail'
 with prefixed.open('xb') as f:f.write(prefix);f.write(small.read_bytes());f.write(suffix)
 out.append({'file':prefixed.name,'bytes':prefixed.stat().st_size,'sha256':sha(prefixed),'offset':len(prefix),'length':small.stat().st_size})
 (a.out/'manifest.json').write_text(json.dumps({'fixtures':out},indent=2)+'\n',encoding='utf8');print(json.dumps(out))
if __name__=='__main__':main()
