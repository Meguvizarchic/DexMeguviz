"""Project-original DEX: two structural paths define the same constant."""
import argparse,hashlib,json,struct,zlib
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
source=a.input.read_bytes()
if hashlib.sha256(source).hexdigest()!='87c9340db46e00cad9573951d6e39ccdb1514993adc6d10626e22890e41f5cf1':raise SystemExit('wrong base DEX')
if a.output.exists():raise SystemExit('output exists')
image=bytearray(source);code=244
if struct.unpack_from('<I',image,code+12)[0]!=26:raise SystemExit('wrong code item')
words=[0x1012,0x0138,4,0x1012,0x0228,0x1012,0x000f]+[0x000e]*19
struct.pack_into('<H',image,code,2);struct.pack_into('<26H',image,code+16,*words)
image[12:32]=hashlib.sha1(image[32:]).digest();struct.pack_into('<I',image,8,zlib.adler32(image[12:])&0xffffffff)
a.output.mkdir(parents=True);(a.output/'dataflow-join.dex').write_bytes(image)
(a.output/'expected.json').write_text(json.dumps({'sha256':hashlib.sha256(image).hexdigest(),'source_sha256':hashlib.sha256(source).hexdigest(),
 'code_offset':code,'uses':[[1,1,0,False,0,0xffffffff],[6,0,0,True,1,0xffffffff]],
 'scope':'32-bit structural join; neither ART verification nor path feasibility'},indent=2)+'\n',encoding='utf-8')
