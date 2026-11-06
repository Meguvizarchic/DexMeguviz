"""Project-original DEX with one opaque invocation and result word."""
import argparse,hashlib,json,struct,zlib
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
source=a.input.read_bytes()
if hashlib.sha256(source).hexdigest()!='8262d2b338e54a7965111b4cec1ef9e628ada9795ad2f6a555d717a2ba9546bc':raise SystemExit('wrong base DEX')
if a.output.exists():raise SystemExit('output exists')
image=bytearray(source);code=416
if struct.unpack_from('<I',image,code+12)[0]!=8:raise SystemExit('wrong code item')
words=(0x7012,0x1071,4,0,0x010a,0x10b0,0x000f,0x000e)
struct.pack_into('<H',image,code,2);struct.pack_into('<H',image,code+4,1);struct.pack_into('<8H',image,code+16,*words)
image[12:32]=hashlib.sha1(image[32:]).digest();struct.pack_into('<I',image,8,zlib.adler32(image[12:])&0xffffffff)
a.output.mkdir(parents=True);(a.output/'dataflow-invoke.dex').write_bytes(image)
(a.output/'expected.json').write_text(json.dumps({'sha256':hashlib.sha256(image).hexdigest(),'source_sha256':hashlib.sha256(source).hexdigest(),
 'code_offset':code,'uses':[[1,0,0,True,7,0],[5,0,0,True,7,0],[5,1,1,False,0,4],[6,0,0,False,0,5]],
 'scope':'checked static instruction encoding; not invoke signature, move-result placement, ART or runtime'},indent=2)+'\n',encoding='utf-8')
