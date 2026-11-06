"""Generate fixed string-use fixtures with NUL and isolated surrogate UTF-16 units."""
from pathlib import Path
import argparse,hashlib,json,struct,zlib

def main():
 a=argparse.ArgumentParser();a.add_argument('--source',type=Path,required=True);a.add_argument('--out',type=Path,required=True);x=a.parse_args();src=x.source.read_bytes();assert hashlib.sha256(src).hexdigest()=='65373dc14bb0b19b3fb4ae8fd236e83befbfee4b69b74e3a8d4a8b7db2637c04'
 old=b'\x0bused-string\x00';assert src.count(old)==1;specs={'nul-high-d800.dex':b'\x08used\xc0\x80\xed\xa0\x80xy\x00','nul-high-d801.dex':b'\x08used\xc0\x80\xed\xa0\x81xy\x00'};x.out.mkdir(parents=True,exist_ok=False);items={}
 for name,replacement in specs.items():
  assert len(old)==len(replacement);data=bytearray(src.replace(old,replacement));data[12:32]=hashlib.sha1(data[32:]).digest();struct.pack_into('<I',data,8,zlib.adler32(data[12:])&0xffffffff);(x.out/name).write_bytes(data);items[name]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'target_index':10,'pcs':[0,2]}
 (x.out/'manifest.json').write_text(json.dumps({'fixtures':items,'scope':'authored modified UTF-8 static strings, no ART or runtime claim'},indent=2)+'\n',encoding='utf-8');print(json.dumps(items))
if __name__=='__main__':main()
