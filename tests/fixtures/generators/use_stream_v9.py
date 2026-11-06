"""Derive two-method use fixtures from the project-original method-facts DEX.

The quiet method becomes a checked invoke/return and the existing uses method
retains its body. A second fixture corrupts an opcode in that later method.
This is static bytecode evidence, not ART or runtime dispatch validation.
"""
import argparse,hashlib,json,struct,zlib
from pathlib import Path

EXPECTED_SOURCE='8262d2b338e54a7965111b4cec1ef9e628ada9795ad2f6a555d717a2ba9546bc'
def u32(b,p):return struct.unpack_from('<I',b,p)[0]
def write32(b,p,v):struct.pack_into('<I',b,p,v)
def read_uleb(b,p):
 value=0
 for i in range(5):
  x=b[p];p+=1;value|=(x&127)<<(7*i)
  if x<128:return value,p
 raise ValueError('invalid ULEB')
def encode_uleb(value):
 out=bytearray()
 while True:
  b=value&127;value>>=7;out.append(b|(128 if value else 0))
  if not value:return out
def generate(source,expected,output):
 b=source.read_bytes();meta=json.loads(expected.read_text(encoding='utf-8'))
 if hashlib.sha256(b).hexdigest()!=EXPECTED_SOURCE or meta['sha256']!=EXPECTED_SOURCE:raise ValueError('unexpected source fixture')
 quiet,uses=meta['quiet']['code_offset'],meta['uses']['code_offset'];old_map=u32(b,52)
 if (quiet,uses,u32(b,quiet+12),u32(b,uses+12))!=(396,416,1,8):raise ValueError('unexpected code layout')
 header=bytearray(b[quiet:quiet+16]);write32(header,12,4)
 body=struct.pack('<4H',0x0071,4,0,0x000e)
 data=bytearray(b[:quiet])+header+body+bytearray(b[uses:]);delta=4
 if len(data)!=len(b)+delta:raise ValueError('unexpected insertion size')
 write32(data,32,len(data));write32(data,52,old_map+delta);write32(data,104,u32(b,104)+delta)
 classes=u32(data,100);old_class=u32(b,classes+24);write32(data,classes+24,old_class+delta)
 cursor=old_class+delta;counts=[]
 for _ in range(4):n,cursor=read_uleb(data,cursor);counts.append(n)
 for count in counts[:2]:
  for _ in range(count):_,cursor=read_uleb(data,cursor);_,cursor=read_uleb(data,cursor)
 changed=0
 for count in counts[2:]:
  ref=0
  for _ in range(count):
   diff,cursor=read_uleb(data,cursor);ref+=diff;_,cursor=read_uleb(data,cursor)
   at=cursor;code,cursor=read_uleb(data,cursor)
   if code==uses:
    encoded=encode_uleb(uses+delta)
    if len(encoded)!=cursor-at:raise ValueError('code offset encoding length changed')
    data[at:cursor]=encoded;changed+=1
 if changed!=1:raise ValueError('missing uses code reference')
 map_at=old_map+delta
 for i in range(u32(data,map_at)):
  at=map_at+4+12*i+8;offset=u32(data,at)
  if offset>=uses:write32(data,at,offset+delta)
 def seal(blob):
  blob[12:32]=hashlib.sha1(blob[32:]).digest();write32(blob,8,zlib.adler32(blob[12:])&0xffffffff)
 output.mkdir(parents=True,exist_ok=False)
 items=[]
 for name,corrupt in [('two-methods.dex',False),('later-corrupt.dex',True)]:
  image=bytearray(data)
  if corrupt:struct.pack_into('<H',image,uses+delta+16+5*2,0x0073)
  seal(image);(output/name).write_bytes(image)
  items.append({'path':name,'sha256':hashlib.sha256(image).hexdigest(),'corrupt':corrupt})
 manifest={'schema_version':1,'source_sha256':EXPECTED_SOURCE,'quiet':{'ordinal':1,'method_ref':2,'code_offset':quiet,'invoke_pc':0,'target':4},
           'uses':{'ordinal':2,'method_ref':3,'code_offset':uses+delta,'invoke_pc':2,'target':4},'files':items,
           'scope':'static checked method ordering; no ART or runtime validation'}
 (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
 return manifest
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--expected',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 print(json.dumps(generate(a.source,a.expected,a.output),sort_keys=True))
