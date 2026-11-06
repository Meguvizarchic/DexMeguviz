"""Project-original DEX graph with an inherited interface field and a numeric/call body."""
import argparse,hashlib,json,struct,zlib
from pathlib import Path

ROOT='Ljava/lang/Object;';CHILD='Lcross/Child;';IFACE='Lcross/Contract;';SINK='Lcross/Sink;'
def leb(n):
 out=bytearray()
 while True:
  b=n&127;n>>=7;out.append(b|(128 if n else 0))
  if not n:return bytes(out)
def build(owner,parent,flags,interfaces=(),field=None,method=False):
 types={owner,*([parent] if parent else []),*interfaces}
 if field:types.add('I')
 if method:types.update(['V',SINK])
 strings=sorted(types|({field} if field else set())|({'access','call'} if method else set()))
 sid={s:i for i,s in enumerate(strings)};types=sorted(types,key=sid.__getitem__);tid={s:i for i,s in enumerate(types)}
 methods=sorted([(CHILD,'access'),(SINK,'call')],key=lambda x:(tid[x[0]],sid[x[1]])) if method else []
 mid={m:i for i,m in enumerate(methods)};image=bytearray(112);sections=[(0,1,0)]
 def table(kind,count,width):
  if not count:return 0
  at=len(image);image.extend(bytes(count*width));sections.append((kind,count,at));return at
 def align():image.extend(bytes(-len(image)%4))
 strings_at=table(1,len(strings),4);types_at=table(2,len(types),4);proto_at=table(3,1 if method else 0,12)
 field_at=table(4,1 if field else 0,8);method_at=table(5,len(methods),8);classes_at=table(6,1,32);data_at=len(image)
 iface_at=0
 if interfaces:
  align();iface_at=len(image);sections.append((0x1001,1,iface_at));image.extend(struct.pack('<I',len(interfaces)))
  for iface in interfaces:image.extend(struct.pack('<H',tid[iface]))
 sections.append((0x2002,len(strings),len(image)))
 for i,s in enumerate(strings):
  struct.pack_into('<I',image,strings_at+4*i,len(image));image.extend(leb(len(s))+s.encode('ascii')+b'\0')
 code_at=0
 if method:
  align();code_at=len(image);sections.append((0x2001,1,code_at))
  # const/4 v0, -1; invoke-static {}, Sink.call; return-void.
  words=[0xf012,0x0071,mid[(SINK,'call')],0,0x000e]
  image.extend(struct.pack('<HHHHII',1,0,0,0,0,len(words)));image.extend(struct.pack('<5H',*words))
 class_data=0
 if field or method:
  class_data=len(image);sections.append((0x2000,1,class_data))
  image.extend(bytes((int(bool(field)),0,int(bool(method)),0)))
  if field:image.extend(leb(0)+leb(0x19))
  if method:image.extend(leb(mid[(CHILD,'access')])+leb(9)+leb(code_at))
 align();map_at=len(image);sections.append((0x1000,1,map_at));image.extend(struct.pack('<I',len(sections)))
 for kind,count,at in sorted(sections,key=lambda s:s[2]):image.extend(struct.pack('<HHII',kind,0,count,at))
 for i,t in enumerate(types):struct.pack_into('<I',image,types_at+4*i,sid[t])
 if method:
  struct.pack_into('<III',image,proto_at,sid['V'],tid['V'],0)
  for i,(mowner,name) in enumerate(methods):struct.pack_into('<HHI',image,method_at+8*i,tid[mowner],0,sid[name])
 if field:struct.pack_into('<HHI',image,field_at,tid[owner],tid['I'],sid[field])
 struct.pack_into('<8I',image,classes_at,tid[owner],flags,0xffffffff if parent is None else tid[parent],iface_at,0xffffffff,0,class_data,0)
 image[:8]=b'dex\n035\0';struct.pack_into('<20I',image,32,len(image),112,0x12345678,0,0,map_at,len(strings),strings_at,len(types),types_at,int(method),proto_at,int(bool(field)),field_at,len(methods),method_at,1,classes_at,len(image)-data_at,data_at)
 image[12:32]=hashlib.sha1(image[32:]).digest();struct.pack_into('<I',image,8,zlib.adler32(image[12:])&0xffffffff)
 return bytes(image)
def main():
 p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=Path);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 files={'child.dex':build(CHILD,ROOT,1,[IFACE],method=True),'contract.dex':build(IFACE,ROOT,0x601,field='parentOnly'),'object.dex':build(ROOT,None,1)}
 manifest={}
 for name,data in files.items():
  (a.output/name).write_bytes(data);manifest[name]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
 (a.output/'manifest.json').write_text(json.dumps({'fixtures':manifest,'scope':'Static DEX cross-capability fixture; no ART/runtime claim'},indent=2)+'\n',encoding='utf-8')
 print('generated',len(files),'deterministic DEX files')
if __name__=='__main__':main()
