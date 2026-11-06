"""Project-original fixed DEX bytes for scoped field declaration tests; no ART claim."""
import argparse,hashlib,json,struct,zlib
from pathlib import Path
ROOT='Ljava/lang/Object;'; CHILD='Lq08/Child;'; PARENT='Lq08/Parent;'; IFACE='Lq08/Interface;'

def leb(x):
 out=bytearray()
 while True:
  a=x&127;x>>=7;out.append(a|(128 if x else 0))
  if not x:return bytes(out)

def build(owner,parent,fields=(),interfaces=(),method=False,flags=1):
 types={owner,CHILD,'I','V',*[t for _,t,_ in fields],*interfaces}
 if parent is not None:types.add(parent)
 strings=sorted(types|{n for n,_,_ in fields}|({'value','access'} if method else set()))
 sid={x:i for i,x in enumerate(strings)};types=sorted(types,key=sid.__getitem__);tid={x:i for i,x in enumerate(types)}
 defs={(owner,n,t):f for n,t,f in fields};refs=set(defs)
 if method:refs.add((CHILD,'value','I'))
 refs=sorted(refs,key=lambda x:(tid[x[0]],sid[x[1]],tid[x[2]]));fid={x:i for i,x in enumerate(refs)}
 image=bytearray(112);sections=[(0,1,0)]
 def table(kind,count,width):
  if not count:return 0
  at=len(image);image.extend(bytes(count*width));sections.append((kind,count,at));return at
 def align():image.extend(bytes(-len(image)%4))
 string_at=table(1,len(strings),4);type_at=table(2,len(types),4);proto_at=table(3,int(bool(method)),12)
 field_at=table(4,len(refs),8);method_at=table(5,int(bool(method)),8);class_at=table(6,1,32);data_at=len(image)
 iface_at=0
 if interfaces:
  align();iface_at=len(image);sections.append((0x1001,1,iface_at));image.extend(struct.pack('<I',len(interfaces)))
  for item in interfaces:image.extend(struct.pack('<H',tid[item]))
 sections.append((0x2002,len(strings),len(image)))
 for i,x in enumerate(strings):struct.pack_into('<I',image,string_at+4*i,len(image));image.extend(leb(len(x))+x.encode('ascii')+b'\0')
 code_at=0
 if method is True:
  align();code_at=len(image);sections.append((0x2001,1,code_at));target=fid[(CHILD,'value','I')]
  words=[0x0052,target,0x0059,target,0x0060,target,0x0067,target,0x000e]
  image.extend(struct.pack('<HHHHII',2,0,0,0,0,len(words)));image.extend(struct.pack('<%dH'%len(words),*words))
 class_data=0
 if defs or method:
  class_data=len(image);sections.append((0x2000,1,class_data))
  stat=sorted((fid[k],v) for k,v in defs.items() if v&8);inst=sorted((fid[k],v) for k,v in defs.items() if not(v&8))
  image.extend(leb(len(stat))+leb(len(inst))+leb(int(method is True))+leb(int(method=='abstract')))
  for group in (stat,inst):
   previous=0
   for i,flags0 in group:image.extend(leb(i-previous)+leb(flags0));previous=i
  if method:image.extend(leb(0)+leb(0x401 if method=='abstract' else 9)+leb(code_at))
 align();map_at=len(image);sections.append((0x1000,1,map_at));image.extend(struct.pack('<I',len(sections)))
 for kind,count,at in sorted(sections,key=lambda x:x[2]):image.extend(struct.pack('<HHII',kind,0,count,at))
 for i,x in enumerate(types):struct.pack_into('<I',image,type_at+4*i,sid[x])
 if method:
  struct.pack_into('<III',image,proto_at,sid['V'],tid['V'],0);struct.pack_into('<HHI',image,method_at,tid[owner],0,sid['access'])
 for i,(o,n,t) in enumerate(refs):struct.pack_into('<HHI',image,field_at+8*i,tid[o],tid[t],sid[n])
 struct.pack_into('<8I',image,class_at,tid[owner],flags,0xffffffff if parent is None else tid[parent],iface_at,0xffffffff,0,class_data,0)
 image[:8]=b'dex\n035\0';struct.pack_into('<20I',image,32,len(image),112,0x12345678,0,0,map_at,len(strings),string_at,len(types),type_at,int(bool(method)),proto_at,len(refs),field_at,int(bool(method)),method_at,1,class_at,len(image)-data_at,data_at)
 image[12:32]=hashlib.sha1(image[32:]).digest();struct.pack_into('<I',image,8,zlib.adler32(image[12:])&0xffffffff)
 return image

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=Path);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 specs={
  'object.dex':(ROOT,None,(),(),False,1),
  'child.dex':(CHILD,PARENT,(),(),False,1),
  'child-interface.dex':(CHILD,PARENT,(),(IFACE,),False,1),
  'parent.dex':(PARENT,ROOT,(('value','I',1),),(),False,1),
  'parent-static.dex':(PARENT,ROOT,(('value','I',0x19),),(),False,1),
  'interface.dex':(IFACE,ROOT,(('value','I',0x19),),(),False,0x601),
  'caller-a.dex':('Lq08/CallerA;',ROOT,(),(),True,1),
  'caller-b.dex':('Lq08/CallerB;',ROOT,(),(),True,1),
  'caller-no-body.dex':('Lq08/CallerEmpty;',ROOT,(),(),'abstract',0x401),
 }
 entries={}
 for name,spec in specs.items():
  data=build(*spec);(a.output/name).write_bytes(data);entries[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
 (a.output/'manifest.json').write_text(json.dumps(entries,indent=2)+'\n',encoding='utf-8')
 print(json.dumps(entries))
if __name__=='__main__':main()
