"""Original cross-DEX classes and interfaces for static field inheritance."""
import argparse,hashlib,json,struct,zlib
from pathlib import Path
OBJ='Ljava/lang/Object;';BASE='Lifx/Base;';CHILD='Lifx/Child;';TOP='Lifx/Top;';LEFT='Lifx/Left;';RIGHT='Lifx/Right;';CYCLE='Lifx/Cycle;';CYCLE2='Lifx/Cycle2;';BAD='Lifx/Bad;'
F=0x19
SPECS={
 'root.dex':(OBJ,None,1,[],[]),
 'base.dex':(BASE,OBJ,1,[('classSame','I',1)],[]),
 'top.dex':(TOP,OBJ,0x601,[('diamond','I',F),('hidden','I',F),('override','I',F)],[]),
 'left.dex':(LEFT,OBJ,0x601,[('classSame','I',F),('same','I',F),('override','I',F)],[TOP]),
 'right.dex':(RIGHT,OBJ,0x601,[('same','I',F)],[TOP]),
 'child.dex':(CHILD,BASE,1,[('hidden','I',2)],[LEFT,RIGHT]),
 'cycle.dex':(CYCLE,OBJ,0x601,[('cycle','I',F)],[CYCLE2]),
 'cycle2.dex':(CYCLE2,OBJ,0x601,[],[CYCLE]),
 'child-cycle.dex':(CHILD,BASE,1,[],[CYCLE]),
 'bad-instance.dex':(BAD,OBJ,0x601,[('bad','I',1)],[]),
 'bad-protected.dex':(BAD,OBJ,0x601,[('bad','I',0x1c)],[]),
 'bad-nofinal.dex':(BAD,OBJ,0x601,[('bad','I',0x09)],[]),
 'bad-type.dex':(BAD,OBJ,0x201,[('bad','I',F)],[]),
 'annotation.dex':(BAD,OBJ,0x3601,[('annotationField','I',F)],[]),
 'child-bad.dex':(CHILD,BASE,1,[],[BAD]),
}
def leb(value):
 out=bytearray()
 while True:
  part=value&127;value>>=7;out.append(part|(128 if value else 0))
  if not value:return bytes(out)
def build(owner,parent,flags,fields,interfaces):
 strings=sorted({owner,*([parent] if parent else []),*interfaces,*(x for name,typ,_ in fields for x in (name,typ))});sid={x:i for i,x in enumerate(strings)}
 types=sorted({owner,*([parent] if parent else []),*interfaces,*(typ for _,typ,_ in fields)},key=sid.__getitem__);tid={x:i for i,x in enumerate(types)}
 fields=sorted(fields,key=lambda x:(sid[x[0]],tid[x[1]]));image=bytearray(112);sections=[(0,1,0)]
 def table(kind,count,width):
  if not count:return 0
  offset=len(image);image.extend(bytes(count*width));sections.append((kind,count,offset));return offset
 def align():image.extend(bytes(-len(image)%4))
 strings_at=table(1,len(strings),4);types_at=table(2,len(types),4);fields_at=table(4,len(fields),8);class_at=table(6,1,32);data_at=len(image)
 iface_at=0
 if interfaces:
  iface_at=len(image);sections.append((0x1001,1,iface_at));image.extend(struct.pack('<I',len(interfaces)))
  for item in interfaces:image.extend(struct.pack('<H',tid[item]))
 sections.append((0x2002,len(strings),len(image)))
 for i,text in enumerate(strings):struct.pack_into('<I',image,strings_at+4*i,len(image));image.extend(leb(len(text))+text.encode('ascii')+b'\0')
 class_data=0
 if fields:
  class_data=len(image);sections.append((0x2000,1,class_data));static=[i for i,x in enumerate(fields) if x[2]&8];instance=[i for i,x in enumerate(fields) if not x[2]&8]
  image.extend(leb(len(static))+leb(len(instance))+b'\0\0')
  for group in (static,instance):
   previous=0
   for index in group:image.extend(leb(index-previous)+leb(fields[index][2]));previous=index
 align();map_at=len(image);sections.append((0x1000,1,map_at));image.extend(struct.pack('<I',len(sections)))
 for kind,count,at in sorted(sections,key=lambda x:x[2]):image.extend(struct.pack('<HHII',kind,0,count,at))
 for i,text in enumerate(types):struct.pack_into('<I',image,types_at+4*i,sid[text])
 for i,(name,typ,_) in enumerate(fields):struct.pack_into('<HHI',image,fields_at+8*i,tid[owner],tid[typ],sid[name])
 struct.pack_into('<8I',image,class_at,tid[owner],flags,0xffffffff if parent is None else tid[parent],iface_at,0xffffffff,0,class_data,0)
 image[:8]=b'dex\n035\0';struct.pack_into('<20I',image,32,len(image),112,0x12345678,0,0,map_at,len(strings),strings_at,len(types),types_at,0,0,len(fields),fields_at,0,0,1,class_at,len(image)-data_at,data_at)
 image[12:32]=hashlib.sha1(image[32:]).digest();struct.pack_into('<I',image,8,zlib.adler32(image[12:])&0xffffffff);return image
def main():
 p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=Path);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);manifest={}
 for name,spec in SPECS.items():
  data=build(*spec);(a.output/name).write_bytes(data);manifest[name]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'owner':spec[0],'parent':spec[1],'flags':spec[2],'fields':spec[3],'interfaces':spec[4]}
 (a.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8');print('generated',len(manifest),'original DEX files')
if __name__=='__main__':main()
