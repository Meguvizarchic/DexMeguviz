"""Static DEX fixtures for inherited-field hiding, type collisions and interface edges."""
import argparse,hashlib,json,struct,zlib
from pathlib import Path
CHILD='Lfixture/EdgeChild;';BASE='Lfixture/EdgeBase;';ROOT='Ljava/lang/Object;';INTERFACE='Lfixture/EdgeInterface;'
SPECS={
 'child-private.dex':(CHILD,BASE,[('shared','I',2)],()),
 'child-clear.dex':(CHILD,BASE,[],()),
 'child-interface.dex':(CHILD,BASE,[],(INTERFACE,)),
 'base-collision.dex':(BASE,ROOT,[('shared','I',1),('shared','J',1)],()),
}
def leb(value):
 out=bytearray()
 while True:
  x=value&127;value>>=7;out.append(x|(128 if value else 0))
  if not value:return bytes(out)
def build(owner,parent,fields,interfaces):
 strings=sorted({owner,parent,*interfaces,*(x for name,typ,flags in fields for x in (name,typ))})
 sid={v:i for i,v in enumerate(strings)}
 types=sorted({owner,parent,*interfaces,*(typ for _,typ,_ in fields)},key=sid.__getitem__);tid={v:i for i,v in enumerate(types)}
 fields=sorted(fields,key=lambda f:(sid[f[0]],tid[f[1]]))
 data=bytearray(112);sections=[(0,1,0)]
 def table(kind,count,width):
  if not count:return 0
  offset=len(data);data.extend(bytes(count*width));sections.append((kind,count,offset));return offset
 def align():data.extend(bytes(-len(data)%4))
 str_off=table(1,len(strings),4);type_off=table(2,len(types),4);field_off=table(4,len(fields),8);class_off=table(6,1,32);data_off=len(data)
 iface_off=0
 if interfaces:
  iface_off=len(data);sections.append((0x1001,1,iface_off));data.extend(struct.pack('<I',len(interfaces)))
  for item in interfaces:data.extend(struct.pack('<H',tid[item]))
 sections.append((0x2002,len(strings),len(data)))
 for i,text in enumerate(strings):struct.pack_into('<I',data,str_off+4*i,len(data));data.extend(leb(len(text))+text.encode('ascii')+b'\0')
 class_data=0
 if fields:
  class_data=len(data);sections.append((0x2000,1,class_data));data.extend(b'\0'+leb(len(fields))+b'\0\0')
  previous=0
  for index,(_,_,flags) in enumerate(fields):data.extend(leb(index-previous)+leb(flags));previous=index
 align();map_off=len(data);sections.append((0x1000,1,map_off));data.extend(struct.pack('<I',len(sections)))
 for kind,count,off in sorted(sections,key=lambda x:x[2]):data.extend(struct.pack('<HHII',kind,0,count,off))
 for i,text in enumerate(types):struct.pack_into('<I',data,type_off+4*i,sid[text])
 for i,(name,typ,_) in enumerate(fields):struct.pack_into('<HHI',data,field_off+8*i,tid[owner],tid[typ],sid[name])
 struct.pack_into('<8I',data,class_off,tid[owner],1,tid[parent],iface_off,0xffffffff,0,class_data,0)
 data[:8]=b'dex\n035\0';struct.pack_into('<20I',data,32,len(data),112,0x12345678,0,0,map_off,len(strings),str_off,len(types),type_off,0,0,len(fields),field_off,0,0,1,class_off,len(data)-data_off,data_off)
 data[12:32]=hashlib.sha1(data[32:]).digest();struct.pack_into('<I',data,8,zlib.adler32(data[12:])&0xffffffff)
 return data
def main():
 p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=Path);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 entries={}
 for name,spec in SPECS.items():
  data=build(*spec);(a.output/name).write_bytes(data);entries[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
 (a.output/'manifest.json').write_text(json.dumps(entries,indent=2)+'\n',encoding='utf-8')
 print(json.dumps(entries))
if __name__=='__main__':main()
