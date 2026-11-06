"""Create a project-original, metadata-only 33-candidate DEX for Q10."""
from pathlib import Path
import argparse, hashlib, json, struct, zlib

OWNER='Lfixture/ThirtyThree;'
NAMES=[f'm{i:02d}' for i in range(33)]

def leb(value):
    assert 0<=value<=0xffffffff
    out=bytearray()
    while True:
        part=value&127;value>>=7;out.append(part|(128 if value else 0))
        if not value:return bytes(out)

def build():
    strings=sorted({'Ljava/lang/Object;',OWNER,'V',*NAMES})
    sid={x:i for i,x in enumerate(strings)}
    types=sorted(['Ljava/lang/Object;',OWNER,'V'],key=sid.__getitem__);tid={x:i for i,x in enumerate(types)}
    image=bytearray(112);sections=[(0,1,0)]
    def table(kind,count,width):
        at=len(image);image.extend(bytes(count*width));sections.append((kind,count,at));return at
    string_at=table(1,len(strings),4);type_at=table(2,len(types),4);proto_at=table(3,1,12)
    method_at=table(5,len(NAMES),8);class_at=table(6,1,32);data_at=len(image)
    sections.append((0x2002,len(strings),len(image)))
    for i,s in enumerate(strings):
        encoded=s.encode('ascii');struct.pack_into('<I',image,string_at+4*i,len(image));image.extend(leb(len(s))+encoded+b'\0')
    image.extend(bytes(-len(image)%4));code_at=len(image);sections.append((0x2001,1,code_at))
    image.extend(struct.pack('<HHHHIIH',0,0,0,0,0,1,0x000e))
    class_data_at=len(image);sections.append((0x2000,1,class_data_at));image.extend(b'\0\0'+leb(len(NAMES))+b'\0')
    declarations=[]
    for i in range(len(NAMES)):
        declarations.append(len(image));image.extend(leb(0 if i==0 else 1)+leb(9)+leb(code_at))
    image.extend(bytes(-len(image)%4));map_at=len(image);sections.append((0x1000,1,map_at))
    image.extend(struct.pack('<I',len(sections)))
    for kind,count,at in sorted(sections,key=lambda x:x[2]):image.extend(struct.pack('<HHII',kind,0,count,at))
    for i,t in enumerate(types):struct.pack_into('<I',image,type_at+4*i,sid[t])
    struct.pack_into('<III',image,proto_at,sid['V'],tid['V'],0)
    for i,name in enumerate(NAMES):struct.pack_into('<HHI',image,method_at+8*i,tid[OWNER],0,sid[name])
    struct.pack_into('<8I',image,class_at,tid[OWNER],1,tid['Ljava/lang/Object;'],0,0xffffffff,0,class_data_at,0)
    image[:8]=b'dex\n035\0'
    struct.pack_into('<20I',image,32,len(image),112,0x12345678,0,0,map_at,len(strings),string_at,len(types),type_at,1,proto_at,0,0,len(NAMES),method_at,1,class_at,len(image)-data_at,data_at)
    image[12:32]=hashlib.sha1(image[32:]).digest();struct.pack_into('<I',image,8,zlib.adler32(image[12:])&0xffffffff)
    expected={'schema_version':1,'description':'33 authored methods; validator accepts m32 only',
              'owner':OWNER,'method_names':NAMES,'declaration_offsets':declarations,'code_offset':code_at,
              'class_data_offset':class_data_at,'sha256':hashlib.sha256(image).hexdigest(),
              'scope':'project-original static DEX; not BIL/ART/runtime evidence'}
    return bytes(image),expected

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    data,expected=build();(a.output/'q10-33.dex').write_bytes(data)
    (a.output/'expected.json').write_text(json.dumps(expected,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'bytes':len(data),'sha256':expected['sha256'],'methods':33}))
if __name__=='__main__':main()
