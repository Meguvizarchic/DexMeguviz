"""Build an original Q03 DEX: annotation, static-value, and code string domains."""
from pathlib import Path
import argparse, hashlib, json, struct, zlib

OWNER='Lq03/Subject;'
ANNOTATION='Lq03/Annotation;'
ANNOTATION_TEXT='annotation-only-q03'
STATIC_TEXT='static-only-q03'
CODE_TEXT='code-use-q03'

def leb(v):
    out=bytearray()
    while True:
        low=v&127;v>>=7;out.append(low|(128 if v else 0))
        if not v:return bytes(out)

def build():
    values=sorted({OWNER,ANNOTATION,'Ljava/lang/Object;','Ljava/lang/String;','V',
        'annValue','holder','quiet','uses',ANNOTATION_TEXT,STATIC_TEXT,CODE_TEXT})
    sid={s:i for i,s in enumerate(values)}
    types=sorted([OWNER,ANNOTATION,'Ljava/lang/Object;','Ljava/lang/String;','V'],key=sid.__getitem__)
    tid={s:i for i,s in enumerate(types)}
    methods=['quiet','uses'];mid={name:i for i,name in enumerate(methods)}
    image=bytearray(112);sections=[(0,1,0)]
    def table(kind,count,width):
        at=len(image);image.extend(bytes(count*width));sections.append((kind,count,at));return at
    def align():image.extend(bytes(-len(image)%4))
    string_at=table(1,len(values),4);type_at=table(2,len(types),4)
    proto_at=table(3,1,12);field_at=table(4,1,8);method_at=table(5,2,8);class_at=table(6,1,32)
    data_at=len(image);sections.append((0x2002,len(values),data_at))
    for i,text in enumerate(values):
        struct.pack_into('<I',image,string_at+4*i,len(image));image.extend(leb(len(text))+text.encode('ascii')+b'\0')
    align();sections.append((0x2001,2,len(image)));code={}
    for name,words in [('quiet',[0x000e]),('uses',[0x001a,sid[CODE_TEXT],0x000e])]:
        align();code[name]=len(image);image.extend(struct.pack('<HHHHII',1,0,0,0,0,len(words)))
        image.extend(struct.pack('<'+'H'*len(words),*words))
    class_data=len(image);sections.append((0x2000,1,class_data))
    image.extend(b'\x01\x00\x02\x00\x00\x09')
    previous=0
    for name in methods:
        image.extend(leb(mid[name]-previous)+leb(9)+leb(code[name]));previous=mid[name]
    annotation=len(image);sections.append((0x2004,1,annotation))
    image.extend(b'\x01'+leb(tid[ANNOTATION])+b'\x01'+leb(sid['annValue'])+b'\x17'+leb(sid[ANNOTATION_TEXT]))
    static=len(image);sections.append((0x2005,1,static))
    image.extend(b'\x01\x17'+leb(sid[STATIC_TEXT]))
    align();annotation_set=len(image);sections.append((0x1003,1,annotation_set))
    image.extend(struct.pack('<II',1,annotation))
    directory=len(image);sections.append((0x2006,1,directory))
    image.extend(struct.pack('<IIII',annotation_set,0,0,0))
    align();map_at=len(image);sections.append((0x1000,1,map_at))
    image.extend(struct.pack('<I',len(sections)))
    for kind,count,at in sorted(sections,key=lambda x:x[2]):image.extend(struct.pack('<HHII',kind,0,count,at))
    for i,name in enumerate(types):struct.pack_into('<I',image,type_at+4*i,sid[name])
    struct.pack_into('<III',image,proto_at,sid['V'],tid['V'],0)
    struct.pack_into('<HHI',image,field_at,tid[OWNER],tid['Ljava/lang/String;'],sid['holder'])
    for i,name in enumerate(methods):struct.pack_into('<HHI',image,method_at+8*i,tid[OWNER],0,sid[name])
    struct.pack_into('<8I',image,class_at,tid[OWNER],1,tid['Ljava/lang/Object;'],0,0xffffffff,directory,class_data,static)
    image[:8]=b'dex\n035\0'
    struct.pack_into('<20I',image,32,len(image),112,0x12345678,0,0,map_at,len(values),string_at,len(types),type_at,1,proto_at,1,field_at,2,method_at,1,class_at,len(image)-data_at,data_at)
    image[12:32]=hashlib.sha1(image[32:]).digest();struct.pack_into('<I',image,8,zlib.adler32(image[12:])&0xffffffff)
    return bytes(image),{'strings':sid,'types':tid,'code':code,'annotation':annotation,'static':static,'annotation_set':annotation_set,'directory':directory,'map':map_at,'class_data':class_data,'bytes':len(image)}

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    args.output.mkdir(parents=True,exist_ok=False);image,positions=build();digest=hashlib.sha256(image).hexdigest()
    (args.output/'q03-domains.dex').write_bytes(image)
    (args.output/'expected.json').write_text(json.dumps({'sha256':digest,'positions':positions,'scope':'authored structural DEX; no ART or runtime claim'},indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'sha256':digest,**positions}))
if __name__=='__main__':main()
