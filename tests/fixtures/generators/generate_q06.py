"""Generate a project-original DEX for Q06 invocation evidence.

The fixture tests static references only: it makes no ART loading, method
dispatch, verifier, or runtime-binding claim. Never overwrites a directory.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import zlib

ROOT='Ljava/lang/Object;'
SPECS={
    'q06.dex':('Lfixture/Caller;','call','()V',[
        ('Lfixture/Lib;','run','()V'), ('Lfixture/Lib;','run','()V'),
        ('Lfixture/Lib;','run','(I)V'), ('Lfixture/External;','absent','()V')]),
}

def uleb(n):
    if n<0 or n>0xffffffff: raise ValueError('uleb out of range')
    result=bytearray()
    while True:
        b=n&0x7f;n>>=7;result.append(b|(0x80 if n else 0))
        if not n:return bytes(result)

def make_dex(owner,name,proto,targets):
    own=(owner,name,proto)
    refs=set(targets+[own])
    proto_names=sorted({item[2] for item in refs},key=lambda v:(v!='()V',v))
    if any(x not in ('()V','(I)V') for x in proto_names):raise ValueError('unsupported fixture prototype')
    types={ROOT,'V',owner,*[x[0] for x in refs]}
    if '(I)V' in proto_names:types.add('I')
    strings=sorted(types | {x[1] for x in refs} | {'VI' if x=='(I)V' else 'V' for x in proto_names})
    sid={s:i for i,s in enumerate(strings)}
    ordered_types=sorted(types,key=sid.__getitem__);tid={s:i for i,s in enumerate(ordered_types)}
    pid={p:i for i,p in enumerate(proto_names)}
    methods=sorted(refs,key=lambda x:(tid[x[0]],sid[x[1]],pid[x[2]]));mid={r:i for i,r in enumerate(methods)}
    image=bytearray(112);sections=[(0,1,0)]
    def table(kind,count,width):
        if not count:return 0
        at=len(image);image.extend(bytes(count*width));sections.append((kind,count,at));return at
    def align():image.extend(bytes(-len(image)%4))
    strings_at=table(1,len(strings),4);types_at=table(2,len(ordered_types),4)
    protos_at=table(3,len(proto_names),12);methods_at=table(5,len(methods),8)
    classes_at=table(6,1,32);data_at=len(image)
    type_list_at=0
    if '(I)V' in proto_names:
        align();type_list_at=len(image);sections.append((0x1001,1,type_list_at))
        image.extend(struct.pack('<IH',1,tid['I']))
    sections.append((0x2002,len(strings),len(image)))
    for i,text in enumerate(strings):
        struct.pack_into('<I',image,strings_at+i*4,len(image));raw=text.encode('ascii')
        image.extend(uleb(len(text))+raw+b'\0')
    align();code_at=len(image);sections.append((0x2001,1,code_at))
    words=[0x0012] if any(target[2]=='(I)V' for target in targets) else []
    for target in targets:
        words.extend([0x1071 if target[2]=='(I)V' else 0x0071,mid[target],0])
    words.append(0x000e)
    incoming=1 if proto=='(I)V' else 0
    uses_arg=any(target[2]=='(I)V' for target in targets)
    image.extend(struct.pack('<HHHHII',max(incoming,int(uses_arg)),incoming,int(uses_arg),0,0,len(words)))
    image.extend(struct.pack('<'+'H'*len(words),*words))
    class_data_at=len(image);sections.append((0x2000,1,class_data_at))
    image.extend(bytes([0,0,1,0])+uleb(mid[own])+uleb(9)+uleb(code_at))
    align();map_at=len(image);sections.append((0x1000,1,map_at))
    image.extend(struct.pack('<I',len(sections)))
    for kind,count,offset in sorted(sections,key=lambda v:v[2]):image.extend(struct.pack('<HHII',kind,0,count,offset))
    for i,t in enumerate(ordered_types):struct.pack_into('<I',image,types_at+i*4,sid[t])
    for i,p in enumerate(proto_names):struct.pack_into('<III',image,protos_at+i*12,sid['VI' if p=='(I)V' else 'V'],tid['V'],type_list_at if p=='(I)V' else 0)
    for i,(mowner,mname,mproto) in enumerate(methods):struct.pack_into('<HHI',image,methods_at+i*8,tid[mowner],pid[mproto],sid[mname])
    struct.pack_into('<8I',image,classes_at,tid[owner],1,tid[ROOT],0,0xffffffff,0,class_data_at,0)
    image[:8]=b'dex\n035\0'
    struct.pack_into('<20I',image,32,len(image),112,0x12345678,0,0,map_at,len(strings),strings_at,len(ordered_types),types_at,len(proto_names),protos_at,0,0,len(methods),methods_at,1,classes_at,len(image)-data_at,data_at)
    image[12:32]=hashlib.sha1(image[32:]).digest()
    struct.pack_into('<I',image,8,zlib.adler32(image[12:])&0xffffffff)
    return bytes(image)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    manifest={}
    for name,spec in SPECS.items():
        data=make_dex(*spec);(args.output/name).write_bytes(data)
        manifest[name]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
    (args.output/'manifest.json').write_text(json.dumps({'fixtures':manifest,'scope':'Project-original raw DEX, static references only'},indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'generated':len(manifest),'output':str(args.output)}))

if __name__=='__main__':main()
