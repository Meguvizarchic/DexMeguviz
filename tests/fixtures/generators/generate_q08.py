"""Generate original DEX separating parent/child declarations and field uses.

This is a static structural fixture; it does not prove inheritance resolution,
class loading, bytecode verification, or runtime behavior. Never overwrites.
"""
from pathlib import Path
import argparse,hashlib,json,struct,zlib

BASE='Lfixture/Base;';CHILD='Lfixture/Child;';ROOT='Ljava/lang/Object;'
FIELDS=[(BASE,'parentOnly','I'),(BASE,'shared','I'),(CHILD,'childOnly','I'),(CHILD,'shared','I')]
METHODS=[(BASE,'baseProbe'),(CHILD,'access'),(CHILD,'quiet')]

def leb(n):
    out=bytearray()
    while True:
        b=n&127;n>>=7;out.append(b|(128 if n else 0))
        if not n:return bytes(out)

def build():
    strings=sorted({BASE,CHILD,ROOT,'I','V',*[n for _,n,_ in FIELDS],*[n for _,n in METHODS]})
    sid={s:i for i,s in enumerate(strings)};types=sorted([BASE,CHILD,ROOT,'I','V'],key=sid.__getitem__);tid={s:i for i,s in enumerate(types)}
    fields=sorted(FIELDS,key=lambda f:(tid[f[0]],sid[f[1]],tid[f[2]]));fid={(o,n):i for i,(o,n,_) in enumerate(fields)}
    methods=sorted(METHODS,key=lambda m:(tid[m[0]],sid[m[1]],0));mid={(o,n):i for i,(o,n) in enumerate(methods)}
    data=bytearray(112);sections=[(0,1,0)]
    def table(kind,count,width):
        if not count:return 0
        at=len(data);data.extend(bytes(count*width));sections.append((kind,count,at));return at
    def align():data.extend(bytes(-len(data)%4))
    string_at=table(1,len(strings),4);type_at=table(2,len(types),4);proto_at=table(3,1,12)
    field_at=table(4,len(fields),8);method_at=table(5,len(methods),8);class_at=table(6,2,32);data_at=len(data)
    sections.append((0x2002,len(strings),data_at))
    for i,text in enumerate(strings):
        struct.pack_into('<I',data,string_at+4*i,len(data));raw=text.encode('ascii');data.extend(leb(len(text))+raw+b'\0')
    align();sections.append((0x2001,len(methods),len(data)));codes={}
    for owner,name in methods:
        align();codes[(owner,name)]=len(data)
        words=[0x0060,fid[(BASE,'shared')],0x0067,fid[(BASE,'shared')],0x0060,fid[(CHILD,'shared')],0x0067,fid[(CHILD,'shared')],0x000e] if name=='access' else [0x000e]
        data.extend(struct.pack('<HHHHII',1,0,0,0,0,len(words)));data.extend(struct.pack('<'+'H'*len(words),*words))
    sections.append((0x2000,2,len(data)));class_data={}
    for owner in [BASE,CHILD]:
        class_data[owner]=len(data);owned_f=[f for f in fields if f[0]==owner];owned_m=[m for m in methods if m[0]==owner]
        data.extend(leb(len(owned_f))+b'\0'+leb(len(owned_m))+b'\0');prev=0
        for _,name,_ in owned_f:
            index=fid[(owner,name)];data.extend(leb(index-prev)+leb(9));prev=index
        prev=0
        for _,name in owned_m:
            index=mid[(owner,name)];data.extend(leb(index-prev)+leb(9)+leb(codes[(owner,name)]));prev=index
    align();map_at=len(data);sections.append((0x1000,1,map_at));data.extend(struct.pack('<I',len(sections)))
    for kind,count,at in sorted(sections,key=lambda x:x[2]):data.extend(struct.pack('<HHII',kind,0,count,at))
    for i,t in enumerate(types):struct.pack_into('<I',data,type_at+i*4,sid[t])
    struct.pack_into('<III',data,proto_at,sid['V'],tid['V'],0)
    for i,(owner,name,field_type) in enumerate(fields):struct.pack_into('<HHI',data,field_at+i*8,tid[owner],tid[field_type],sid[name])
    for i,(owner,name) in enumerate(methods):struct.pack_into('<HHI',data,method_at+i*8,tid[owner],0,sid[name])
    for i,owner in enumerate([BASE,CHILD]):struct.pack_into('<8I',data,class_at+i*32,tid[owner],1,tid[ROOT] if owner==BASE else tid[BASE],0,0xffffffff,0,class_data[owner],0)
    data[:8]=b'dex\n035\0';struct.pack_into('<20I',data,32,len(data),112,0x12345678,0,0,map_at,len(strings),string_at,len(types),type_at,1,proto_at,len(fields),field_at,len(methods),method_at,2,class_at,len(data)-data_at,data_at)
    data[12:32]=hashlib.sha1(data[32:]).digest();struct.pack_into('<I',data,8,zlib.adler32(data[12:])&0xffffffff);return bytes(data)

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=Path);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    image=build();(a.output/'q08.dex').write_bytes(image)
    info={'fixture':'q08.dex','sha256':hashlib.sha256(image).hexdigest(),'bytes':len(image),'scope':'project-original static DEX references; no ART or runtime inheritance claim'}
    (a.output/'manifest.json').write_text(json.dumps(info,indent=2)+'\n',encoding='utf-8');print(json.dumps(info))
if __name__=='__main__':main()
