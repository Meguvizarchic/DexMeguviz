"""Generate one project-original DEX with multi-method string-use patterns.

Static DEX reference fixture only; no ART loading or runtime behavior claim.
The output folder must not exist.
"""
from pathlib import Path
import argparse, hashlib, json, struct, zlib

OWNER='Lfixture/Pattern;'
ROOT='Ljava/lang/Object;'
NAMES=['alpha','beta','both','neither']
USES={'alpha':['alpha-goal'],'beta':['beta-goal'],'both':['alpha-goal','beta-goal'],'neither':[]}

def uleb(n):
    assert 0<=n<=0xffffffff
    out=bytearray()
    while True:
        v=n&127;n>>=7;out.append(v|(128 if n else 0))
        if not n:return bytes(out)

def build():
    strings=sorted({OWNER,ROOT,'V','alpha-goal','beta-goal','pool-only',*NAMES})
    sid={s:i for i,s in enumerate(strings)};types=sorted([OWNER,ROOT,'V'],key=sid.__getitem__);tid={s:i for i,s in enumerate(types)}
    methods=sorted(NAMES,key=sid.__getitem__);mid={s:i for i,s in enumerate(methods)}
    data=bytearray(112);sections=[(0,1,0)]
    def table(kind,count,width):
        if not count:return 0
        at=len(data);data.extend(bytes(count*width));sections.append((kind,count,at));return at
    def align():data.extend(bytes(-len(data)%4))
    string_at=table(1,len(strings),4);type_at=table(2,len(types),4);proto_at=table(3,1,12)
    method_at=table(5,len(methods),8);class_at=table(6,1,32);data_at=len(data)
    sections.append((0x2002,len(strings),data_at))
    for i,text in enumerate(strings):
        struct.pack_into('<I',data,string_at+i*4,len(data));encoded=text.encode('ascii');data.extend(uleb(len(text))+encoded+b'\0')
    align();sections.append((0x2001,len(methods),len(data)));codes={}
    for name in methods:
        align();codes[name]=len(data);words=[]
        for literal in USES[name]:words.extend([0x001a,sid[literal]])
        words.append(0x000e);data.extend(struct.pack('<HHHHII',1,0,0,0,0,len(words)));data.extend(struct.pack('<'+'H'*len(words),*words))
    class_data=len(data);sections.append((0x2000,1,class_data));data.extend(b'\0\0\x04\0')
    previous=0
    for name in methods:
        current=mid[name];data.extend(uleb(current-previous)+uleb(9)+uleb(codes[name]));previous=current
    align();map_at=len(data);sections.append((0x1000,1,map_at));data.extend(struct.pack('<I',len(sections)))
    for kind,count,at in sorted(sections,key=lambda x:x[2]):data.extend(struct.pack('<HHII',kind,0,count,at))
    for i,t in enumerate(types):struct.pack_into('<I',data,type_at+4*i,sid[t])
    struct.pack_into('<III',data,proto_at,sid['V'],tid['V'],0)
    for i,name in enumerate(methods):struct.pack_into('<HHI',data,method_at+8*i,tid[OWNER],0,sid[name])
    struct.pack_into('<8I',data,class_at,tid[OWNER],1,tid[ROOT],0,0xffffffff,0,class_data,0)
    data[:8]=b'dex\n035\0';struct.pack_into('<20I',data,32,len(data),112,0x12345678,0,0,map_at,len(strings),string_at,len(types),type_at,1,proto_at,0,0,len(methods),method_at,1,class_at,len(data)-data_at,data_at)
    data[12:32]=hashlib.sha1(data[32:]).digest();struct.pack_into('<I',data,8,zlib.adler32(data[12:])&0xffffffff)
    return bytes(data)

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=Path);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    image=build();(a.output/'q04.dex').write_bytes(image)
    manifest={'fixture':'q04.dex','sha256':hashlib.sha256(image).hexdigest(),'bytes':len(image),'scope':'project-original static strings and methods; no ART/runtime claim'}
    (a.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8');print(json.dumps(manifest))
if __name__=='__main__':main()
