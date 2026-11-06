"""Build authored multi-source TopN fixtures, with overloaded tied names."""
from pathlib import Path
import argparse,hashlib,json,struct,zlib

OWNER='Lq11/Sort;'
ROOT='Ljava/lang/Object;'

def leb(value):
    data=bytearray()
    while True:
        x=value&127;value>>=7;data.append(x|(128 if value else 0))
        if not value:return bytes(data)

def build(which):
    if which=='early':methods=[('alpha','()V'),('middle','()V'),('middle','(I)V')]
    elif which=='late':methods=[('middle','()V'),('middle','(I)V'),('zzzzzz','()V')]
    else:raise ValueError('unknown source')
    strings=sorted({OWNER,ROOT,'I','V','VI',*(name for name,_ in methods)})
    sid={s:i for i,s in enumerate(strings)};types=sorted([OWNER,ROOT,'I','V'],key=sid.__getitem__);tid={s:i for i,s in enumerate(types)}
    protos=['()V','(I)V'];pid={p:i for i,p in enumerate(protos)}
    methods=sorted(methods,key=lambda x:(sid[x[0]],pid[x[1]]));data=bytearray(112);sections=[(0,1,0)]
    def table(kind,count,width):
        at=len(data);data.extend(bytes(count*width));sections.append((kind,count,at));return at
    def align():data.extend(bytes(-len(data)%4))
    strings_at=table(1,len(strings),4);types_at=table(2,len(types),4);proto_at=table(3,2,12)
    method_at=table(5,len(methods),8);class_at=table(6,1,32);data_at=len(data)
    align();type_list=len(data);sections.append((0x1001,1,type_list));data.extend(struct.pack('<IH',1,tid['I']))
    sections.append((0x2002,len(strings),len(data)))
    for i,text in enumerate(strings):
        struct.pack_into('<I',data,strings_at+4*i,len(data));raw=text.encode('ascii');data.extend(leb(len(raw))+raw+b'\0')
    align();sections.append((0x2001,len(methods),len(data)));code=[]
    for name,proto in methods:
        virtual=which=='early' and (name,proto)==('middle','()V')
        align();code.append(len(data));data.extend(struct.pack('<HHHHIIH',1,1 if proto=='(I)V' or virtual else 0,0,0,0,1,0x000e))
    direct=[0,2] if which=='early' else [0,1,2];virtual=[1] if which=='early' else []
    class_data=len(data);sections.append((0x2000,1,class_data));data.extend(bytes([0,0,len(direct),len(virtual)]));declarations=[]
    for group,indices in enumerate([direct,virtual]):
        previous=0
        for i in indices:
            declarations.append(len(data));data.extend(leb(i-previous)+leb(9 if group==0 else 1)+leb(code[i]));previous=i
    align();map_at=len(data);sections.append((0x1000,1,map_at));data.extend(struct.pack('<I',len(sections)))
    for kind,count,at in sorted(sections,key=lambda x:x[2]):data.extend(struct.pack('<HHII',kind,0,count,at))
    for i,t in enumerate(types):struct.pack_into('<I',data,types_at+4*i,sid[t])
    struct.pack_into('<III',data,proto_at,sid['V'],tid['V'],0)
    struct.pack_into('<III',data,proto_at+12,sid['VI'],tid['V'],type_list)
    for i,(name,proto) in enumerate(methods):struct.pack_into('<HHI',data,method_at+8*i,tid[OWNER],pid[proto],sid[name])
    struct.pack_into('<8I',data,class_at,tid[OWNER],1,tid[ROOT],0,0xffffffff,0,class_data,0)
    data[:8]=b'dex\n035\0';struct.pack_into('<20I',data,32,len(data),112,0x12345678,0,0,map_at,len(strings),strings_at,len(types),types_at,2,proto_at,0,0,len(methods),method_at,1,class_at,len(data)-data_at,data_at)
    data[12:32]=hashlib.sha1(data[32:]).digest();struct.pack_into('<I',data,8,zlib.adler32(data[12:])&0xffffffff)
    return bytes(data),{'methods':methods,'definition_refs':direct+virtual,'code_offsets':code,'declarations':declarations,'class_data':class_data,'map':map_at,'strings':strings,'types':types,'bytes':len(data)}

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    args.output.mkdir(parents=True,exist_ok=False);records={}
    for key in ['early','late']:
        data,layout=build(key);name=key+'.dex';(args.output/name).write_bytes(data)
        records[name]={'sha256':hashlib.sha256(data).hexdigest(),**layout}
    (args.output/'manifest.json').write_text(json.dumps({'fixtures':records,'scope':'project-original DEX; static sorting only, no ART or runtime binding'},indent=2)+'\n',encoding='utf-8')
    print(json.dumps(records))
if __name__=='__main__':main()
