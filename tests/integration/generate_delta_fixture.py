"""Project-original DEX with all four independent multi-member delta groups.

This is a structural fixture, not a claim of ART execution or verification.
The output directory must not exist. No production files are touched.
"""
import argparse, hashlib, json, struct, zlib
from pathlib import Path

def leb(value):
    out=bytearray()
    while True:
        b=value&0x7f; value >>= 7; out.append(b | (0x80 if value else 0))
        if not value: return bytes(out)

def checksum(data):
    data[12:32]=hashlib.sha1(data[32:]).digest()
    struct.pack_into('<I',data,8,zlib.adler32(data[12:])&0xffffffff)

def create():
    owner='Lsample/Delta;'; external='Lx/External;'; obj='Ljava/lang/Object;'
    types=sorted(['I','V',owner,external,obj])
    names=list('abcdef')
    strings=sorted(set(types+names+['z']))
    sid={s:i for i,s in enumerate(strings)}
    tid={s:i for i,s in enumerate(types)}
    fields=sorted([(owner,n,'I') for n in names]+[(external,'z','I')], key=lambda x:(tid[x[0]],sid[x[1]],tid[x[2]]))
    methods=sorted([(owner,n) for n in names]+[(external,'z')],key=lambda x:(tid[x[0]],sid[x[1]]))
    fid={(o,n):i for i,(o,n,t) in enumerate(fields)}; mid={(o,n):i for i,(o,n) in enumerate(methods)}
    data=bytearray(112);sections=[(0,1,0)]
    def table(kind,count,width):
        offset=len(data);data.extend(bytes(count*width));sections.append((kind,count,offset));return offset
    def align():data.extend(bytes(-len(data)%4))
    st=table(1,len(strings),4);ty=table(2,len(types),4);proto=table(3,1,12)
    ft=table(4,len(fields),8);mt=table(5,len(methods),8);cl=table(6,1,32);data_off=len(data)
    sections.append((0x2002,len(strings),len(data)))
    for i,s in enumerate(strings):
        struct.pack_into('<I',data,st+4*i,len(data));data.extend(leb(len(s))+s.encode('ascii')+b'\0')
    align();code_static=len(data);sections.append((0x2001,2,code_static))
    data.extend(struct.pack('<HHHHIIH',0,0,0,0,0,1,0x000e));align();code_instance=len(data)
    data.extend(struct.pack('<HHHHIIH',1,1,0,0,0,1,0x000e))
    class_data=len(data);sections.append((0x2000,1,class_data));data.extend(bytes([3,3,3,3]))
    groups=[('static_fields', [('b',9),('d',9),('f',9)]),('instance_fields',[('a',1),('c',1),('e',1)]),
            ('direct_methods',[('b',0x109),('d',9),('f',2)]),('virtual_methods',[('a',0x401),('c',1),('e',0x101)])]
    expected={}; locations={}
    for group,items in groups:
        previous=0;rows=[];locations[group]=[]
        for name,flags in items:
            index=(fid if group.endswith('fields') else mid)[owner,name]
            delta=index-previous;previous=index;offset=len(data);delta_bytes=leb(delta);flag_bytes=leb(flags)
            data.extend(delta_bytes+flag_bytes)
            code=0
            if group.endswith('methods'):
                code=0 if flags & (0x100|0x400) else code_static if flags&8 else code_instance
                data.extend(leb(code))
            rows.append({'name':name,'reference_index':index,'declaration_offset':offset,'delta':delta,'delta_hex':delta_bytes.hex(),'flags':flags,'flag_hex':flag_bytes.hex(),'code_offset':code})
            locations[group].append(offset)
        expected[group]=rows
    align();map_at=len(data);sections.append((0x1000,1,map_at));data.extend(struct.pack('<I',len(sections)))
    for kind,count,at in sorted(sections,key=lambda x:x[2]):data.extend(struct.pack('<HHII',kind,0,count,at))
    for i,t in enumerate(types):struct.pack_into('<I',data,ty+4*i,sid[t])
    struct.pack_into('<III',data,proto,sid['V'],tid['V'],0)
    for i,(o,n,t) in enumerate(fields):struct.pack_into('<HHI',data,ft+8*i,tid[o],tid[t],sid[n])
    for i,(o,n) in enumerate(methods):struct.pack_into('<HHI',data,mt+8*i,tid[o],0,sid[n])
    struct.pack_into('<8I',data,cl,tid[owner],0x401,tid[obj],0,0xffffffff,0,class_data,0)
    data[:8]=b'dex\n035\0'
    struct.pack_into('<20I',data,32,len(data),112,0x12345678,0,0,map_at,len(strings),st,len(types),ty,1,proto,len(fields),ft,len(methods),mt,1,cl,len(data)-data_off,data_off)
    checksum(data)
    return data, {'owner':owner,'groups':expected,'external_field_index':fid[external,'z'],'external_method_index':mid[external,'z'],
                  'class_data':class_data,'map':map_at,'code_static':code_static,'code_instance':code_instance,'locations':locations}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True,type=Path);args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    original,info=create(); variants={}
    def write(name,data):
        checksum(data);(args.output/(name+'.dex')).write_bytes(data)
        variants[name]={'sha256':hashlib.sha256(data).hexdigest(),'length':len(data)}
    write('four-groups',bytearray(original))
    for group,offsets in info['locations'].items():
        for suffix,value in [('duplicate',0),('out-of-range',0x7f)]:
            mutant=bytearray(original);mutant[offsets[1]]=value;write(group+'-'+suffix,mutant)
    for suffix,group,value in [('duplicate-field-across-groups','instance_fields',1),('duplicate-method-across-groups','virtual_methods',1),
                               ('static-field-wrong-group','static_fields',1),('instance-field-wrong-group','instance_fields',9),
                               ('direct-method-wrong-group','direct_methods',1),('virtual-method-wrong-group','virtual_methods',9)]:
        mutant=bytearray(original);at=info['locations'][group][1 if suffix in ('direct-method-wrong-group','virtual-method-wrong-group') else 0]
        mutant[at if suffix.startswith('duplicate') else at+1]=value;write(suffix,mutant)
    for suffix,group,payload in [('delta-overflow','static_fields',b'\xff\xff\xff\xff\x0f'),('delta-overlong','direct_methods',b'\x80\x80\x80\x80\x80')]:
        mutant=bytearray(original);at=info['locations'][group][1];mutant[at:at+len(payload)]=payload;write(suffix,mutant)
    # The original class_data ends at 494 and has two bytes of alignment
    # padding before the map at 496.  Register a valid empty encoded_array at
    # 494, so class_data's mapped end is exactly 494.  The map grows by one
    # entry; all section offsets before it remain unchanged.
    assert info['locations']['virtual_methods'][-1] == 490 and info['map'] == 496
    assert original[490:496] == bytes.fromhex('02 81 02 00 00 00')
    count=struct.unpack_from('<I',original,info['map'])[0]
    entries=[struct.unpack_from('<HHII',original,info['map']+4+i*12) for i in range(count)]
    assert entries[-2][0]==0x2000 and entries[-1][0]==0x1000 and entries[-1][3]==496
    with_empty=bytearray(original[:496]);with_empty.extend(struct.pack('<I',count+1))
    for entry in entries[:-1]:with_empty.extend(struct.pack('<HHII',*entry))
    with_empty.extend(struct.pack('<HHII',0x2005,0,1,494));with_empty.extend(struct.pack('<HHII',*entries[-1]))
    struct.pack_into('<I',with_empty,32,len(with_empty))
    struct.pack_into('<I',with_empty,104,len(with_empty)-struct.unpack_from('<I',with_empty,108)[0])
    write('delta-section-end-control',bytearray(with_empty))
    truncated=bytearray(with_empty);truncated[493]=0x80
    write('delta-section-end-truncated',truncated)
    info['variants']=variants
    (args.output/'manifest.json').write_text(json.dumps(info,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'output':str(args.output),'cases':len(variants),'fixture_sha256':variants['four-groups']['sha256']}))
if __name__=='__main__':main()
