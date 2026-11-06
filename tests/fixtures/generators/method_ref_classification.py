"""Small project-original DEX fixtures for four static rule filters."""
import hashlib,struct,zlib

def leb(n):
    out=bytearray()
    while True:
        b=n&127;n>>=7;out.append(b|(128 if n else 0))
        if not n:return bytes(out)

def build(owner,name,ret,params,used=(),pool=(),target=None,targets=(),static=True,raw_flags=None,invoke_kinds=(),extra_abstract=(),extra_native=(),extra_bodies=(),zero_code=False):
    obj='Ljava/lang/Object;'; proto=(ret,tuple(params)); refs=[(owner,name,proto)]
    if target and targets:raise ValueError('choose target or targets')
    calls=list(targets) if targets else ([target] if target else [])
    kinds=list(invoke_kinds) if invoke_kinds else ['static']*len(calls)
    if len(kinds)!=len(calls) or any(k not in ('static','virtual','interface') for k in kinds):raise ValueError('invalid fixture invoke kinds')
    for item in calls:refs.append((item[0],item[1],(item[2],tuple(item[3]))))
    abstract_refs=[]
    for item in extra_abstract:
        if len(item)!=4 or not item[3]&0x400:raise ValueError('extra definition must be abstract')
        ref=(owner,item[0],(item[1],tuple(item[2])));refs.append(ref);abstract_refs.append((ref,item[3]))
    native_refs=[]
    for item in extra_native:
        if len(item)!=4 or not item[3]&0x100 or item[3]&0x400:raise ValueError('extra definition must be native')
        ref=(owner,item[0],(item[1],tuple(item[2])));refs.append(ref);native_refs.append((ref,item[3]))
    for bname,bret,bparams,bused,bcalls,bflags in extra_bodies:
        if not bflags&8 or bflags&(0x100|0x400):raise ValueError('extra body must be concrete static')
        refs.append((owner,bname,(bret,tuple(bparams))))
        for ro,rn,rr,rp in bcalls:refs.append((ro,rn,(rr,tuple(rp))))
    protos=set(x[2] for x in refs);type_set={obj,owner,ret,*params}
    for ro,rn,(rr,rp) in refs:type_set.add(ro);type_set.add(rr);type_set.update(rp)
    def shorty(p):return ''.join('L' if x.startswith(('L','[')) else x for x in (p[0],*p[1]))
    strings=sorted(type_set|{x[1] for x in refs}|{shorty(p) for p in protos}|set(used)|set(pool)|{s for b in extra_bodies for s in b[3]})
    sid={s:i for i,s in enumerate(strings)};types=sorted(type_set,key=sid.__getitem__);tid={s:i for i,s in enumerate(types)}
    protos=sorted(protos,key=lambda p:(tid[p[0]],tuple(tid[x] for x in p[1])));pid={p:i for i,p in enumerate(protos)}
    refs=sorted(set(refs),key=lambda r:(tid[r[0]],sid[r[1]],pid[r[2]]));mid={m:i for i,m in enumerate(refs)}
    own=mid[(owner,name,proto)];img=bytearray(112);sections=[(0,1,0)]
    def table(kind,count,width):
        at=len(img);img.extend(bytes(count*width));sections.append((kind,count,at));return at
    def align():img.extend(bytes(-len(img)%4))
    s_at=table(1,len(strings),4);t_at=table(2,len(types),4);p_at=table(3,len(protos),12);m_at=table(5,len(refs),8);c_at=table(6,1,32);data_at=len(img)
    lists={};nonempty=sorted({p[1] for p in protos if p[1]},key=lambda v:tuple(tid[x] for x in v))
    if nonempty:
        align();sections.append((0x1001,len(nonempty),len(img)))
        for args in nonempty:
            align();lists[args]=len(img);img.extend(struct.pack('<I',len(args)))
            for item in args:img.extend(struct.pack('<H',tid[item]))
    sections.append((0x2002,len(strings),len(img)))
    for i,text in enumerate(strings):
        raw=text.encode('ascii');struct.pack_into('<I',img,s_at+4*i,len(img));img.extend(leb(len(text))+raw+b'\0')
    align();sections.append((0x2001,1+len(extra_bodies),len(img)))
    def add_code(result,parameters,used_strings,call_targets,call_kinds,is_static):
        align(); code_at=len(img); words=[]
        for text in used_strings:words.extend((0x001a,sid[text]))
        invoke_counts=[]
        for target,kind in zip(call_targets,call_kinds):
            item=(target[0],target[1],(target[2],tuple(target[3])))
            count=len(target[3])+(kind!='static')
            if count>255 or any(x in ('J','D') for x in target[3]):raise ValueError('unsupported fixture invoke parameters')
            invoke_counts.append(count)
            if count>5:words.extend(((count<<8)|{'static':0x77,'virtual':0x74,'interface':0x78}[kind],mid[item],0))
            else:words.extend(((count<<12)|{'static':0x71,'virtual':0x6e,'interface':0x72}[kind],mid[item],0))
        if zero_code:
            if result!='V' or words:raise ValueError('empty body fixture requires empty void code')
        elif result=='V':words.append(0x000e)
        elif result in ('I','Z'):words.extend((0x0012,0x000f))
        else:words.extend((0x0012,0x0011))
        incoming=len(parameters)+(0 if is_static else 1);max_call=max(invoke_counts,default=0)
        img.extend(struct.pack('<HHHHII',max(incoming+1,max_call),incoming,max_call,0,0,len(words)))
        img.extend(struct.pack('<'+'H'*len(words),*words));return code_at
    code=add_code(ret,params,used,calls,kinds,static);body_defs=[]
    for bname,bret,bparams,bused,bcalls,bflags in extra_bodies:
        off=add_code(bret,bparams,bused,bcalls,['static']*len(bcalls),True)
        body_defs.append((mid[(owner,bname,(bret,tuple(bparams)))],bflags,off))
    class_data=len(img);sections.append((0x2000,1,class_data))
    flags=(9 if static else 1) if raw_flags is None else raw_flags
    definitions=[(own,flags,code)]+[(mid[ref],f,0) for ref,f in abstract_refs+native_refs]+body_defs
    if len({x[0] for x in definitions})!=len(definitions):raise ValueError('duplicate fixture definition')
    direct=sorted((x for x in definitions if x[1]&(0x2|0x8|0x10000)),key=lambda x:x[0])
    virtual=sorted((x for x in definitions if not x[1]&(0x2|0x8|0x10000)),key=lambda x:x[0])
    img.extend(leb(0)+leb(0)+leb(len(direct))+leb(len(virtual)))
    for group in (direct,virtual):
        previous=0
        for index,method_flags,offset in group:
            img.extend(leb(index-previous)+leb(method_flags)+leb(offset));previous=index
    align();map_at=len(img);sections.append((0x1000,1,map_at));img.extend(struct.pack('<I',len(sections)))
    for kind,count,at in sorted(sections,key=lambda x:x[2]):img.extend(struct.pack('<HHII',kind,0,count,at))
    for i,t in enumerate(types):struct.pack_into('<I',img,t_at+4*i,sid[t])
    for i,p in enumerate(protos):struct.pack_into('<III',img,p_at+12*i,sid[shorty(p)],tid[p[0]],lists.get(p[1],0))
    for i,(ro,rn,rp) in enumerate(refs):struct.pack_into('<HHI',img,m_at+8*i,tid[ro],pid[rp],sid[rn])
    struct.pack_into('<8I',img,c_at,tid[owner],1,tid[obj],0,0xffffffff,0,class_data,0)
    img[:8]=b'dex\n035\0';struct.pack_into('<20I',img,32,len(img),112,0x12345678,0,0,map_at,len(strings),s_at,len(types),t_at,len(protos),p_at,0,0,len(refs),m_at,1,c_at,len(img)-data_at,data_at)
    img[12:32]=hashlib.sha1(img[32:]).digest();struct.pack_into('<I',img,8,zlib.adler32(img[12:])&0xffffffff)
    return bytes(img)


def generate(destination):
    from pathlib import Path
    import json
    destination=Path(destination)
    if destination.exists():raise ValueError('output must not exist')
    destination.mkdir(parents=True)
    target=('Lsample/Target;','sink','V',[])
    payloads={'reference.dex':build('Lsample/Caller;','caller','V',[],targets=[target]),
              'definition-with-return.dex':build('Lsample/Target;','sink','V',[]),
              'empty-code-invalid.dex':build('Lsample/Target;','sink','V',[],zero_code=True)}
    for name,data in payloads.items():
        with (destination/name).open('xb') as f:f.write(data)
    print(json.dumps({name:hashlib.sha256(data).hexdigest() for name,data in payloads.items()},sort_keys=True))
if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);generate(p.parse_args().out)
