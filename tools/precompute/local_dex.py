"""Bounded local byte identities, not a DEX verifier or a query evaluator."""
import hashlib,struct

class LocalError(ValueError):pass
class Unsupported(LocalError):pass

class Dex:
    def __init__(self,data):
        self.data=data;self.work=0;self.described={}
        if len(data)<112 or len(data)>64*1024*1024 or data[:4]!=b'dex\n' or data[4:8] not in [b'035\0',b'037\0',b'038\0',b'039\0',b'040\0']:raise Unsupported('DEX version/size')
        if self.u32(32)!=len(data) or self.u32(36)!=112 or self.u32(40)!=0x12345678:raise LocalError('DEX header')
        for at,width in [(56,4),(64,4),(72,12),(80,8),(88,8),(96,32)]:
            if self.u32(at)>1000000:raise LocalError('table limit')
            self.span(self.u32(at+4),self.u32(at)*width)
    def span(self,p,n):
        self.work+=1
        if self.work>2000000 or type(p)!=int or type(n)!=int or p<0 or n<0 or p>len(self.data)-n:raise LocalError('local work/range limit')
        return self.data[p:p+n]
    def u16(self,p):return int.from_bytes(self.span(p,2),'little')
    def u32(self,p):return int.from_bytes(self.span(p,4),'little')
    def leb(self,p):
        v=0
        for i in range(5):
            x=self.span(p,1)[0];p+=1
            if i==4 and x>15:raise LocalError('ULEB overflow')
            v|=(x&127)<<(i*7)
            if x<128:return v,p
        raise LocalError('ULEB length')
    def table(self,at,i,width):
        if type(i)!=int or i<0 or i>=self.u32(at):raise LocalError('table index')
        return self.u32(at+4)+i*width
    def string(self,i):
        p=self.u32(self.table(56,i,4));n,p=self.leb(p)
        if n>1048576:raise LocalError('string limit')
        chars=[]
        for _ in range(n):
            a=self.span(p,1)[0];p+=1
            if 0<a<128:v=a
            elif a&224==192:
                b=self.span(p,1)[0];p+=1;v=(a&31)<<6|b&63
                if b&192!=128 or (v<128 and (a,b)!=(192,128)):raise LocalError('MUTF')
            elif a&240==224:
                b,c=self.span(p,2);p+=2;v=(a&15)<<12|(b&63)<<6|c&63
                if b&192!=128 or c&192!=128 or v<2048:raise LocalError('MUTF')
            else:raise LocalError('MUTF')
            chars.append(v)
        if self.span(p,1)!=b'\0':raise LocalError('string terminator')
        return b''.join(x.to_bytes(2,'little') for x in chars).decode('utf-16le','surrogatepass')
    def typename(self,i):return self.string(self.u32(self.table(64,i,4)))
    def method_ref(self,i):
        p=self.table(88,i,8);owner,proto,name=self.u16(p),self.u16(p+2),self.u32(p+4)
        q=self.table(72,proto,12);params=self.u32(q+8);count=self.u32(params) if params else 0
        if count>65535:raise LocalError('parameter count')
        prototype='('+''.join(self.typename(self.u16(params+4+j*2)) for j in range(count))+')'+self.typename(self.u32(q+4))
        return {'owner':self.typename(owner),'name':self.string(name),'prototype':prototype,'record_offset':p,'reference_index':i}
    def field_ref(self,i):
        p=self.table(80,i,8)
        return {'owner':self.typename(self.u16(p)),'name':self.string(self.u32(p+4)),'type_descriptor':self.typename(self.u16(p+2)),'record_offset':p,'reference_index':i}
    def reference_definition(self,kind,index):
        owner=self.u16(self.table(88 if kind=='method_refs' else 80,index,8))
        for cls in range(self.u32(96)):
            cp=self.table(96,cls,32)
            if self.u32(cp)!=owner:continue
            p=self.u32(cp+24)
            if not p:break
            counts=[]
            for _ in range(4):n,p=self.leb(p);counts.append(n)
            for group,n in enumerate(counts):
                ref=0
                for _ in range(n):
                    start=p;delta,p=self.leb(p);ref+=delta;flags,p=self.leb(p)
                    if group>=2:_,p=self.leb(p)
                    if ((group>=2)==(kind=='method_refs')) and ref==index:return {'has_local_definition':True,'declaration_offset':start,'access_flags':flags}
            break
        return {'has_local_definition':False}
    def definition(self,kind,index):
        # Only class-data count headers preceding the selected class are read;
        # no unrelated code bodies or query predicates are scanned.
        prefix=0
        for cls in range(self.u32(96)):
            cp=self.table(96,cls,32);p=self.u32(cp+24)
            if not p:continue
            counts=[]
            for _ in range(4):v,p=self.leb(p);counts.append(v)
            if any(v>1000000 for v in counts):raise LocalError('class data count')
            total=sum(counts[:2] if kind=='field_defs' else counts[2:])
            if index>=prefix+total:prefix+=total;continue
            ordinal=prefix
            for group,n in enumerate(counts):
                ref=0
                for _ in range(n):
                    start=p;delta,p=self.leb(p);ref+=delta;flags,p=self.leb(p);code=0
                    if group>=2:code,p=self.leb(p)
                    relevant=(group<2)==(kind=='field_defs')
                    if relevant:
                        if ordinal==index:
                            result=self.field_ref(ref) if group<2 else self.method_ref(ref)
                            if result['owner']!=self.typename(self.u32(cp)):raise LocalError('definition owner')
                            result.update(record_offset=start,declaration_offset=start,access_flags=flags,class_index=cls)
                            if group>=2:result['code_offset']=code
                            return result
                        ordinal+=1
        raise LocalError('definition ordinal')
    def describe(self,kind,index):
        key=(kind,index)
        if key in self.described:return self.described[key]
        if kind in ('method_defs','field_defs'):v=self.definition(kind,index);v['has_local_definition']=True
        elif kind=='method_refs':v={**self.method_ref(index),**self.reference_definition(kind,index)}
        elif kind=='field_refs':v={**self.field_ref(index),**self.reference_definition(kind,index)}
        elif kind=='class_defs':
            p=self.table(96,index,32);v={'record_offset':p,'declaration_offset':p,'access_flags':self.u32(p+4),'type_descriptor':self.typename(self.u32(p)),'reference_index':self.u32(p),'has_local_definition':True}
        elif kind=='type_refs':
            v={'record_offset':self.table(64,index,4),'type_descriptor':self.typename(index),'reference_index':index,'has_local_definition':False}
            for cls in range(self.u32(96)):
                cp=self.table(96,cls,32)
                if self.u32(cp)==index:v.update(has_local_definition=True,declaration_offset=cp,access_flags=self.u32(cp+4));break
        elif kind=='string_values':v={'record_offset':self.table(56,index,4),'value':self.string(index),'reference_index':index,'has_local_definition':False}
        else:raise Unsupported('entity relation '+str(kind))
        v={'relation':kind,'local_index':index,**v};self.described[key]=v;return v
    def method_from_ref(self,index,at):
        # Generation fallback for legacy v1 rows without ordinal; consumption
        # uses the stored ordinal and never repeats this member search.
        ordinal=0
        for cls in range(self.u32(96)):
            p=self.u32(self.table(96,cls,32)+24)
            if not p:continue
            counts=[]
            for _ in range(4):n,p=self.leb(p);counts.append(n)
            for group,n in enumerate(counts):
                ref=0
                for _ in range(n):
                    start=p;delta,p=self.leb(p);ref+=delta;_,p=self.leb(p)
                    if group>=2:
                        _,p=self.leb(p)
                        if ref==index and start==at:return ordinal
                        ordinal+=1
        raise LocalError('method declaration not found')
    def code(self,ordinal):
        d=self.describe('method_defs',ordinal);at=d['code_offset']
        if not at:return b'',0
        if at%4:raise LocalError('unaligned code')
        n=self.u32(at+12)
        if n>16000000:raise LocalError('code bound')
        return self.span(at+16,n*2),at
    def code_certificate(self,ordinal):
        code,at=self.code(ordinal)
        return {'method_ordinal':ordinal,'code_offset':at,'code_units':len(code)//2,'sha256':hashlib.sha256(code).hexdigest()}
    def event(self,ordinal,pc,widths):
        code,at=self.code(ordinal);count=len(code)//2;position=0
        while position<count:
            word=self.u16(at+16+2*position);op=word&255
            if op==0 and word:
                if word==0x100:width=4+2*self.u16(at+18+2*position)
                elif word==0x200:width=2+4*self.u16(at+18+2*position)
                elif word==0x300:width=4+(self.u16(at+18+2*position)*self.u32(at+20+2*position)+1)//2
                else:raise LocalError('payload tag')
            else:width=widths.get(op,0)
            if width<=0 or width>count-position:raise LocalError('instruction bound')
            if position==pc:
                if word>255 and op==0:raise Unsupported('payload is not a use event')
                raw=self.span(at+16+pc*2,width*2);domain=None;target=None
                if op in (0x1a,0x1b):domain='string_value';target=self.u16(at+18+pc*2) if op==0x1a else self.u32(at+18+pc*2)
                elif op in range(0x6e,0x73) or op in range(0x74,0x79):domain='method_ref';target=self.u16(at+18+pc*2)
                elif 0x52<=op<=0x6d:domain='field_ref';target=self.u16(at+18+pc*2)
                elif op in (0x1c,0x1f,0x20,0x22,0x23,0x24,0x25):domain='type_ref';target=self.u16(at+18+pc*2)
                else:raise Unsupported('local use opcode')
                target_relation={'string_value':'string_values','method_ref':'method_refs','field_ref':'field_refs','type_ref':'type_refs'}[domain]
                return {'method_ordinal':ordinal,'dex_pc':pc,'opcode':op,'code_offset':at,'target_domain':domain,'target_index':target,'bytes_sha256':hashlib.sha256(raw).hexdigest(),'target':self.describe(target_relation,target)}
            position+=width
        raise LocalError('PC is not an instruction boundary')
