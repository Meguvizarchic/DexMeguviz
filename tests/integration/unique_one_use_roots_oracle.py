"""Independent fixed-sample DEX and v12 row/witness oracle; no ART claims."""
from pathlib import Path
import copy,hashlib,json,struct,subprocess,sys,tempfile,zlib

root=Path(__file__).resolve().parents[2];exe=Path(sys.argv[1]).resolve();out=Path(sys.argv[2]) if len(sys.argv)>2 else Path(tempfile.mkdtemp(prefix='dmg-unique-oracle-'))/'report';out.mkdir(exist_ok=False)
u32le=lambda n:struct.pack('<I',n)
u64le=lambda n:struct.pack('<Q',n)
frame=lambda b:u64le(len(b))+b

def canonical_identity(rel,cap):
    # Authored schema for default Unique/1 root scan; independent of the library.
    predicate=b''.join(u32le(n) for n in (0,0,0,0,0xffffffff,0))
    caps=2+512+4096+131072+1048576+cap
    top=b''.join(u32le(n) for n in (rel,2,1))+u64le(100000000)+b''.join(u32le(n) for n in (7,1,0,caps,0,100000,0,0))
    node=b''.join(u32le(n) for n in (0,rel,1))+frame(predicate)+b''.join(u32le(n) for n in (0,1,0xffffffff,1,0,0,0,0,0,0))
    raw=b'DexMeguviz:QueryIR:unique-one-v12'+top+node
    assert len(raw)==169
    return 'query:v12:'+hashlib.sha256(raw).hexdigest(),caps,raw

def parse_fixture(path,sha,kind):
    d=path.read_bytes();assert len(d)==608 and hashlib.sha256(d).hexdigest()==sha
    u16=lambda i:struct.unpack_from('<H',d,i)[0]
    u32=lambda i:struct.unpack_from('<I',d,i)[0]
    def leb(i):
        value=0
        for n in range(5):
            b=d[i+n];value|=(b&127)<<(7*n)
            if not b&128:return value,i+n+1
        raise AssertionError('invalid leb')
    assert d[:8]==b'dex\n035\0' and u32(32)==len(d) and d[12:32]==hashlib.sha1(d[32:]).digest() and u32(8)==zlib.adler32(d[12:])&0xffffffff
    def strbytes(idx):
        assert idx<u32(56); pos=u32(u32(60)+4*idx); length,p=leb(pos);end=d.index(0,p);return length,d[p:end]
    def ascii_string(idx):
        count,b=strbytes(idx);assert count==len(b);return b.decode('ascii')
    def typ(idx):assert idx<u32(64);return ascii_string(u32(u32(68)+4*idx))
    def meth(idx):
        assert idx<u32(88);p=u32(92)+idx*8;owner=typ(u16(p));proto=u16(p+2);name=ascii_string(u32(p+4));q=u32(76)+proto*12
        assert proto<u32(72) and u32(q+8)==0
        return owner,name,'()'+typ(u32(q+4))
    assert u32(96)==1; class_data=u32(u32(100)+24);cur=class_data;sizes=[]
    for _ in range(4):v,cur=leb(cur);sizes.append(v)
    assert sizes==[1,0,3,1]
    # encoded_field and direct methods; caller ordinal is method definition order.
    for _ in range(sizes[0]+sizes[1]):_,cur=leb(cur);_,cur=leb(cur)
    method_index=0; methods=[]
    for i in range(sizes[2]):
        diff,cur=leb(cur);flags,cur=leb(cur);code,cur=leb(cur);method_index+=diff;methods.append((method_index,flags,code))
    method_index=0
    for i in range(sizes[3]):
        diff,cur=leb(cur);flags,cur=leb(cur);code,cur=leb(cur);method_index+=diff;methods.append((method_index,flags,code))
    # Method definition order follows direct methods, then virtual methods.
    ref,flags,code=methods[2]
    assert (ref,flags,code)==(3,9,416) and meth(ref)==('Lfacts/Example;','uses','()V')
    count=u32(code+12);assert count==8;words=list(struct.unpack_from('<8H',d,code+16))
    if kind=='string_uses':
        assert words==[0x1a,10,0x1b,10,0,0,0,0xe]
        length,data=strbytes(10);assert length==7 and data==b'used\xed\xa0\xbd\xed\xb8\x80x'
        assert data.decode('utf-8','surrogatepass').encode('utf-16-le','surrogatepass')==b'u\x00s\x00e\x00d\x00\x3d\xd8\x00\xde\x78\x00'
        events=[(0,words[0],words[1]),(2,words[2],words[3]|words[4]<<16)]
    else:
        assert words==[0x60,0,0x67,0,0,0,0,0xe] and u32(80)==1
        p=u32(84);owner,type_index,name=u16(p),u16(p+2),u32(p+4)
        assert (typ(owner),typ(type_index),ascii_string(name))==('Lfacts/Example;','I','counter')
        events=[(0,words[0],words[1]),(2,words[2],words[3])]
    return {'sha':sha,'code':code,'code_units':count,'caller_ordinal':2,'caller_ref':ref,'caller':meth(ref),'events':events}

def verify(result,model,kind,pc,limited,expected_id=None):
    assert result['profile']=='dex-query-unique-one-v12' and result['relation']==kind
    assert (result['execution_status'],result['coverage'],result['decision'],result['reason'])==(('BudgetExceeded','Partial','Undetermined','ResultLimit') if limited else ('Complete','Complete','ProvenTrue','None'))
    if expected_id is not None:assert result['query_id']==expected_id
    assert result['source_sha256']==model['sha'] and len(result['sources'])==1
    source=result['sources'][0];assert source['source_sha256']==model['sha'] and source['source_index']==source['input_index']==0
    assert len(result['candidates'])==1;row=result['candidates'][0]
    raw=next(e for e in model['events'] if e[0]==pc);_,opcode,target=raw
    domain='string_value' if kind=='string_uses' else 'field_ref';refkind='string' if kind=='string_uses' else 'field'
    expected={'source_index':0,'input_index':0,'source_sha256':model['sha'],'value_kind':'use','relation':kind,'local_index':model['caller_ordinal'],'caller_ordinal':model['caller_ordinal'],'caller_method_ref':model['caller_ref'],'dex_pc':pc,'opcode':opcode,'code_offset':model['code'],'instruction_offset':model['code']+16+pc*2,'target_domain':domain,'target_index':target,'extra_proto':None,'caller_owner':model['caller'][0],'caller_name':model['caller'][1],'caller_prototype':model['caller'][2],'bindings':[]}
    for k,v in expected.items():assert row[k]==v,(k,row[k],v)
    for k in ('content_id','occurrence_id','logical_dex_id','snapshot_id'):assert row[k]==source[k]
    entity={'relation':kind,'source_index':0,'local_index':model['caller_ordinal'],'dex_pc':pc}
    use={'kind':'string_use' if kind=='string_uses' else 'field_use','node_id':1,'matched':True,'dex_pc':pc,'opcode':opcode,'reference_index':target,'reference_kind':refkind,'extra_proto':None,'code_units':model['code_units'],'operator_node':0,'entity':entity}
    metadata={'kind':'metadata','node_id':1,'matched':True,'dex_pc':None,'opcode':None,'reference_index':None,'reference_kind':None,'extra_proto':None,'code_units':0,'operator_node':0,'entity':entity}
    assert row['evidence']==[use,metadata],row['evidence']

records=[];forged=[]
for kind,path,sha,rel,cap,golden in [
 ('string_uses','unique-one-v12/string-utf16-v12.dex','67e58385794f6bc1f8fe56a30bbcb4a4eb973e26b4e6449a52ed0c671668292a',7,32,'query:v12:81ff44a941596cf3df7ddd18081b9b9c03600ca06e42777d9626cd999e646e2b'),
 ('field_uses','use_relations/field-read-write.dex','7558a8945c3a87f727de782d885c687539d839e460497f6d2e86c2a7c7f46e8d',9,128,'query:v12:7e1cb8ee7b5cbb51c18b0a3a1b9043911336f953430d423625af601acceb6f45')]:
    fixture=root/'tests/fixtures/generated'/path;model=parse_fixture(fixture,sha,kind);query_id,caps,canonical=canonical_identity(rel,cap);assert query_id==golden
    (out/(kind+'.canonical.bin')).write_bytes(canonical)
    for pc in (None,0,2):
        relation={'op':'scan','relation':kind};
        if pc is not None:relation['where']={'pc':pc}
        q={'schema_version':1,'relation':relation,'intent':'unique','max_results':1,'required_capabilities':['unique_one_stream']}
        label=kind+('-all' if pc is None else '-pc'+str(pc));qp=out/(label+'.query.json');qp.write_text(json.dumps(q),encoding='utf-8')
        proc=subprocess.run([str(exe),'query',str(fixture),'--query',str(qp.resolve()),'--json'],capture_output=True,timeout=30)
        (out/(label+'.stdout.json')).write_bytes(proc.stdout);(out/(label+'.stderr.log')).write_bytes(proc.stderr)
        assert proc.returncode==(3 if pc is None else 0),(label,proc.returncode,proc.stderr)
        result=json.loads(proc.stdout);assert result['query']['required_capabilities']==caps
        verify(result,model,kind,0 if pc is None else pc,pc is None,golden if pc is None else None)
        records.append({'case':label,'query_id':result['query_id'],'pc':0 if pc is None else pc})
        # Mutate one claim at a time, including every witness field and target identity.
        # Bind v as a default argument; each mutation must differ from the sample.
        mutations=[('row_'+k,lambda x,k=k,v=v:x['candidates'][0].__setitem__(k,v)) for k,v in {'target_index':999,'target_domain':'wrong','dex_pc':99,'opcode':0,'instruction_offset':0,'caller_ordinal':0,'caller_method_ref':0,'source_sha256':'wrong'}.items()]
        for wi in (0,1):
            for key in ('kind','node_id','matched','dex_pc','opcode','reference_index','reference_kind','extra_proto','code_units','operator_node'):
                def mutate(x,wi=wi,key=key):
                    w=x['candidates'][0]['evidence'][wi];v=w[key];w[key]='forged' if isinstance(v,str) or v is None else (not v if isinstance(v,bool) else v+1000)
                mutations.append((f'witness{wi}_{key}',mutate))
            for key in ('relation','source_index','local_index','dex_pc'):
                def mutate_entity(x,wi=wi,key=key):
                    e=x['candidates'][0]['evidence'][wi]['entity'];v=e[key];e[key]='forged' if isinstance(v,str) else v+1000
                mutations.append((f'witness{wi}_entity_{key}',mutate_entity))
        for name,mutate in mutations:
            bad=copy.deepcopy(result);mutate(bad)
            try:verify(bad,model,kind,0 if pc is None else pc,pc is None,golden if pc is None else None)
            except (AssertionError,KeyError):forged.append(label+':'+name)
            else:raise AssertionError('forged claim accepted: '+label+':'+name)
summary={'records':records,'forged_rejected':forged,'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'scope':'fixed static DEX byte and query output verification; no ART, Android or runtime proof'}
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
print('PASS',len(records),'raw-byte witness/target cases,',len(forged),'forgeries rejected, 2 independently encoded identities; report:',out)
