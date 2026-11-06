"""Q11 independent full-order oracle for authored multi-source TopN DEX."""
from pathlib import Path
from functools import cmp_to_key
import argparse,copy,hashlib,json,struct,subprocess,sys,time,zlib

PINS={'early.dex':'2c842eaddb4f7b505acfad875c433b24ac4b415df19c760893a83d9284c909fe',
      'late.dex':'d169c51725b9520a685f878e344af1a3e09c5a4b0b447ec2c731054e14e1baa2'}
GENERATOR_SHA='9dd009631543042739cc9fe235e45550393a94391d2a3f2e0b990cc91b0d6abd'
METHODS={'early.dex':[('alpha','()V'),('middle','()V'),('middle','(I)V')],
         'late.dex':[('middle','()V'),('middle','(I)V'),('zzzzzz','()V')]}
OWNER='Lq11/Sort;'
def u16(d,o):return struct.unpack_from('<H',d,o)[0]
def u32(d,o):return struct.unpack_from('<I',d,o)[0]
def leb(d,o):
    v=0
    for i in range(5):
        assert o<len(d);b=d[o];o+=1;assert i<4 or b<=15;v|=(b&127)<<(7*i)
        if b<128:return v,o
    raise AssertionError('overlong ULEB')

def raw(path):
    d=path.read_bytes();assert len(d)==512 and hashlib.sha256(d).hexdigest()==PINS[path.name]
    assert d[:8]==b'dex\n035\0' and u32(d,32)==len(d) and u32(d,36)==112 and u32(d,40)==0x12345678
    assert d[12:32]==hashlib.sha1(d[32:]).digest() and u32(d,8)==zlib.adler32(d[12:])&0xffffffff
    assert (u32(d,52),u32(d,104),u32(d,108))==(376,276,236)
    assert u32(d,376)==11
    items=[struct.unpack_from('<HHII',d,380+12*i) for i in range(11)]
    assert items==[(0,0,1,0),(1,0,7,112),(2,0,4,140),(3,0,2,156),(5,0,3,180),(6,0,1,204),(0x1001,0,1,236),(0x2002,0,7,242),(0x2001,0,3,300),(0x2000,0,1,358),(0x1000,0,1,376)]
    strings=[]
    for i in range(u32(d,56)):
        at=u32(d,u32(d,60)+4*i);n,pos=leb(d,at);end=d.index(0,pos);value=d[pos:end]
        assert len(value)==n and all(0<c<128 for c in value);strings.append(value.decode('ascii'))
    types=[strings[u32(d,u32(d,68)+4*i)] for i in range(u32(d,64))]
    assert types==['I','Ljava/lang/Object;',OWNER,'V'] and u32(d,72)==2
    protos=[]
    for i in range(2):
        at=u32(d,76)+12*i;off=u32(d,at+8);params=[] if not off else [types[u16(d,off+4+2*j)] for j in range(u32(d,off))]
        protos.append('('+''.join(params)+')'+types[u32(d,at+4)])
    assert protos==['()V','(I)V'] and u32(d,88)==3
    refs=[]
    for i in range(3):
        at=u32(d,92)+8*i;refs.append((types[u16(d,at)],strings[u32(d,at+4)],protos[u16(d,at+2)]))
    assert refs==[(OWNER,name,proto) for name,proto in METHODS[path.name]]
    cls=u32(d,100);assert u32(d,96)==1 and types[u32(d,cls)]==OWNER
    assert (u32(d,cls+4),types[u32(d,cls+8)],u32(d,cls+12),u32(d,cls+16),u32(d,cls+20),u32(d,cls+28))==(1,'Ljava/lang/Object;',0,0xffffffff,0,0)
    pos=u32(d,cls+24);assert pos==358;sizes=[]
    assert d[358:374]==(bytes.fromhex('00 00 02 01 00 09 ac 02 02 09 d4 02 01 01 c0 02') if path.name=='early.dex' else bytes.fromhex('00 00 03 00 00 09 ac 02 01 09 c0 02 01 09 d4 02'))
    for _ in range(4):n,pos=leb(d,pos);sizes.append(n)
    assert sizes==([0,0,2,1] if path.name=='early.dex' else [0,0,3,0]);rows=[]
    expected=([(0,9,300,362),(2,9,340,366),(1,1,320,370)] if path.name=='early.dex'
              else [(0,9,300,362),(1,9,320,366),(2,9,340,370)])
    for group,count in enumerate(sizes[2:]):
        previous=0
        for _ in range(count):
            ordinal=len(rows);declaration=pos;delta,pos=leb(d,pos);index=previous+delta;previous=index;flags,pos=leb(d,pos);code,pos=leb(d,pos)
            assert (index,flags,code,declaration)==expected[ordinal]
            assert bool(flags&8)==(group==0)
            incoming=(1 if refs[index][2]=='(I)V' else 0)+(0 if flags&8 else 1)
            assert (u16(d,code),u16(d,code+2),u16(d,code+4),u16(d,code+6),u32(d,code+8),u32(d,code+12),u16(d,code+16))==(1,incoming,0,0,0,1,0x000e)
            rows.append({'ordinal':ordinal,'reference':index,'name':refs[index][1],'prototype':refs[index][2],'owner':OWNER,'flags':flags,'code':code,'declaration':declaration})
    assert pos==374
    return rows

def units(text):return tuple(struct.unpack('<'+'H'*(len(text.encode('utf-16-le'))//2),text.encode('utf-16-le')))
def compare(a,b,keys):
    for field,direction in keys:
        av,bv=units(a[field]),units(b[field]);value=(av>bv)-(av<bv)
        if value:return value if direction=='asc' else -value
    return ((a['source'],a['ordinal'])>(b['source'],b['ordinal']))-((a['source'],a['ordinal'])<(b['source'],b['ordinal']))

def main():
    p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--root',type=Path,required=True);p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--generator',type=Path,required=True);p.add_argument('--output',type=Path);args=p.parse_args()
    args.root=args.root.resolve();args.fixtures=args.fixtures.resolve();args.generator=args.generator.resolve();args.exe=args.exe.resolve()
    if args.output is None:args.output=args.root/'docs/evidence/q11-topn'/('run-'+str(time.time_ns()))
    args.output.mkdir(parents=True,exist_ok=False);paths=[args.fixtures/'early.dex',args.fixtures/'late.dex',args.fixtures/'early.dex']
    original=[raw(path) for path in paths];rebuild=args.output/'rebuilt'
    assert hashlib.sha256(args.generator.read_bytes()).hexdigest()==GENERATOR_SHA
    proc=subprocess.run([sys.executable,str(args.generator),'--output',str(rebuild)],capture_output=True,timeout=30)
    assert proc.returncode==0 and all((rebuild/name).read_bytes()==(args.fixtures/name).read_bytes() for name in PINS)
    sys.path.insert(0,str(args.root/'tests/integration'));sys.path.insert(0,str(args.root/'tools/evidence_verifier'))
    import q_source_oracle as provenance
    from multisource import load_source_set
    datasets={complete:load_source_set([{'path':str(path)} for path in paths],args.root,complete,args.root) for complete in (False,True)}
    all_rows=[{'source':source,**item} for source,items in enumerate(original) for item in items]
    assert len(all_rows)==9 and PINS['early.dex']!=PINS['late.dex']
    assert (original[0][1]['name'],original[0][1]['ordinal'],original[0][1]['reference'])==('middle',1,2)
    assert (original[0][2]['name'],original[0][2]['ordinal'],original[0][2]['reference'])==('middle',2,1)
    exe_sha=hashlib.sha256(args.exe.read_bytes()).hexdigest();records=[];rejected=[]
    def call(name,version,order,limit,complete=True,scope=None):
        rel='method_defs' if version=='v1' else {'op':'scan','relation':'method_defs'}
        query={'schema_version':1,'relation':rel,'intent':'top_n','max_results':limit,'order_by':[{'field':field,'direction':direction} for field,direction in order]}
        if scope is not None:query['scope']={'slots':[datasets[complete]['inputs'][index]['slot_key'] for index in scope]}
        q=args.output/(name+'.query.json');q.write_text(json.dumps(query),encoding='utf-8')
        cmd=[str(args.exe),'query',str(paths[0]),'--query',str(q),'--json','--source',str(paths[1]),'--source',str(paths[2])]
        if not complete:cmd+=['--scope-incomplete']
        proc=subprocess.run(cmd,capture_output=True,timeout=30)
        (args.output/(name+'.stdout.json')).write_bytes(proc.stdout);(args.output/(name+'.stderr.log')).write_bytes(proc.stderr)
        assert proc.returncode==0,(name,proc.returncode,proc.stderr.decode('utf-8','replace'))
        value=json.loads(proc.stdout);selected=set(range(3) if scope is None else scope)
        candidates=sorted((x for x in all_rows if x['source'] in selected),key=cmp_to_key(lambda x,y:compare(x,y,order)))[:limit]
        expected_complete=complete or scope is not None
        def check(v):
            assert v['profile']==('dex-query-method-v1' if version=='v1' else 'dex-query-relational-v3')
            provenance.verify(v,datasets[complete])
            assert (v['execution_status'],v['coverage'],v['decision'],v['reason'])==('Complete','Complete' if expected_complete else 'Partial','ProvenTrue' if expected_complete else 'Undetermined','None' if expected_complete else 'SourceScopeIncomplete')
            assert v['query_profile']['order_verified'] is expected_complete
            assert v['query_scope']['sources']==sorted(selected) and v['query_scope']['complete'] is expected_complete
            assert len(v['candidates'])==len(candidates)
            count=3*len(selected)
            if version=='v1':assert (v['visited_methods'],v['total_methods'])==(count,count)
            else:assert (v['visited_rows'],v['total_rows'])==(count,count)
            for actual,expected in zip(v['candidates'],candidates):
                provenance.verify_row(actual,v,datasets[complete])
                assert actual['source_index']==expected['source'] and actual['name']==expected['name'] and actual['owner']==expected['owner'] and actual['prototype']==expected['prototype'] and actual['access_flags']==expected['flags'] and actual['code_offset']==expected['code']
                if version=='v1':assert actual['method_index']==expected['reference'] and actual['declaration_offset']==expected['declaration']
                else:assert actual['local_index']==expected['ordinal'] and actual['reference_index']==expected['reference'] and actual['record_offset']==actual['definition_offset']==expected['declaration']
        check(value)
        if name=='v1-desc-4':
            for label,mutate in [('wrong-rank',lambda x:x['candidates'].reverse()),('reference-index-tie',lambda x:x['candidates'].__setitem__(slice(1,3),list(reversed(x['candidates'][1:3])))),('wrong-source',lambda x:x['candidates'][1].__setitem__('source_index',2)),('wrong-ordinal',lambda x:x['candidates'][1].__setitem__('method_index',1)),('wrong-prototype',lambda x:x['candidates'][1].__setitem__('prototype','()V')),('wrong-input-index',lambda x:x['candidates'][0].__setitem__('input_index',0)),('wrong-occurrence',lambda x:x['candidates'][1].__setitem__('occurrence_id',x['sources'][2]['occurrence_id'])),('wrong-snapshot',lambda x:x['candidates'][0].__setitem__('snapshot_id','forged')),('missing',lambda x:x['candidates'].pop())]:
                fake=copy.deepcopy(value);mutate(fake)
                try:check(fake)
                except (AssertionError,KeyError,IndexError,TypeError):rejected.append(label)
                else:raise AssertionError('forged ranking accepted: '+label)
        if name=='v1-incomplete':
            fake=copy.deepcopy(value);fake.update(coverage='Complete',decision='ProvenTrue',reason='None');fake['query_profile']['order_verified']=True
            try:check(fake)
            except (AssertionError,KeyError):rejected.append('fake-global-complete')
            else:raise AssertionError('incomplete ranking accepted as complete')
        records.append({'name':name,'stdout_sha256':hashlib.sha256(proc.stdout).hexdigest(),'expected':[(x['source'],x['ordinal']) for x in candidates]})
    for version in ['v1','v3']:
        for n in [1,2,3,4,7,9,12]:call(version+'-desc-'+str(n),version,[('name','desc')],n)
        call(version+'-asc-5',version,[('name','asc')],5)
        call(version+'-multi-key',version,[('name','asc'),('prototype','desc')],7)
        call(version+'-incomplete',version,[('name','desc')],4,complete=False)
        call(version+'-explicit-scope',version,[('name','desc')],3,complete=False,scope=[1])
    assert hashlib.sha256(args.exe.read_bytes()).hexdigest()==exe_sha
    assert hashlib.sha256(args.generator.read_bytes()).hexdigest()==GENERATOR_SHA
    assert all(hashlib.sha256((args.fixtures/name).read_bytes()).hexdigest()==digest for name,digest in PINS.items())
    summary={'passed':len(records),'failed':0,'forged_rejected':rejected,'fixture_sha256':PINS,'generator_sha256':GENERATOR_SHA,'exe_sha256':exe_sha,'scope':'ASCII authored static method definitions and multi-source ordering; no runtime binding or ART claim','records':records}
    (args.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':len(records),'forged_rejected':len(rejected),'failed':0}))
if __name__=='__main__':main()
