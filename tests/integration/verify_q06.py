"""Q06: independent bytes/CLI checks for repeated invokes, overloads, external refs.

Project-original DEX; static reference evidence only.  No ART, dispatch or device
claim. Every generated run is fresh and the fixture identity is pinned.
"""
from pathlib import Path
from collections import Counter
import argparse, copy, hashlib, json, struct, subprocess, sys, time, zlib
import q_source_oracle as provenance

FIXTURE_SHA='d0641987a3ba58396dbf2ece5608b6979bcea46ed12a3d8edcd353fc82dec6e7'
GENERATOR_SHA='95534be10ac817f8d8a903e2a91f690bb5e61960bda23dab29c2ca764ddaa624'
METHODS=[('Lfixture/Caller;','call','()V'),('Lfixture/External;','absent','()V'),
         ('Lfixture/Lib;','run','()V'),('Lfixture/Lib;','run','(I)V')]
WORDS=[0x0012,0x0071,2,0,0x0071,2,0,0x1071,3,0,0x0071,1,0,0x000e]
CALLS={1:2,4:2,7:3,10:1}

def read_raw(path):
    d=path.read_bytes();assert len(d)==560 and hashlib.sha256(d).hexdigest()==FIXTURE_SHA
    u16=lambda at:struct.unpack_from('<H',d,at)[0]
    u32=lambda at:struct.unpack_from('<I',d,at)[0]
    assert d[:8]==b'dex\n035\0' and u32(32)==len(d) and u32(36)==112 and u32(40)==0x12345678
    assert d[12:32]==hashlib.sha1(d[32:]).digest() and u32(8)==zlib.adler32(d[12:])&0xffffffff
    def leb(at):
        value=0
        for i in range(5):
            assert at+i<len(d);byte=d[at+i];assert i<4 or byte<=15
            value|=(byte&127)<<(7*i)
            if byte<128:return value,at+i+1
        raise AssertionError('overlong uleb')
    strings=[]
    for i in range(u32(56)):
        at=u32(u32(60)+i*4);n,pos=leb(at);end=d.index(0,pos);raw=d[pos:end]
        assert len(raw)==n and all(0<c<128 for c in raw);strings.append(raw.decode('ascii'))
    types=[strings[u32(u32(68)+i*4)] for i in range(u32(64))]
    protos=[]
    for i in range(u32(72)):
        at=u32(76)+12*i;items=u32(at+8)
        params=[] if not items else [types[u16(items+4+j*2)] for j in range(u32(items))]
        protos.append('('+''.join(params)+')'+types[u32(at+4)])
    method_at=u32(92);methods=[]
    for i in range(u32(88)):
        at=method_at+8*i;methods.append((types[u16(at)],strings[u32(at+4)],protos[u16(at+2)]))
    assert method_at==200 and methods==METHODS and u32(96)==1
    cls=u32(100);assert cls==232 and types[u32(cls)]=='Lfixture/Caller;'
    cursor=u32(cls+24);sizes=[]
    for _ in range(4):v,cursor=leb(cursor);sizes.append(v)
    assert sizes==[0,0,1,0]
    method,cursor=leb(cursor);flags,cursor=leb(cursor);code,cursor=leb(cursor)
    assert (method,flags,code)==(0,9,372)
    assert (u16(code),u16(code+2),u16(code+4),u16(code+6),u32(code+12))==(1,0,1,0,14)
    words=list(struct.unpack_from('<14H',d,code+16));assert words==WORDS
    # 35c invoke: reference ID, argument count and zeroed register list are
    # checked from bytes, not inferred from native query output.
    for pc,ref in CALLS.items():
        assert words[pc]&0xff==0x71 and words[pc+1]==ref and words[pc+2]==0
        assert words[pc]>>12==(1 if pc==7 else 0)
    return {'sha256':FIXTURE_SHA,'code_offset':code,'method_offset':method_at,
            'calls':{pc:{'ref':ref,'symbol':METHODS[ref]} for pc,ref in CALLS.items()}}

def main():
    p=argparse.ArgumentParser();p.add_argument('--exe',required=True,type=Path);p.add_argument('--fixture',required=True,type=Path);p.add_argument('--generator',required=True,type=Path);p.add_argument('--output',type=Path);p.add_argument('--root',type=Path);args=p.parse_args()
    args.root=provenance.project_root(args.root,args.generator)
    args.fixture=args.fixture.resolve();args.generator=args.generator.resolve();args.exe=args.exe.resolve()
    if args.output is None:
        if args.root is None:p.error('one of --output or --root is required')
        args.output=args.root/'docs/evidence/q06'/('run-'+str(time.time_ns()))
    args.output.mkdir(parents=True,exist_ok=False)
    expected_sources={repeat:provenance.dataset(args.root,args.fixture,repeat) for repeat in (False,True)}
    raw=read_raw(args.fixture);exe_hash=hashlib.sha256(args.exe.read_bytes()).hexdigest();records=[];rejected=[]
    assert hashlib.sha256(args.generator.read_bytes()).hexdigest()==GENERATOR_SHA
    rebuild=args.output/'rebuilt';command=[sys.executable,str(args.generator),'--output',str(rebuild)]
    generated=subprocess.run(command,capture_output=True,timeout=30)
    assert generated.returncode==0,(generated.stdout,generated.stderr)
    assert (rebuild/'q06.dex').read_bytes()==args.fixture.read_bytes()
    assert json.loads((rebuild/'manifest.json').read_text(encoding='utf-8'))['fixtures']['q06.dex']['sha256']==FIXTURE_SHA
    scan=lambda relation:{'op':'scan','relation':relation}
    def call(name,expression,repeat=False,**options):
        query={'schema_version':1,'relation':expression,'max_results':100,**options}
        q=args.output/(name+'.query.json');q.write_text(json.dumps(query,indent=2),encoding='utf-8')
        command=[str(args.exe),'query',str(args.fixture),'--query',str(q),'--json']
        if repeat:command+=['--source',str(args.fixture)]
        run=subprocess.run(command,capture_output=True,timeout=30)
        (args.output/(name+'.stdout.json')).write_bytes(run.stdout);(args.output/(name+'.stderr.log')).write_bytes(run.stderr)
        assert run.returncode==0,(name,run.returncode,run.stderr.decode('utf-8','replace'))
        value=json.loads(run.stdout);records.append({'name':name,'argv':command,'exit_code':run.returncode,'stdout_sha256':hashlib.sha256(run.stdout).hexdigest()})
        (args.output/'commands.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
        return value
    def check(value,repeat=False,joined=False,calls=None):
        assert value['profile']=='dex-query-use-v4' and value['relation']=='invoke_sites'
        assert value['execution_status']=='Complete' and value['coverage']=='Complete' and value['unknown_rows']==0
        provenance.verify(value,expected_sources[repeat])
        sources=value['sources'];assert len(sources)==(2 if repeat else 1)
        assert all(s['source_sha256']==FIXTURE_SHA for s in sources)
        if repeat:assert sources[0]['content_id']==sources[1]['content_id'] and sources[0]['occurrence_id']!=sources[1]['occurrence_id']
        assert value['events_collected']==4*len(sources) and value['method_total']==value['method_visited']==len(sources)
        found=[]
        for row in value['candidates']:
            source=row['source_index'];assert 0<=source<len(sources)
            provenance.verify_row(row,value,expected_sources[repeat])
            for f in ('source_sha256','content_id','occurrence_id','logical_dex_id'):assert row[f]==sources[source][f]
            pc=row['dex_pc'];assert pc in raw['calls'];expected=raw['calls'][pc];ref=expected['ref']
            assert row['value_kind']=='use' and row['relation']=='invoke_sites' and row['local_index']==row['caller_ordinal']==row['caller_method_ref']==0
            assert (row['opcode'],row['code_offset'],row['instruction_offset'])==(0x71,372,388+2*pc)
            assert row['target_domain']=='method_ref' and row['target_index']==ref and row['extra_proto'] is None
            assert (row['caller_owner'],row['caller_name'],row['caller_prototype'])==METHODS[0]
            w=[x for x in row['evidence'] if x['kind']=='invoke']
            assert len(w)==1 and w[0]['matched'] and (w[0]['dex_pc'],w[0]['opcode'],w[0]['reference_index'],w[0]['reference_kind'])==(pc,0x71,ref,'method')
            assert w[0]['entity']=={'relation':'invoke_sites','source_index':source,'local_index':0,'dex_pc':pc}
            if joined:
                assert len(row['links'])==1 and row['links'][0]['key']=='target_ref'
                link=row['links'][0];assert link['left']=={'relation':'invoke_sites','source_index':source,'local_index':0,'dex_pc':pc}
                assert link['right']=={'relation':'method_refs','source_index':source,'local_index':ref,'dex_pc':None}
                assert len(row['bindings'])==2
                left=next(x for x in row['bindings'] if x['value_kind']=='use');right=next(x for x in row['bindings'] if x['value_kind']=='entity')
                assert left['path']==['L'] and left['dex_pc']==pc and left['source_index']==source
                assert right['path']==['R'] and right['source_index']==source and right['relation']=='method_refs'
                assert right['local_index']==right['reference_index']==ref and right['record_offset']==200+8*ref
                assert (right['owner'],right['name'],right['prototype'])==expected['symbol']
                assert right['has_local_definition'] is False and right['definition_offset'] is None and right['access_flags'] is None
            else:assert row['bindings']==[]
            found.append((source,pc,ref))
        expected_calls=CALLS if calls is None else calls
        assert Counter(found)==Counter((source,pc,ref) for source in range(len(sources)) for pc,ref in expected_calls.items())
    root=call('root',scan('invoke_sites'));check(root)
    expr={'op':'join','on':'target_ref','left':scan('invoke_sites'),'right':scan('method_refs')}
    joined=call('target-join',expr);check(joined,joined=True)
    repeated=call('repeat',scan('invoke_sites'),repeat=True);check(repeated,repeat=True)
    repeated_join=call('repeat-target-join',expr,repeat=True);check(repeated_join,repeat=True,joined=True)
    for name,where,calls in [
        ('overload-zero',{'owner':'Lfixture/Lib;','name':'run','prototype':'()V'},{1:2,4:2}),
        ('overload-one',{'owner':'Lfixture/Lib;','name':'run','prototype':'(I)V'},{7:3}),
        ('external-only',{'owner':'Lfixture/External;','name':'absent','prototype':'()V'},{10:1}),
    ]:
        right=scan('method_refs');right['where']=where
        value=call(name,{'op':'join','on':'target_ref','left':scan('invoke_sites'),'right':right})
        check(value,joined=True,calls=calls)
    # Identical bytes are different occurrence domains: an event from input 0
    # must not join a bare local reference ID from input 1.
    slots=[x['slot_key'] for x in expected_sources[True]['inputs']]
    left=scan('invoke_sites');left['scope']={'slots':[slots[0]]}
    right=scan('method_refs');right['scope']={'slots':[slots[1]]}
    cross=call('cross-occurrence',{'op':'join','on':'target_ref','left':left,'right':right},repeat=True,intent='exists')
    provenance.verify(cross,expected_sources[True])
    assert cross['coverage']=='Complete' and cross['decision']=='ProvenFalse' and cross['reason']=='NoMatch' and cross['candidates']==[]
    for name,mutation,source,repeat,is_join in [
        ('pc',lambda x:x['candidates'][0].update(dex_pc=99),root,False,False),
        ('ref',lambda x:x['candidates'][0].update(target_index=3),root,False,False),
        ('opcode',lambda x:x['candidates'][0].update(opcode=0),root,False,False),
        ('target-domain',lambda x:x['candidates'][0].update(target_domain='call_site'),root,False,False),
        ('event-count',lambda x:x.update(events_collected=3),root,False,False),
        ('witness',lambda x:next(w for w in x['candidates'][0]['evidence'] if w['kind']=='invoke').update(reference_index=3),root,False,False),
        ('omit',lambda x:x['candidates'].pop(),root,False,False),
        ('overload',lambda x:next(b for b in x['candidates'][0]['bindings'] if b['value_kind']=='entity').update(prototype='(I)V'),joined,False,True),
        ('external',lambda x:next(b for b in x['candidates'][0]['bindings'] if b['value_kind']=='entity').update(has_local_definition=True),joined,False,True),
        ('cross-source',lambda x:x['candidates'][0]['links'][0]['right'].update(source_index=1),repeated_join,True,True),
        ('occurrence',lambda x:x['candidates'][0].update(occurrence_id=x['sources'][1]['occurrence_id']),repeated,True,False),
        ('input-index',lambda x:x['candidates'][0].update(input_index=1),repeated,True,False),
        ('candidate-snapshot',lambda x:x['candidates'][0].update(snapshot_id='forged'),repeated,True,False),
        ('source-occurrence',lambda x:x['sources'][0].update(occurrence_id='forged'),repeated,True,False),
        ('root-snapshot',lambda x:x.update(snapshot_id='forged'),repeated,True,False),
        ('coverage-change',lambda x:x.update(coverage='Partial'),root,False,False),
    ]:
        forged=copy.deepcopy(source);mutation(forged)
        try:check(forged,repeat,is_join)
        except (AssertionError,KeyError,StopIteration,TypeError):rejected.append(name)
        else:raise AssertionError('forged evidence accepted: '+name)
    assert hashlib.sha256(args.exe.read_bytes()).hexdigest()==exe_hash
    (args.output/'summary.json').write_text(json.dumps({'passed':len(records),'forged_rejected':rejected,'fixture_sha256':FIXTURE_SHA,'generator_sha256':GENERATOR_SHA,'rebuild_argv':command,'exe_sha256':exe_hash,'scope':'static generated DEX only; no ART or runtime dispatch claim'},indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':len(records),'forged_rejected':len(rejected),'fixture_sha256':FIXTURE_SHA}))
if __name__=='__main__':main()
