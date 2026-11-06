"""Q04 independent raw-byte and relation-query checks; no ART/runtime claim."""
from pathlib import Path
from collections import Counter
import argparse,copy,hashlib,json,struct,subprocess,sys,time,zlib
import q_source_oracle as provenance

FIXTURE_SHA='5d7d17c93289fe3d644560edd32070790e9fb1796e9a883b4188bb877e0593f4'
GENERATOR_SHA='90ccf5471441ab2fcc1b5d790b32b6b1aa93e456bacc00983c9612c4272357d0'
OWNER='Lfixture/Pattern;'
ROWS={
 'alpha':{'ordinal':0,'declaration':442,'code':344,'words':[0x1a,4,0xe],'uses':[(0,4,'alpha-goal')]},
 'beta':{'ordinal':1,'declaration':446,'code':368,'words':[0x1a,6,0xe],'uses':[(0,6,'beta-goal')]},
 'both':{'ordinal':2,'declaration':450,'code':392,'words':[0x1a,4,0x1a,6,0xe],'uses':[(0,4,'alpha-goal'),(2,6,'beta-goal')]},
 'neither':{'ordinal':3,'declaration':454,'code':420,'words':[0xe],'uses':[]},
}
STRINGS=[OWNER,'Ljava/lang/Object;','V','alpha','alpha-goal','beta','beta-goal','both','neither','pool-only']

def raw_oracle(path):
    d=path.read_bytes();assert len(d)==584 and hashlib.sha256(d).hexdigest()==FIXTURE_SHA
    u16=lambda at:struct.unpack_from('<H',d,at)[0];u32=lambda at:struct.unpack_from('<I',d,at)[0]
    assert d[:8]==b'dex\n035\0' and u32(32)==len(d) and u32(36)==112 and u32(40)==0x12345678
    assert d[12:32]==hashlib.sha1(d[32:]).digest() and u32(8)==zlib.adler32(d[12:])&0xffffffff
    def leb(at):
        result=0
        for i in range(5):
            assert at+i<len(d);byte=d[at+i];assert i<4 or byte<=15;result|=(byte&127)<<(7*i)
            if byte<128:return result,at+i+1
        raise AssertionError('overlong uleb')
    strings=[]
    for i in range(u32(56)):
        at=u32(u32(60)+i*4);size,pos=leb(at);end=d.index(0,pos);v=d[pos:end]
        assert len(v)==size and all(0<c<128 for c in v);strings.append(v.decode('ascii'))
    assert strings==STRINGS
    types=[strings[u32(u32(68)+4*i)] for i in range(u32(64))]
    assert types==[OWNER,'Ljava/lang/Object;','V'] and u32(72)==1
    proto=u32(76);assert (strings[u32(proto)],types[u32(proto+4)],u32(proto+8))==('V','V',0)
    refs=[]
    for i in range(u32(88)):
        at=u32(92)+8*i;assert u16(at+2)==0;refs.append((types[u16(at)],strings[u32(at+4)]))
    assert refs==[(OWNER,n) for n in ROWS] and u32(96)==1
    cls=u32(100);assert types[u32(cls)]==OWNER;cursor=u32(cls+24);assert cursor==438
    sizes=[]
    for _ in range(4):n,cursor=leb(cursor);sizes.append(n)
    assert sizes==[0,0,4,0];previous=0
    for name,row in ROWS.items():
        start=cursor;delta,cursor=leb(cursor);previous+=delta;flags,cursor=leb(cursor);code,cursor=leb(cursor)
        assert (previous,start,flags,code)==(row['ordinal'],row['declaration'],9,row['code'])
        assert (u16(code),u16(code+2),u16(code+4),u16(code+6),u32(code+12))==(1,0,0,0,len(row['words']))
        words=list(struct.unpack_from('<'+'H'*len(row['words']),d,code+16));assert words==row['words']
        for pc,index,literal in row['uses']:assert words[pc]==0x1a and words[pc+1]==index and strings[index]==literal
    assert cursor==458
    return d

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--exe',required=True,type=Path);ap.add_argument('--fixture',required=True,type=Path);ap.add_argument('--generator',required=True,type=Path);ap.add_argument('--output',type=Path);ap.add_argument('--root',type=Path);args=ap.parse_args()
    args.root=provenance.project_root(args.root,args.generator)
    args.fixture=args.fixture.resolve();args.generator=args.generator.resolve();args.exe=args.exe.resolve()
    if args.output is None:
        if args.root is None:ap.error('one of --output or --root is required')
        args.output=args.root/'docs/evidence/q04'/('run-'+str(time.time_ns()))
    args.output.mkdir(parents=True,exist_ok=False);data=raw_oracle(args.fixture);exe_hash=hashlib.sha256(args.exe.read_bytes()).hexdigest()
    assert hashlib.sha256(args.generator.read_bytes()).hexdigest()==GENERATOR_SHA
    rebuild=args.output/'rebuilt';gen=[sys.executable,str(args.generator),'--output',str(rebuild)];p=subprocess.run(gen,capture_output=True,timeout=30)
    assert p.returncode==0,(p.stdout,p.stderr);assert (rebuild/'q04.dex').read_bytes()==data
    expected_sources={(repeat,complete):provenance.dataset(args.root,args.fixture,repeat,complete)
                      for repeat in (False,True) for complete in (False,True)}
    records=[];rejected=[]
    def contains(text):return {'op':'contains','value':text}
    alpha,beta,goal=contains('alpha'),contains('beta'),contains('goal')
    def scan(mode,patterns,slot=None):
        node={'op':'scan','relation':'method_defs','where':{'using_strings':{mode:patterns}}}
        if slot is not None:node['scope']={'slots':[slot]}
        return node
    def call(name,expr,repeat=False,incomplete=False,**options):
        query={'schema_version':1,'relation':expr,'max_results':100,**options};q=args.output/(name+'.query.json');q.write_text(json.dumps(query,indent=2),encoding='utf-8')
        cmd=[str(args.exe),'query',str(args.fixture),'--query',str(q),'--json']
        if repeat:cmd+=['--source',str(args.fixture)]
        if incomplete:cmd+=['--scope-incomplete']
        p=subprocess.run(cmd,capture_output=True,timeout=30);(args.output/(name+'.stdout.json')).write_bytes(p.stdout);(args.output/(name+'.stderr.log')).write_bytes(p.stderr)
        assert p.returncode==0,(name,p.returncode,p.stderr.decode('utf-8','replace'))
        records.append({'name':name,'argv':cmd,'exit_code':p.returncode,'stdout_sha256':hashlib.sha256(p.stdout).hexdigest()})
        (args.output/'commands.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
        return json.loads(p.stdout)
    def check(v,expected,mode,patterns,repeat=False,decision='NotApplicable',reason='None',exact=None,incomplete=False):
        assert v['profile']=='dex-query-relational-v3' and v['relation']=='method_defs'
        assert (v['execution_status'],v['coverage'],v['decision'],v['reason'],v['unknown_rows'])==('Complete','Partial' if incomplete else 'Complete',decision,reason,0)
        expected_source=expected_sources[(repeat,not incomplete)];provenance.verify(v,expected_source)
        sources=v['sources'];assert len(sources)==(2 if repeat else 1) and all(x['source_sha256']==FIXTURE_SHA for x in sources)
        if repeat:assert sources[0]['content_id']==sources[1]['content_id'] and sources[0]['occurrence_id']!=sources[1]['occurrence_id']
        ids={x['node_id'] for x in v['relation_profile']['operators']};found=[]
        for row in v['candidates']:
            source=row['source_index'];name=row['name'];assert 0<=source<len(sources) and name in ROWS;spec=ROWS[name]
            provenance.verify_row(row,v,expected_source)
            for key in ('source_sha256','content_id','occurrence_id','logical_dex_id'):assert row[key]==sources[source][key]
            assert row['relation']=='method_defs' and row['owner']==OWNER and row['prototype']=='()V'
            assert row['local_index']==row['reference_index']==spec['ordinal'] and row['access_flags']==9
            assert row['definition_offset']==row['record_offset']==spec['declaration'] and row['code_offset']==spec['code']
            witness=[]
            for item in row['evidence']:
                if item['kind']!='string_use':continue
                assert item['matched'] and item['opcode']==0x1a and item['reference_kind']=='string' and item['operator_node'] in ids
                match=[literal for pc,index,literal in spec['uses'] if item['dex_pc']==pc and item['reference_index']==index]
                assert len(match)==1 and item['entity']=={'relation':'method_defs','source_index':source,'local_index':spec['ordinal']};witness.append(match[0])
            assert witness
            if mode=='all':assert all(any(pattern in value for value in witness) for pattern in patterns)
            else:assert any(any(pattern in value for pattern in patterns) for value in witness)
            if exact is not None:assert Counter(witness)==Counter(exact[name])
            found.append((source,name))
        assert Counter(found)==Counter(expected),(found,expected)
    all_cross=scan('all',[alpha,beta]);any_cross=scan('any',[alpha,beta]);overlap=scan('all',[alpha,goal])
    all_result=call('all-cross',all_cross);check(all_result,[(0,'both')],'all',['alpha','beta'],exact={'both':['alpha-goal','beta-goal']})
    any_result=call('any-cross',any_cross);check(any_result,[(0,'alpha'),(0,'beta'),(0,'both')],'any',['alpha','beta'])
    overlap_result=call('all-overlap',overlap);check(overlap_result,[(0,'alpha'),(0,'both')],'all',['alpha','goal'],exact={'alpha':['alpha-goal','alpha-goal'],'both':['alpha-goal','alpha-goal']})
    overlap_any=call('any-overlap',scan('any',[alpha,goal]));check(overlap_any,[(0,'alpha'),(0,'beta'),(0,'both')],'any',['alpha','goal'])
    both=call('repeat-any',any_cross,repeat=True);all_rows=[(s,n) for s in range(2) for n in ('alpha','beta','both')];check(both,all_rows,'any',['alpha','beta'],repeat=True)
    slots=[x['slot_key'] for x in expected_sources[(True,True)]['inputs']]
    scoped=call('scope-one',any_cross,repeat=True,scope={'slots':[slots[1]]});check(scoped,[(1,n) for n in ('alpha','beta','both')],'any',['alpha','beta'],repeat=True)
    bag={'op':'union','inputs':[any_cross,any_cross],'semantics':'bag'}
    bagged=call('bag',bag);check(bagged,[(0,n) for n in ('alpha','beta','both')]*2,'any',['alpha','beta'])
    distinct={'op':'distinct','input':bag,'identity':'entity'}
    dedup=call('distinct',distinct);check(dedup,[(0,n) for n in ('alpha','beta','both')],'any',['alpha','beta'])
    scoped_bag={'op':'union','inputs':[scan('any',[alpha,beta],slots[0]),scan('any',[alpha,beta],slots[0]),scan('any',[alpha,beta],slots[1])],'semantics':'bag'}
    scoped_distinct=call('scope-distinct',{'op':'distinct','input':scoped_bag,'identity':'entity'},repeat=True)
    check(scoped_distinct,all_rows,'any',['alpha','beta'],repeat=True)
    scoped_all_bag={'op':'union','inputs':[scan('all',[alpha,beta],slots[0]),scan('all',[alpha,beta],slots[0]),scan('all',[alpha,beta],slots[1])],'semantics':'bag'}
    scoped_all=call('all-scope-distinct',{'op':'distinct','input':scoped_all_bag,'identity':'entity'},repeat=True)
    check(scoped_all,[(0,'both'),(1,'both')],'all',['alpha','beta'],repeat=True,exact={'both':['alpha-goal','beta-goal']})
    alpha_only=scan('all',[alpha]);unique=call('scope-unique',alpha_only,repeat=True,scope={'slots':[slots[0]]},intent='unique')
    # Both alpha and both match the substring; restrict method name to create
    # one identity without conflating scope with substring semantics.
    assert unique['decision']=='ProvenFalse' and unique['reason']=='Ambiguous'
    alpha_name={'op':'scan','relation':'method_defs','where':{'all':[{'name':'alpha'},{'using_strings':{'all':[alpha]}}]}}
    one=call('scope-one-unique',alpha_name,repeat=True,scope={'slots':[slots[0]]},intent='unique')
    check(one,[(0,'alpha')],'all',['alpha'],repeat=True,decision='ProvenTrue')
    two=call('repeat-unique',alpha_name,repeat=True,intent='unique')
    check(two,[(0,'alpha'),(1,'alpha')],'all',['alpha'],repeat=True,decision='ProvenFalse',reason='Ambiguous')
    partial=call('partial-exists',all_cross,incomplete=True,intent='exists')
    check(partial,[(0,'both')],'all',['alpha','beta'],decision='ProvenTrue',reason='Witness',incomplete=True)
    missing=call('partial-absent',scan('all',[contains('notpresent')]),incomplete=True,intent='exists')
    provenance.verify(missing,expected_sources[(False,False)])
    assert (missing['execution_status'],missing['coverage'],missing['decision'],missing['reason'],missing['candidates'])==('Complete','Partial','Undetermined','SourceScopeIncomplete',[])
    for name,source,expected,mode,patterns,repeat,mutation in [
      ('wrong-pc',all_result,[(0,'both')],'all',['alpha','beta'],False,lambda x:x['candidates'][0]['evidence'][0].update(dex_pc=99)),
      ('wrong-string',all_result,[(0,'both')],'all',['alpha','beta'],False,lambda x:x['candidates'][0]['evidence'][0].update(reference_index=9)),
      ('omit-result',any_result,[(0,'alpha'),(0,'beta'),(0,'both')],'any',['alpha','beta'],False,lambda x:x['candidates'].pop()),
      ('wrong-name',any_result,[(0,'alpha'),(0,'beta'),(0,'both')],'any',['alpha','beta'],False,lambda x:x['candidates'][0].update(name='neither')),
      ('wrong-occurrence',both,all_rows,'any',['alpha','beta'],True,lambda x:x['candidates'][0].update(occurrence_id=x['sources'][1]['occurrence_id'])),
      ('wrong-input-index',both,all_rows,'any',['alpha','beta'],True,lambda x:x['candidates'][0].update(input_index=1)),
      ('wrong-candidate-snapshot',both,all_rows,'any',['alpha','beta'],True,lambda x:x['candidates'][0].update(snapshot_id='forged')),
      ('wrong-source-occurrence',both,all_rows,'any',['alpha','beta'],True,lambda x:x['sources'][0].update(occurrence_id='forged')),
      ('wrong-root-snapshot',both,all_rows,'any',['alpha','beta'],True,lambda x:x.update(snapshot_id='forged')),
      ('wrong-coverage',any_result,[(0,'alpha'),(0,'beta'),(0,'both')],'any',['alpha','beta'],False,lambda x:x.update(coverage='Partial')),
    ]:
        fake=copy.deepcopy(source);mutation(fake)
        try:check(fake,expected,mode,patterns,repeat)
        except (AssertionError,KeyError,TypeError):rejected.append(name)
        else:raise AssertionError('forged evidence accepted: '+name)
    fake=copy.deepcopy(partial);fake['coverage']='Complete'
    try:check(fake,[(0,'both')],'all',['alpha','beta'],decision='ProvenTrue',reason='Witness',incomplete=True)
    except AssertionError:rejected.append('fake-complete')
    else:raise AssertionError('forged completeness accepted')
    assert hashlib.sha256(args.exe.read_bytes()).hexdigest()==exe_hash
    summary={'passed':len(records),'forged_rejected':rejected,'fixture_sha256':FIXTURE_SHA,'generator_sha256':GENERATOR_SHA,'rebuild_argv':gen,'exe_sha256':exe_hash,'scope':'generated DEX metadata and string-use only; no ART/runtime claim'}
    (args.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8');print(json.dumps({'passed':len(records),'forged_rejected':len(rejected)}))
if __name__=='__main__':main()
