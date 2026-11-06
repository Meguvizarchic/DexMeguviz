"""Q08 independent declaration, direct-parent and field-use byte/CLI checks."""
from pathlib import Path
from collections import Counter
import argparse,copy,hashlib,json,struct,subprocess,sys,time,zlib

FIXTURE_SHA='83bca6b796f3e343b84b29ddef6949dade9b8c66c2807b6bb89f15b03981e8a8'
GENERATOR_SHA='4650926a3b7608b9aa683c5df329b777c7ef96eeb8aa6a27c62cd96bee2db642'
BASE='Lfixture/Base;';CHILD='Lfixture/Child;';ROOT='Ljava/lang/Object;'
FIELD_REFS=[(BASE,'parentOnly','I'),(BASE,'shared','I'),(CHILD,'childOnly','I'),(CHILD,'shared','I')]
METHOD_REFS=[(BASE,'baseProbe'),(CHILD,'access'),(CHILD,'quiet')]
FIELD_DECL=[502,504,514,516];METHOD_DECL=[506,518,522];CODE=[424,444,480]
CALLS={0:(0x60,1),2:(0x67,1),4:(0x60,3),6:(0x67,3)}

def source_identities(path,count):
    # SourceSet v2 contract: compute every identity from authored fixture bytes,
    # caller-supplied path, slot, role and ordering, never from CLI output.
    def frame(text):
        value=text.encode('utf-8');return str(len(value)).encode('ascii')+b':'+value
    content=f'sha256:raw-dex:v1:664:{FIXTURE_SHA}'
    logical='logical-dex:v1:'+frame(content).decode('ascii')+'header-offset:0'
    items=[]
    for index in range(count):
        slot=f'input:{index}:{path}';role='base' if index==0 else 'code-split'
        material=b'dmg:occurrence:v2:'+b''.join(frame(x) for x in ('cli-v1','raw-input',slot,role,'',content))
        occurrence='occurrence:v2:'+hashlib.sha256(material).hexdigest()
        items.append({'source_index':index,'input_index':index,'slot_key':slot,'role':role,
                      'source_sha256':FIXTURE_SHA,'content_id':content,'occurrence_id':occurrence,'logical_dex_id':logical})
    material=b'dmg:snapshot:source-set-v1:'+frame('cli-v1')+frame('complete')+frame(str(count))
    for item in items:
        material+=b''.join(frame(x) for x in (item['slot_key'],item['role'],'1','0',content))
    material+=frame(str(count))+b''.join(frame(item['occurrence_id']) for item in items)
    snapshot='snapshot:v2:'+hashlib.sha256(material).hexdigest()
    for item in items:item['snapshot_id']=snapshot
    return items,snapshot

def read_raw(path):
    d=path.read_bytes();assert len(d)==664 and hashlib.sha256(d).hexdigest()==FIXTURE_SHA
    u16=lambda at:struct.unpack_from('<H',d,at)[0];u32=lambda at:struct.unpack_from('<I',d,at)[0]
    assert d[:8]==b'dex\n035\0' and u32(32)==len(d) and u32(36)==112 and u32(40)==0x12345678
    assert d[12:32]==hashlib.sha1(d[32:]).digest() and u32(8)==zlib.adler32(d[12:])&0xffffffff
    def leb(at):
        v=0
        for i in range(5):
            assert at+i<len(d);byte=d[at+i];assert i<4 or byte<=15;v|=(byte&127)<<(7*i)
            if byte<128:return v,at+i+1
        raise AssertionError('overlong uleb')
    strings=[]
    for i in range(u32(56)):
        at=u32(u32(60)+i*4);n,pos=leb(at);end=d.index(0,pos);raw=d[pos:end]
        assert len(raw)==n and all(0<c<128 for c in raw);strings.append(raw.decode('ascii'))
    assert strings==['I',BASE,CHILD,ROOT,'V','access','baseProbe','childOnly','parentOnly','quiet','shared']
    types=[strings[u32(u32(68)+i*4)] for i in range(u32(64))];assert types==['I',BASE,CHILD,ROOT,'V']
    assert u32(72)==1;proto=u32(76);assert (strings[u32(proto)],types[u32(proto+4)],u32(proto+8))==('V','V',0)
    fields=[]
    for i in range(u32(80)):
        at=u32(84)+8*i;fields.append((types[u16(at)],strings[u32(at+4)],types[u16(at+2)]))
    assert u32(84)==188 and fields==FIELD_REFS
    methods=[]
    for i in range(u32(88)):
        at=u32(92)+8*i;assert u16(at+2)==0;methods.append((types[u16(at)],strings[u32(at+4)]))
    assert u32(92)==220 and methods==METHOD_REFS and u32(96)==2 and u32(100)==244
    field_ordinal=method_ordinal=0
    for c,(owner,parent,data_at,sizes) in enumerate([(BASE,ROOT,498,[2,0,1,0]),(CHILD,BASE,510,[2,0,2,0])]):
        cls=u32(100)+32*c;assert (types[u32(cls)],types[u32(cls+8)],u32(cls+24))==(owner,parent,data_at)
        cursor=data_at;actual=[]
        for _ in range(4):v,cursor=leb(cursor);actual.append(v)
        assert actual==sizes
        for group,count in enumerate(sizes):
            prev=0
            for _ in range(count):
                declaration=cursor;delta,cursor=leb(cursor);prev+=delta;flags,cursor=leb(cursor);assert flags==9
                if group<2:
                    assert (prev,declaration,fields[prev][0])==(field_ordinal,FIELD_DECL[field_ordinal],owner);field_ordinal+=1
                else:
                    code,cursor=leb(cursor);assert (prev,declaration,code,methods[prev][0])==(method_ordinal,METHOD_DECL[method_ordinal],CODE[method_ordinal],owner)
                    count=u32(code+12);assert (u16(code),u16(code+2),u16(code+4),u16(code+6))==(1,0,0,0)
                    words=list(struct.unpack_from('<'+'H'*count,d,code+16))
                    if method_ordinal==1:
                        assert words==[0x60,1,0x67,1,0x60,3,0x67,3,0x0e]
                        for pc,(opcode,ref) in CALLS.items():assert words[pc]==opcode and words[pc+1]==ref
                    else:assert words==[0x0e]
                    method_ordinal+=1
    assert (field_ordinal,method_ordinal)==(4,3);return d

def main():
    p=argparse.ArgumentParser();p.add_argument('--exe',required=True,type=Path);p.add_argument('--fixture',required=True,type=Path);p.add_argument('--generator',required=True,type=Path);p.add_argument('--output',type=Path);p.add_argument('--root',type=Path);args=p.parse_args()
    if args.output is None:
        if args.root is None:p.error('one of --output or --root is required')
        args.output=args.root/'docs/evidence/q08'/('run-'+str(time.time_ns()))
    args.output.mkdir(parents=True,exist_ok=False);raw=read_raw(args.fixture);exe_hash=hashlib.sha256(args.exe.read_bytes()).hexdigest()
    assert hashlib.sha256(args.generator.read_bytes()).hexdigest()==GENERATOR_SHA
    rebuild=args.output/'rebuilt';gen=[sys.executable,str(args.generator),'--output',str(rebuild)];run=subprocess.run(gen,capture_output=True,timeout=30)
    assert run.returncode==0 and (rebuild/'q08.dex').read_bytes()==raw
    assert json.loads((rebuild/'manifest.json').read_text())['sha256']==FIXTURE_SHA
    records=[];rejected=[];scan=lambda relation:{'op':'scan','relation':relation}
    def call(name,expr,repeat=False,code=0,**options):
        q={'schema_version':1,'relation':expr,'max_results':100,**options};qp=args.output/(name+'.query.json');qp.write_text(json.dumps(q,indent=2),encoding='utf-8')
        command=[str(args.exe),'query',str(args.fixture),'--query',str(qp),'--json']
        if repeat:command+=['--source',str(args.fixture)]
        result=subprocess.run(command,capture_output=True,timeout=30);(args.output/(name+'.stdout.json')).write_bytes(result.stdout);(args.output/(name+'.stderr.log')).write_bytes(result.stderr)
        assert result.returncode==code,(name,result.returncode,result.stderr.decode('utf-8','replace'))
        records.append({'name':name,'argv':command,'exit_code':result.returncode,'stdout_sha256':hashlib.sha256(result.stdout).hexdigest()})
        (args.output/'commands.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8');return json.loads(result.stdout),result.stderr.decode('utf-8','replace')
    def sources(value,repeat):
        count=2 if repeat else 1;expected,snapshot=source_identities(str(args.fixture),count)
        assert value['snapshot_id']==snapshot and value['scope_complete'] is True
        assert value['input_count']==value['source_count']==count
        assert len(value['inputs'])==len(value['sources'])==count
        for index,item in enumerate(expected):
            actual=value['sources'][index];input_item=value['inputs'][index]
            for key,want in item.items():assert actual[key]==want,(index,key,actual[key],want)
            for key in ('input_index','slot_key','role','source_sha256','content_id'):assert input_item[key]==item[key]
            assert input_item['format']=='RawDex' and input_item['allow_no_dex'] is False and input_item['source_count']==1
            assert actual['counts']=={'strings':11,'types':5,'classes':2,'method_refs':3,'method_defs':3}
        if repeat:
            assert expected[0]['content_id']==expected[1]['content_id'] and expected[0]['occurrence_id']!=expected[1]['occurrence_id']
            assert value['content_id'] is value['occurrence_id'] is value['logical_dex_id'] is None
        else:
            for key in ('content_id','occurrence_id','logical_dex_id'):assert value[key]==expected[0][key]
        return expected
    def origin(row,all_sources):
        i=row['source_index'];assert 0<=i<len(all_sources)
        for key in ('input_index','source_sha256','content_id','occurrence_id','logical_dex_id','snapshot_id'):assert row[key]==all_sources[i][key]
        return i
    def check_fields(v,repeat=False):
        assert v['profile']=='dex-query-relational-v3' and v['coverage']=='Complete'
        src=sources(v,repeat);found=[]
        for row in v['candidates']:
            i=origin(row,src);n=row['local_index'];assert 0<=n<4
            assert (row['owner'],row['name'],row['type_descriptor'])==FIELD_REFS[n]
            assert row['reference_index']==n and row['record_offset']==row['definition_offset']==FIELD_DECL[n]
            assert row['has_local_definition'] is True and row['access_flags']==9;found.append((i,n))
        assert Counter(found)==Counter((i,n) for i in range(len(src)) for n in range(4))
    def check_uses(v,repeat=False,joined=False,calls=None):
        assert v['profile']=='dex-query-use-v4' and v['relation']=='field_uses' and v['coverage']=='Complete' and v['unknown_rows']==0
        src=sources(v,repeat);expected=CALLS if calls is None else calls;found=[]
        assert v['events_collected']==4*len(src) and v['method_visited']==v['method_total']==3*len(src)
        for row in v['candidates']:
            source=origin(row,src);pc=row['dex_pc'];assert pc in CALLS;opcode,ref=CALLS[pc]
            assert row['value_kind']=='use' and row['relation']=='field_uses' and row['local_index']==row['caller_ordinal']==row['caller_method_ref']==1
            assert (row['caller_owner'],row['caller_name'],row['caller_prototype'])==(CHILD,'access','()V')
            assert (row['opcode'],row['code_offset'],row['instruction_offset'],row['target_domain'],row['target_index'],row['extra_proto'])==(opcode,444,460+2*pc,'field_ref',ref,None)
            proof=[w for w in row['evidence'] if w['kind']=='field_use'];assert len(proof)==1 and proof[0]['matched']
            assert (proof[0]['dex_pc'],proof[0]['opcode'],proof[0]['reference_index'],proof[0]['reference_kind'])==(pc,opcode,ref,'field')
            assert proof[0]['entity']=={'relation':'field_uses','source_index':source,'local_index':1,'dex_pc':pc}
            if joined:
                assert len(row['links'])==1 and row['links'][0]['key']=='target_ref'
                link=row['links'][0];assert link['left']=={'relation':'field_uses','source_index':source,'local_index':1,'dex_pc':pc}
                assert link['right']=={'relation':'field_refs','source_index':source,'local_index':ref,'dex_pc':None}
                assert len(row['bindings'])==2
                left=next(x for x in row['bindings'] if x['value_kind']=='use');right=next(x for x in row['bindings'] if x['value_kind']=='entity')
                assert (left['path'],left['source_index'],left['dex_pc'])==(['L'],source,pc)
                assert (right['path'],right['source_index'],right['relation'],right['local_index'],right['reference_index'])==(['R'],source,'field_refs',ref,ref)
                assert (right['owner'],right['name'],right['type_descriptor'])==FIELD_REFS[ref]
                assert right['has_local_definition'] is True and right['record_offset']==188+8*ref and right['definition_offset']==FIELD_DECL[ref]
            found.append((source,pc,opcode,ref))
        assert Counter(found)==Counter((s,pc,op,ref) for s in range(len(src)) for pc,(op,ref) in expected.items())
    def methods(name,where,expected):
        expr=scan('method_defs');expr['where']=where;v,_=call(name,expr)
        assert v['profile']=='dex-query-relational-v3' and v['coverage']=='Complete' and v['unknown_rows']==0
        src=sources(v,False);out=[]
        for row in v['candidates']:
            assert origin(row,src)==0;key=(row['owner'],row['name']);assert key in METHOD_REFS
            n=METHOD_REFS.index(key);assert row['local_index']==row['reference_index']==n and row['definition_offset']==METHOD_DECL[n] and row['code_offset']==CODE[n]
            assert row['prototype']=='()V' and row['access_flags']==9;out.append(key)
        assert Counter(out)==Counter(expected),(name,out,expected)
        return v
    fields,_=call('field-definitions',scan('field_defs'));check_fields(fields)
    repeated_fields,_=call('repeat-field-definitions',scan('field_defs'),repeat=True);check_fields(repeated_fields,True)
    uses,_=call('field-uses',scan('field_uses'));check_uses(uses)
    join={'op':'join','on':'target_ref','left':scan('field_uses'),'right':scan('field_refs')}
    linked,_=call('field-uses-target',join);check_uses(linked,joined=True)
    repeat_linked,_=call('repeat-field-uses-target',join,repeat=True);check_uses(repeat_linked,repeat=True,joined=True)
    read=scan('field_uses');read['where']={'opcode':0x60};v,_=call('reads',read);check_uses(v,calls={0:CALLS[0],4:CALLS[4]})
    write=scan('field_uses');write['where']={'opcode':0x67};v,_=call('writes',write);check_uses(v,calls={2:CALLS[2],6:CALLS[6]})
    for owner,expected in [(BASE,{0:CALLS[0],2:CALLS[2]}),(CHILD,{4:CALLS[4],6:CALLS[6]})]:
        right=scan('field_refs');right['where']={'owner':owner,'name':'shared'}
        v,_=call('field-target-'+('base' if owner==BASE else 'child'),{'op':'join','on':'target_ref','left':scan('field_uses'),'right':right});check_uses(v,joined=True,calls=expected)
    own=lambda owner,name:{'all':[{'owner':owner},{'declares_fields':{'where':{'name':name},'min':1}}]}
    methods('base-own-parentOnly',own(BASE,'parentOnly'),[(BASE,'baseProbe')])
    methods('child-not-own-parentOnly',own(CHILD,'parentOnly'),[])
    methods('child-own-childOnly',own(CHILD,'childOnly'),[(CHILD,'access'),(CHILD,'quiet')])
    methods('base-not-own-childOnly',own(BASE,'childOnly'),[])
    methods('base-own-shared',own(BASE,'shared'),[(BASE,'baseProbe')])
    methods('child-own-shared',own(CHILD,'shared'),[(CHILD,'access'),(CHILD,'quiet')])
    methods('not-two-shared-per-owner',{'declares_fields':{'where':{'name':'shared'},'min':2}},[])
    methods('child-direct-parent',{'all':[{'owner':CHILD},{'superclass':BASE}]},[(CHILD,'access'),(CHILD,'quiet')])
    methods('child-not-grandparent',{'all':[{'owner':CHILD},{'superclass':ROOT}]},[])
    methods('base-direct-parent',{'all':[{'owner':BASE},{'superclass':ROOT}]},[(BASE,'baseProbe')])
    accesses=[{'owner':o,'name':'shared','type':'I','access':a} for o in [BASE,CHILD] for a in ['read','write']]
    access=methods('child-reads-writes-both-owners',{'all':[{'owner':CHILD},{'field_access':{'all':accesses}}]},[(CHILD,'access')])
    witnesses=[w for w in access['candidates'][0]['evidence'] if w['kind']=='field_use']
    assert Counter((w['dex_pc'],w['opcode'],w['reference_index']) for w in witnesses)==Counter((pc,op,ref) for pc,(op,ref) in CALLS.items())
    methods('child-does-not-access-parentOnly',{'all':[{'owner':CHILD},{'field_access':{'all':[{'owner':BASE,'name':'parentOnly','access':'read'}]}}]},[])
    inherited=scan('method_defs');inherited['where']={'all':[{'owner':CHILD},{'declares_fields':{'where':{'name':'parentOnly'},'scope':'inherited','min':1}}]}
    inherited_result,_=call('inherited-closure',inherited)
    def check_inherited(value):
        assert value['profile']=='dex-query-inherited-v6' and value['coverage']=='Complete' and value['unknown_rows']==0
        src=sources(value,False);assert len(value['candidates'])==2
        found=[]
        for row in value['candidates']:
            assert origin(row,src)==0
            key=(row['owner'],row['name']);assert key in ((CHILD,'access'),(CHILD,'quiet'))
            n=METHOD_REFS.index(key)
            assert row['local_index']==row['reference_index']==n and row['definition_offset']==METHOD_DECL[n] and row['code_offset']==CODE[n]
            proofs=[w for w in row['evidence'] if w['kind']=='inherited']
            assert proofs and all(w['matched'] is True for w in proofs)
            paths=[w['inherited'] for w in proofs if w['inherited']['item']==1]
            assert {(p['path'],p['source_index'],p['local_index'],p['aux'],p['detail']) for p in paths}=={(0,0,1,None,0),(1,0,0,0,1)}
            fields=[w['inherited'] for w in proofs if w['inherited']['item']==4]
            assert len(fields)==1 and (fields[0]['source_index'],fields[0]['relation'],fields[0]['local_index'],fields[0]['path'])==(0,'field_defs',0,1)
            ends=[w['inherited'] for w in proofs if w['inherited']['item']==2]
            assert len(ends)==1 and ends[0]['aux']==1 # missing Object definition in this fixture
            found.append(key)
        assert Counter(found)==Counter([(CHILD,'access'),(CHILD,'quiet')])
    check_inherited(inherited_result)
    def forge_snapshot_consistently(value):
        fake='snapshot:v2:'+'0'*64;value['snapshot_id']=fake
        for source in value['sources']:source['snapshot_id']=fake
        for row in value['candidates']:row['snapshot_id']=fake
    def forge_occurrence_consistently(value):
        fake='occurrence:v2:'+'1'*64;value['sources'][0]['occurrence_id']=fake
        for row in value['candidates']:
            if row['source_index']==0:row['occurrence_id']=fake
    def forge_input_consistently(value):
        value['sources'][0]['input_index']=1
        for row in value['candidates']:
            if row['source_index']==0:row['input_index']=1
    for name,value,verify,mutation in [
      ('field-owner',fields,lambda x:check_fields(x),lambda x:x['candidates'][1].update(owner=CHILD)),
      ('field-offset',fields,lambda x:check_fields(x),lambda x:x['candidates'][1].update(definition_offset=516)),
      ('event-pc',uses,lambda x:check_uses(x),lambda x:x['candidates'][0].update(dex_pc=1)),
      ('event-opcode',uses,lambda x:check_uses(x),lambda x:x['candidates'][0].update(opcode=0x67)),
      ('event-ref',uses,lambda x:check_uses(x),lambda x:x['candidates'][0].update(target_index=3)),
      ('event-domain',uses,lambda x:check_uses(x),lambda x:x['candidates'][0].update(target_domain='method_ref')),
      ('inherited-field-source',inherited_result,lambda x:check_inherited(x),lambda x:next(w for w in x['candidates'][0]['evidence'] if w['kind']=='inherited' and w['inherited']['item']==4)['inherited'].update(source_index=1)),
      ('omit-event',uses,lambda x:check_uses(x),lambda x:x['candidates'].pop()),
      ('binding-owner',linked,lambda x:check_uses(x,joined=True),lambda x:next(b for b in x['candidates'][0]['bindings'] if b['value_kind']=='entity').update(owner=CHILD)),
      ('binding-source',repeat_linked,lambda x:check_uses(x,repeat=True,joined=True),lambda x:x['candidates'][0]['links'][0]['right'].update(source_index=1)),
      ('row-input-index',repeat_linked,lambda x:check_uses(x,repeat=True,joined=True),lambda x:x['candidates'][0].update(input_index=1)),
      ('consistent-input-index',repeat_linked,lambda x:check_uses(x,repeat=True,joined=True),forge_input_consistently),
      ('row-snapshot',repeat_linked,lambda x:check_uses(x,repeat=True,joined=True),lambda x:x['candidates'][0].update(snapshot_id='snapshot:v2:'+'0'*64)),
      ('consistent-snapshot',repeat_linked,lambda x:check_uses(x,repeat=True,joined=True),forge_snapshot_consistently),
      ('consistent-occurrence',repeat_linked,lambda x:check_uses(x,repeat=True,joined=True),forge_occurrence_consistently),
      ('coverage-change',uses,lambda x:check_uses(x),lambda x:x.update(coverage='Partial')),
    ]:
        fake=copy.deepcopy(value);mutation(fake)
        try:verify(fake)
        except (AssertionError,KeyError,StopIteration,TypeError):rejected.append(name)
        else:raise AssertionError('forged evidence accepted: '+name)
    assert hashlib.sha256(args.exe.read_bytes()).hexdigest()==exe_hash
    assert hashlib.sha256(args.fixture.read_bytes()).hexdigest()==FIXTURE_SHA
    assert hashlib.sha256(args.generator.read_bytes()).hexdigest()==GENERATOR_SHA
    one,one_snapshot=source_identities(str(args.fixture),1);two,two_snapshot=source_identities(str(args.fixture),2)
    summary={'passed':len(records),'forged_rejected':rejected,'fixture_sha256':FIXTURE_SHA,'generator_sha256':GENERATOR_SHA,'rebuild_argv':gen,'exe_sha256':exe_hash,
             'source_identity_oracle':{'single':{'sources':one,'snapshot_id':one_snapshot},'repeated':{'sources':two,'snapshot_id':two_snapshot}},
             'scope':'static own declarations, direct parent and explicit field uses only; no inherited closure or ART/runtime claim'}
    (args.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8');print(json.dumps({'passed':len(records),'forged_rejected':len(rejected)}))
if __name__=='__main__':main()
