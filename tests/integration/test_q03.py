"""Q03 byte and CLI oracle; no annotation verifier or ART/runtime claim."""
from pathlib import Path
import argparse,copy,hashlib,json,struct,subprocess,sys,time,zlib
import q_source_oracle as sources

SHA='ea6e44ec68dfbb6c68a88171c5c64b77dca38b73bfdf0cc1b820d4d1e5ccb062'
IDS={'annotation-only-q03':6,'code-use-q03':7,'static-only-q03':10}
NAMES={'quiet':(0,408),'uses':(1,428)}

def u32(data,at):return struct.unpack_from('<I',data,at)[0]
def u16(data,at):return struct.unpack_from('<H',data,at)[0]
def leb(data,at):
    n=0
    for i in range(5):
        assert at<len(data);b=data[at];at+=1
        assert i!=4 or b<=15
        n|=(b&127)<<(7*i)
        if b<128:return n,at
    raise AssertionError('overlong ULEB')

def verify_raw(data):
    assert len(data)==684 and hashlib.sha256(data).hexdigest()==SHA
    assert data[:8]==b'dex\n035\0' and u32(data,32)==len(data)
    assert data[12:32]==hashlib.sha1(data[32:]).digest() and u32(data,8)==zlib.adler32(data[12:])&0xffffffff
    count,off=u32(data,56),u32(data,60);assert count==12
    strings=[]
    for i in range(count):
        at=u32(data,off+4*i);length,at=leb(data,at);end=data.index(0,at)
        assert end-at==length and all(0<c<128 for c in data[at:end]);strings.append(data[at:end].decode('ascii'))
    for value,index in IDS.items():assert strings[index]==value
    type_count,type_off=u32(data,64),u32(data,68)
    types=[strings[u32(data,type_off+4*i)] for i in range(type_count)]
    assert types==['Ljava/lang/Object;','Ljava/lang/String;','Lq03/Annotation;','Lq03/Subject;','V']
    assert u32(data,96)==1;clazz=u32(data,100)
    assert u32(data,clazz)==3 and u32(data,clazz+20)==484 and u32(data,clazz+24)==450 and u32(data,clazz+28)==470
    assert struct.unpack_from('<HHI',data,u32(data,84))==(3,1,8)
    assert u32(data,72)==1 and struct.unpack_from('<III',data,u32(data,76))==(4,4,0)
    assert u32(data,88)==2
    assert [struct.unpack_from('<HHI',data,u32(data,92)+8*i) for i in range(2)]==[(3,0,9),(3,0,11)]
    assert u32(data,clazz+16)==0xffffffff
    assert struct.unpack_from('<IIII',data,484)==(476,0,0,0)
    assert struct.unpack_from('<II',data,476)==(1,464)
    assert data[464:470]==bytes.fromhex('01 02 01 05 17 06')
    assert data[470:473]==bytes.fromhex('01 17 0a')
    at=450;sizes=[]
    for _ in range(4):value,at=leb(data,at);sizes.append(value)
    assert sizes==[1,0,2,0]
    field,at=leb(data,at);flags,at=leb(data,at);assert (field,flags)==(0,9)
    found={};previous=0
    for ordinal in range(2):
        delta,at=leb(data,at);flags,at=leb(data,at);code,at=leb(data,at);idx=previous+delta;previous=idx
        assert flags==9;found[idx]=code
    assert at==464 and found=={0:408,1:428}
    methods={}
    for name,(idx,code) in NAMES.items():
        words=[u16(data,code+16+2*i) for i in range(u32(data,code+12))]
        assert words==([0x000e] if name=='quiet' else [0x001a,7,0x000e]);methods[name]=words
    # Only code-use-q03 is referenced by a const-string in either method.
    assert methods['uses'][1] == IDS['code-use-q03'] and methods['quiet']==[0x000e]
    return strings

def main():
    p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--generator',type=Path,required=True);p.add_argument('--output',type=Path);p.add_argument('--root',type=Path);args=p.parse_args()
    args.root=sources.project_root(args.root,args.generator)
    args.fixture=args.fixture.resolve();args.generator=args.generator.resolve();args.exe=args.exe.resolve()
    if args.output is None:
        if args.root is None:p.error('one of --output or --root is required')
        args.output=args.root/'docs/evidence/q03-domains'/('run-'+str(time.time_ns()))
    args.output.mkdir(parents=True,exist_ok=False)
    data=args.fixture.read_bytes();verify_raw(data)
    rebuilt=args.output/'rebuilt';built=subprocess.run([sys.executable,str(args.generator),'--output',str(rebuilt)],capture_output=True,timeout=30)
    assert built.returncode==0 and (rebuilt/'q03-domains.dex').read_bytes()==data
    complete_source=sources.dataset(args.root,args.fixture)
    incomplete_source=sources.dataset(args.root,args.fixture,complete=False)
    binary_sha=hashlib.sha256(args.exe.read_bytes()).hexdigest();records=[];forged=[]
    def query(name,where,intent='unique',relation='method_defs',incomplete=False):
        path=args.output/(name+'.query.json');path.write_text(json.dumps({'schema_version':1,'relation':relation,'where':where,'intent':intent,'max_results':20}),encoding='utf-8')
        command=[str(args.exe),'query',str(args.fixture),'--query',str(path),'--json']
        if incomplete:command.append('--scope-incomplete')
        proc=subprocess.run(command,capture_output=True,timeout=30)
        (args.output/(name+'.stdout.json')).write_bytes(proc.stdout);(args.output/(name+'.stderr.log')).write_bytes(proc.stderr)
        assert proc.returncode==0,(name,proc.returncode,proc.stderr.decode('utf-8','replace'))
        value=json.loads(proc.stdout);sources.verify(value,incomplete_source if incomplete else complete_source)
        records.append({'name':name,'sha256':hashlib.sha256(proc.stdout).hexdigest()});return value
    for literal,index in IDS.items():
        result=query('pool-'+str(index),{'value':literal},relation='string_values')
        assert (result['coverage'],result['decision'])==('Complete','ProvenTrue') and len(result['candidates'])==1
        row=result['candidates'][0];sources.verify_row(row,result,complete_source)
        assert row['local_index']==index and row['string_value']==literal and row['source_sha256']==SHA
    def verify_positive(result):
        sources.verify(result,complete_source)
        assert (result['execution_status'],result['coverage'],result['decision'])==('Complete','Complete','ProvenTrue')
        assert len(result['candidates'])==1;row=result['candidates'][0]
        sources.verify_row(row,result,complete_source)
        assert (row['source_index'],row['source_sha256'],row['method_index'],row['owner'],row['name'],row['prototype'],row['code_offset'])==(0,SHA,1,'Lq03/Subject;','uses','()V',428)
        hits=[w for w in row['evidence'] if w['kind']=='string_use' and w['matched']]
        assert len(hits)==1;hit=hits[0]
        assert (hit['dex_pc'],hit['opcode'],hit['reference_index'],hit['reference_kind'])==(0,0x1a,7,'string')
        offset=row['code_offset']+16+2*hit['dex_pc']
        assert u16(data,offset)==hit['opcode'] and u16(data,offset+2)==hit['reference_index']
    positive=query('code',{'using_strings':{'all':['code-use-q03']}});verify_positive(positive)
    for literal in ['annotation-only-q03','static-only-q03']:
        negative=query('not-used-'+literal,{'using_strings':{'all':[literal]}})
        assert (negative['coverage'],negative['decision'],negative['reason'],len(negative['candidates']))==('Complete','ProvenFalse','NoMatch',0)
        assert negative['query_profile']['methods_decoded']==2 and negative['query_profile']['code_units']==4
    all_result=query('all-cross-domains',{'using_strings':{'all':['code-use-q03','annotation-only-q03']}})
    assert (all_result['coverage'],all_result['decision'],all_result['reason'],len(all_result['candidates']))==('Complete','ProvenFalse','NoMatch',0)
    any_result=query('any-cross-domains',{'using_strings':{'any':['code-use-q03','static-only-q03']}});verify_positive(any_result)
    inverted=query('not-annotation',{'not':{'using_strings':{'all':['annotation-only-q03']}}},intent='enumerate')
    assert inverted['coverage']=='Complete' and {x['name'] for x in inverted['candidates']}=={'quiet','uses'}
    for row in inverted['candidates']:sources.verify_row(row,inverted,complete_source)
    incomplete=query('incomplete-annotation',{'using_strings':{'all':['annotation-only-q03']}},incomplete=True)
    def verify_incomplete(value):
        sources.verify(value,incomplete_source)
        assert (value['execution_status'],value['coverage'],value['decision'],value['reason'],value['candidates'])==('Complete','Partial','Undetermined','SourceScopeIncomplete',[])
    verify_incomplete(incomplete)
    for label,mutate in [
        ('wrong-pc',lambda x:x['candidates'][0]['evidence'][0].__setitem__('dex_pc',1)),
        ('wrong-opcode',lambda x:x['candidates'][0]['evidence'][0].__setitem__('opcode',0x1b)),
        ('annotation-index-as-use',lambda x:x['candidates'][0]['evidence'][0].__setitem__('reference_index',6)),
        ('static-index-as-use',lambda x:x['candidates'][0]['evidence'][0].__setitem__('reference_index',10)),
        ('wrong-source',lambda x:x['candidates'][0].__setitem__('source_index',1)),
        ('wrong-input-index',lambda x:x['candidates'][0].__setitem__('input_index',1)),
        ('wrong-occurrence',lambda x:x['candidates'][0].__setitem__('occurrence_id','forged')),
        ('wrong-snapshot',lambda x:x['candidates'][0].__setitem__('snapshot_id','forged')),
        ('wrong-source-occurrence',lambda x:x['sources'][0].__setitem__('occurrence_id','forged')),
        ('wrong-source-snapshot',lambda x:x.__setitem__('snapshot_id','forged')),
        ('wrong-method',lambda x:x['candidates'][0].__setitem__('name','quiet')),
        ('coverage-change',lambda x:x.__setitem__('coverage','Partial'))]:
        fake=copy.deepcopy(positive);mutate(fake)
        try:verify_positive(fake)
        except (AssertionError,KeyError,IndexError):forged.append(label)
        else:raise AssertionError('forged result accepted: '+label)
    fake=copy.deepcopy(incomplete);fake.update(coverage='Complete',decision='ProvenFalse',reason='NoMatch')
    try:verify_incomplete(fake)
    except (AssertionError,KeyError,IndexError):forged.append('fake-complete-incomplete')
    else:raise AssertionError('forged incomplete coverage accepted')
    assert hashlib.sha256(args.exe.read_bytes()).hexdigest()==binary_sha
    summary={'passed':len(records),'failed':0,'forged_rejected':forged,'fixture_sha256':SHA,'exe_sha256':binary_sha,'scope':'independent authored DEX bytes and method-use query; annotation structure is not an ART or full verifier proof','records':records}
    (args.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':len(records),'forged_rejected':len(forged),'failed':0}))
if __name__=='__main__':main()
