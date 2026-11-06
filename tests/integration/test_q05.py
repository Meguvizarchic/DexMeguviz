"""Q05 raw DEX flags and Unknown semantics; reflection remains Unsupported."""
from pathlib import Path
import argparse,copy,hashlib,json,struct,subprocess,sys,time,zlib

SHA='e1059582b6c893690880403d00f6b5be8dfceb7be282793e2117bdf15b14e77a'
CLASSES=[('Ljava/lang/Object;',1,7,252),('Lcatalog/InterfaceA;',0x601,4,284),
         ('Lcatalog/InterfaceB;',0x601,5,316),('Lcatalog/Base;',1,2,348),('Lcatalog/Child;',0x401,3,380)]
FIELDS=[('Lcatalog/Base;','instanceField','I'),('Lcatalog/Base;','shared','J'),
        ('Lcatalog/Child;','shared','I'),('Lexternal/External;','externalField','I')]
MASK=0x401
def u16(d,o):return struct.unpack_from('<H',d,o)[0]
def u32(d,o):return struct.unpack_from('<I',d,o)[0]
def leb(d,o):
    value=0
    for i in range(5):
        assert o<len(d);b=d[o];o+=1;assert i<4 or b<=15
        value|=(b&127)<<(7*i)
        if b<128:return value,o
    raise AssertionError('overlong ULEB')
def raw_oracle(data):
    assert len(data)==804 and hashlib.sha256(data).hexdigest()==SHA
    assert data[:8]==b'dex\n035\0' and u32(data,32)==len(data)
    assert data[12:32]==hashlib.sha1(data[32:]).digest() and u32(data,8)==zlib.adler32(data[12:])&0xffffffff
    n,off=u32(data,56),u32(data,60);strings=[]
    for i in range(n):
        pos=u32(data,off+4*i);length,pos=leb(data,pos);end=data.index(0,pos)
        assert end-pos==length and all(0<c<128 for c in data[pos:end]);strings.append(data[pos:end].decode('ascii'))
    types=[strings[u32(data,u32(data,68)+4*i)] for i in range(u32(data,64))]
    assert u32(data,96)==len(CLASSES) and u32(data,100)==252
    for i,(descriptor,flags,typeid,offset) in enumerate(CLASSES):
        pos=u32(data,100)+32*i;assert pos==offset and u32(data,pos)==typeid and types[typeid]==descriptor and u32(data,pos+4)==flags
    assert u32(data,80)==len(FIELDS)
    for i,(owner,name,typ) in enumerate(FIELDS):
        at=u32(data,84)+8*i;assert (types[u16(data,at)],strings[u32(data,at+4)],types[u16(data,at+2)])==(owner,name,typ)
    declarations={}
    for i in range(len(CLASSES)):
        at=u32(data,u32(data,100)+32*i+24)
        if not at:continue
        counts=[]
        for _ in range(4):n,at=leb(data,at);counts.append(n)
        for group,count in enumerate(counts):
            prev=0
            for _ in range(count):
                offset=at;delta,at=leb(data,at);flags,at=leb(data,at);idx=prev+delta;prev=idx
                if group>=2:_,at=leb(data,at)
                else:assert idx not in declarations;declarations[idx]=(flags,offset)
    assert declarations=={1:(9,611),0:(1,613),2:(1,619)} and 3 not in declarations
    return declarations

def main():
    p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--generator',type=Path,required=True);p.add_argument('--output',type=Path);p.add_argument('--root',type=Path);args=p.parse_args()
    if args.output is None:
        if args.root is None:p.error('one of --output or --root is required')
        args.output=args.root/'docs/evidence/q05-flags'/('run-'+str(time.time_ns()))
    args.output.mkdir(parents=True,exist_ok=False);data=args.fixture.read_bytes();raw_oracle(data)
    rebuilt=args.output/'rebuilt';proc=subprocess.run([sys.executable,str(args.generator),'--output',str(rebuilt)],capture_output=True,timeout=30)
    assert proc.returncode==0 and (rebuilt/'definitions.dex').read_bytes()==data
    binary=hashlib.sha256(args.exe.read_bytes()).hexdigest();records=[];rejected=[]
    def call(name,relation,where,intent='enumerate',exit_code=0):
        q=args.output/(name+'.query.json');q.write_text(json.dumps({'schema_version':1,'relation':relation,'where':where,'intent':intent,'max_results':100}),encoding='utf-8')
        proc=subprocess.run([str(args.exe),'query',str(args.fixture),'--query',str(q),'--json'],capture_output=True,timeout=30)
        (args.output/(name+'.stdout.json')).write_bytes(proc.stdout);(args.output/(name+'.stderr.log')).write_bytes(proc.stderr)
        assert proc.returncode==exit_code,(name,proc.returncode,proc.stderr.decode('utf-8','replace'))
        value=json.loads(proc.stdout);records.append({'name':name,'stdout_sha256':hashlib.sha256(proc.stdout).hexdigest()})
        return value,proc.stderr.decode('utf-8','replace')
    def verify_classes(value,expected):
        assert (value['execution_status'],value['coverage'],value['unknown_rows'])==('Complete','Complete',0)
        rows=value['candidates'];assert {x['local_index'] for x in rows}==set(expected) and len(rows)==len(expected)
        for x in rows:
            i=x['local_index'];desc,flags,typeid,offset=CLASSES[i]
            assert (x['relation'],x['source_index'],x['source_sha256'],x['type_descriptor'],x['access_flags'],x['reference_index'],x['record_offset'],x['definition_offset'])==('class_defs',0,SHA,desc,flags,typeid,offset,offset)
            assert u32(data,offset+4)==x['access_flags']
    predicates={'contains':{'flags_contains':MASK},'any':{'flags_any':MASK},'exact':{'flags_exact':MASK}}
    expected={'contains':[1,2,4],'any':[0,1,2,3,4],'exact':[4]};baseline={}
    for mode in predicates:
        v,_=call(mode,'class_defs',predicates[mode]);verify_classes(v,expected[mode]);baseline[mode]=v
        typed,_=call('typed-'+mode,'class_defs',{'flags':{'mode':mode,'value':MASK,'domain':'dex'}})
        verify_classes(typed,expected[mode]);assert typed['query_id']==v['query_id']
    for name,where,indices in [('zero-contains',{'flags_contains':0},[0,1,2,3,4]),('zero-any',{'flags_any':0},[]),('zero-exact',{'flags_exact':0},[]),('not-contains',{'not':{'flags_contains':MASK}},[0,3]),('not-any',{'not':{'flags_any':MASK}},[]),('not-exact',{'not':{'flags_exact':MASK}},[0,1,2,3])]:
        v,_=call(name,'class_defs',where);verify_classes(v,indices)
    def verify_unknown(v):
        assert (v['execution_status'],v['coverage'],v['decision'],v['reason'],v['unknown_rows'])==('Complete','Partial','Undetermined','UnknownAttribute',1)
        assert v['candidates']==[]
    for name,predicate in [('contains',{'flags_contains':9}),('any',{'flags_any':9}),('exact',{'flags_exact':0}),('contains-zero',{'flags_contains':0}),('not-contains',{'not':{'flags_contains':9}}),('owner',{'owner_flags':{'mode':'contains','value':1,'domain':'dex'}})]:
        v,_=call('unknown-'+name,'field_refs',{'name':'externalField',**predicate},intent='unique');verify_unknown(v)
    v,_=call('false-and-unknown','field_refs',{'all':[{'name':'missing'},{'flags_contains':9}]},intent='unique')
    assert (v['coverage'],v['decision'],v['reason'],v['unknown_rows'],v['candidates'])==('Complete','ProvenFalse','NoMatch',0,[])
    v,_=call('true-or-unknown','field_refs',{'any':[{'name':'externalField'},{'flags_contains':9}]})
    assert v['coverage']=='Complete' and v['unknown_rows']==0 and {(x['local_index'],x['name'],x['access_flags']) for x in v['candidates']}=={(1,'shared',9),(3,'externalField',None)}
    for name,where in [('reflection',{'flags':{'mode':'contains','value':MASK,'domain':'reflection'}}),('reflection-in-dead-branch',{'any':[True,{'flags':{'mode':'contains','value':MASK,'domain':'reflection'}}]})]:
        v,stderr=call(name,'class_defs',where,intent='unique',exit_code=2)
        assert v['execution_status']=='Unsupported' and v['decision']=='Undetermined' and not v['candidates'] and 'Unsupported' in stderr
    for label,mutate in [
        ('wrong-source',lambda x:x['candidates'][0].__setitem__('source_index',1)),
        ('wrong-flags',lambda x:x['candidates'][0].__setitem__('access_flags',0x401)),
        ('wrong-offset',lambda x:x['candidates'][0].__setitem__('record_offset',380)),
        ('missing-row',lambda x:x['candidates'].pop()),
        ('duplicate-row',lambda x:x['candidates'].append(copy.deepcopy(x['candidates'][0])))]:
        fake=copy.deepcopy(baseline['contains']);mutate(fake)
        try:verify_classes(fake,expected['contains'])
        except (AssertionError,KeyError,IndexError):rejected.append(label)
        else:raise AssertionError('forged result accepted: '+label)
    assert hashlib.sha256(args.exe.read_bytes()).hexdigest()==binary
    summary={'passed':len(records),'failed':0,'forged_rejected':rejected,'fixture_sha256':SHA,'exe_sha256':binary,'scope':'raw DEX flags and three-valued metadata only; reflection explicitly Unsupported; no ART/runtime claim','records':records}
    (args.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':len(records),'forged_rejected':len(rejected),'failed':0}))
if __name__=='__main__':main()
