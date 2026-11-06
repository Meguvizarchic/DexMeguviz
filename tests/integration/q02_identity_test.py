"""Q02: independent occurrence/definition checks for equal symbols."""
from pathlib import Path
import argparse, copy, hashlib, importlib.util, json, struct, subprocess, sys, time

PINS={'amb-b1.dex':'c811692d62f01e48bb23d83edb7c642501be7d7e6f1c7bceb6abacb80558371f',
      'amb-b2.dex':'c605e9132c416a210acc409890c6003ac3228e7b03553397834c057f170e45a4'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--exe',type=Path,required=True);ap.add_argument('--root',type=Path,required=True);ap.add_argument('--fixtures',type=Path,required=True);ap.add_argument('--oracle',type=Path,required=True);ap.add_argument('--output',type=Path)
    a=ap.parse_args();a.exe=a.exe.resolve();a.root=a.root.resolve();a.fixtures=a.fixtures.resolve();a.oracle=a.oracle.resolve()
    out=a.output or a.root/'docs/evidence/q02-identity'/('run-'+str(time.time_ns()));out.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(a.root/'tools/evidence_verifier'))
    from multisource import load_source_set,verify_metadata
    spec=importlib.util.spec_from_file_location('raw_graph_oracle',a.oracle);raw=importlib.util.module_from_spec(spec);spec.loader.exec_module(raw)
    for name,digest in PINS.items():
        path=a.fixtures/name;assert hashlib.sha256(path.read_bytes()).hexdigest()==digest
        info=raw.parse(path);assert tuple(info['definition'])==('Lamb/B;','b','()V') and info['method_ref']==0 and info['code_offset']==260
        data=path.read_bytes();classes=struct.unpack_from('<I',data,100)[0];class_data=struct.unpack_from('<I',data,classes+24)[0]
        assert data[class_data:class_data+4]==bytes([0,0,1,0]) and class_data+4==288
    assert PINS['amb-b1.dex']!=PINS['amb-b2.dex']
    exe_sha=hashlib.sha256(a.exe.read_bytes()).hexdigest();records=[];rejected=[]
    def case(name,files,intent,limit,complete,expected):
        paths=[a.fixtures/x for x in files];dataset=load_source_set([{'path':str(p)} for p in paths],a.root,complete,a.root)
        query={'schema_version':1,'relation':'method_defs','where':{'owner':'Lamb/B;','name':'b'},'intent':intent,'max_results':limit}
        q=out/(name+'.query.json');q.write_text(json.dumps(query),encoding='utf-8')
        cmd=[str(a.exe),'query',str(paths[0]),'--query',str(q),'--json']
        for path in paths[1:]:cmd+=['--source',str(path)]
        if not complete:cmd+=['--scope-incomplete']
        p=subprocess.run(cmd,capture_output=True,timeout=60);(out/(name+'.stdout.json')).write_bytes(p.stdout);(out/(name+'.stderr.log')).write_bytes(p.stderr)
        assert p.returncode==expected['exit'],(name,p.returncode,p.stderr)
        result=json.loads(p.stdout)
        def verify(value):
            verify_metadata(dataset,value)
            for key in ('execution_status','coverage','decision','reason'):assert value[key]==expected[key],(name,key,value[key])
            rows=value['candidates'];assert len(rows)==expected['rows']
            indices=[row['source_index'] for row in rows];assert indices==expected['sources']
            origins=value['sources'];assert len({x['occurrence_id'] for x in origins})==len(files)
            for row in rows:
                source=row['source_index'];origin=origins[source];parsed=raw.parse(paths[source])
                for field in ('source_index','input_index','source_sha256','content_id','occurrence_id','logical_dex_id','snapshot_id'):assert row[field]==origin[field] if field!='snapshot_id' else row[field]==value[field]
                assert row['source_sha256']==PINS[files[source]] and row['method_index']==parsed['method_ref']
                assert (row['owner'],row['name'],row['prototype'])==tuple(parsed['definition'])
                assert row['declaration_offset']==288 and row['code_offset']==parsed['code_offset'] and row['access_flags']==9
            if len(files)==3:
                assert origins[0]['content_id']==origins[2]['content_id'] and origins[0]['occurrence_id']!=origins[2]['occurrence_id']
                assert origins[0]['content_id']!=origins[1]['content_id']
        verify(result)
        if name=='enumerate-three':
            for label,change in [('source',lambda x:x['candidates'][2].__setitem__('source_index',0)),('occurrence',lambda x:x['candidates'][2].__setitem__('occurrence_id',x['candidates'][0]['occurrence_id'])),('content',lambda x:x['sources'][1].__setitem__('content_id',x['sources'][0]['content_id'])),('method-index',lambda x:x['candidates'][1].__setitem__('method_index',1)),('signature',lambda x:x['candidates'][1].__setitem__('prototype','(I)V')),('missing',lambda x:x['candidates'].pop()),('wrong-coverage',lambda x:x.__setitem__('coverage','Partial'))]:
                fake=copy.deepcopy(result);change(fake)
                try:verify(fake)
                except (AssertionError,ValueError,KeyError,IndexError):rejected.append(label)
                else:raise AssertionError('forged result accepted: '+label)
        if name=='unique-incomplete':
            fake=copy.deepcopy(result);fake['coverage']='Complete';fake['decision']='ProvenTrue'
            try:verify(fake)
            except (AssertionError,ValueError):rejected.append('fake-complete-unique')
            else:raise AssertionError('forged incomplete unique accepted')
        records.append({'name':name,'result_sha256':hashlib.sha256(p.stdout).hexdigest()})
    ok={'exit':0,'execution_status':'Complete','coverage':'Complete','decision':'NotApplicable','reason':'None','rows':3,'sources':[0,1,2]}
    case('enumerate-three',['amb-b1.dex','amb-b2.dex','amb-b1.dex'],'enumerate',20,True,ok)
    case('unique-one',['amb-b1.dex'],'unique',20,True,{'exit':0,'execution_status':'Complete','coverage':'Complete','decision':'ProvenTrue','reason':'None','rows':1,'sources':[0]})
    for name,files in [('unique-different',['amb-b1.dex','amb-b2.dex']),('unique-repeated',['amb-b1.dex','amb-b1.dex'])]:
        case(name,files,'unique',20,True,{'exit':0,'execution_status':'Complete','coverage':'Complete','decision':'ProvenFalse','reason':'Ambiguous','rows':2,'sources':[0,1]})
    case('unique-limit',['amb-b1.dex','amb-b2.dex'],'unique',1,True,{'exit':3,'execution_status':'BudgetExceeded','coverage':'Partial','decision':'Undetermined','reason':'ResultLimit','rows':1,'sources':[0]})
    case('unique-incomplete',['amb-b1.dex'],'unique',20,False,{'exit':0,'execution_status':'Complete','coverage':'Partial','decision':'Undetermined','reason':'SourceScopeIncomplete','rows':1,'sources':[0]})
    assert hashlib.sha256(a.exe.read_bytes()).hexdigest()==exe_sha
    (out/'summary.json').write_text(json.dumps({'passed':len(records),'failed':0,'forged_rejected':rejected,'exe_sha256':exe_sha,'records':records,'scope':'authored static DEX occurrence identity, not runtime binding'},indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':len(records),'forged_rejected':len(rejected)}))
if __name__=='__main__':main()
