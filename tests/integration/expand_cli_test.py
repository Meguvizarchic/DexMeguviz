"""Compare v5 paths with a byte-level graph oracle; no ART/runtime claim."""
from pathlib import Path
from collections import Counter
import argparse, copy, hashlib, importlib.util, json, subprocess, time

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--exe',type=Path,required=True)
    parser.add_argument('--fixtures',type=Path,required=True)
    parser.add_argument('--oracle',type=Path,required=True)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--root',type=Path)
    args=parser.parse_args()
    if args.output is None:
        if args.root is None:parser.error('one of --output or --root is required')
        args.output=args.root/'docs/evidence/expand-cli'/('run-'+str(time.time_ns()))
    args.output.mkdir(parents=True,exist_ok=False)
    spec=importlib.util.spec_from_file_location('raw_graph_oracle',args.oracle)
    oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
    for name in oracle.PINS:oracle.parse(args.fixtures/name)
    exe_sha=hashlib.sha256(args.exe.read_bytes()).hexdigest()
    records=[];rejected=[]
    def run(name,entries,seed,depth,output='paths',direction='outgoing',incomplete=False,seed_scope=False,**options):
        items=oracle.dataset(args.fixtures,entries)
        start=next(x for x in items if x['occurrence']==seed)
        owner,method,_=start['definition']
        query={'schema_version':1,'relation':{'op':'bounded_expand','input':{'op':'scan','relation':'method_defs','where':{'all':[{'owner':owner},{'name':method}]}},'max_depth':depth,'min_depth':depth,'output':output,'direction':direction},'max_results':100}
        if seed_scope:
            index=next(i for i,(label,_) in enumerate(entries) if label==seed)
            query['relation']['input']['scope']={'slots':[f'input:{index}:{args.fixtures/entries[index][1]}']}
        query.update(options)
        q=args.output/(name+'.query.json');q.write_text(json.dumps(query),encoding='utf-8')
        cmd=[str(args.exe),'query',str(args.fixtures/entries[0][1]),'--query',str(q),'--json']
        for _,filename in entries[1:]:cmd+=['--source',str(args.fixtures/filename)]
        if incomplete:cmd+=['--scope-incomplete']
        p=subprocess.run(cmd,capture_output=True,timeout=60)
        (args.output/(name+'.stdout.json')).write_bytes(p.stdout)
        (args.output/(name+'.stderr.log')).write_bytes(p.stderr)
        assert p.returncode==0,(name,p.returncode,p.stderr.decode('utf-8','replace'))
        value=json.loads(p.stdout)
        mapping={i:label for i,(label,_) in enumerate(entries)}
        raw={x['occurrence']:x for x in items}
        if direction=='outgoing':expected=oracle.paths(items,seed,depth)
        else:
            pending=[(seed,[])];expected=[];edges=oracle.edges(items)
            while pending:
                current,path=pending.pop(0)
                if len(path)==depth:expected.append(path);continue
                for edge in edges:
                    if edge['target']==current:pending.append((edge['caller'],path+[edge]))
        expected_paths=Counter(tuple((h['caller'],h['pc'],h['opcode'],h['method_ref'],h['target'],tuple(h['symbol']),h['candidate_count']) for h in path) for path in expected)
        expected_endpoints={(path[-1]['target'] if direction=='outgoing' else path[-1]['caller']) if path else seed for path in expected}
        def verify(result):
            assert result['profile']=='dex-query-expand-v5' and result['execution_status']=='Complete'
            assert result['coverage']==('Partial' if incomplete else 'Complete')
            actual_paths=[]
            for candidate in result['candidates']:
                for path in candidate['paths']:
                    assert mapping[path['seed']['source_index']]==seed
                    assert path['seed']['relation']=='method_defs' and path['seed']['local_index']==0
                    current=seed;normalized=[]
                    for hop in path['hops']:
                        caller=mapping[hop['caller']['source_index']];resolved=mapping[hop['resolved']['source_index']]
                        assert (caller if direction=='outgoing' else resolved)==current
                        assert hop['caller']['local_index']==0 and hop['resolved']['local_index']==0
                        assert hop['code_offset']==raw[caller]['code_offset'] and hop['resolution_complete']==(not incomplete)
                        target=hop['target_symbol'];symbol=(target['owner'],target['name'],target['prototype'])
                        assert target['source_index']==hop['caller']['source_index'] and target['local_index']==hop['target_method_ref']
                        normalized.append((caller,hop['dex_pc'],hop['opcode'],hop['target_method_ref'],resolved,symbol,hop['candidate_count']))
                        current=resolved if direction=='outgoing' else caller
                    assert mapping[path['endpoint']['source_index']]==current and candidate['source_index']==path['endpoint']['source_index']
                    actual_paths.append(tuple(normalized))
            assert Counter(actual_paths)==expected_paths,(name,actual_paths,expected_paths)
            assert len(result['candidates'])==(len(expected) if output=='paths' else len(expected_endpoints)),name
            return actual_paths
        actual_paths=verify(value)
        if name=='amb-paths':
            for label,change in [
                ('wrong-pc',lambda x:x['candidates'][0]['paths'][0]['hops'][0].__setitem__('dex_pc',1)),
                ('wrong-source',lambda x:x['candidates'][0]['paths'][0]['hops'][0]['caller'].__setitem__('source_index',1)),
                ('wrong-ref',lambda x:x['candidates'][0]['paths'][0]['hops'][0].__setitem__('target_method_ref',65535)),
                ('wrong-target',lambda x:x['candidates'][0]['paths'][0]['hops'][0]['resolved'].__setitem__('source_index',5)),
                ('wrong-count',lambda x:x['candidates'][0]['paths'][0]['hops'][0].__setitem__('candidate_count',1)),
                ('wrong-symbol',lambda x:x['candidates'][0]['paths'][0]['hops'][0]['target_symbol'].__setitem__('name','forged')),
                ('wrong-order',lambda x:x['candidates'][0]['paths'][0]['hops'].reverse()),
                ('missing-path',lambda x:x['candidates'].pop())]:
                fake=copy.deepcopy(value);change(fake)
                try:verify(fake)
                except (AssertionError,KeyError,IndexError):rejected.append(label)
                else:raise AssertionError('forged evidence accepted: '+label)
        if incomplete:
            fake=copy.deepcopy(value);fake['coverage']='Complete'
            try:verify(fake)
            except AssertionError:rejected.append('fake-complete')
            else:raise AssertionError('forged completeness accepted')
        records.append({'name':name,'paths':len(actual_paths),'endpoints':len(expected_endpoints),'sha256':hashlib.sha256(p.stdout).hexdigest()})
        return value
    amb=[('a','amb-a.dex'),('b1','amb-b1.dex'),('b2','amb-b2.dex'),('c1','amb-c1.dex'),('c2','amb-c2.dex'),('overload','amb-overload.dex')]
    run('amb-paths',amb,'a',2);run('amb-endpoints',amb,'a',2,'endpoints')
    run('amb-repeat',amb[:2]+[('b1-copy','amb-b1.dex')]+amb[2:],'a',2)
    run('amb-incoming-b1',amb,'b1',1,direction='incoming',seed_scope=True)
    run('amb-incoming-c1',amb,'c1',2,direction='incoming')
    run('amb-incoming-repeat',amb[:2]+[('b1-copy','amb-b1.dex')]+amb[2:],'c1',2,direction='incoming')
    run('amb-incoming-incomplete',amb,'c1',2,direction='incoming',incomplete=True)
    cycle=[('ca','cycle-a.dex'),('cb','cycle-b.dex')]
    run('cycle-two',cycle,'ca',2);run('cycle-three',cycle,'ca',3);run('depth-zero',cycle,'ca',0)
    run('cycle-incoming',cycle,'cb',2,direction='incoming')
    diamond=[('da','diamond-a.dex'),('db','diamond-b.dex'),('dc','diamond-c.dex'),('dd','diamond-d.dex')]
    run('diamond-paths',diamond,'da',2);run('diamond-endpoints',diamond,'da',2,'endpoints')
    partial=run('amb-incomplete',amb,'a',2,incomplete=True)
    assert partial['frontiers'] and partial['unknown_rows']>0
    def status_case(name,entries,query,expected,incomplete=False):
        q=args.output/(name+'.query.json');q.write_text(json.dumps(query),encoding='utf-8')
        cmd=[str(args.exe),'query',str(args.fixtures/entries[0][1]),'--query',str(q),'--json']
        for _,filename in entries[1:]:cmd+=['--source',str(args.fixtures/filename)]
        if incomplete:cmd.append('--scope-incomplete')
        p=subprocess.run(cmd,capture_output=True,timeout=60)
        (args.output/(name+'.stdout.json')).write_bytes(p.stdout);(args.output/(name+'.stderr.log')).write_bytes(p.stderr)
        assert p.returncode==expected['exit'],(name,p.returncode,p.stderr.decode('utf-8','replace'))
        value=json.loads(p.stdout)
        for field in ['execution_status','coverage','decision','reason']:
            assert value[field]==expected[field],(name,field,value[field],expected[field])
        assert len(value['candidates'])==expected['rows']
        records.append({'name':name,'sha256':hashlib.sha256(p.stdout).hexdigest()})
    diamond_query={'schema_version':1,'relation':{'op':'bounded_expand','input':{'op':'scan','relation':'method_defs','where':{'owner':'Ldiamond/A;'}},'min_depth':2,'max_depth':2,'output':'paths'},'intent':'unique','max_results':100}
    status_case('unique-paths',diamond,diamond_query,{'exit':0,'execution_status':'Complete','coverage':'Complete','decision':'ProvenFalse','reason':'Ambiguous','rows':2})
    entity_query=copy.deepcopy(diamond_query);entity_query['unique_by']='entity'
    status_case('unique-endpoint-identity',diamond,entity_query,{'exit':0,'execution_status':'Complete','coverage':'Complete','decision':'ProvenTrue','reason':'None','rows':1})
    capped=copy.deepcopy(diamond_query);capped['max_results']=1
    status_case('unique-output-limit',diamond,capped,{'exit':3,'execution_status':'BudgetExceeded','coverage':'Partial','decision':'Undetermined','reason':'ResultLimit','rows':1})
    exists=copy.deepcopy(diamond_query);exists['intent']='exists'
    status_case('exists-partial-witness',diamond,exists,{'exit':0,'execution_status':'Complete','coverage':'Partial','decision':'ProvenTrue','reason':'Witness','rows':1},incomplete=True)
    empty=copy.deepcopy(diamond_query);empty['intent']='exists';empty['relation']['scope']={'slots':[]}
    status_case('explicit-empty-scope',diamond,empty,{'exit':0,'execution_status':'Complete','coverage':'Complete','decision':'ProvenFalse','reason':'NoMatch','rows':0})
    assert hashlib.sha256(args.exe.read_bytes()).hexdigest()==exe_sha
    (args.output/'summary.json').write_text(json.dumps({'passed':len(records),'failed':0,'forged_rejected':rejected,'records':records,'exe_sha256':exe_sha,'scope':'fixed authored DEX paths only; no runtime dispatch or ART claim'},indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':len(records),'failed':0}))
if __name__=='__main__':main()
