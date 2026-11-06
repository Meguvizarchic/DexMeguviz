"""Bounded command contract for the existing single-source metadata oracle."""
from __future__ import annotations
import argparse,importlib.util,json,sys
from pathlib import Path

class Unsupported(ValueError):pass
class Budget(ValueError):pass
def read(path,limit):
    with Path(path).open('rb') as stream:data=stream.read(limit+1)
    if len(data)>limit:raise Budget('input byte limit')
    return data
def pairs(items):
    out={}
    for key,value in items:
        if key in out:raise ValueError('duplicate JSON key')
        out[key]=value
    return out
def load_json(data):
    def reject(_):raise ValueError('JSON number must be integral and finite')
    value=json.loads(data,object_pairs_hook=pairs,parse_float=reject,parse_constant=reject)
    count=0
    def walk(v,depth):
        nonlocal count
        count+=1
        if count>200000 or depth>64:raise Budget('JSON structure limit')
        if isinstance(v,str) and len(v)>1048576:raise Budget('JSON text limit')
        if isinstance(v,dict):
            for k,x in v.items():walk(k,depth+1);walk(x,depth+1)
        elif isinstance(v,list):
            for x in v:walk(x,depth+1)
    walk(value,0);return value
def admit_query(q):
    if not isinstance(q,dict) or set(q)-{'schema_version','relation','where','intent','max_results','max_work','evidence_profile'}:raise Unsupported('metadata verifier does not support this query shape')
    if type(q.get('schema_version')) is not int or q.get('schema_version')!=1 or q.get('relation')!='method_defs':raise Unsupported('query version/relation')
    if q.get('intent','enumerate') not in ('enumerate','exists','unique') or q.get('evidence_profile','minimal')!='minimal':raise Unsupported('intent/evidence profile')
    for name,default in (('max_results',4096),('max_work',100000000)):
        if type(q.get(name,default)) is not int or not 1<=q.get(name,default)<=(100000 if name=='max_results' else (1<<64)-1):raise ValueError('positive query limit required')
    where=q.get('where',{})
    if not isinstance(where,dict) or set(where)-{'name','owner','flags_contains'}:raise Unsupported('metadata verifier predicates are name/owner/raw flags only')
    for name in ('name','owner'):
        if name not in where:continue
        spec=where[name]
        if not isinstance(spec,dict) or set(spec)-{'op','value','u16'} or spec.get('op','exact') not in ('exact','contains'):raise Unsupported('text matcher')
        if ('value' in spec)==('u16' in spec):raise ValueError('exactly one text representation required')
        if 'value' in spec and not isinstance(spec['value'],str):raise ValueError('text value')
        if 'u16' in spec and (not isinstance(spec['u16'],list) or any(type(x) is not int or not 0<=x<=65535 for x in spec['u16'])):raise ValueError('UTF16 units')
    if 'flags_contains' in where and (type(where['flags_contains']) is not int or not 0<=where['flags_contains']<=0xffffffff):raise ValueError('raw flags')
def admit_result(r,single_source=True):
    if not isinstance(r,dict) or type(r.get('schema_version')) is not int or r['schema_version']!=1:raise ValueError('result schema')
    if r.get('profile') not in ('raw-dex-metadata-v0','dex-method-metadata-v1','dex-query-method-v1'):raise Unsupported('result profile')
    if single_source:
        if type(r.get('source_count',1)) is not int or r.get('source_count',1)!=1:raise Unsupported('single-source verifier only')
    elif type(r.get('source_count')) is not int or not 1<=r['source_count']<=16:raise Unsupported('source count outside SourceSet verifier scope')
    for name in ('total_methods','visited_methods'):
        if type(r.get(name)) is not int or r[name]<0:raise ValueError('result counter')
    if r.get('execution_status') not in ('Complete','InvalidArgument','CorruptInput','Unsupported','BudgetExceeded','OutOfMemory','InternalError','Closed','SourceMismatch','Cancelled','DeadlineExceeded','NotReady','EndOfStream'):raise ValueError('execution status')
    rows=r.get('candidates')
    if not isinstance(rows,list) or len(rows)>100000:raise Budget('candidate count')
    for row in rows:
        if not isinstance(row,dict):raise ValueError('candidate object')
        for name in ('method_index','access_flags','declaration_offset','code_offset'):
            if type(row.get(name)) is not int or not 0<=row[name]<=0xffffffff:raise ValueError('candidate integer field')
        for name in ('owner','name','prototype'):
            if not isinstance(row.get(name),str):raise ValueError('candidate text field')
def main(argv=None):
    p=argparse.ArgumentParser(description='Independently verify supported raw DEX method metadata evidence; never ART or runtime binding')
    sources=p.add_mutually_exclusive_group(required=True)
    sources.add_argument('--dex',type=Path)
    sources.add_argument('--sources',type=Path,help='independent ordered raw/APK SourceSet manifest')
    for name in ('result','query'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args(argv)
    try:
        query=load_json(read(a.query,65536));result=load_json(read(a.result,8*1024*1024));admit_query(query);admit_result(result,single_source=a.sources is None)
        if len(result['candidates'])>query.get('max_results',4096):raise ValueError('candidate count exceeds query limit')
        module_path=Path(__file__).with_name('raw_sources.py' if a.sources else 'verify.py');spec=importlib.util.spec_from_file_location('dexmeguviz_independent_metadata_oracle',module_path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        if a.sources:value=module.verify(load_json(read(a.sources,65536)),a.sources,query,result,read)
        else:value=module.verify_result(read(a.dex,64*1024*1024),result,query)
        print(json.dumps({'schema_version':1,'status':'MetadataEvidenceVerified','scope':value,'query_identity_verified':False,'runtime_binding':'NotPerformed','producer_execution_status':result['execution_status']},ensure_ascii=True));return 0
    except (Unsupported,Budget,ValueError,OSError,KeyError,TypeError,RecursionError) as error:
        status='Unsupported' if isinstance(error,Unsupported) or getattr(error,'status',None)=='Unsupported' else 'BudgetExceeded' if isinstance(error,Budget) or getattr(error,'status',None)=='BudgetExceeded' else 'InvalidEvidence'
        print(json.dumps({'schema_version':1,'status':status,'detail':str(error),'verified':False},ensure_ascii=True));return 3 if status=='BudgetExceeded' else 2

if __name__=='__main__':raise SystemExit(main())
