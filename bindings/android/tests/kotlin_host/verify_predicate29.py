"""Compare Kotlin method-v1 predicates to independently written CLI queries."""
import argparse, json, subprocess, tempfile
from pathlib import Path

p=argparse.ArgumentParser()
for name in ('exe','fixture-param','fixture-q03','lines'): p.add_argument('--'+name,required=True,type=Path)
a=p.parse_args()
generated={}
for line in a.lines.read_text(encoding='utf-8').splitlines():
    name,query=line.split('\t',1); assert name not in generated; generated[name]=json.loads(query)
golden={
 'count-exact':({'param_count':1},'param'),
 'count-range':({'param_count':{'min':1,'max':3}},'param'),
 'param-exact':({'parameter':{'index':0,'type':{'op':'exact','value':'I'}}},'param'),
 'param-absent':({'parameter':{'index':1,'type':{'op':'exact','value':'I'}}},'param'),
 'param-unicode':({'parameter':{'index':1,'type':{'op':'prefix','u16':[0,55296,34,92,57343],'ascii_case_insensitive':True}}},'param'),
 'owner-flags':({'owner_flags':{'mode':'contains','value':1,'domain':'dex'}},'param'),
 'owner-exact':({'owner_flags':{'mode':'exact','value':4294967295,'domain':'dex'}},'param'),
 'normal':({'kind':'normal'},'param'),
 'constructor':({'kind':'constructor'},'param'),
 'clinit':({'kind':'clinit'},'param'),
 'body-use':({'using_strings':{'all':[{'op':'exact','value':'code-use-q03'}]}},'q03'),
 'pool-only':({'using_strings':{'all':[{'op':'exact','value':'annotation-only-q03'}]}},'q03'),
 'use-fold':({'using_strings':{'all':[{'op':'prefix','value':'CODE-USE','ascii_case_insensitive':True}]}},'q03'),
 'combined':({'all':[{'param_count':1},{'parameter':{'index':0,'type':{'op':'exact','value':'I'}}},{'kind':'normal'}]},'param')
}
assert set(generated)==set(golden)
with tempfile.TemporaryDirectory(prefix='dmg-kotlin-pred29-') as temp:
    temp=Path(temp)
    def run(label,query,fixture):
        path=temp/(label+'.json'); path.write_text(json.dumps(query,ensure_ascii=True),encoding='utf-8')
        result=subprocess.run([str(a.exe.resolve()),'query',str(fixture.resolve()),'--query',str(path),'--json'],capture_output=True,text=True,encoding='utf-8',timeout=30)
        assert result.returncode==0,(label,result.returncode,result.stdout,result.stderr)
        return json.loads(result.stdout)
    for name,(where,which) in golden.items():
        expected={'schema_version':1,'relation':'method_defs','where':where,'intent':'enumerate','max_results':4096,'max_work':100000000}
        fixture=a.fixture_param if which=='param' else a.fixture_q03
        actual=run(name+'-kotlin',generated[name],fixture); control=run(name+'-control',expected,fixture)
        assert actual['profile']=='dex-query-method-v1' and actual['query_id'].startswith('query:v1:')
        for key in ('query_id','coverage','decision','reason','execution_status'): assert actual[key]==control[key],(name,key)
        def rows(x):return [(r['source_index'],r['method_index'],r['owner'],r['name'],r['prototype'],r['access_flags']) for r in x['candidates']]
        assert rows(actual)==rows(control),name
        if name in ('count-exact','count-range','param-exact','normal','combined'): assert [r['name'] for r in actual['candidates']]==['b'],name
        if name in ('param-absent','param-unicode','owner-exact','constructor','clinit','pool-only'): assert not actual['candidates'],name
        if name in ('body-use','use-fold'): assert [r['name'] for r in actual['candidates']]==['uses'],name
print('PASS 14 Kotlin method-v1 predicates vs independent CLI controls on two fixed DEX inputs')
