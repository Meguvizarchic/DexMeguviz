"""Repeatable CLI v22 static semantics. Retains all outputs in a unique receipt directory."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess,tempfile
p=argparse.ArgumentParser();p.add_argument('--cli',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True);out=Path(tempfile.mkdtemp(prefix='method-type-',dir=a.out));exe=a.cli.resolve();fixture=a.fixture.resolve();sha=lambda x:hashlib.sha256(x.read_bytes()).hexdigest();before={str(x):sha(x) for x in (Path(__file__).resolve(),exe,fixture)};records=[]
base={'schema_version':1,'required_capabilities':['type_uses'],'relation':'method_defs','max_results':64}
type_leaf={'using_types':{'all':[{'descriptor':'Lfixture/MethodTypeCases$Target;','opcode':34}]}}
def run(name,where,dex=fixture,expected=0,capability=True):
 q={**base,'where':where};
 if not capability:q.pop('required_capabilities')
 qp=out/(name+'.json');qp.write_text(json.dumps(q,separators=(',',':')),encoding='utf8');argv=[str(exe),'query',str(dex),'--query',str(qp),'--json'];r=subprocess.run(argv,capture_output=True,timeout=120);(out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr);records.append({'argv':argv,'exit':r.returncode,'query_sha256':sha(qp),'stdout_sha256':sha(out/(name+'.stdout')),'stderr_sha256':sha(out/(name+'.stderr'))});assert r.returncode==expected,(name,r.returncode,r.stderr.decode(errors='replace'));return json.loads(r.stdout) if r.stdout else None
v=run('composite',{'all':[type_leaf,{'using_strings':{'all':['needle']}},{'invokes':{'all':[{'name':'sink'}]}},{'field_access':{'all':[{'name':'field','access':'write'}]}}]});assert [x['name'] for x in v['candidates']]==['together'];row=v['candidates'][0];assert {x['kind'] for x in row['evidence']}=={'string_use','invoke','field_use','type_use'};assert [x['dex_pc'] for x in row['evidence'] if x['kind']=='type_use']==[8]
v=run('reuse',{'using_types':{'all':[{'descriptor':'Lfixture/MethodTypeCases$Target;','opcode':34},{'descriptor':'Lfixture/MethodTypeCases$Target;'}]}});assert {x['name'] for x in v['candidates']}=={'together','typeOnly'};assert all(sum(w['kind']=='type_use' for w in row['evidence'])==2 for row in v['candidates'])
v=run('nobody',{'all':[{'name':'noBody'},{'not':type_leaf}]});assert len(v['candidates'])==1 and any(w['kind']=='no_body' and w['matched'] is False for w in v['candidates'][0]['evidence'])
v=run('split',{'all':[{'name':'typeOnly'},type_leaf,{'using_strings':{'all':['needle']}}]});assert not v['candidates']
run('invalid-op',{'using_types':{'all':[{'descriptor':'Lfixture/MethodTypeCases$Target;','opcode':0}]}} ,expected=2)
# A corrupt invoke index follows the already matching type instruction; no positive row may escape checked decoding.
bad=bytearray(fixture.read_bytes());code=row['code_offset'];offset=code+16+10*2+2;struct.pack_into('<H',bad,offset,0xffff);badpath=out/'late-invalid.dex';badpath.write_bytes(bad);run('late-invalid',{'all':[{'name':'together'},type_leaf]},badpath,2)
# A missing first matcher may fall through to the second; one event can satisfy any.
any_types={'using_types':{'any':[{'descriptor':'Lfixture/Missing;'}, {'descriptor':'Lfixture/MethodTypeCases$Target;','opcode':34}]}}
v=run('types-any-hit',any_types);assert {x['name'] for x in v['candidates']}=={'together','typeOnly'} and all(sum(w['kind']=='type_use' for w in x['evidence'])==1 for x in v['candidates'])
v=run('types-any-miss',{'using_types':{'any':[{'descriptor':'Lfixture/Missing;'}, {'descriptor':'Lfixture/Absent;'}]}});assert not v['candidates']
# Metadata is examined before body predicates even if listed later. The corrupt
# method is skipped for all, and an any metadata hit must not decode that body.
v=run('all-metadata-skips-corrupt',{'all':[type_leaf,{'name':'doesNotExist'}]},badpath);assert not v['candidates'] and v['query_profile']['fact_requests']==0 and v['query_profile']['methods_decoded']==0
v=run('all-selects-other-method',{'all':[type_leaf,{'name':'typeOnly'}]},badpath);assert [x['name'] for x in v['candidates']]==['typeOnly'] and v['query_profile']['fact_requests']==1
v=run('any-metadata-skips-corrupt',{'any':[type_leaf,{'name':'together'}]},badpath);assert {x['name'] for x in v['candidates']}=={'together','typeOnly'} and v['query_profile']['fact_requests']<v['total_methods']
# An empty type leaf retains v22 identity when the capability is selected;
# mentioning the new syntax without its capability must never enter a legacy ID.
for op in ('all','any'):
 empty={'using_types':{op:[]}}
 v=run('empty-'+op+'-with-capability',empty);assert v['query_id'].startswith('query:v22:') and len(v['candidates'])==(v['total_methods'] if op=='all' else 0) and v['query_profile']['fact_requests']==0
 run('empty-'+op+'-without-capability',empty,expected=2,capability=False)
 run('mixed-empty-'+op+'-without-capability',{'all':[type_leaf,empty]},expected=2,capability=False)
run('type-leaf-without-capability',type_leaf,expected=2,capability=False)
v=run('empty-all-with-leaf',{'all':[type_leaf,{'using_types':{'all':[]}}]});assert {x['name'] for x in v['candidates']}=={'together','typeOnly'}
v=run('empty-any-with-leaf',{'all':[type_leaf,{'using_types':{'any':[]}}]});assert not v['candidates'] and v['query_profile']['fact_requests']==0
v=run('empty-all-short-circuits-or',{'any':[type_leaf,{'using_types':{'all':[]}}]},badpath);assert len(v['candidates'])==v['total_methods'] and v['query_profile']['fact_requests']==0 and v['query_id'].startswith('query:v22:')
v=run('empty-any-or-with-leaf',{'any':[type_leaf,{'using_types':{'any':[]}}]});assert {x['name'] for x in v['candidates']}=={'together','typeOnly'}
# Old Boolean-only QueryIR stays valid and remains in the historical ID domain.
for op in ('all','any'):
 v=run('legacy-boolean-'+op,{op:[]},capability=False);assert v['query_id'].startswith('query:v1:') and len(v['candidates'])==(v['total_methods'] if op=='all' else 0) and v['query_profile']['fact_requests']==0
after={str(x):sha(x) for x in (Path(__file__).resolve(),exe,fixture)};assert before==after;(out/'receipt.json').write_text(json.dumps({'status':'passed','scope':'self-authored DEX static CLI; no ART','inputs_before':before,'inputs_after':after,'mutated_sha256':sha(badpath),'records':records},indent=2)+'\n');print('PASS method type CLI:',out)
