"""Compare JNI v3 graph rows and proofs to the independently exercised CLI."""
import argparse,hashlib,json,subprocess,tempfile
from pathlib import Path
import sys
if not __debug__: raise SystemExit('graph differential requires assertions enabled')
p=argparse.ArgumentParser();p.add_argument('--root',required=True,type=Path);p.add_argument('--cli',required=True,type=Path);p.add_argument('--java',required=True,type=Path);p.add_argument('--classes',required=True,type=Path);p.add_argument('--native',required=True,type=Path);a=p.parse_args()
fixture=a.root/'tests/fixtures/generated/definition_catalog/definitions.dex'
assert hashlib.sha256(fixture.read_bytes()).hexdigest()=='e1059582b6c893690880403d00f6b5be8dfceb7be282793e2117bdf15b14e77a'
relations=['method_defs','class_defs','field_defs','method_refs','field_refs','string_values','type_refs']
ops=['scan','filter','union','distinct','label','group_by_owner','join','semi_join']; keys=['same_entity','local_definition','local_owner','symbol']
status={'Complete':0,'BudgetExceeded':4,'Cancelled':9,'DeadlineExceeded':10}; coverage={'Complete':0,'Partial':1}; decision={'NotApplicable':0,'Undetermined':1,'ProvenFalse':2,'ProvenTrue':3}; reason={'None':0,'NoMatch':1,'Ambiguous':2,'Witness':3,'ResultLimit':4,'SourceScopeIncomplete':5,'UnknownAttribute':6}
def scan(r,where=None):
    x={'op':'scan','relation':r}
    if where is not None:x['where']=where
    return x
def join(op,left,right,on):return {'op':op,'left':left,'right':right,'on':on}
def label(x,n):return {'op':'label','input':x,'label':n}
def entity(c):return {'relation':relations.index(c['relation']),'source_index':c['source_index'],'local_index':c['local_index'],'reference_index':c['reference_index'],'record_offset':c['record_offset'],'definition_offset':c.get('definition_offset'),'access_flags':c.get('access_flags'),'code_offset':c.get('code_offset'),'owner':c.get('owner'),'name':c.get('name'),'prototype':c.get('prototype'),'type_descriptor':c.get('type_descriptor'),'string_value':c.get('string_value')}
def binding(b,proof=False):
    src=b['entity'] if proof else b
    return {'operator_node':b['operator_node'] if proof else 4294967295,'label':b['label'],'path':[0 if x=='L' else 1 for x in b.get('path',[])],'entity':entity(src)}
def link(l):return [l['operator_node'],keys.index(l['key']),l['left']['source_index'],relations.index(l['left']['relation']),l['left']['local_index'],l['right']['source_index'],relations.index(l['right']['relation']),l['right']['local_index']]
def witness(w):
    assert w['kind']=='metadata'
    return [1,w['node_id'],{True:1,False:0,None:2}[w['matched']],w['operator_node'],w['entity']['source_index'],relations.index(w['entity']['relation']),w['entity']['local_index']]
def compare(expected,actual):
    for key,mapping in [('execution_status',status),('coverage',coverage),('decision',decision),('reason',reason)]:assert actual[key]==mapping[expected[key]],(key,expected[key],actual[key])
    for key in ('query_id','visited_rows','total_rows','unknown_rows'):assert actual[key]==expected[key],key
    profile=expected['relation_profile']; assert actual['root_node']==profile['root_node'] and actual['identity_count']==profile['identity_count'] and actual['unique_identity']=={'entity':0,'tuple':1}[profile['unique_by']]
    assert actual['work']==expected['query_profile']['work_units'] and actual['matches']==expected['query_profile']['matches_seen']
    actual_ops=[[x['node_id'],ops.index(x['op']),x['input_rows'],x['output_rows'],x['unknown_rows'],x['visited_rows'],x['total_rows'],x['complete']] for x in profile['operators']]
    assert actual['operators']==actual_ops,(actual['operators'],actual_ops)
    want=[]
    for c in expected['candidates']:
        want.append({'entity':entity(c),'bindings':[binding(b) for b in c.get('bindings',[])],'proof':[binding(b,True) for b in c.get('proof_bindings',[])],'links':[link(l) for l in c.get('links',[])],'witnesses':[witness(w) for w in c.get('evidence',[])]})
    assert actual['rows']==want,(actual['rows'],want)
left=scan('method_defs');right=scan('class_defs');fields=scan('field_defs');refs=scan('field_refs')
queries=[
 ('join-owner',join('join',left,right,'local_owner'),{}),('semi-owner',join('semi_join',left,right,'local_owner'),{}),
 ('join-same',join('join',fields,fields,'same_entity'),{}),('join-symbol',join('join',fields,refs,'symbol'),{}),
 ('join-definition',join('join',fields,refs,'local_definition'),{}),
 ('projection',join('join',left,right,'local_owner'),{'projection':['identity']}),
 ('labeled-union',{'op':'union','semantics':'bag','inputs':[label(fields,'left'),label(fields,'right')]},{}),
 ('distinct',{'op':'distinct','identity':'tuple','input':{'op':'union','semantics':'bag','inputs':[label(fields,'x'),label(fields,'x')]}},{}),
 ('filter',{'op':'filter','input':fields,'where':{'name':'shared'}},{}),
 ('unknown',scan('field_refs',{'flags_contains':0}),{}),
 ('group',{'op':'group_by_owner','inputs':[left,fields],'min':1},{}),
 ('exists',join('semi_join',left,right,'local_owner'),{'intent':'exists'}),
 ('unique',join('join',left,right,'local_owner'),{'intent':'unique'}),
]
with tempfile.TemporaryDirectory(prefix='dmg-graph-oracle-') as tmp:
    records=[]
    for name,relation,extra in queries:
        q={'schema_version':1,'relation':relation,**extra};path=Path(tmp)/(name+'.json');path.write_text(json.dumps(q,separators=(',',':')),encoding='utf-8')
        cmd=[str(a.cli),'query',str(fixture),'--source',str(fixture),'--scope-incomplete','--query',str(path),'--json']
        c=subprocess.run(cmd,capture_output=True,text=True,encoding='utf-8',timeout=120);assert c.returncode==0,(name,c.stdout,c.stderr)
        cmd=[str(a.java),'-ea','-Xcheck:jni','-Djava.library.path='+str(a.native),'-cp',str(a.classes),'io.github.jichuo1.dexmeguviz.JniGraphDump',str(fixture),str(path)]
        j=subprocess.run(cmd,capture_output=True,text=True,encoding='utf-8',timeout=120);assert j.returncode==0,(name,j.stdout,j.stderr)
        assert 'WARNING in native method' not in j.stdout+j.stderr and 'JNI DETECTED ERROR' not in j.stdout+j.stderr
        expected=json.loads(c.stdout);actual=json.loads(j.stdout);compare(expected,actual);records.append({'case':name,'query_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'rows':len(actual['rows'])})
print(json.dumps({'outcome':'passed','cases':records,'scope':'fixed DEX v3 metadata graphs; Windows JNI vs CLI, no ART'},indent=2))


