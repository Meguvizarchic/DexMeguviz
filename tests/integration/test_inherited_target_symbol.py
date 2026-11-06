"""v18 inherited/target-symbol static evidence vs independently decoded fixture bytes."""
from pathlib import Path
from collections import Counter
import argparse,copy,hashlib,importlib.util,json,struct,subprocess,sys
if not __debug__:raise SystemExit('assertions required')
p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--old',type=Path,required=True);p.add_argument('--root',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
sha=lambda q:hashlib.sha256(q.read_bytes()).hexdigest();files=a.root/'tests/fixtures/generated';method=files/'inherited-use/local-target.dex';field=files/'use_relations/field-read-write.dex';parent=files/'inherited/root.dex';oracle=a.root/'tools/evidence_verifier/verify.py';entity_oracle=a.root/'tests/integration/entity_query_test.py';use_oracle=a.root/'tests/integration/use_query_test.py';inherit_oracle=a.root/'tests/integration/verify_inherited_fixture.py'
def load(n,path):
 spec=importlib.util.spec_from_file_location(n,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
raw=load('raw56',oracle);entities=load('entity56',entity_oracle);uses=load('use56',use_oracle);hierarchy=load('hierarchy56',inherit_oracle)
assert hierarchy.inspect(parent.read_bytes())==('Ljava/lang/Object;',None,{})
def class_symbols(path):
 data=path.read_bytes();parsed=raw.parse_dex(data);u32=lambda off:struct.unpack_from('<I',data,off)[0];types=[parsed['strings'][u32(u32(68)+i*4)] for i in range(u32(64))];at=u32(100);own,_,super_id=struct.unpack_from('<III',data,at);return types[own],types[super_id]
for path in (method,field):assert class_symbols(path)==('Lfacts/Example;','Ljava/lang/Object;')
m=raw.parse_dex(method.read_bytes());assert m['references'][3]['owner']=='Lfacts/Example;' and m['references'][3]['name']=='uses' and m['references'][3]['prototype']=='()V'
body=method.read_bytes();assert [(struct.unpack_from('<H',body,416+16+2*pc)[0]&255,struct.unpack_from('<H',body,416+16+2*(pc+1))[0]) for pc in (0,3)]==[(0x71,3),(0x71,3)]
f=entities.raw_entities(field,a.root);assert f['field_defs'][0]['owner']=='Lfacts/Example;' and f['field_defs'][0]['name']=='counter' and f['field_refs'][0]['type_descriptor']=='I'
fe=[x for x in uses.raw_fixture(field) if x[0]=='field_uses'];assert [(x[1],x[2],x[4]) for x in fe]==[(0,0x60,0),(2,0x67,0)]
inputs=[a.exe,a.old,method,field,parent,files/'method_facts/method-uses.dex',oracle,entity_oracle,use_oracle,inherit_oracle,Path(__file__)];before={str(x.resolve()):sha(x) for x in inputs};records=[]
inh={'declares_fields':{'scope':'inherited','where':{'name':'unseen'},'min':0,'max':0}}
def graph(relation,target,name,reverse=False,semi=False):
 left={'op':'scan','relation':relation};right={'op':'scan','relation':target,'where':{'all':[{'name':name},copy.deepcopy(inh)]}}
 if reverse:left,right=right,left
 return {'schema_version':1,'required_capabilities':['inherited_fields','use_target_symbol','inherited_target_symbol'],'relation':{'op':'semi_join' if semi else 'join','on':'target_symbol','left':left,'right':right},'max_results':100}
def run(name,q,source,*,missing=False,partial=False,expected_code=0,exe=None):
 query=a.out/(name+'.query.json');query.write_text(json.dumps(q),encoding='utf-8');cmd=[str(exe or a.exe),'query',str(source),'--source',str(source)];cmd+=[] if missing else ['--source',str(parent)];cmd+=['--query',str(query),'--json'];cmd+=['--scope-incomplete'] if partial else []
 r=subprocess.run(cmd,capture_output=True,timeout=60);(a.out/(name+'.stdout.json')).write_bytes(r.stdout);(a.out/(name+'.stderr.log')).write_bytes(r.stderr);v=json.loads(r.stdout);assert r.returncode==expected_code,(name,r.returncode,r.stderr.decode(errors='replace'),v)
 records.append({'name':name,'exit_code':r.returncode,'query_id':v.get('query_id'),'sha256':sha(a.out/(name+'.stdout.json'))});return v

def rows(v,relation,target,pcs,reverse=False,semi=False,multiplicity=1):
 assert v['profile']=='dex-query-inherited-target-symbol-v18' and v['query_id'].startswith('query:v18:') and v['coverage']=='Complete' and v['unknown_rows']==0
 expected={(src,pc,dst) for src in (0,1) for pc in pcs for dst in (0,1)};actual=[]
 for row in v['candidates']:
  assert len(row['links'])==1 and row['links'][0]['key']=='target_symbol';link=row['links'][0];event=link['right'] if reverse else link['left'];obj=link['left'] if reverse else link['right'];assert event['relation']==relation and obj['relation']==target
  values=row['bindings']+[row]+[b['value'] for b in row.get('proof_bindings',[])]
  event_binding=next(b for b in values if b['relation']==relation);target_binding=next(b for b in values if b['relation']==target)
  assert event_binding['source_index']==event['source_index'] and event_binding['dex_pc']==event['dex_pc'] and target_binding['source_index']==obj['source_index']
  assert event_binding['target_index']==(3 if relation=='invoke_sites' else 0)
  assert target_binding['owner']=='Lfacts/Example;' and target_binding['name']==('uses' if target=='method_defs' else 'counter')
  paths=[w['inherited'] for w in row['evidence'] if w['kind']=='inherited' and w['inherited']['item']==1]
  assert [(w['source_index'],w['local_index']) for w in paths]==[(obj['source_index'],0),(2,0)]
  actual.append((event['source_index'],event['dex_pc'],obj['source_index']))
 assert set(actual)<=expected
 if not semi:assert Counter(actual)==Counter({item:multiplicity for item in expected})
 elif reverse:assert {x[2] for x in actual}=={0,1} and len(actual)==2
 else:assert {(x[0],x[1]) for x in actual}=={(src,pc) for src in (0,1) for pc in pcs} and len(actual)==4
for relation,target,name,fixture,pcs in [('invoke_sites','method_defs','uses',method,(0,3)),('field_uses','field_defs','counter',field,(0,2))]:
 for reverse in (False,True):
  for semi in (False,True):
   label=('method' if relation=='invoke_sites' else 'field')+('-rev' if reverse else '-fwd')+('-semi' if semi else '-join');rows(run(label,graph(relation,target,name,reverse,semi),fixture),relation,target,pcs,reverse,semi)
# Inherited Filter nested under target-symbol Join preserves the same concrete evidence.
for relation,target,name,fixture,pcs in [('invoke_sites','method_defs','uses',method,(0,3)),('field_uses','field_defs','counter',field,(0,2))]:
 for reverse in (False,True):
  q=graph(relation,target,name,reverse);side='left' if reverse else 'right';q['relation'][side]={'op':'filter','input':{'op':'scan','relation':target,'where':{'name':name}},'where':copy.deepcopy(inh)}
  rows(run('filter-'+relation+('-reverse' if reverse else '-forward'),q,fixture),relation,target,pcs,reverse)
# Distinguish bag multiplicity from entity-set and Distinct for duplicated inherited branches.
for mode in ('bag','set','distinct'):
 q=graph('invoke_sites','method_defs','uses');scan_node=q['relation']['right'];union={'op':'union','semantics':'bag' if mode!='set' else 'set','identity':'entity','inputs':[copy.deepcopy(scan_node),copy.deepcopy(scan_node)]};q['relation']['right']={'op':'distinct','identity':'entity','input':union} if mode=='distinct' else union
 rows(run('union-'+mode,q,method),'invoke_sites','method_defs',(0,3),multiplicity=2 if mode=='bag' else 1)
# A nested caller join may attach inheritance evidence before the outer string target join.
fixture=files/'method_facts/method-uses.dex';assert class_symbols(fixture)==('Lfacts/Example;','Ljava/lang/Object;');assert [x for x in uses.raw_fixture(fixture) if x[0]=='string_uses']==[('string_uses',0,0x1a,'string_value',10,None)]
parsed=raw.parse_dex(fixture.read_bytes());assert parsed['strings'][10]=='used-string'
q=graph('invoke_sites','method_defs','uses');methods=q['relation']['right'];inner={'op':'join','on':'caller','left':{'op':'scan','relation':'string_uses'},'right':methods};q['relation']={'op':'join','on':'target_symbol','left':inner,'right':{'op':'scan','relation':'string_values','where':{'value':'used-string'}}};v=run('nested-string-caller-target',q,fixture)
assert v['coverage']=='Complete' and v['unknown_rows']==0 and len(v['candidates'])==4;actual=[]
for row in v['candidates']:
 links={link['key']:link for link in row['links']};assert set(links)=={'caller','target_symbol'}
 event=links['target_symbol']['left'];target=links['target_symbol']['right'];assert event['relation']=='string_uses' and event['dex_pc']==0 and target['relation']=='string_values' and target['local_index']==10
 caller=links['caller']['right'];assert caller['relation']=='method_defs' and caller['source_index']==event['source_index']
 paths=[w['inherited'] for w in row['evidence'] if w['kind']=='inherited' and w['inherited']['item']==1];assert [(x['source_index'],x['local_index']) for x in paths]==[(event['source_index'],0),(2,0)]
 actual.append((event['source_index'],target['source_index']))
assert set(actual)=={(i,j) for i in (0,1) for j in (0,1)}
# Hand-authored canonical frames for one fixed v18 plan; not copied from CLI output.
u32=lambda n:struct.pack('<I',n);u64=lambda n:struct.pack('<Q',n);frame=lambda x:u64(len(x))+x
text_frame=lambda x:u32(1)+u32(0)+u32(0)+u64(len(x))+x.encode('utf-16le')
def node(kind,t=b'\0\0\0\0',arg=0,minimum=0,maximum=0xffffffff,extra=b'',children=()):return u32(kind)+t+u32(arg)+u32(minimum)+u32(maximum)+extra+u32(len(children))+b''.join(frame(c) for c in sorted(children))
yes=node(0);named=node(5,text_frame('uses'));field_extra=u32(0)+text_frame('unseen')+u32(0)+u32(0)+u32(0);inherited=node(29,minimum=0,maximum=0,extra=field_extra);pred=node(2,children=(named,inherited))
def scan(kind,predicate):return b''.join(map(u32,(0,kind,1)))+frame(predicate)+b''.join(map(u32,(0,1,0xffffffff,1,0,0,0,0,0,0)))
relation=b''.join(map(u32,(6,8,0,0,1,0xffffffff,1,0,0,0,6,0,0,2)))+frame(scan(8,yes))+frame(scan(0,pred))
top=b''.join(map(u32,(8,0,100)))+u64(100000000)+b''.join(map(u32,(7,1,0,83909191,0,100000,0,0)))
canonical=b'DexMeguviz:QueryIR:inherited-target-symbol-v18'+top+relation;digest='dec94d1d5a0c5e0db8fb4fbe879b33073c8416c24614d82e342cdae70eb9383f'
assert len(canonical)==474 and hashlib.sha256(canonical).hexdigest()==digest;(a.out/'canonical.bin').write_bytes(canonical)
q=graph('invoke_sites','method_defs','uses');assert run('canonical',q,method)['query_id']=='query:v18:'+digest
q['relation']['right']['where']['all'].reverse();assert run('canonical-reordered',q,method)['query_id']=='query:v18:'+digest
q['max_results']=101;assert run('canonical-limit',q,method)['query_id']!='query:v18:'+digest
for missing,partial in ((True,False),(False,True)):
 q=graph('invoke_sites','method_defs','uses');q['intent']='exists';v=run('unknown-'+str(missing)+str(partial),q,method,missing=missing,partial=partial);assert v['coverage']=='Partial' and v['decision']=='Undetermined' and v['unknown_rows']>0 and not v['candidates']
# Per-branch explicit scope closes only selected sources; parent outside the target subtree is not consulted.
for label,include_parent,partial in [('closed',True,False),('closed-partial',True,True),('outside-parent',False,False)]:
 q=graph('invoke_sites','method_defs','uses');q['intent']='exists';q['relation']['left']['scope']={'slots':[f'input:0:{method}']};q['relation']['right']['scope']={'slots':[f'input:1:{method}']+([f'input:2:{parent}'] if include_parent else [])};v=run('scope-'+label,q,method,partial=partial)
 if include_parent:
  assert v['coverage']=='Complete' and v['decision']=='ProvenTrue' and len(v['candidates'])==1
  paths=[x['inherited'] for x in v['candidates'][0]['evidence'] if x['kind']=='inherited' and x['inherited']['item']==1];assert [(x['source_index'],x['local_index']) for x in paths]==[(1,0),(2,0)]
 else:assert v['coverage']=='Partial' and v['decision']=='Undetermined' and v['unknown_rows']>0 and not v['candidates']
q=graph('invoke_sites','method_defs','uses');q['intent']='unique';v=run('unique-ambiguous',q,method);assert v['decision']=='ProvenFalse' and len(v['candidates'])>=2
q['max_results']=1;v=run('unique-limit',q,method,expected_code=3);assert v['coverage']=='Partial' and v['decision']=='Undetermined' and len(v['candidates'])==1
q=graph('invoke_sites','method_defs','uses');q['max_work']=1;v=run('budget',q,method,expected_code=3);assert v['execution_status']=='BudgetExceeded' and not v.get('candidates')
for cap in ('inherited_fields','use_target_symbol','inherited_target_symbol'):
 q=graph('invoke_sites','method_defs','uses');q['required_capabilities'].remove(cap);v=run('missing-cap-'+cap,q,method,expected_code=2);assert v['execution_status']=='Unsupported'
for cap in ('interface_fields','numeric_literals','use_streaming','reflection_flags_static','composite','interface_resolved','unique_one_stream'):
 q=graph('invoke_sites','method_defs','uses');q['required_capabilities'].append(cap);v=run('incompatible-'+cap,q,method,expected_code=2);assert v['execution_status']=='Unsupported'
q=graph('invoke_sites','method_defs','uses');q['relation']['right']['where']={'name':'uses'};v=run('missing-inherited-predicate',q,method,expected_code=2);assert v['execution_status']=='Unsupported'
q=graph('invoke_sites','method_defs','uses');q['relation']['on']='caller';v=run('missing-symbol-join',q,method,expected_code=2);assert v['execution_status']=='Unsupported'
# Selected legacy plans retain their profiles, identities, and static result values.
q=graph('invoke_sites','method_defs','uses');q['required_capabilities']=['use_target_symbol'];q['relation']['right']['where']={'name':'uses'}
for profile,plan in [('v16',q),('v6',{'schema_version':1,'relation':{'op':'join','on':'caller','left':{'op':'scan','relation':'invoke_sites'},'right':{'op':'scan','relation':'method_defs','where':{'all':[{'name':'uses'},copy.deepcopy(inh)]}}},'max_results':100})]:
 old=run('old-'+profile,plan,method,exe=a.old);new=run('new-'+profile,plan,method);assert old['query_id']==new['query_id'] and old['profile']==new['profile'] and old['candidates']==new['candidates'] and old['coverage']==new['coverage']
# v17 reflection/body relation remains byte-identical in the selected fixed plan.
q={'schema_version':1,'required_capabilities':['reflection_flags_static','reflection_relational','reflection_body_relational'],'relation':{'op':'scan','relation':'method_defs','where':{'all':[{'name':'uses'},{'flags':{'domain':'reflection','mode':'contains','value':8}},{'using_strings':{'all':[{'op':'exact','value':'used-string'}]}}]}},'max_results':100}
fixture=files/'method_facts/method-uses.dex';old=run('old-v17',q,fixture,exe=a.old);new=run('new-v17',q,fixture);assert old['query_id']==new['query_id'] and old['profile']==new['profile'] and old['candidates']==new['candidates'] and old['coverage']==new['coverage']
after={str(x.resolve()):sha(x) for x in inputs};assert before==after
(a.out/'summary.json').write_text(json.dumps({'outcome':'passed','cases':len(records),'records':records,'inputs_before':before,'inputs_after':after,'scope':'fixed duplicate occurrence + parent DEX; static inheritance and call/field uses, not ART or full Q08'},indent=2)+'\n',encoding='utf-8');print('PASS inherited-target static sample cases',len(records))
