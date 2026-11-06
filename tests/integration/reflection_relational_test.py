"""Fixed v14 static reflection graph controls; no ART/runtime equivalence."""
import argparse, copy, hashlib, json, struct, subprocess, sys, tempfile
from pathlib import Path

p=argparse.ArgumentParser()
for name in ('exe','fixture'):p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args()
assert hashlib.sha256(a.fixture.read_bytes()).hexdigest()=='e1059582b6c893690880403d00f6b5be8dfceb7be282793e2117bdf15b14e77a'
project=a.fixture.resolve().parents[4]
sys.path.insert(0,str(project/'tests/integration'))
from relational_test import Oracle
u32=lambda *v:struct.pack('<'+'I'*len(v),*v)
predicate=u32(11,0,2,1,0xffffffff,0)
top=struct.pack('<IIIQIIIIIIII',4,0,4096,100000000,11,1,0,6292226,0,100000,0,0)
scan=u32(0,4,1)+struct.pack('<Q',len(predicate))+predicate+u32(0,1,0xffffffff,1,0,0,0,0,0,0)
canonical=b'DexMeguviz:QueryIR:reflection-relational-v14'+top+scan
assert len(canonical)==180
golden='query:v14:'+hashlib.sha256(canonical).hexdigest()
assert golden=='query:v14:f522ae279f590b3030bf24859db7c29278106408a709323bdd699b4ac221a69f'
flag=lambda mode,value:{'flags':{'domain':'reflection','mode':mode,'value':value}}
scan_node=lambda relation,where=None:dict({'op':'scan','relation':relation},**({'where':where} if where is not None else {}))
caps=['reflection_flags_static','reflection_relational']
count=0
with tempfile.TemporaryDirectory(prefix='dmg-reflection-graph-') as directory:
 root=Path(directory)
 def run(name,relation,where=None,intent='enumerate',capabilities=caps,extra=None,sources=(),incomplete=False):
  global count
  doc={'schema_version':1,'relation':relation,'intent':intent,'required_capabilities':capabilities}
  if where is not None:doc['where']=where
  if extra:doc.update(extra)
  path=root/(name+'.json');path.write_text(json.dumps(doc),encoding='utf-8')
  cmd=[str(a.exe.resolve()),'query',str(a.fixture.resolve())]
  for source in sources:cmd+=['--source',str(source.resolve())]
  if incomplete:cmd+=['--scope-incomplete']
  p=subprocess.run(cmd+['--query',str(path),'--json'],capture_output=True,text=True,encoding='utf-8',timeout=60)
  try:result=json.loads(p.stdout)
  except Exception:raise AssertionError((name,p.returncode,p.stdout,p.stderr))
  count+=1;return p.returncode,result
 def ok(name,relation,where=None,**kwargs):
  code,result=run(name,relation,where,**kwargs)
  assert code==0 and result['execution_status']=='Complete',(name,code,result)
  assert result['profile']=='dex-query-reflection-relational-v14' and result['query_id'].startswith('query:v14:'),(name,result['profile'])
  return result
 def rows(result):return [(x['source_index'],x['local_index'],x.get('name')) for x in result['candidates']]
 r=ok('scan',scan_node('field_refs',flag('contains',1)))
 assert r['query_id']==golden and rows(r)==[(0,0,'instanceField'),(0,1,'shared'),(0,2,'shared')]
 assert (r['coverage'],r['reason'],r['unknown_rows'])==('Partial','UnknownAttribute',1)
 filtered=ok('filter',{'op':'filter','input':scan_node('field_refs'),'where':flag('contains',1)})
 assert rows(filtered)==rows(r) and filtered['unknown_rows']==1
 absent=ok('not-unknown',{'op':'filter','input':scan_node('field_refs',{'name':'externalField'}),'where':{'not':flag('contains',0)}},intent='unique')
 assert not rows(absent) and absent['unknown_rows']==1 and absent['decision']=='Undetermined'
 pure_false=ok('false-and-unknown',scan_node('field_refs',{'all':[{'name':'missing'},flag('contains',1)]}),intent='unique')
 assert pure_false['coverage']=='Complete' and pure_false['decision']=='ProvenFalse' and pure_false['unknown_rows']==0
 left=scan_node('field_defs',flag('exact',9));right=scan_node('field_refs')
 joined=ok('local-definition',{'op':'join','on':'local_definition','left':left,'right':right})
 assert rows(joined)==[(0,0,'shared')] and len(joined['candidates'][0]['links'])==1
 semi=ok('semi-definition',{'op':'semi_join','on':'local_definition','left':left,'right':right})
 assert rows(semi)==[(0,0,'shared')] and len(semi['candidates'][0]['proof_bindings'])>=1
 unknown_right=scan_node('field_refs',{'owner_flags':{'domain':'reflection','mode':'contains','value':1}})
 unknown_semi=ok('semi-unknown-right',{'op':'semi_join','on':'local_definition','left':scan_node('field_defs',{'name':'instanceField'}),'right':unknown_right},intent='unique')
 assert not rows(unknown_semi) and unknown_semi['unknown_rows']==1 and unknown_semi['decision']=='Undetermined'
 repeated=ok('symbol-cross',{'op':'join','on':'symbol','left':left,'right':right},sources=(a.fixture,))
 assert len(rows(repeated))==4 and {x['source_index'] for x in repeated['candidates']}=={0,1}
 union={'op':'union','semantics':'bag','inputs':[left,left]}
 bag=ok('bag',union);assert len(rows(bag))==2 and rows(bag)[0]==rows(bag)[1]
 distinct=ok('distinct',{'op':'distinct','identity':'entity','input':union});assert len(rows(distinct))==1
 # A reliable duplicate dominates an Unknown copy of the same entity.
 uncertain=scan_node('field_refs',{'all':[{'name':'externalField'},flag('contains',1)]})
 certain=scan_node('field_refs',{'name':'externalField'})
 resolve=ok('set-resolves-unknown',{'op':'union','semantics':'set','identity':'entity','inputs':[uncertain,certain]})
 assert rows(resolve)==[(0,3,'externalField')] and resolve['unknown_rows']==0 and resolve['coverage']=='Complete'
 grouped=ok('group',{'op':'group_by_owner','inputs':[{'op':'label','label':'field','input':left}],'required_roles':['field']})
 assert len(grouped['candidates'])==1 and grouped['candidates'][0]['relation']=='class_defs'
 # Independent raw DEX oracle checks entity/source identities and relation
 # endpoints; it does not infer a ClassLoader or validate every graph shape.
 one=Oracle(project,[a.fixture.resolve()]);two=Oracle(project,[a.fixture.resolve(),a.fixture.resolve()])
 def key(item):return item['relation'],item['source_index'],item['local_index']
 def verify_graph(value,oracle):
  for row in value['candidates']:
   oracle.check_entity(row,key(row))
   for binding in row.get('bindings',[]):oracle.check_entity(binding,key(binding),True)
   for proof in row.get('proof_bindings',[]):oracle.check_entity(proof['entity'],key(proof['entity']),True)
   for link in row.get('links',[]):
    akey,bkey=key(link['left']),key(link['right']);assert akey in oracle.entities and bkey in oracle.entities
    leftrow,rightrow=oracle.entities[akey],oracle.entities[bkey]
    if link['key']=='local_definition':assert akey[1]==bkey[1] and leftrow['reference_index']==rightrow['reference_index']
    elif link['key']=='symbol':assert all(leftrow.get(k)==rightrow.get(k) for k in ('owner','name','prototype','type_descriptor','string_value'))
    else:raise AssertionError('unexpected link key')
 for value,oracle in ((r,one),(joined,one),(semi,one),(repeated,two),(grouped,one)):verify_graph(value,oracle)
 forged=copy.deepcopy(joined);forged['candidates'][0]['reference_index']+=1
 try:verify_graph(forged,one)
 except (AssertionError,KeyError):pass
 else:raise AssertionError('forged entity accepted')
 forged=copy.deepcopy(joined);forged['candidates'][0]['links'][0]['right']['local_index']=3
 try:verify_graph(forged,one)
 except (AssertionError,KeyError):pass
 else:raise AssertionError('forged join endpoint accepted')
 ordered=ok('ordered',scan_node('field_refs',flag('contains',1)),extra={'order_by':[{'field':'name','direction':'desc'}]})
 assert [x[2] for x in rows(ordered)]==['shared','shared','instanceField']
 raw_order=ok('raw-flag-order',scan_node('field_refs',flag('contains',1)),extra={'order_by':[{'field':'flags','direction':'desc'}]})
 assert [x['access_flags'] for x in raw_order['candidates']]==[9,1,1]
 top=ok('top-n',scan_node('field_refs',flag('contains',1)),intent='top_n',extra={'order_by':[{'field':'name','direction':'desc'}],'max_results':2})
 assert len(rows(top))==2 and [x[2] for x in rows(top)]==['shared','shared'] and top['coverage']=='Partial'
 limited=ok('exists-partial',scan_node('field_refs',flag('contains',1)),intent='exists',incomplete=True)
 assert limited['decision']=='ProvenTrue' and limited['coverage']=='Partial'
 unknown=ok('incomplete-unique',scan_node('field_defs',flag('exact',9)),intent='unique',incomplete=True)
 assert unknown['decision']=='Undetermined' and unknown['coverage']=='Partial'
 incomplete_group=ok('incomplete-group',{'op':'group_by_owner','inputs':[left]},intent='unique',incomplete=True)
 assert incomplete_group['coverage']=='Partial' and incomplete_group['decision']=='Undetermined'
 restricted=ok('explicit-scope',scan_node('field_defs',flag('exact',9)),intent='unique',incomplete=True,
               extra={'scope':{'slots':[r['inputs'][0]['slot_key']]}})
 assert restricted['query_scope']['complete'] and restricted['decision']=='ProvenTrue'
 for name,relation,capabilities,where in [
  ('old-reflection-graph',scan_node('field_refs',flag('contains',1)),['reflection_flags_static'],None),
  ('missing-reflection-cap',scan_node('field_refs',flag('contains',1)),['reflection_relational'],None),
  ('missing-reflection-predicate',scan_node('field_refs'),caps,None),
  ('not-graph','field_refs',caps,flag('contains',1)),
  ('mixed-numeric',scan_node('field_refs',flag('contains',1)),caps+['numeric_literals'],None)]:
  code,value=run(name,relation,where=where,capabilities=capabilities);assert code==2 and value['execution_status']=='Unsupported',(name,code,value)
 code,budget=run('budget',scan_node('field_refs',flag('contains',1)),extra={'max_work':1})
 assert code==3 and budget['execution_status']=='BudgetExceeded' and budget['coverage']=='Partial',(code,budget)
 code,budget=run('intermediate-budget',scan_node('field_refs',flag('contains',1)),extra={'max_intermediate_rows':1})
 assert code==3 and budget['execution_status']=='BudgetExceeded' and budget['coverage']=='Partial',(code,budget)
print('PASS',count,'static reflection relational controls; fixed DEX only')
