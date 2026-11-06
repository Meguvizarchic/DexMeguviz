"""Independent raw-Dex oracle for relational inherited scopes and evidence."""
import argparse,copy,hashlib,json,subprocess,tempfile
from pathlib import Path
from verify_inherited_fixture import EXPECTED,inspect

p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--fixtures',type=Path,required=True);a=p.parse_args()
names=('child.dex','base-a.dex','root.dex');paths=[a.fixtures/n for n in names]
manifest=json.loads((a.fixtures/'manifest.json').read_text(encoding='utf-8'))
for name,path in zip(names,paths):
 data=path.read_bytes();assert hashlib.sha256(data).hexdigest()==manifest[name]['sha256'];assert inspect(data)==EXPECTED[name]
assert EXPECTED['base-a.dex'][2]['parentOnly']==1
pred={'all':[{'descriptor':'Lfixture/Child;'}, {'declares_fields':{'scope':'inherited','where':{'name':'parentOnly'},'min':1,'max':1}}]}
slots=[f'input:{i}:{path}' for i,path in enumerate(paths)]

def check_proof(result):
 assert result['profile']=='dex-query-inherited-v6' and result['query_id'].startswith('query:v6:')
 assert result['coverage']=='Complete' and result['decision']=='ProvenTrue' and len(result['candidates'])==1
 candidate=result['candidates'][0];assert candidate['source_index']==0
 events=[w['inherited'] for w in candidate['evidence'] if w['kind']=='inherited']
 links=[e for e in events if e['item']==1];fields=[e for e in events if e['item']==4]
 assert [(x['source_index'],x['local_index']) for x in links]==[(0,0),(1,0),(2,0)]
 assert len(fields)==1 and (fields[0]['source_index'],fields[0]['relation'],fields[0]['local_index'],fields[0]['path'])==(1,'field_defs',1,1)
 assert result['sources'][1]['source_sha256']==hashlib.sha256(paths[1].read_bytes()).hexdigest()

with tempfile.TemporaryDirectory(prefix='dmg-inherited-graph-') as tmp:
 def run(label,relation,extra=()):
  q={'schema_version':1,'relation':relation,'intent':'unique'};query=Path(tmp)/(label+'.json');query.write_text(json.dumps(q),encoding='utf-8')
  cmd=[str(a.exe),'query',str(paths[0]),'--source',str(paths[1]),'--source',str(paths[2]),'--query',str(query),'--json',*extra]
  r=subprocess.run(cmd,capture_output=True,text=True,encoding='utf-8',timeout=30)
  assert r.returncode==0,(label,r.returncode,r.stderr,r.stdout);return json.loads(r.stdout)
 scan={'op':'scan','relation':'class_defs','where':pred}
 filt={'op':'filter','input':{'op':'scan','relation':'class_defs'},'where':pred}
 for shape in (scan,filt):
  result=run(shape['op'],shape);check_proof(result)
  for index,key in [(1,'source_index'),(1,'local_index')]:
   forged=copy.deepcopy(result);field=next(w['inherited'] for w in forged['candidates'][0]['evidence'] if w['kind']=='inherited' and w['inherited']['item']==4)
   field[key]+=index
   try:check_proof(forged)
   except AssertionError:pass
   else:raise AssertionError('forged inheritance proof accepted')
 only_child={'op':'scan','relation':'class_defs','scope':{'slots':[slots[0]]},'where':pred}
 others={'op':'scan','relation':'class_defs','scope':{'slots':slots[1:]},'where':False}
 union={'op':'union','semantics':'bag','inputs':[only_child,others]}
 limited=run('separate-scopes',union)
 assert limited['coverage']=='Partial' and limited['decision']=='Undetermined' and limited['unknown_rows']==1 and not limited['candidates']
 child_scan={'op':'scan','relation':'class_defs','scope':{'slots':[slots[0]]},'where':{'descriptor':'Lfixture/Child;'}}
 union['inputs'][0]=child_scan
 result=run('filter-over-union',{'op':'filter','input':union,'where':pred});check_proof(result)
print('PASS inherited graph: raw DEX, scoped branches, subtree union, and forged proof controls')
