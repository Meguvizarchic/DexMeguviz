"""Entity CLI contract vs independent raw-byte metadata and authored truth cases."""
from pathlib import Path
import argparse, copy, hashlib, json, struct, subprocess, sys, time


def raw_entities(source, root):
 sys.path.insert(0,str(root/'tools/evidence_verifier'))
 from verify import parse_dex
 data=source.read_bytes();parsed=parse_dex(data);strings=parsed['strings']
 word=lambda at:struct.unpack_from('<I',data,at)[0]
 def leb(at):
  value=0
  for i in range(5):
   b=data[at+i];value|=(b&127)<<(7*i)
   if b<128:return value,at+i+1
  raise AssertionError('invalid fixture LEB')
 types=[strings[word(word(68)+4*i)] for i in range(word(64))]
 def base(i,ref,offset):
  return {'local_index':i,'reference_index':ref,'record_offset':offset,'has_local_definition':False,'definition_offset':None,'access_flags':None,'code_offset':None}
 classes=[];fields=[];fielddefs=[]
 for i in range(word(80)):
  at=word(84)+8*i;owner,typ,name=struct.unpack_from('<HHI',data,at)
  fields.append({**base(i,i,at),'owner':types[owner],'name':strings[name],'type_descriptor':types[typ]})
 for i in range(word(96)):
  at=word(100)+32*i;typ,flags=struct.unpack_from('<II',data,at)
  classes.append({**base(i,typ,at),'has_local_definition':True,'definition_offset':at,'access_flags':flags,'type_descriptor':types[typ]})
  cursor=word(at+24)
  if not cursor:continue
  counts=[]
  for _ in range(4):n,cursor=leb(cursor);counts.append(n)
  for count in counts[:2]:
   ref=0
   for _ in range(count):
    start=cursor;delta,cursor=leb(cursor);flags,cursor=leb(cursor);ref+=delta
    fields[ref].update(has_local_definition=True,definition_offset=start,access_flags=flags)
    fielddefs.append({**fields[ref],'local_index':len(fielddefs),'record_offset':start})
 methods=[]
 definitions={v['method_index']:v for v in parsed['definitions']}
 for i,ref in enumerate(parsed['references']):
  row={**base(i,i,word(92)+8*i),**{k:ref[k] for k in ('owner','name','prototype')}}
  if i in definitions:
   d=definitions[i];row.update(has_local_definition=True,definition_offset=d['declaration_offset'],access_flags=d['access_flags'])
  methods.append(row)
 types_out=[]
 classes_by_type={c['reference_index']:c for c in classes}
 for i,t in enumerate(types):
  row={**base(i,i,word(68)+4*i),'type_descriptor':t}
  if i in classes_by_type:
   c=classes_by_type[i];row.update(has_local_definition=True,definition_offset=c['definition_offset'],access_flags=c['access_flags'])
  types_out.append(row)
 return {'class_defs':classes,'field_defs':fielddefs,'field_refs':fields,'method_refs':methods,'type_refs':types_out,
         'string_values':[{**base(i,i,word(60)+4*i),'string_value':s} for i,s in enumerate(strings)]}


def verify_rows(value,relation,expected,sources=1):
 assert value['profile']=='dex-query-entity-v2' and value['relation']==relation
 assert value['coverage']=='Complete' and value['execution_status']=='Complete'
 assert value['visited_rows']==value['total_rows']==len(expected)*sources and value['unknown_rows']==0
 assert 'visited_methods' not in value and 'total_methods' not in value
 kinds={'class_defs':1,'field_defs':2,'method_refs':3,'field_refs':4,'string_values':5,'type_refs':6}
 projections={'class_defs':8,'field_defs':11,'method_refs':7,'field_refs':11,'string_values':16,'type_refs':8}
 canonical=b'DexMeguviz:QueryIR:entity-v2'+struct.pack('<IIIQIIIIII',kinds[relation],0,100,100000000,projections[relation],0,0,258,0,0)+struct.pack('<6I',0,0,0,0,0xffffffff,0)
 assert value['query_id']=='query:v2:'+hashlib.sha256(canonical).hexdigest() and value['query_scope']['complete']
 rows=value['candidates'];assert len(rows)==len(expected)*sources
 seen=set()
 for row in rows:
  src=row['source_index'];local=row['local_index'];assert 0<=src<sources and 0<=local<len(expected)
  assert (src,local) not in seen;seen.add((src,local))
  assert row['relation']==relation
  for key,val in expected[local].items():assert row[key]==val,(relation,local,key,row[key],val)
  for key in ('input_index','source_sha256','content_id','occurrence_id','logical_dex_id','snapshot_id'):
   assert row[key]==value['sources'][src][key],key
  assert value['sources'][src]['local_scope']['relation']==relation
 assert len(seen)==len(expected)*sources


def run(exe,root):
 source=root/'tests/fixtures/generated/definition_catalog/definitions.dex'
 expected=raw_entities(source,root);binary=hashlib.sha256(exe.read_bytes()).hexdigest()
 out=root/'docs/evidence/entity-query'/('run-'+str(time.time_ns()));out.mkdir(parents=True)
 records=[]
 def call(name,relation='field_refs',where=None,extra=(),code=0,**options):
  query={'schema_version':1,'relation':relation,'where':{} if where is None else where,'max_results':100,**options}
  path=out/(name+'.query.json');path.write_text(json.dumps(query),encoding='utf-8')
  command=[str(exe),'query',str(source),'--query',str(path),'--json',*extra]
  p=subprocess.run(command,capture_output=True,timeout=20)
  (out/(name+'.stdout.json')).write_bytes(p.stdout);(out/(name+'.stderr.log')).write_bytes(p.stderr)
  records.append({'name':name,'command':command,'exit_code':p.returncode,'stdout_sha256':hashlib.sha256(p.stdout).hexdigest()})
  (out/'commands.json').write_text(json.dumps(records,indent=2),encoding='utf-8')
  assert p.returncode==code,(name,p.stdout,p.stderr)
  return json.loads(p.stdout)
 for relation,rows in expected.items():
  v=call(relation,relation);verify_rows(v,relation,rows)
  v=call(relation+'-two-sources',relation,extra=['--source',str(source)]);verify_rows(v,relation,rows,2)
  assert v['sources'][0]['content_id']==v['sources'][1]['content_id'] and v['sources'][0]['occurrence_id']!=v['sources'][1]['occurrence_id']
  # Controls ensure the oracle rejects a missing candidate and swapped raw identity.
  for mutation in ('missing','offset','query-id'):
   forged=copy.deepcopy(v)
   if mutation=='missing':forged['candidates'].pop()
   elif mutation=='offset':forged['candidates'][0]['record_offset']+=1
   else:forged['query_id']='query:v2:'+'0'*64
   try:verify_rows(forged,relation,rows,2)
   except AssertionError:pass
   else:raise AssertionError('forged evidence accepted')
 unknown=call('not-unknown',where={'not':{'flags_contains':8}},intent='unique')
 # Two real nonstatic definitions are sufficient to disprove uniqueness, even before the unknown row.
 assert unknown['decision']=='ProvenFalse' and unknown['reason']=='Ambiguous'
 unknown=call('external-not',where={'owner':'Lexternal/External;','not':{'flags_contains':8}},intent='unique')
 assert unknown['coverage']=='Partial' and unknown['decision']=='Undetermined' and unknown['reason']=='UnknownAttribute'
 assert unknown['unknown_rows']==1 and not unknown['candidates'] and unknown['query_scope']['complete']
 guarded=call('known-only',where={'has_local_definition':True,'not':{'flags_contains':8}})
 assert guarded['coverage']=='Complete' and guarded['unknown_rows']==0 and len(guarded['candidates'])==2
 absent=call('known-negative',where={'name':'does-not-exist','not':{'flags_contains':8}},intent='exists')
 assert absent['decision']=='ProvenFalse' and absent['coverage']=='Complete' and absent['unknown_rows']==0
 for direction,indices in [('asc',[3,0,2,1]),('desc',[1,0,2,3])]:
  v=call('nullable-sort-'+direction,order_by=[{'field':'flags','direction':direction}],intent='top_n')
  assert [x['reference_index'] for x in v['candidates']]==indices
  assert v['decision']=='ProvenTrue' and v['query_profile']['order_verified']
 v=call('project-identity','class_defs',projection=['identity'])
 assert all('type_descriptor' not in r and r['definition_offset'] is not None for r in v['candidates'])
 v=call('explicit-scope','class_defs',extra=['--source',str(source),'--scope-incomplete'],scope={'slots':['input:1:'+str(source)]})
 assert v['coverage']=='Complete' and {r['source_index'] for r in v['candidates']}=={1} and v['scope_complete'] is False
 for relation,where in [('method_refs',{'using_strings':{'all':[]}}),('field_defs',{'parameters':[]}),('class_defs',{'name':'X'}),('string_values',{'has_local_definition':False})]:
  assert call('reject-'+relation,relation,where,code=2)['execution_status']=='Unsupported'
 assert hashlib.sha256(exe.read_bytes()).hexdigest()==binary
 summary={'passed':len(records),'failed':0,'forged_evidence_rejected':18,'executable_sha256':binary,'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'raw_entity_identity_verified':True,'canonical_unfiltered_query_ids_verified':True,'scope':'Six non-method roots over original fixture; method roots covered separately; not complete relational IR or runtime evidence','evidence':str(out)}
 (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8');return summary


if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--root',type=Path,required=True);a=p.parse_args()
 print(json.dumps(run(a.exe.resolve(),a.root.resolve()),indent=2))
