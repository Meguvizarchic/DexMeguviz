"""Independent byte-oracle check of scoped v11 candidate results; retains outputs."""
from pathlib import Path
from collections import Counter
import argparse,copy,hashlib,importlib.util,json,subprocess,sys
if not __debug__:raise SystemExit('assertions required')
p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();base=Path(__file__).resolve().parent;fix=base/'fixtures';out=a.out.resolve();assert not out.exists();out.mkdir(parents=True);h=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();manifest=json.loads((fix/'manifest.json').read_text());spec=importlib.util.spec_from_file_location('raw_world_oracle',base/'raw_worlds.py');oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle);records=[];mutations=Counter();inputs=[Path(__file__),base/'raw_worlds.py',fix/'manifest.json',a.exe];
for n in ('child.dex','base.dex','root.dex','top.dex','left.dex','left-alt.dex','right.dex'):
 f=fix/n;assert h(f)==manifest['records'][n]['sha256'];inputs.append(f)
before={str(p):h(p) for p in inputs};exe=a.exe.resolve();relations={'class_defs':1,'field_defs':2,'type_refs':6}
def frame(t):
 b=t.encode('utf8');return str(len(b)).encode()+b':'+b
def identities(paths,complete):
 sources=[]
 for i,path in enumerate(paths):
  size=path.stat().st_size;sha=h(path);content=f'sha256:raw-dex:v1:{size}:{sha}';logical='logical-dex:v1:'+frame(content).decode()+'header-offset:0';slot=f'input:{i}:{path}';role='base' if i==0 else 'code-split';material=b'dmg:occurrence:v2:'+b''.join(frame(x) for x in ('cli-v1','raw-input',slot,role,'',content));sources.append({'source_index':i,'input_index':i,'slot_key':slot,'role':role,'source_sha256':sha,'content_id':content,'occurrence_id':'occurrence:v2:'+hashlib.sha256(material).hexdigest(),'logical_dex_id':logical})
 material=b'dmg:snapshot:source-set-v1:'+frame('cli-v1')+frame('complete' if complete else 'incomplete')+frame(str(len(paths)))
 for s in sources:material+=b''.join(frame(x) for x in (s['slot_key'],s['role'],'1','0',s['content_id']))
 material+=frame(str(len(sources)))+b''.join(frame(s['occurrence_id']) for s in sources);snap='snapshot:v2:'+hashlib.sha256(material).hexdigest()
 for s in sources:s['snapshot_id']=snap
 return sources,snap
cases=[
 ('consistent-all',['child.dex','base.dex','root.dex','top.dex','left.dex','left-alt.dex','right.dex'],'diamond',1,1,'all',True,'yes'),
 ('disagree-all',['child.dex','base.dex','root.dex','top.dex','left.dex','left-alt.dex','right.dex'],'same',2,2,'all',True,'unknown'),
 ('closed-excluding-alt',['child.dex','base.dex','root.dex','top.dex','left.dex','left-alt.dex','right.dex'],'same',2,2,'exclude-alt',True,'yes'),
 ('closed-subset-partial',['child.dex','base.dex','root.dex','top.dex','left.dex','left-alt.dex','right.dex'],'same',2,2,'exclude-alt',False,'yes'),
 ('partial-implicit',['child.dex','base.dex','root.dex','top.dex','left.dex','left-alt.dex','right.dex'],'diamond',1,1,'all',False,'unknown'),
 ('missing-top',['child.dex','base.dex','root.dex','left.dex','right.dex'],'diamond',1,1,'all',True,'unknown'),
 ('repeat-top',['child.dex','base.dex','root.dex','top.dex','top.dex','left.dex','right.dex'],'diamond',1,1,'all',True,'yes'),
 ('filter-union-scope',['child.dex','base.dex','root.dex','top.dex','left.dex','left-alt.dex','right.dex'],'same',2,2,'filter-exclude-alt',True,'yes'),
]
def verify_row(body,expected_sources,selected,parsed,expected,truth):
 assert body['profile']=='dex-query-interface-resolved-v11' and body['query_id'].startswith('query:v11:') and body['execution_status']=='Complete'
 assert body['decision']=='ProvenTrue' and body['coverage']=='Complete' and body['unknown_rows']==0 and len(body['candidates'])==1
 row=body['candidates'][0];assert row['source_index']==0 and row['type_descriptor']=='Lifx/Child;'
 for k in ('source_index','input_index','source_sha256','content_id','occurrence_id','logical_dex_id','snapshot_id'):assert row[k]==expected_sources[0][k],k
 events=[];rev={g:i for i,g in enumerate(selected)}
 for w in row['evidence']:
  if w['kind']!='interface_resolved':continue
  assert w['matched'] is True;v=w['interface'];assert v['source_index'] in rev and v['relation'] in relations
  conv=lambda x:0xffffffff if x is None else x
  events.append((v['item'],conv(v['branch']),conv(v['node']),conv(v['aux']),v['detail'],rev[v['source_index']],relations[v['relation']],v['local_index']))
 assert events;oracle.verify(events,parsed,expected,truth)
 # Raw input identities do not come from the engine's own proof.
 for i,w in enumerate(expected_sources):
  for k,v in w.items():assert body['sources'][i][k]==v,(i,k)
 return events
for name,names,field,lo,hi,selection,complete,want in cases:
 paths=[(fix/n).resolve() for n in names];expected_sources,snapshot=identities(paths,complete);selected=[i for i in range(len(paths)) if not (selection in ('exclude-alt','filter-exclude-alt') and names[i]=='left-alt.dex')];slots=[x['slot_key'] for x in expected_sources];predicate={'all':[{'descriptor':'Lifx/Child;'}, {'declares_fields':{'scope':'inherited_interfaces_resolved','where':{'name':field},'min':lo,'max':hi}}]}
 if selection=='filter-exclude-alt':
  left={'op':'scan','relation':'class_defs','scope':{'slots':[slots[0]]},'where':{'descriptor':'Lifx/Child;'}};other={'op':'scan','relation':'class_defs','scope':{'slots':[slots[i] for i in selected if i]},'where':False};rel={'op':'filter','input':{'op':'union','semantics':'bag','inputs':[left,other]},'where':predicate}
 elif selection=='exclude-alt':rel={'op':'scan','relation':'class_defs','scope':{'slots':[slots[i] for i in selected]},'where':predicate}
 else:rel={'op':'scan','relation':'class_defs','where':predicate}
 q={'schema_version':1,'relation':rel,'intent':'unique','max_results':100};qp=out/(name+'.query.json');qp.write_text(json.dumps(q,indent=2));cmd=[str(exe),'query',str(paths[0])]
 for path in paths[1:]:cmd.extend(['--source',str(path)])
 if not complete:cmd.append('--scope-incomplete')
 cmd.extend(['--query',str(qp),'--json']);run=subprocess.run(cmd,capture_output=True,timeout=120);(out/(name+'.stdout.json')).write_bytes(run.stdout);(out/(name+'.stderr.log')).write_bytes(run.stderr);assert run.returncode==0,(name,run.returncode,run.stderr.decode('utf8','replace'),run.stdout.decode('utf8','replace'));body=json.loads(run.stdout);assert body['snapshot_id']==snapshot
 for i,w in enumerate(expected_sources):
  for k,v in w.items():assert body['sources'][i][k]==v,(name,i,k)
 assert len({x['occurrence_id'] for x in expected_sources})==len(paths)
 assert body['scope_complete'] is complete
 assert body['query_scope']=={'explicit':False,'complete':True if selection in ('exclude-alt','filter-exclude-alt') else complete,'sources':selected},(name,body['query_scope'])
 if want=='unknown':
  assert body['decision']=='Undetermined' and body['coverage']=='Partial' and body['unknown_rows']==1 and not body['candidates'],(name,body)
  parsed=[oracle.parse(paths[i]) for i in selected]
  if name=='disagree-all':assert {w[4] for w in oracle.expected_worlds(parsed,False,field,lo,hi)}=={0,1}
  elif name=='partial-implicit':assert {w[4] for w in oracle.expected_worlds(parsed,False,field,lo,hi)}=={1}
  elif name=='missing-top':
   available={s['owner'] for s in parsed};missing={(s['owner'],s['types'][i]) for s in parsed for i in s['ifaces'] if s['types'][i] not in available};assert missing and {target for _,target in missing}=={'Lifx/Top;'},missing
 else:
  parsed=[oracle.parse(paths[i]) for i in selected];worlds=oracle.expected_worlds(parsed,False,field,lo,hi);assert {x[4] for x in worlds}=={1};events=verify_row(body,expected_sources,selected,parsed,worlds,1)
  # Feed altered real JSON through the same verifier as the original output.
  forged_json=copy.deepcopy(body);forged_json['candidates'][0]['occurrence_id']='occurrence:v2:'+'0'*64
  try:verify_row(forged_json,expected_sources,selected,parsed,worlds,1)
  except (AssertionError,IndexError,KeyError,ValueError):mutations['row-origin']+=1
  else:raise AssertionError((name,'forged row origin accepted'))
  # Falsified source and node/edge/field evidence must fail the same comparison.
  for kind,column in ((1,5),(2,3),(4,7),(5,3),(6,5)):
   idx=next((i for i,e in enumerate(events) if e[0]==kind),None)
   if idx is None:continue
   forged=list(events);value=list(forged[idx]);value[column]=0xffffffff if value[column]!=0xffffffff else 0;forged[idx]=tuple(value)
   try:oracle.verify(forged,parsed,worlds,1)
   except (AssertionError,IndexError,KeyError,ValueError):mutations[str(kind)]+=1
   else:raise AssertionError((name,'forged event accepted',kind,column))
 records.append({'name':name,'argv':cmd,'source_indexes':selected,'expected':want,'exit_code':run.returncode,'stdout_sha256':h(out/(name+'.stdout.json'))})
assert all(mutations[str(k)]>0 for k in (1,2,4,5,6)) and mutations['row-origin']>0,mutations
assert all(h(p)==v for p,v in before.items());outputs={str(p):h(p) for p in out.rglob('*') if p.is_file()};(out/'summary.json').write_text(json.dumps({'outcome':'passed','scope':'single-class ASCII authored DEX static v11 scoped worlds; no ART/loader or exhaustive coverage','inputs_before':before,'inputs_after':before,'outputs_sha256':outputs,'mutations_rejected':dict(mutations),'cases':records},indent=2)+'\n');print('PASS v11 scoped independent byte worlds')
