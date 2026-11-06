"""Independent DEX-byte oracle for caller class relationships; no ART claim."""
from pathlib import Path
import argparse,copy,hashlib,json,struct,subprocess,zlib
if not __debug__:raise SystemExit('assertions required')
p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--old',type=Path,required=True);p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
def leb(d,p):
 x=0;s=0
 while True:
  b=d[p];p+=1;x|=(b&127)<<s
  if b<128:return x,p
  s+=7;assert s<=28

def read(path):
 d=path.read_bytes();u=lambda x:struct.unpack_from('<I',d,x)[0];h=lambda x:struct.unpack_from('<H',d,x)[0]
 assert d[:8]==b'dex\n035\0' and u(32)==len(d) and d[12:32]==hashlib.sha1(d[32:]).digest() and u(8)==zlib.adler32(d[12:])&0xffffffff
 strings=[]
 for i in range(u(56)):
  n,pos=leb(d,u(u(60)+4*i));end=d.index(0,pos);value=d[pos:end].decode('ascii');assert len(value)==n;strings.append(value)
 types=[strings[u(u(68)+i*4)] for i in range(u(64))]
 refs=[]
 for i in range(u(80)):
  owner,typ,name=struct.unpack_from('<HHI',d,u(84)+8*i);refs.append((types[owner],strings[name],types[typ]))
 assert u(96)==1
 owner,flags,parent,interfaces,_,_,data,_=struct.unpack_from('<8I',d,u(100));iface=[types[h(interfaces+4+i*2)] for i in range(u(interfaces))] if interfaces else []
 defs=[];events=[]
 if data:
  counts=[];pos=data
  for _ in range(4):n,pos=leb(d,pos);counts.append(n)
  for n in counts[:2]:
   idx=0
   for _ in range(n):
    delta,pos=leb(d,pos);idx+=delta;f,pos=leb(d,pos);defs.append((refs[idx],f))
  for n in counts[2:]:
   idx=0
   for _ in range(n):
    delta,pos=leb(d,pos);idx+=delta;_,pos=leb(d,pos);code,pos=leb(d,pos)
    if code:
     size=u(code+12);words=[h(code+16+i*2) for i in range(size)];pc=0
     while pc<size:
      opcode=words[pc]&255
      if 0x52<=opcode<=0x6d:
       events.append((pc,opcode,refs[words[pc+1]]));pc+=2
      elif opcode==0x0e:pc+=1
      else:raise AssertionError(('unknown instruction in oracle',opcode))
 return {'owner':types[owner],'flags':flags,'parent':None if parent==0xffffffff else types[parent], 'interfaces':iface,'defs':defs,'events':events}

def resolve(world,ref):
 owner,name,typ=ref;trail=[]
 def visit(descriptor,edge,index):
  found=[(i,c) for i,c in enumerate(world) if c['owner']==descriptor]
  if len(found)!=1:return None
  i,c=found[0]
  if any(t[0]==i for t in trail):return None
  if edge==1 and not c['flags']&0x200:return None
  if edge==2 and c['flags']&0x200:return None
  trail.append((i,0,edge,index))
  if c['flags']&0x200 and any((f&0x19)!=0x19 or (f&7)!=1 for _,f in c['defs']):return None
  matches=[(j,f) for j,(r,f) in enumerate(c['defs']) if r[1:]==(name,typ)]
  if len(matches)>1:return None
  if matches:return (tuple(trail),i,matches[0][0],matches[0][1])
  for n,child in enumerate(c['interfaces']):
   r=visit(child,1,n)
   if r is None:return None
   if r is not False:return r
  if c['flags']&0x200 and c['parent'] is not None:return None
  if c['parent'] is not None:
   r=visit(c['parent'],2,0xffffffff)
   if r is None:return None
   if r is not False:return r
  trail.pop();return False
 r=visit(owner,0,0xffffffff)
 return None if r is False else r

def direct(world,source):
 c=world[source];out=[]
 for i,d in enumerate(c['interfaces']):out.append((1,i,d))
 if c['flags']&0x200:
  if c['parent']!='Ljava/lang/Object;':return None
 elif c['parent'] is not None:out.append((2,None,c['parent']))
 elif c['owner']!='Ljava/lang/Object;':return None
 return out
def verify(row,world,wanted_status,wanted_reason):
 link=row['links'][0];caller=link['left']['source_index'];event=link['right'];assert caller==event['source_index'] and link['left']['local_index']==event['local_index'];used=next(x for x in world[caller]['events'] if x[0]==event['dex_pc']);target=resolve(world,used[2]);assert target not in (None,False);_,fieldsource,fieldordinal,_=target
 fproof=[x['field_declaration'] for x in row['evidence'] if x['kind']=='field_declaration'];assert fproof[-1]['item']==1 and fproof[-1]['source_index']==fieldsource and fproof[-1]['local_index']==fieldordinal
 parts=[x['caller_field_relation'] for x in row['evidence'] if x['kind']=='caller_field_relation'];assert parts and parts[0]['item']==0;head=parts[0]
 assert head['status']==wanted_status and head['reason']==wanted_reason and head['source_index']==caller and head['class_ordinal']==0 and head['target_source']==fieldsource and head['target_class']==0 and head['target_field']==fieldordinal and head['event_source']==caller and head['event_caller']==0 and head['event_pc']==event['dex_pc']
 nodes=[x for x in parts[1:] if x['item']==1];edges=[x for x in parts[1:] if x['item']==2];checks=[x for x in parts[1:] if x['item']==3];assert len(nodes)+len(edges)+len(checks)==len(parts)-1
 if wanted_status==4:assert not nodes and not edges and not checks;return
 assert nodes and nodes[0]['source_index']==caller and nodes[0]['class_ordinal']==0 and nodes[0]['path_index']==0 and nodes[0]['parent_index'] is None
 for i,n in enumerate(nodes):assert n['path_index']==i and n['class_ordinal']==0 and n['source_index']<len(world)
 if wanted_status==1:assert len(nodes)==1 and not edges and not checks and caller==fieldsource;return
 if wanted_status==2:
  assert len(nodes)>=2 and not edges and not checks and nodes[-1]['source_index']==fieldsource
  for i,n in enumerate(nodes[1:],1):
   assert n['parent_index']==i-1;parent=world[nodes[i-1]['source_index']];possible=direct(world,nodes[i-1]['source_index']);assert possible is not None
   assert any(k==n['edge_kind'] and ix==n['interface_index'] and desc==world[n['source_index']]['owner'] for k,ix,desc in possible)
  return
 assert wanted_status==3 and all(n['source_index']!=fieldsource for n in nodes)
 # External is checked against an independently decoded full adjacency set.
 expected=set();actual=set();names={x['owner']:i for i,x in enumerate(world)};assert len(names)==len(world)
 for i,n in enumerate(nodes):
  outgoing=direct(world,n['source_index']);assert outgoing is not None
  for kind,idx,desc in outgoing:
   assert desc in names;expected.add((n['source_index'],names[desc],kind,idx))
 for e in edges:
  i=e['path_index'];j=e['parent_index'];assert i<len(nodes) and j<len(nodes)
  actual.add((nodes[i]['source_index'],nodes[j]['source_index'],e['edge_kind'],e['interface_index']))
 assert expected==actual
 # Interface/Object requirements are separate from ancestry edges and must be complete.
 iface_nodes={i for i,n in enumerate(nodes) if world[n['source_index']]['flags']&0x200};seen=set()
 for c in checks:
  i=c['path_index'];assert i in iface_nodes and i not in seen;seen.add(i)
  obj=world[c['source_index']];assert obj['owner']=='Ljava/lang/Object;' and obj['flags']&1 and not(obj['flags']&~0x1021) and obj['parent'] is None and not obj['interfaces']
 assert seen==iface_nodes

def plan(paths,observe=True,op='join',intent='enumerate',maxresults=4096):
 caps=['field_declaration_static']+(['caller_field_relation_observation'] if observe else []);slots=['input:'+str(i)+':'+str(x) for i,x in enumerate(paths)]
 return {'schema_version':1,'required_capabilities':caps,'scope':{'slots':slots},'relation':{'op':op,'on':'caller','left':{'op':'scan','relation':'method_defs'},'right':{'op':'scan','relation':'field_uses','where':{'target_field_declaration':{'scope':'any'}}}},'intent':intent,'max_results':maxresults}
def run(label,paths,q,exe=None):
 f=a.out/(label+'.json');f.write_text(json.dumps(q),encoding='utf-8');cmd=[str(exe or a.exe),'query',str(paths[0])]
 for x in paths[1:]:cmd+=['--source',str(x)]
 cmd+=['--query',str(f),'--json'];r=subprocess.run(cmd,capture_output=True,text=True);(a.out/(label+'.out')).write_text(r.stdout,encoding='utf-8');(a.out/(label+'.err')).write_text(r.stderr,encoding='utf-8');return r,json.loads(r.stdout) if r.stdout.strip().startswith('{') else None
cases=[
 ('self',['child-self.dex','parent-target.dex','object.dex'],1,0),
 ('ancestor',['child-ancestor.dex','parent-target.dex','object.dex'],2,0),
 ('hidden',['child-hide.dex','parent-target.dex','object.dex'],2,0),
 ('different-type',['child-different-type.dex','parent-target.dex','object.dex'],2,0),
 ('external',['caller-external.dex','child-target.dex','parent-target.dex','object.dex'],3,0),
 ('missing',['caller-missing.dex','child-target.dex','parent-target.dex'],4,1),
 ('duplicate',['caller-external.dex','child-target.dex','parent-target.dex','object.dex','object.dex'],4,2),
 ('cycle',['caller-cycle-a.dex','caller-cycle-b.dex','child-target.dex','parent-target.dex'],4,3),
 ('positive-other-unknown',['child-unknown-branch.dex','parent-target.dex','object.dex'],2,0),
 ('interface',['caller-interface.dex','interface-a.dex','interface-common.dex','object.dex'],2,0),
 ('diamond-ancestor',['caller-diamond-target.dex','interface-a.dex','interface-b.dex','interface-common.dex','object.dex'],2,0),
 ('interface-object-missing',['interface-caller.dex','child-target.dex','parent-target.dex'],4,1),
 ('interface-object-valid',['interface-caller.dex','child-target.dex','parent-target.dex','object.dex'],3,0),
 ('interface-object-duplicate',['interface-caller.dex','child-target.dex','parent-target.dex','object.dex','object.dex'],4,2),
 ('interface-object-invalid',['interface-caller.dex','child-target.dex','parent-target.dex','object-invalid.dex'],4,4),
 ('diamond-external',['caller-diamond.dex','child-target.dex','parent-target.dex','object.dex','interface-a.dex','interface-b.dex','interface-common.dex'],3,0)]
for name,names,status,reason in cases:
 paths=[a.fixtures/x for x in names];world=[read(x) for x in paths];r,v=run(name,paths,plan(paths));assert r.returncode==0 and len(v['candidates'])==2,(name,r.returncode,r.stdout,r.stderr)
 for row in v['candidates']:verify(row,world,status,reason)
 # Observation must not change original query's selection, decision or Unknown.
 r0,v0=run(name+'-without',paths,plan(paths,False));assert r0.returncode==0 and (v['coverage'],v['decision'],v['unknown_rows'])==(v0['coverage'],v0['decision'],v0['unknown_rows'])
 assert [(x['source_index'],x['local_index']) for x in v['candidates']]==[(x['source_index'],x['local_index']) for x in v0['candidates']]
# The target has two distinct structural interface paths; ANCESTOR promises only one.
diamond=[read(a.fixtures/x) for x in ('caller-diamond-target.dex','interface-a.dex','interface-b.dex','interface-common.dex','object.dex')]
assert diamond[0]['interfaces']==[diamond[1]['owner'],diamond[2]['owner']] and diamond[1]['interfaces']==diamond[2]['interfaces']==[diamond[3]['owner']]
# A SemiJoin keeps one event annotation, not a statement about every access.
paths=[a.fixtures/x for x in cases[4][1]];world=[read(x) for x in paths];r,v=run('semi',paths,plan(paths,True,'semi_join'));assert r.returncode==0 and len(v['candidates'])==1;verify(v['candidates'][0],world,3,0)
# Independent closure forgery negatives: missing edge, altered node or target cannot pass.
r,v=run('external-proof',paths,plan(paths));row=v['candidates'][0]
for kind in ('missing-edge','node-source','target-class','event-pc'):
 f=copy.deepcopy(row);records=[x for x in f['evidence'] if x['kind']=='caller_field_relation']
 if kind=='missing-edge':f['evidence'].remove(next(x for x in records if x['caller_field_relation']['item']==2))
 elif kind=='node-source':next(x for x in records if x['caller_field_relation']['item']==1)['caller_field_relation']['source_index']=2
 elif kind=='target-class':records[0]['caller_field_relation']['target_source']=1
 else:records[0]['caller_field_relation']['event_pc']=77
 try:verify(f,world,3,0)
 except (AssertionError,StopIteration,KeyError,IndexError):pass
 else:raise AssertionError('forgery accepted '+kind)
# A forged External proof cannot omit a required interface/Object check.
pathsIface=[a.fixtures/x for x in ('interface-caller.dex','child-target.dex','parent-target.dex','object.dex')];worldIface=[read(x) for x in pathsIface];r,v=run('interface-object-proof',pathsIface,plan(pathsIface));assert r.returncode==0;verify(v['candidates'][0],worldIface,3,0)
f=copy.deepcopy(v['candidates'][0]);f['evidence'].remove(next(x for x in f['evidence'] if x['kind']=='caller_field_relation' and x['caller_field_relation']['item']==3))
try:verify(f,worldIface,3,0)
except AssertionError:pass
else:raise AssertionError('missing interface Object check accepted')
# Existing raw v19 query is unchanged relative to iteration122.
q=plan(paths,False);r,v=run('old-v19-current',paths,q);r0,v0=run('old-v19-baseline',paths,q,a.old);assert r.returncode==r0.returncode==0 and v['query_id']==v0['query_id'];assert [(x['source_index'],x['local_index']) for x in v['candidates']]==[(x['source_index'],x['local_index']) for x in v0['candidates']]
print('PASS caller class relationship independent byte oracle, exact paths and closure negatives')
