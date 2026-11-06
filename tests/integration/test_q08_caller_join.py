"""Independent byte-level Q08 caller Join/SemiJoin oracle; no ART claim."""
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

def slots(paths):return ['input:'+str(i)+':'+str(path) for i,path in enumerate(paths)]
def plan(paths,op='join',right=None,left=None,intent='enumerate',maxresults=4096,unique_by='entity'):
 target={'target_field_declaration':{'scope':'inherited'}}
 if right is not None:target={'all':[target,right]}
 return {'schema_version':1,'required_capabilities':['field_declaration_static'],'scope':{'slots':slots(paths)},'relation':{'op':op,'on':'caller','left':{'op':'scan','relation':'method_defs','where':True if left is None else left},'right':{'op':'scan','relation':'field_uses','where':target}},'intent':intent,'max_results':maxresults,'unique_by':unique_by}
def run(label,paths,q,exe=None):
 f=a.out/(label+'.json');f.write_text(json.dumps(q),encoding='utf-8');cmd=[str(exe or a.exe),'query',str(paths[0])]
 for x in paths[1:]:cmd+=['--source',str(x)]
 cmd+=['--query',str(f),'--json'];r=subprocess.run(cmd,capture_output=True,text=True);(a.out/(label+'.out')).write_text(r.stdout,encoding='utf-8');(a.out/(label+'.err')).write_text(r.stderr,encoding='utf-8')
 return r,json.loads(r.stdout) if r.stdout.strip().startswith('{') else None
def verify(row,world,semi=False):
 assert row['relation']=='method_defs';src=row['source_index'];links=row['links'];assert len(links)==1 and links[0]['key']=='caller';l,r=links[0]['left'],links[0]['right'];assert l['relation']=='method_defs' and l['source_index']==src==r['source_index'] and l['local_index']==r['local_index'] and r['relation']=='field_uses'
 event=next(e for e in world[src]['events'] if e[0]==r['dex_pc']);answer=resolve(world,event[2]);assert answer not in (None,False);path,target,ordinal,flags=answer;assert bool(event[1]>=0x60)==bool(flags&8)
 if semi:
  assert len(row['proof_bindings'])==1;event_value=row['proof_bindings'][0]['value'];assert event_value['relation']=='field_uses' and event_value['source_index']==src and event_value['dex_pc']==r['dex_pc']
 else:
  assert len(row['bindings'])==2;event_value=next(x for x in row['bindings'] if x['relation']=='field_uses');assert event_value['source_index']==src and event_value['dex_pc']==r['dex_pc']
 ps=[x['field_declaration'] for x in row['evidence'] if x['kind']=='field_declaration'];assert len(ps)==len(path)+1
 observed=tuple((v['source_index'],v['local_index'],v['edge'],0xffffffff if v['interface_index'] is None else v['interface_index']) for v in ps[:-1]);assert observed==path
 end=ps[-1];assert (end['item'],end['source_index'],end['local_index'],end['detail'])==(1,target,ordinal,flags)
 return src,r['dex_pc']
names=['caller-a.dex','caller-b.dex','child.dex','parent.dex','object.dex'];paths=[a.fixtures/x for x in names];world=[read(x) for x in paths]
for op,expected,unknown in [('join',[(0,0),(0,2),(1,0),(1,2)],4),('semi_join',[(0,0),(1,0)],0)]:
 r,v=run(op,paths,plan(paths,op));assert r.returncode==0 and v['profile']=='dex-query-field-declaration-v19' and v['unknown_rows']==unknown,(op,r.stdout,r.stderr);assert sorted(verify(x,world,op=='semi_join') for x in v['candidates'])==expected
# Duplicate caller bytes have different source occurrence but share one target definition.
paths2=[a.fixtures/x for x in ('caller-a.dex','caller-a.dex','child.dex','parent.dex','object.dex')];world2=[read(x) for x in paths2];r,v=run('duplicate-callers',paths2,plan(paths2,'join'));assert r.returncode==0 and sorted(verify(x,world2) for x in v['candidates'])==[(0,0),(0,2),(1,0),(1,2)]
# Empty methods do not produce an event; visible scope is not a runtime absence proof.
paths3=[a.fixtures/x for x in ('caller-a.dex','caller-no-body.dex','child.dex','parent.dex','object.dex')];world3=[read(x) for x in paths3];r,v=run('no-body',paths3,plan(paths3,'semi_join'));assert r.returncode==0 and sorted(verify(x,world3,True) for x in v['candidates'])==[(0,0)]
# Only static accesses reach a static mismatch: no true right witness, Unknown survives.
static={'opcode':{'min':96,'max':109}}
for op in ('join','semi_join'):
 r,v=run('unknown-'+op,paths,plan(paths,op,right=static,intent='exists'));assert r.returncode==0 and not v['candidates'] and v['decision']=='Undetermined' and v['unknown_rows']==(4 if op=='join' else 2)
for op in ('join','semi_join'):
 missing=[a.fixtures/x for x in ('caller-a.dex','caller-b.dex','child.dex','object.dex')];r,v=run('missing-'+op,missing,plan(missing,op,intent='exists'));assert r.returncode==0 and not v['candidates'] and v['decision']=='Undetermined'
# Entity uniqueness collapses multiple PCs per method, but not different occurrences.
left={'owner':'Lq08/CallerA;'};r,v=run('unique-entity',paths,plan(paths,'join',left=left,intent='unique'));assert r.returncode==0 and v['decision']=='ProvenTrue' and len(v['candidates'])==1
r,v=run('unique-tuple',paths,plan(paths,'join',left=left,intent='unique',unique_by='tuple'));assert r.returncode==0 and v['decision']=='ProvenFalse' and len(v['candidates'])==2
r,v=run('unique-limit',paths,plan(paths,'join',intent='unique',maxresults=1));assert r.returncode!=0 and v['coverage']=='Partial' and v['decision']=='Undetermined' and v['reason']=='ResultLimit'
r,v=run('enumerate-limit',paths,plan(paths,'join',maxresults=1));assert r.returncode!=0 and v['coverage']=='Partial' and v['reason']=='ResultLimit'
# Independent proof tampering must fail reconstruction.
r,v=run('proof-source',paths,plan(paths,'join'));assert r.returncode==0;row=v['candidates'][0]
for kind in ('caller-source','caller-ordinal','pc','path-source','path-edge','field-index'):
 fake=copy.deepcopy(row)
 if kind=='caller-source':fake['links'][0]['right']['source_index']=1-fake['links'][0]['right']['source_index']
 elif kind=='caller-ordinal':fake['links'][0]['right']['local_index']+=1
 elif kind=='pc':fake['links'][0]['right']['dex_pc']=12345
 else:
  e=[x['field_declaration'] for x in fake['evidence'] if x['kind']=='field_declaration']
  if kind=='path-source':e[0]['source_index']=4
  elif kind=='path-edge':e[1]['edge']=1
  else:e[-1]['local_index']+=1
 try:verify(fake,world)
 except (AssertionError,StopIteration):pass
 else:raise AssertionError('forgery accepted '+kind)
# Old v19 single scan remains byte-for-byte query identity and results compatible.
scan={'schema_version':1,'required_capabilities':['field_declaration_static'],'scope':{'slots':slots(paths)},'relation':{'op':'scan','relation':'field_uses','where':{'target_field_declaration':{'scope':'inherited'}}}}
x,n=run('old-scan-current',paths,scan);y,o=run('old-scan-prior',paths,scan,a.old);assert x.returncode==y.returncode==0 and n['query_id']==o['query_id'];assert [(z['source_index'],z['dex_pc']) for z in n['candidates']]==[(z['source_index'],z['dex_pc']) for z in o['candidates']]
# Independent canonical framing for the default Join plan (query scope order normalized).
u32=lambda n:struct.pack('<I',n);u64=lambda n:struct.pack('<Q',n);frame=lambda x:u64(len(x))+x
node=lambda kind,arg=0,extra=b'':b''.join(map(u32,(kind,0,arg,0,0xffffffff)))+extra+u32(0)
yes=node(0);decl=node(33,1,b''.join(map(u32,(0,0,0,0,0))))
def scan(rel,pred):return b''.join(map(u32,(0,rel,1)))+frame(pred)+b''.join(map(u32,(0,1,0xffffffff,1,0,0,0,0,0,0)))
relation=b''.join(map(u32,(6,0,0,0,1,0xffffffff,1,0,0,0,4,0,0,2)))+frame(scan(0,yes))+frame(scan(9,decl))
req=1|2|8|128|512|2048|4096|134217728
qscope=sorted(slots(paths));top=b''.join(map(u32,(0,0,4096)))+u64(100000000)+b''.join(map(u32,(7,1,1,req,0,100000,len(qscope))))+b''.join(frame(x.encode('ascii')) for x in qscope)+u32(0)
expected='query:v19:'+hashlib.sha256(b'DexMeguviz:QueryIR:field-declaration-v19'+top+relation).hexdigest();r,v=run('query-id-golden',paths,plan(paths));assert r.returncode==0 and v['query_id']==expected,(expected,v['query_id'])
print('PASS independent Q08 caller Join/SemiJoin byte oracle, Unknown, proof and QueryID')
