"""Independent byte-level field lookup and CLI evidence comparison (static only)."""
from pathlib import Path
import argparse,copy,hashlib,json,struct,subprocess,zlib
if not __debug__:raise SystemExit('assertions required')
p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)

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

def query(paths,scope='any',access='any',extra=None):
 slots=['input:'+str(i)+':'+str(path) for i,path in enumerate(paths)]
 d={'scope':scope};d.update(extra or {})
 pred={'target_field_declaration':d}
 if access!='any':
  ranges=((0x52,0x58),(0x60,0x66)) if access=='read' else ((0x59,0x5f),(0x67,0x6d))
  pred={'all':[pred,{'any':[{'opcode':{'min':x,'max':y}} for x,y in ranges]}]}
 return {'schema_version':1,'required_capabilities':['field_declaration_static'],'scope':{'slots':slots},'relation':{'op':'scan','relation':'field_uses','where':pred},'intent':'enumerate'}

def check(label,names,scope='any',access='any',expected=(),unknown=0,partial=False):
 paths=[a.fixtures/x for x in names];world=[read(x) for x in paths];q=query(paths,scope,access);qp=a.out/(label+'.json');qp.write_text(json.dumps(q),encoding='utf-8')
 cmd=[str(a.exe),'query',str(paths[0])]
 for x in paths[1:]:cmd+=['--source',str(x)]
 cmd+=['--query',str(qp),'--json']
 if partial:cmd+=['--scope-incomplete']
 r=subprocess.run(cmd,capture_output=True,text=True);(a.out/(label+'.stdout')).write_text(r.stdout,encoding='utf-8');(a.out/(label+'.stderr')).write_text(r.stderr,encoding='utf-8');assert r.returncode==0,(label,r.returncode,r.stderr,r.stdout)
 got=json.loads(r.stdout);assert got['profile']=='dex-query-field-declaration-v19' and got['unknown_rows']==unknown,(label,got)
 rows=got['candidates'];assert sorted(x['dex_pc'] for x in rows)==list(expected),(label,rows)
 for row in rows:
  event=next(e for e in world[row['source_index']]['events'] if e[0]==row['dex_pc']);resolved=resolve(world,event[2]);assert resolved not in (None,False)
  path,source,field,flags=resolved;assert bool(event[1]>=0x60)==bool(flags&8)
  proofs=[v['field_declaration'] for v in row['evidence'] if v['kind']=='field_declaration'];assert len(proofs)==len(path)+1
  observed=tuple((v['source_index'],v['local_index'],v['edge'],0xffffffff if v['interface_index'] is None else v['interface_index']) for v in proofs[:-1])
  assert observed==path,(label,observed,path)
  terminal=proofs[-1];assert (terminal['item'],terminal['source_index'],terminal['local_index'],terminal['detail'])==(1,source,field,flags)
 return got

sample=check('parent',['child.dex','parent.dex','object.dex'],'inherited',expected=(0,2),unknown=2)
# The independent oracle rejects a changed path, declaring field or flags.
world=[read(a.fixtures/x) for x in ('child.dex','parent.dex','object.dex')]
row=sample['candidates'][0];resolved=resolve(world,world[row['source_index']]['events'][0][2]);path,source,field,flags=resolved
def authentic(r):
 proofs=[v['field_declaration'] for v in r['evidence'] if v['kind']=='field_declaration']
 if len(proofs)!=len(path)+1:return False
 observed=tuple((v['source_index'],v['local_index'],v['edge'],0xffffffff if v['interface_index'] is None else v['interface_index']) for v in proofs[:-1])
 end=proofs[-1]
 return observed==path and (end['item'],end['source_index'],end['local_index'],end['detail'])==(1,source,field,flags)
assert authentic(row)
for which,key,value in [(0,'source_index',2),(1,'edge',1),(-1,'source_index',2),(-1,'local_index',17),(-1,'detail',flags^8)]:
 forged=copy.deepcopy(row);e=[v['field_declaration'] for v in forged['evidence'] if v['kind']=='field_declaration'];e[which][key]=value;assert not authentic(forged)
check('parent-declared',['child.dex','parent.dex','object.dex'],'declared',expected=(),unknown=2)
check('own',['child-own.dex','parent.dex','object.dex'],'declared',expected=(0,2),unknown=2)
check('own-before-static-parent',['child-own.dex','parent-static.dex','object.dex'],'declared',expected=(0,2),unknown=2)
check('own-static-before-parent',['child-own-static.dex','parent.dex','object.dex'],'declared',expected=(4,6),unknown=2)
check('invalid-flags',['child-invalid-flags.dex','parent.dex','object.dex'],'any',expected=(),unknown=4)
check('type-collision',['child-different-type.dex','parent.dex','object.dex'],'inherited',expected=(0,2),unknown=2)
check('read',['child.dex','parent.dex','object.dex'],'inherited','read',expected=(0,),unknown=1)
check('write',['child.dex','parent.dex','object.dex'],'inherited','write',expected=(2,),unknown=1)
check('interface-first',['child-interface.dex','interface.dex','parent-static.dex','object.dex'],'inherited',expected=(4,6),unknown=2)
check('interface-bad',['child-interface.dex','interface-bad.dex','parent-static.dex','object.dex'],'any',expected=(),unknown=4)
check('interface-empty',['child-interface.dex','interface-empty.dex','parent.dex','object.dex'],'any',expected=(),unknown=4)
check('missing',['child.dex','object.dex'],'any',expected=(),unknown=4)
check('duplicate',['child.dex','parent.dex','parent.dex','object.dex'],'any',expected=(),unknown=4)
check('cycle',['child.dex','parent-cycle.dex','object.dex'],'any',expected=(),unknown=4)
check('scoped-incomplete',['child.dex','parent.dex','object.dex'],'inherited',expected=(0,2),unknown=2,partial=True)
print('PASS Q08 scoped field declaration byte oracle, paths and Unknown boundaries')
