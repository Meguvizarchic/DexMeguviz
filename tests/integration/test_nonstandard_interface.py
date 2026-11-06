"""Independent bytes: an already-witnessed interface edge does not validate that interface's malformed superclass."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess,zlib
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

paths=[a.fixtures/x for x in ('caller-interface.dex','interface-a-bad-super.dex','interface-common.dex','object.dex')];world=[read(p) for p in paths];assert world[0]['interfaces']==['Lq08/IA;'] and world[1]['owner']=='Lq08/IA;' and world[1]['parent']=='Lq08/Parent;' and world[1]['interfaces']==['Lq08/ICommon;'] and world[2]['owner']=='Lq08/ICommon;' and world[2]['flags']&0x200
slots=['input:'+str(i)+':'+str(x) for i,x in enumerate(paths)];q={'schema_version':1,'required_capabilities':['field_declaration_static','caller_field_relation_observation'],'scope':{'slots':slots},'relation':{'op':'join','on':'caller','left':{'op':'scan','relation':'method_defs'},'right':{'op':'scan','relation':'field_uses','where':{'target_field_declaration':{'scope':'any'}}}}};query=a.out/'query.json';query.write_text(json.dumps(q),encoding='utf-8');cmd=[str(a.exe),'query',str(paths[0])]
for x in paths[1:]:cmd+=['--source',str(x)]
cmd+=['--query',str(query),'--json'];r=subprocess.run(cmd,capture_output=True,text=True);(a.out/'cli.stdout').write_text(r.stdout,encoding='utf-8');(a.out/'cli.stderr').write_text(r.stderr,encoding='utf-8');assert r.returncode==0,(r.returncode,r.stdout,r.stderr);v=json.loads(r.stdout);assert len(v['candidates'])==2 and v['unknown_rows']==2
for row in v['candidates']:
 event=row['links'][0]['right'];assert event['source_index']==0 and event['dex_pc'] in (4,6);used=next(x for x in world[0]['events'] if x[0]==event['dex_pc']);answer=resolve(world,used[2]);assert answer not in (None,False) and answer[1]==2
 proof=[x['caller_field_relation'] for x in row['evidence'] if x['kind']=='caller_field_relation'];assert proof[0]['status']==2 and proof[0]['reason']==0;nodes=[x for x in proof if x['item']==1];assert [(x['source_index'],x['edge_kind']) for x in nodes]==[(0,0),(1,1),(2,1)]
 # Each chosen interface edge is verifiable without claiming the visited node is otherwise valid.
 assert world[0]['interfaces'][0]==world[1]['owner'] and world[1]['interfaces'][0]==world[2]['owner']
print('PASS nonstandard interface superclass: one static ancestor path only, no ART validity claim')
