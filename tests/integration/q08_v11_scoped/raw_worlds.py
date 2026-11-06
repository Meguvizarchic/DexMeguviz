"""Independent raw-DEX oracle and forged v11 event checks for bounded fixtures.

The probe transports events from the implementation; all expected graphs,
choices, hiding, declaration identities, counts and truth values are rebuilt
here from source bytes. This is a static subset, not a DEX/ART verifier.
"""
import argparse, collections, copy, hashlib, itertools, json, struct, subprocess, zlib
from pathlib import Path

ROOT=Path(__file__).parent
def leb(data,pos):
 value=0
 for shift in range(0,35,7):
  b=data[pos];pos+=1;value|=(b&127)<<shift
  if b<128:return value,pos
 raise ValueError('invalid uleb')
def parse(path):
 d=path.read_bytes();u=lambda p:struct.unpack_from('<I',d,p)[0]
 assert d[:8]==b'dex\n035\0' and u(32)==len(d) and d[12:32]==hashlib.sha1(d[32:]).digest() and u(8)==zlib.adler32(d[12:])&0xffffffff
 strings=[]
 for i in range(u(56)):
  n,p=leb(d,u(u(60)+4*i));e=d.index(0,p);s=d[p:e].decode('ascii');assert len(s)==n;strings.append(s)
 types=[strings[u(u(68)+4*i)] for i in range(u(64))];refs=[]
 for i in range(u(80)):
  owner,typ,name=struct.unpack_from('<HHI',d,u(84)+8*i);refs.append((owner,typ,strings[name]))
 assert u(96)==1
 owner,flags,parent,ifaces,_,_,class_data,_=struct.unpack_from('<8I',d,u(100))
 interfaces=[struct.unpack_from('<H',d,ifaces+4+2*i)[0] for i in range(u(ifaces))] if ifaces else []
 fields=[]
 if class_data:
  counts=[];p=class_data
  for _ in range(4):n,p=leb(d,p);counts.append(n)
  assert counts[2:]==[0,0]
  for count in counts[:2]:
   index=0
   for _ in range(count):
    delta,p=leb(d,p);access,p=leb(d,p);index+=delta;o,t,name=refs[index];assert o==owner
    fields.append((name,types[t],access))
 return {'owner':types[owner],'flags':flags,'parent':None if parent==0xffffffff else parent,'ifaces':interfaces,'types':types,'fields':fields,'sha256':hashlib.sha256(d).hexdigest()}

def expected_worlds(sources,root_interface,name,minimum,maximum):
 # Scope and inputs in this complete-world oracle are deliberately bounded to
 # one class per fixture DEX, public supported interfaces, DAGs and no missing.
 by_type=collections.defaultdict(list)
 for i,s in enumerate(sources):by_type[s['owner']].append(i)
 ambiguous=[(descriptor,indices) for descriptor,indices in by_type.items() if len(indices)>1]
 output=set()
 for chosen in itertools.product(*(x[1] for x in ambiguous)):
  binding=dict(zip((x[0] for x in ambiguous),chosen));binding[sources[0]['owner']]=0
  nodes={0};edges=set();choices=set();queue=[0]
  while queue:
   origin=queue.pop();src=sources[origin];refs=[]
   if src['parent'] is not None and not (root_interface and origin==0) and not (src['flags']&0x200):refs.append((0,src['parent']))
   refs.extend((1,index) for index in src['ifaces'])
   for kind,local in refs:
    descriptor=src['types'][local];candidates=by_type[descriptor];assert candidates
    target=binding.get(descriptor,candidates[0]);assert target in candidates
    if kind==1:
     assert sources[target]['flags']&0x601==0x601 and sources[target]['flags']&~0x3601==0
     if len(candidates)>1:choices.add((origin,target,local,len(candidates)))
    edges.add((origin,target,kind,local))
    if target not in nodes:nodes.add(target);queue.append(target)
  visiting=set();cache={}
  def members(node):
   if node in cache:return cache[node]
   assert node not in visiting;visiting.add(node)
   own={(node,i) for i,_ in enumerate(sources[node]['fields'])};own_names={sources[node]['fields'][i][0] for _,i in own};result=set(own)
   for origin,target,kind,local in edges:
    if origin!=node:continue
    for member in members(target):
     source,ordinal=member;field_name,_,flags=sources[source]['fields'][ordinal]
     if field_name not in own_names and flags&7 in (1,4):result.add(member)
   visiting.remove(node);cache[node]=result;return result
  matched=frozenset((s,i) for s,i in members(0) if s!=0 and sources[s]['fields'][i][0]==name)
  value=int(minimum<=len(matched)<=maximum)
  output.add((frozenset(nodes),frozenset(edges),frozenset(choices),matched,value))
 return output

def verify(events,sources,expected,overall):
 groups=collections.defaultdict(list)
 for e in events:groups[e[1]].append(e)
 assert set(groups)==set(range(len(groups))) and len(groups)==len(expected)
 actual=set()
 for records in groups.values():
  assert all(1<=r[0]<=6 for r in records)
  node_events=[r for r in records if r[0]==1];nodes={r[2]:r[5] for r in node_events}
  assert len(nodes)==len(node_events) and set(nodes)==set(range(len(nodes))) and nodes[0]==0
  for r in node_events:
   assert r[3]==0xffffffff and r[6]==1 and r[7]==0 and r[4]==int(bool(sources[r[5]]['flags']&0x200))
  edges=set()
  for r in records:
   if r[0]!=2:continue
   _,_,node,aux,kind,source,relation,local=r
   assert node in nodes and aux in nodes and source==nodes[node] and relation==6 and kind in (0,1)
   src=sources[source];target=nodes[aux];assert local<len(src['types']) and src['types'][local]==sources[target]['owner']
   assert (kind==0 and local==src['parent']) or (kind==1 and local in src['ifaces'])
   edges.add((source,target,kind,local))
  assert len(edges)==sum(r[0]==2 for r in records)
  choices=set()
  for r in records:
   if r[0]!=6:continue
   _,_,node,count,local,target,relation,ordinal=r
   assert node in nodes and relation==1 and ordinal==0 and local<len(sources[nodes[node]]['types'])
   descriptor=sources[nodes[node]]['types'][local];assert sources[target]['owner']==descriptor
   candidates=[i for i,s in enumerate(sources) if s['owner']==descriptor];assert count==len(candidates)>1 and target in candidates
   choices.add((nodes[node],target,local,count))
  assert len(choices)==sum(r[0]==6 for r in records)
  fields=set()
  for r in records:
   if r[0]!=4:continue
   _,_,node,aux,detail,source,relation,ordinal=r
   assert node in nodes and nodes[node]==source and aux==0xffffffff and detail==0 and relation==2 and ordinal<len(sources[source]['fields'])
   fields.add((source,ordinal))
  assert len(fields)==sum(r[0]==4 for r in records) and not any(r[0]==3 for r in records)
  branches=[r for r in records if r[0]==5];assert len(branches)==1
  b=branches[0];assert b[2]==0 and b[3]==len(fields) and b[4] in (0,2) and b[5]==0 and b[6]==1 and b[7]==0
  actual.add((frozenset(nodes.values()),frozenset(edges),frozenset(choices),frozenset(fields),b[4]>>1))
 assert actual==expected
 values={x[4] for x in expected};assert overall==(next(iter(values)) if len(values)==1 else 2)

def verify_missing(events,sources,overall):
 assert overall==2 and all(e[1]==0 for e in events)
 nodes={e[2]:e[5] for e in events if e[0]==1};assert nodes[0]==0 and set(nodes.values())==set(range(len(sources)))
 available={s['owner'] for s in sources}
 missing={(i,index) for i,s in enumerate(sources) for index in s['ifaces'] if s['types'][index] not in available}
 observed=set()
 for item,branch,node,aux,detail,source,relation,ordinal in events:
  if item==3:
   assert node in nodes and nodes[node]==source and aux==0 and detail==1 and relation==6 and ordinal in sources[source]['ifaces']
   assert sources[source]['types'][ordinal] not in available;observed.add((source,ordinal))
  if item==2:
   assert node in nodes and aux in nodes and source==nodes[node] and relation==6
   assert sources[source]['types'][ordinal]==sources[nodes[aux]]['owner']
 assert observed==missing and len(observed)==2 and not any(e[0]==4 for e in events)
 branches=[e for e in events if e[0]==5];assert len(branches)==1 and branches[0][3:5]==(0,5)

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--probe',type=Path,default=ROOT/'oracle-probe.exe');ap.add_argument('--fixtures',type=Path,default=ROOT/'fixtures');args=ap.parse_args()
 cases=[
  (['child.dex','base.dex','root.dex','top.dex','left.dex','left-alt.dex','right.dex'],False,'diamond',1,1),
  (['child.dex','base.dex','root.dex','top.dex','left.dex','left-alt.dex','right.dex'],False,'same',2,2),
  (['child.dex','base.dex','root.dex','top.dex','left.dex','left-alt.dex','right.dex'],False,'diamond',2,2),
  (['child.dex','base.dex','root.dex','top.dex','top.dex','left.dex','right.dex'],False,'diamond',1,1),
  (['child.dex','base.dex','root.dex','top.dex','top-alt.dex','left.dex','right.dex'],False,'diamond',1,1),
  (['left.dex','top.dex','root.dex'],True,'diamond',1,1),
  (['left.dex','top.dex','root.dex'],True,'override',0,0),
  (['child.dex','base.dex','root.dex','top.dex','left.dex','right.dex'],False,'hidden',0,0),
 ]
 mutations=collections.Counter()
 for names,root_interface,name,lo,hi in cases:
  sources=[parse(args.fixtures/n) for n in names];expected=expected_worlds(sources,root_interface,name,lo,hi)
  p=subprocess.run([str(args.probe),name,str(lo),str(hi),str(int(root_interface)),'1',*(str(args.fixtures/n) for n in names)],capture_output=True,text=True,encoding='utf-8',check=True)
  lines=p.stdout.splitlines();overall=int(lines[0]);events=[tuple(map(int,line.split())) for line in lines[1:]];verify(events,sources,expected,overall)
  for item,column,label in [(1,5,'node source'),(2,3,'edge target'),(4,7,'field ordinal'),(5,3,'branch count'),(5,4,'branch decision'),(6,5,'choice source')]:
   idx=next((i for i,e in enumerate(events) if e[0]==item),None)
   if idx is None:continue
   forged=list(events);row=list(forged[idx]);row[column]=(row[column]+1)%len(sources) if column in (3,5,7) else row[column]^2;forged[idx]=tuple(row)
   try:verify(forged,sources,expected,overall)
   except (AssertionError,IndexError,KeyError,ValueError):mutations[label]+=1
   else:raise AssertionError('forgery accepted: '+label)
 assert all(mutations[label] for label in ['node source','edge target','field ordinal','branch count','branch decision','choice source'])
 names=['child.dex','base.dex','root.dex','left.dex','right.dex'];sources=[parse(args.fixtures/n) for n in names]
 p=subprocess.run([str(args.probe),'diamond','1','1','0','1',*(str(args.fixtures/n) for n in names)],capture_output=True,text=True,encoding='utf-8',check=True)
 lines=p.stdout.splitlines();overall=int(lines[0]);events=[tuple(map(int,line.split())) for line in lines[1:]];verify_missing(events,sources,overall)
 idx=next(i for i,e in enumerate(events) if e[0]==3);forged=list(events);row=list(forged[idx]);row[4]=2;forged[idx]=tuple(row)
 try:verify_missing(forged,sources,overall)
 except AssertionError:mutations['frontier reason']+=1
 else:raise AssertionError('forged missing frontier accepted')
 print('PASS independent raw DEX worlds, edges, choices, hiding, fields, branch truth and forged events:',dict(mutations))
if __name__=='__main__':main()
