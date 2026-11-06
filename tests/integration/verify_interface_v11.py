import argparse,hashlib,json,subprocess,sys,struct,tempfile,zlib
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('--exe',required=True,type=Path);parser.add_argument('--fixtures',required=True,type=Path);args=parser.parse_args()
fixtures=args.fixtures;exe=args.exe;workspace=tempfile.TemporaryDirectory(prefix='dmg-interface-v11-');here=Path(workspace.name)
manifest=json.loads((fixtures/'manifest.json').read_text())
def leb(b,p):
 n=0
 for shift in range(0,35,7):
  x=b[p];p+=1;n|=(x&127)<<shift
  if x<128:return n,p
 raise AssertionError('bad uleb')
def read(b):
 assert b[:8]==b'dex\n035\0' and struct.unpack_from('<I',b,32)[0]==len(b)
 assert hashlib.sha1(b[32:]).digest()==b[12:32] and struct.unpack_from('<I',b,8)[0]==zlib.adler32(b[12:])&0xffffffff
 u=lambda x:struct.unpack_from('<I',b,x)[0]
 strings=[]
 for i in range(u(56)):
  n,p=leb(b,u(u(60)+4*i));e=b.index(0,p);s=b[p:e].decode('ascii');assert len(s)==n;strings.append(s)
 types=[strings[u(u(68)+4*i)] for i in range(u(64))]
 refs=[]
 for i in range(u(80)):
  owner,typ,name=struct.unpack_from('<HHI',b,u(84)+8*i);refs.append((types[owner],types[typ],strings[name]))
 assert u(96)==1
 owner,flags,parent,ifaces,_,_,data,_=struct.unpack_from('<8I',b,u(100));interfaces=[]
 if ifaces:
  for i in range(u(ifaces)):interfaces.append(types[struct.unpack_from('<H',b,ifaces+4+2*i)[0]])
 fields=[]
 if data:
  counts=[];p=data
  for _ in range(4):x,p=leb(b,p);counts.append(x)
  assert counts[2:]==[0,0]
  for count in counts[:2]:
   index=0
   for _ in range(count):
    delta,p=leb(b,p);flags_field,p=leb(b,p);index+=delta;o,t,n=refs[index];assert o==types[owner];fields.append([n,t,flags_field])
 return [types[owner],None if parent==0xffffffff else types[parent],flags,fields,interfaces]
parsed={}
for name in ['child.dex','base.dex','root.dex','top.dex','top-alt.dex','left.dex','left-alt.dex','right.dex']:
 b=(fixtures/name).read_bytes();r=manifest['records'][name];assert hashlib.sha256(b).hexdigest()==r['sha256'];parsed[name]=read(b)
 expected=r['spec'];expected[3]=sorted(expected[3]);assert parsed[name]==expected,(name,parsed[name],expected)
def run(names,owner,field,count,scope='inherited_interfaces_resolved',label='v11'):
 query={'schema_version':1,'relation':'class_defs','intent':'unique','where':{'all':[{'descriptor':owner},{'declares_fields':{'scope':scope,'where':{'name':field},'min':count,'max':count}}]}}
 q=here/(label+'.json');q.write_text(json.dumps(query),encoding='utf-8')
 args=[str(exe),'query',str(fixtures/names[0])]
 for name in names[1:]:args+=['--source',str(fixtures/name)]
 p=subprocess.run(args+['--query',str(q),'--json'],capture_output=True,text=True,encoding='utf-8')
 assert p.returncode==0,(p.returncode,p.stdout,p.stderr)
 return json.loads(p.stdout)
names=['child.dex','base.dex','root.dex','top.dex','left.dex','left-alt.dex','right.dex']
r=run(names,'Lifx/Child;','diamond',1);assert r['profile']=='dex-query-interface-resolved-v11' and r['query_id'].startswith('query:v11:') and r['decision']=='ProvenTrue',r
events=[e['interface'] for e in r['candidates'][0]['evidence'] if e['kind']=='interface_resolved'];assert len([e for e in events if e['item']==6])==2
r=run(names,'Lifx/Child;','same',2);assert r['coverage']=='Partial' and r['unknown_rows']==1 and not r['candidates'],r
r=run(['left.dex','top.dex','root.dex'],'Lifx/Left;','diamond',1);assert r['decision']=='ProvenTrue',r
r=run(names,'Lifx/Child;','diamond',1,scope='inherited_interfaces',label='v8');assert r['profile']=='dex-query-interface-v8' and r['query_id'].startswith('query:v8:') and r['unknown_rows']==1,r
print('PASS raw DEX hash, checksum, tables, interface roots, multi-definition decisions, public v11 and v8 isolation')
