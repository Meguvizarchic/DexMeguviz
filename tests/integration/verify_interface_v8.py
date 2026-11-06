"""Independent raw DEX and v8 graph/witness checks, including forgeries."""
import argparse,copy,hashlib,json,struct,subprocess,sys,tempfile,zlib
from pathlib import Path
O='Ljava/lang/Object;';B='Lifx/Base;';C='Lifx/Child;';T='Lifx/Top;';L='Lifx/Left;';R='Lifx/Right;';X='Lifx/Cycle;';Y='Lifx/Cycle2;';BAD='Lifx/Bad;'
EXPECTED={
 'root.dex':(O,None,1,[],[]),'base.dex':(B,O,1,[('classSame','I',1)],[]),
 'top.dex':(T,O,0x601,[('diamond','I',25),('hidden','I',25),('override','I',25)],[]),
 'left.dex':(L,O,0x601,[('classSame','I',25),('override','I',25),('same','I',25)],[T]),
 'right.dex':(R,O,0x601,[('same','I',25)],[T]),'child.dex':(C,B,1,[('hidden','I',2)],[L,R]),
 'cycle.dex':(X,O,0x601,[('cycle','I',25)],[Y]),'cycle2.dex':(Y,O,0x601,[],[X]),
 'child-cycle.dex':(C,B,1,[],[X]),'bad-instance.dex':(BAD,O,0x601,[('bad','I',1)],[]),
 'bad-protected.dex':(BAD,O,0x601,[('bad','I',28)],[]),'bad-nofinal.dex':(BAD,O,0x601,[('bad','I',9)],[]),
 'bad-type.dex':(BAD,O,0x201,[('bad','I',25)],[]),'annotation.dex':(BAD,O,0x3601,[('annotationField','I',25)],[]),
 'child-bad.dex':(C,B,1,[],[BAD]),
}
def uleb(data,pos):
 n=0
 for shift in range(0,35,7):
  x=data[pos];pos+=1;n|=(x&127)<<shift
  if x<128:return n,pos
 raise AssertionError('bad uleb')
def read(data):
 assert data[:8]==b'dex\n035\0' and struct.unpack_from('<I',data,32)[0]==len(data)
 assert data[12:32]==hashlib.sha1(data[32:]).digest() and struct.unpack_from('<I',data,8)[0]==zlib.adler32(data[12:])&0xffffffff
 u32=lambda p:struct.unpack_from('<I',data,p)[0];strings=[]
 for i in range(u32(56)):
  n,pos=uleb(data,u32(u32(60)+4*i));end=data.index(0,pos);text=data[pos:end].decode('ascii');assert len(text)==n;strings.append(text)
 types=[strings[u32(u32(68)+4*i)] for i in range(u32(64))];refs=[]
 for i in range(u32(80)):
  owner,typ,name=struct.unpack_from('<HHI',data,u32(84)+8*i);refs.append((types[owner],types[typ],strings[name]))
 assert u32(96)==1;owner,flags,parent,interfaces,_,_,class_data,_=struct.unpack_from('<8I',data,u32(100))
 iface=[]
 if interfaces:
  for i in range(u32(interfaces)):iface.append(types[struct.unpack_from('<H',data,interfaces+4+2*i)[0]])
 fields=[]
 if class_data:
  counts=[];pos=class_data
  for _ in range(4):n,pos=uleb(data,pos);counts.append(n)
  assert counts[2:]==[0,0]
  for n in counts[:2]:
   index=0
   for _ in range(n):
    delta,pos=uleb(data,pos);field_flags,pos=uleb(data,pos);index+=delta;ref_owner,typ,name=refs[index];assert ref_owner==types[owner];fields.append((name,typ,field_flags))
 return {'owner':types[owner],'parent':None if parent==0xffffffff else types[parent],'flags':flags,'fields':fields,'interfaces':iface,'types':types}

p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--generator',type=Path,required=True);a=p.parse_args()
manifest=json.loads((a.fixtures/'manifest.json').read_text(encoding='utf-8'));assert set(manifest)==set(EXPECTED)
parsed={}
for name,expected in EXPECTED.items():
 raw=(a.fixtures/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==manifest[name]['sha256'];value=read(raw);parsed[name]=value
 assert (value['owner'],value['parent'],value['flags'],value['fields'],value['interfaces'])==expected,(name,value,expected)
names=['child.dex','base.dex','root.dex','top.dex','left.dex','right.dex'];paths=[a.fixtures/name for name in names]
def verify(result,field_name,wanted):
 assert result['profile']=='dex-query-interface-v8' and result['query_id'].startswith('query:v8:')
 assert result['coverage']=='Complete' and result['decision']=='ProvenTrue' and len(result['candidates'])==1
 candidate=result['candidates'][0];assert candidate['source_index']==0
 events=[x['interface'] for x in candidate['evidence'] if x['kind']=='interface_inherited']
 nodes={x['node']:x for x in events if x['item']==1};assert set(nodes)==set(range(6))
 assert {names[x['source_index']] for x in nodes.values()}==set(names)
 assert all(x['relation']=='class_defs' and x['local_index']==0 for x in nodes.values())
 edges=[x for x in events if x['item']==2];assert len(edges)==6
 for edge in edges:
  source=nodes[edge['node']];target=nodes[edge['aux']];assert edge['source_index']==source['source_index'] and edge['relation']=='type_refs'
  entry=parsed[names[source['source_index']]];desc=entry['types'][edge['local_index']]
  assert desc==parsed[names[target['source_index']]]['owner']
  assert (edge['detail']==0 and desc==entry['parent']) or (edge['detail']==1 and desc in entry['interfaces'])
 fields=[x for x in events if x['item']==4];assert len(fields)==wanted
 for field in fields:
  assert field['relation']=='field_defs' and field['node'] in nodes and nodes[field['node']]['source_index']==field['source_index']
  entry=parsed[names[field['source_index']]];assert entry['fields'][field['local_index']][0]==field_name
 assert len({(x['source_index'],x['local_index']) for x in fields})==wanted

with tempfile.TemporaryDirectory(prefix='dmg-interface-oracle-') as tmp:
 rebuilt=Path(tmp)/'rebuilt';generated=subprocess.run([sys.executable,str(a.generator),'--output',str(rebuilt)],capture_output=True,text=True,encoding='utf-8',timeout=30)
 assert generated.returncode==0,(generated.returncode,generated.stderr)
 for path in a.fixtures.iterdir():
  if path.is_file():assert (rebuilt/path.name).read_bytes()==path.read_bytes()
 def run(label,name,count,relational=False,srcs=paths):
  pred={'all':[{'descriptor':C},{'declares_fields':{'scope':'inherited_interfaces','where':{'name':name},'min':count,'max':count}}]}
  relation={'op':'scan','relation':'class_defs','where':pred} if relational else 'class_defs'
  query={'schema_version':1,'relation':relation,'intent':'unique'}
  if not relational:query['where']=pred
  qfile=Path(tmp)/(label+'.json');qfile.write_text(json.dumps(query),encoding='utf-8')
  cmd=[str(a.exe),'query',str(srcs[0])]
  for path in srcs[1:]:cmd+=['--source',str(path)]
  result=subprocess.run(cmd+['--query',str(qfile),'--json'],capture_output=True,text=True,encoding='utf-8',timeout=40)
  assert result.returncode==0,(label,result.returncode,result.stderr,result.stdout);return json.loads(result.stdout)
 for name,count in [('diamond',1),('same',2),('classSame',2),('override',2),('hidden',0)]:
  result=run(name,name,count);verify(result,name,count)
  forged=copy.deepcopy(result);edge=next(x['interface'] for x in forged['candidates'][0]['evidence'] if x['kind']=='interface_inherited' and x['interface']['item']==2);edge['aux']=(edge['aux']+1)%6
  try:verify(forged,name,count)
  except (AssertionError,KeyError,IndexError):pass
  else:raise AssertionError('forged graph edge accepted')
  if count:
   forged=copy.deepcopy(result);field=next(x['interface'] for x in forged['candidates'][0]['evidence'] if x['kind']=='interface_inherited' and x['interface']['item']==4);field['source_index']=(field['source_index']+1)%6
   try:verify(forged,name,count)
   except (AssertionError,KeyError,IndexError):pass
   else:raise AssertionError('forged field origin accepted')
 verify(run('graph','diamond',1,True),'diamond',1)
 missing=run('missing','diamond',1,srcs=paths[:3]+paths[4:]);assert missing['coverage']=='Partial' and missing['unknown_rows']==1 and not missing['candidates']
 for name in ('bad-instance.dex','bad-protected.dex','bad-nofinal.dex','bad-type.dex'):
  badpaths=[a.fixtures/'child-bad.dex',a.fixtures/'base.dex',a.fixtures/'root.dex',a.fixtures/name]
  invalid=run(name,'bad',1,srcs=badpaths);assert invalid['coverage']=='Partial' and invalid['unknown_rows']==1 and not invalid['candidates']
 annotationpaths=[a.fixtures/'child-bad.dex',a.fixtures/'base.dex',a.fixtures/'root.dex',a.fixtures/'annotation.dex']
 valid_annotation=run('annotation','annotationField',1,srcs=annotationpaths)
 assert valid_annotation['coverage']=='Complete' and valid_annotation['decision']=='ProvenTrue' and len(valid_annotation['candidates'])==1
print('PASS v8 independent raw DEX, field graph, diamond, invalid flags and forged witnesses')
