"""Independent raw-byte oracle for real v10 interface + numeric + caller-use composition."""
import argparse,copy,hashlib,json,struct,subprocess,sys,tempfile,zlib
from pathlib import Path

HERE=Path(__file__).resolve().parent
def leb(data,pos):
 value=0
 for shift in range(0,35,7):
  byte=data[pos];pos+=1;value|=(byte&127)<<shift
  if byte<128:return value,pos
 raise ValueError('invalid uleb')
def parse(path):
 d=path.read_bytes();u=lambda n:struct.unpack_from('<I',d,n)[0]
 assert d[:8]==b'dex\n035\0' and u(32)==len(d) and d[12:32]==hashlib.sha1(d[32:]).digest() and u(8)==zlib.adler32(d[12:])&0xffffffff
 strings=[]
 for i in range(u(56)):
  length,pos=leb(d,u(u(60)+i*4));end=d.index(0,pos);s=d[pos:end].decode('ascii');assert len(s)==length;strings.append(s)
 types=[strings[u(u(68)+i*4)] for i in range(u(64))]
 fields=[]
 for i in range(u(80)):
  owner,typ,name=struct.unpack_from('<HHI',d,u(84)+i*8);fields.append((types[owner],types[typ],strings[name]))
 methods=[]
 for i in range(u(88)):
  owner,proto,name=struct.unpack_from('<HHI',d,u(92)+i*8);methods.append((types[owner],proto,strings[name]))
 assert u(96)==1
 owner,flags,parent,ifaces,_,_,class_data,_=struct.unpack_from('<8I',d,u(100));interface_indices=[struct.unpack_from('<H',d,ifaces+4+2*i)[0] for i in range(u(ifaces))] if ifaces else []
 definitions=[];declared=[]
 if class_data:
  counts=[];pos=class_data
  for _ in range(4):count,pos=leb(d,pos);counts.append(count)
  for count in counts[:2]:
   index=0
   for _ in range(count):
    delta,pos=leb(d,pos);access,pos=leb(d,pos);index+=delta;declared.append((index,access))
  for count in counts[2:]:
   index=0
   for _ in range(count):
    delta,pos=leb(d,pos);access,pos=leb(d,pos);code,pos=leb(d,pos);index+=delta;definitions.append((index,access,code))
 return {'bytes':d,'sha':hashlib.sha256(d).hexdigest(),'types':types,'owner':types[owner],'flags':flags,'parent':None if parent==0xffffffff else types[parent],
         'interfaces':[types[x] for x in interface_indices],'interface_indices':interface_indices,'fields':fields,'declared':declared,'methods':methods,'definitions':definitions}
def verify(result,sources,joined):
 assert result['profile']=='dex-query-composite-v10' and result['query_id'].startswith('query:v10:') and result['coverage']=='Complete' and result['decision']=='ProvenTrue'
 assert len(result['candidates'])==1
 row=result['candidates'][0];child,iface,root=sources
 assert row['source_index']==0 and row['source_sha256']==child['sha'] and row['relation']=='method_defs' and row['local_index']==0 and row['reference_index']==0
 assert (row['owner'],row['name'],row['prototype'])==('Lcross/Child;','access','()V')
 witnesses=row['evidence'];events=[w['interface'] for w in witnesses if w['kind']=='interface_inherited']
 nodes={e['node']:e for e in events if e['item']==1};assert len(nodes)==3 and {e['source_index'] for e in nodes.values()}=={0,1,2}
 for e in nodes.values():assert e['relation']=='class_defs' and e['local_index']==0 and e['detail']==int(bool(sources[e['source_index']]['flags']&0x200))
 edges=[e for e in events if e['item']==2];assert len(edges)==2
 for e in edges:
  source=nodes[e['node']]['source_index'];target=nodes[e['aux']]['source_index'];entry=sources[source]
  assert e['source_index']==source and e['relation']=='type_refs' and entry['types'][e['local_index']]==sources[target]['owner']
  assert (e['detail']==0 and entry['parent']==sources[target]['owner']) or (e['detail']==1 and sources[target]['owner'] in entry['interfaces'])
 assert any(e['detail']==1 and nodes[e['aux']]['source_index']==1 for e in edges)
 fs=[e for e in events if e['item']==4];assert len(fs)==1 and fs[0]['source_index']==1 and fs[0]['relation']=='field_defs' and fs[0]['local_index']==0
 assert iface['fields'][0]==('Lcross/Contract;','I','parentOnly') and iface['declared']==[(0,25)]
 branch=[e for e in events if e['item']==5];assert len(branch)==1 and branch[0]['aux']==1 and branch[0]['detail']==2
 numeric=[w for w in witnesses if w['kind']=='numeric_literal'];assert len(numeric)==1
 n=numeric[0];assert n['matched'] is True and n['dex_pc']==0 and n['opcode']==0x12 and n['width_bits']==32 and n['bits']=='ffffffff' and n['literal_kind']=='constant'
 assert n['entity']['source_index']==0 and n['entity']['local_index']==0 and n['code_units']==5
 if joined:
  uses=[b for b in row['bindings'] if b['relation']=='invoke_sites'];assert len(uses)==1
  use=uses[0];assert (use['source_index'],use['local_index'],use['caller_ordinal'],use['dex_pc'],use['opcode'],use['target_index'])==(0,0,0,1,0x71,1)
  assert child['methods'][use['target_index']]==('Lcross/Sink;',0,'call')
  links=row['links'];assert len(links)==1 and links[0]['key']=='caller' and links[0]['left']['local_index']==0 and links[0]['right']['dex_pc']==1
  invoke=[w for w in witnesses if w['kind']=='invoke'];assert len(invoke)==1 and invoke[0]['dex_pc']==1 and invoke[0]['reference_index']==1 and invoke[0]['entity']['source_index']==0

def main():
 p=argparse.ArgumentParser();p.add_argument('--exe',required=True,type=Path);p.add_argument('--fixtures',type=Path);a=p.parse_args();exe=a.exe.resolve()
 with tempfile.TemporaryDirectory(prefix='cross-v10-') as tmp:
  tmp=Path(tmp);generated=tmp/'generated';subprocess.run([sys.executable,'-B',str(HERE.parent/'fixtures/generators/generate_cross_v10.py'),'--output',str(generated)],check=True,capture_output=True)
  fixtures=a.fixtures.resolve() if a.fixtures else generated
  for name in ('child.dex','contract.dex','object.dex','manifest.json'):assert (fixtures/name).read_bytes()==(generated/name).read_bytes()
  sources=[parse(fixtures/name) for name in ('child.dex','contract.dex','object.dex')]
  child,iface,root=sources;assert child['owner']=='Lcross/Child;' and child['parent']=='Ljava/lang/Object;' and child['interfaces']==['Lcross/Contract;']
  assert iface['owner']=='Lcross/Contract;' and iface['flags']==0x601 and root['owner']=='Ljava/lang/Object;'
  ref,flags,code=child['definitions'][0];assert (ref,flags)==(0,9) and child['methods'][ref]==('Lcross/Child;',0,'access')
  data=child['bytes'];assert struct.unpack_from('<I',data,code+12)[0]==5
  words=struct.unpack_from('<5H',data,code+16);assert words==(0xf012,0x0071,1,0,0x000e)
  # Independently decode signed nibble of const/4 and method-ref operand of invoke-static.
  literal=words[0]>>12;literal=literal-16 if literal&8 else literal
  assert literal&0xffffffff==0xffffffff and words[1]&255==0x71 and child['methods'][words[2]]==('Lcross/Sink;',0,'call')
  pred={'all':[{'name':'access'},{'declares_fields':{'scope':'inherited_interfaces','where':{'name':'parentOnly'},'min':1,'max':1}},{'numeric_bits':{'width':32,'bits':'ffffffff','kind':'constant'}}]}
  method={'op':'scan','relation':'method_defs','where':pred};uses={'op':'scan','relation':'invoke_sites'}
  def run(label,query,paths=None):
   path=tmp/(label+'.json');path.write_text(json.dumps({'schema_version':1,'intent':'unique',**query}),encoding='utf-8')
   paths=paths or [fixtures/'child.dex',fixtures/'contract.dex',fixtures/'object.dex'];cmd=[str(exe),'query',str(paths[0])]
   for source in paths[1:]:cmd+=['--source',str(source)]
   q=subprocess.run(cmd+['--query',str(path),'--json'],capture_output=True,text=True,encoding='utf-8',timeout=30)
   assert q.returncode==0,(label,q.returncode,q.stdout,q.stderr);return json.loads(q.stdout)
  single=run('method',{'relation':method});verify(single,sources,False)
  joined=run('join',{'relation':{'op':'join','on':'caller','left':method,'right':uses},'required_capabilities':['use_streaming']});verify(joined,sources,True)
  no_number=copy.deepcopy(method);no_number['where']['all'][2]['numeric_bits']['bits']='00000000'
  negative=run('wrong-numeric',{'relation':no_number});assert negative['coverage']=='Complete' and negative['decision']=='ProvenFalse' and not negative['candidates']
  no_field=copy.deepcopy(method);no_field['where']['all'][1]['declares_fields']['where']['name']='absent'
  negative=run('wrong-field',{'relation':no_field});assert negative['coverage']=='Complete' and negative['decision']=='ProvenFalse' and not negative['candidates']
  absent=run('missing-interface',{'relation':method},[fixtures/'child.dex',fixtures/'object.dex']);assert absent['coverage']=='Partial' and absent['unknown_rows']==1 and not absent['candidates']
  wrong_pc=run('wrong-pc',{'relation':{'op':'join','on':'caller','left':method,'right':{'op':'scan','relation':'invoke_sites','where':{'pc':3}}},'required_capabilities':['use_streaming']});assert wrong_pc['coverage']=='Complete' and wrong_pc['decision']=='ProvenFalse' and not wrong_pc['candidates']
  for label,mutate in [
   ('edge',lambda r:next(w['interface'] for w in r['candidates'][0]['evidence'] if w['kind']=='interface_inherited' and w['interface']['item']==2 and w['interface']['detail']==1).update(aux=1)),
   ('field',lambda r:next(w['interface'] for w in r['candidates'][0]['evidence'] if w['kind']=='interface_inherited' and w['interface']['item']==4).update(source_index=0)),
   ('number',lambda r:next(w for w in r['candidates'][0]['evidence'] if w['kind']=='numeric_literal').update(bits='00000000')),
   ('invoke',lambda r:next(b for b in r['candidates'][0]['bindings'] if b['relation']=='invoke_sites').update(dex_pc=3)),
  ]:
   forged=copy.deepcopy(joined);mutate(forged)
   try:verify(forged,sources,True)
   except (AssertionError,IndexError,KeyError):pass
   else:raise AssertionError('forgery accepted: '+label)
 print('PASS v10 actual interface edge + numeric literal + streamed caller use, raw DEX oracle and negative controls')
if __name__=='__main__':main()
