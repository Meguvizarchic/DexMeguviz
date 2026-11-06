"""Independent canonical encoding and profile collision checks for v8."""
import argparse,hashlib,json,struct,subprocess,tempfile
from pathlib import Path
u32=lambda x:struct.pack('<I',x);u64=lambda x:struct.pack('<Q',x)
prefix=b'DexMeguviz:QueryIR:interface-v8'
def canonical(relation,projection,caps,node):
 return prefix+u32(relation)+u32(0)+u32(4096)+u64(100000000)+u32(projection)+u32(0)+u32(0)+u32(caps)+u32(0)+u32(0)+node
yes=u32(0)+u32(0)+u32(0)+u32(0)+u32(0xffffffff)+u32(0)
name='diamond';leaf=u32(31)+u32(0)+u32(0)+u32(1)+u32(1)
leaf+=u32(0)+(u32(1)+u32(0)+u32(0)+u64(len(name))+name.encode('utf-16le'))+u32(0)+u32(0)+u32(0)+u32(0)
expected={'capability':'query:v8:'+hashlib.sha256(canonical(0,7,65539,yes)).hexdigest(),
          'predicate':'query:v8:'+hashlib.sha256(canonical(1,8,65794,leaf)).hexdigest()}
assert expected['capability']=='query:v8:2703d67716f1775d3b8bfe864336ff827746b6dc4cf3842d63396b40c21facd3'
assert expected['predicate']=='query:v8:a2a118ec856532a0d696ef21086054299731521bf03c7243cb706fac8bda1caf'
p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True);a=p.parse_args()
interface={'declares_fields':{'scope':'inherited_interfaces','where':{'name':name},'min':1,'max':1}}
old={'declares_fields':{'scope':'inherited','where':{'name':name},'min':1,'max':1}}
numeric={'numeric_bits':{'width':32,'bits':'ffffffff','kind':'constant'}}
valid={'capability':{'schema_version':1,'relation':'method_defs','required_capabilities':['interface_fields']},
       'predicate':{'schema_version':1,'relation':'class_defs','where':interface}}
invalid=[{'where':{'all':[interface,old]}},
 {'where':interface,'required_capabilities':['inherited_fields']},
 {'where':old,'required_capabilities':['interface_fields']},
 {'required_capabilities':['interface_fields','inherited_fields']},
 {'where':interface,'required_capabilities':['bounded_expand']},{'where':interface,'required_capabilities':['use_streaming']},
 {'required_capabilities':['interface_fields','bounded_expand']},{'required_capabilities':['interface_fields','use_streaming']}]
with tempfile.TemporaryDirectory(prefix='dmg-v8-queryid-') as tmp:
 def run(label,q):
  path=Path(tmp)/(label+'.json');path.write_text(json.dumps(q),encoding='utf-8')
  r=subprocess.run([str(a.exe),'query',str(a.fixture),'--query',str(path),'--json'],capture_output=True,text=True,encoding='utf-8',timeout=30)
  return r.returncode,json.loads(r.stdout)
 for label,q in valid.items():
  rc,v=run(label,q);assert rc==0 and v['profile']=='dex-query-interface-v8' and v['query_id']==expected[label],(label,rc,v.get('query_id'))
 for i,q in enumerate(invalid):
  rc,v=run('invalid-'+str(i),{'schema_version':1,'relation':'method_defs',**q});assert rc==2 and v['execution_status']=='Unsupported' and not v['candidates']
print('PASS independently encoded v8 QueryIDs and unsupported mixed-capability rejection')
