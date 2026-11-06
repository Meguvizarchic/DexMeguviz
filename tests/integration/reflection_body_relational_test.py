"""Independent DEX bytes and targeted v17 graph/compatibility controls."""
import argparse,copy,hashlib,json,os,struct,subprocess,sys,zlib
from pathlib import Path
if not __debug__:raise SystemExit('assertions required')
p=argparse.ArgumentParser()
for x in ('exe','old-exe','fixture','out'):p.add_argument('--'+x,type=Path,required=True)
a=p.parse_args();out=a.out;assert not out.exists();out.mkdir(parents=True)
data=a.fixture.read_bytes();sha=lambda x:hashlib.sha256(x).hexdigest();exe_before=sha(a.exe.read_bytes());old_before=sha(a.old_exe.read_bytes());assert sha(data)=='8262d2b338e54a7965111b4cec1ef9e628ada9795ad2f6a555d717a2ba9546bc'
u32=lambda at:struct.unpack_from('<I',data,at)[0]
def leb(pos):
 value=0
 for i in range(5):
  b=data[pos+i];assert i<4 or b<=15;value|=(b&127)<<(7*i)
  if b<128:return value,pos+i+1
 raise AssertionError('invalid leb')
strings=[]
for i in range(u32(56)):
 at=u32(u32(60)+4*i);n,pos=leb(at);end=data.index(0,pos);raw=data[pos:end];assert len(raw)==n and all(0<x<128 for x in raw);strings.append(raw.decode('ascii'))
names=[strings[u32(u32(92)+8*i+4)] for i in range(u32(88))];assert names==['abstractMethod','nativeMethod','quiet','uses','sink']
cursor=u32(u32(100)+24);sizes=[]
for i in range(4):n,cursor=leb(cursor);sizes.append(n)
assert sizes==[1,0,3,1]
for i in range(sum(sizes[:2])):_,cursor=leb(cursor);_,cursor=leb(cursor)
methods=[];idx=0;flag_at=None
for i in range(sizes[2]):
 delta,cursor=leb(cursor);idx+=delta;at=cursor;flags,cursor=leb(cursor);code,cursor=leb(cursor);methods.append((names[idx],flags,code))
 if names[idx]=='uses':flag_at=at
assert methods==[('nativeMethod',0x109,0),('quiet',9,396),('uses',9,416)] and flag_at is not None
assert list(struct.unpack_from('<8H',data,432))==[0x001a,strings.index('used-string'),0x0071,4,0,0x0060,0,0x000e]
def variant(name,changes):
 b=bytearray(data)
 for at,value in changes:b[at]=value
 b[12:32]=hashlib.sha1(b[32:]).digest();struct.pack_into('<I',b,8,zlib.adler32(b[12:])&0xffffffff);f=out/(name+'.dex');f.write_bytes(b);return f
normal=out/'normal.dex';normal.write_bytes(data);unknown=variant('unknown',[(flag_at,0x0b)]);broken=variant('bad-body',[(432,0x3e)])
flag={'flags':{'domain':'reflection','mode':'contains','value':8}}
uses={'using_strings':{'all':[{'op':'exact','value':'used-string'}]}}
missing={'using_strings':{'all':[{'op':'exact','value':'not-in-pool'}]}}
inv={'invokes':{'all':[{'name':'sink','param_count':0}]}}
field={'field_access':{'all':[{'name':'counter','access':'read'}]}}
caps=['reflection_flags_static','reflection_relational','reflection_body_relational']
scan=lambda rel,where=None:dict({'op':'scan','relation':rel},**({'where':where} if where is not None else {}))
all3={'all':[{'name':'uses'},flag,uses,inv,field]};target=scan('method_defs',all3)
base={'schema_version':1,'relation':target,'intent':'unique','max_results':100,'required_capabilities':caps};records=[]
def call(name,q,src=normal,code=0,sources=(),partial=False,exe=None):
 qp=out/(name+'.query.json');qp.write_text(json.dumps(q,ensure_ascii=True),encoding='utf-8');cmd=[str((exe or a.exe).resolve()),'query',str(src.resolve())]
 for f in sources:cmd+=['--source',str(f.resolve())]
 if partial:cmd+=['--scope-incomplete']
 cmd+=['--query',str(qp.resolve()),'--json'];r=subprocess.run(cmd,capture_output=True,timeout=60,env=os.environ.copy());(out/(name+'.stdout.json')).write_bytes(r.stdout);(out/(name+'.stderr.log')).write_bytes(r.stderr)
 assert r.returncode==code,(name,r.returncode,r.stdout,r.stderr);v=json.loads(r.stdout);records.append({'name':name,'argv':cmd,'exit_code':r.returncode,'stdout_sha256':sha(r.stdout),'stderr_sha256':sha(r.stderr)})
 (out/'commands.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8');return v
def ok(name,rel,**kw):
 q={**base,'relation':rel,**kw.pop('query',{})};v=call(name,q,**kw);assert v['profile']=='dex-query-reflection-body-relational-v17' and v['query_id'].startswith('query:v17:') and v['execution_status']=='Complete',(name,v);return v
def vals(v):return [(x['source_index'],x['local_index'],x['name']) for x in v['candidates']]
r=ok('all',target);assert vals(r)==[(0,2,'uses')] and r['decision']=='ProvenTrue' and r['coverage']=='Complete'
assert {(e['kind'],e['dex_pc']) for e in r['candidates'][0]['evidence'] if e['kind'] in ('string_use','invoke','field_use')}=={('string_use',0),('invoke',2),('field_use',5)}
split={'op':'filter','input':scan('method_defs',{'all':[{'name':'uses'},flag]}),'where':{'all':[uses,inv,field]}}
r=ok('filter',split);assert vals(r)==[(0,2,'uses')] and {(e['kind'],e['dex_pc']) for e in r['candidates'][0]['evidence'] if e['kind'] in ('string_use','invoke','field_use')}=={('string_use',0),('invoke',2),('field_use',5)}
right=scan('method_refs',{'name':'uses'});join={'op':'join','on':'symbol','left':target,'right':right};r=ok('join-two-occurrences',join,sources=(normal,),query={'intent':'enumerate'});assert len(r['candidates'])==4 and [x['source_index'] for x in r['candidates']]==[0,0,1,1]
for x in r['candidates']:
 assert x['local_index']==2 and len(x['links'])==1 and x['links'][0]['left']['source_index']==x['source_index'] and x['links'][0]['right']['relation']=='method_refs' and x['links'][0]['right']['local_index']==names.index('uses')
semi={'op':'semi_join','on':'symbol','left':target,'right':right};r=ok('semi-two-occurrences',semi,sources=(normal,),query={'intent':'enumerate'});assert vals(r)==[(0,2,'uses'),(1,2,'uses')] and all(x['proof_bindings'] for x in r['candidates'])
group={'op':'group_by_owner','inputs':[{'op':'label','label':'m','input':target}],'required_roles':['m']};r=ok('group',group,query={'intent':'enumerate'});assert len(r['candidates'])==1 and r['candidates'][0]['relation']=='class_defs' and r['candidates'][0]['type_descriptor']=='Lfacts/Example;'
u={'op':'union','semantics':'bag','inputs':[target,target]};r=ok('bag',u,query={'intent':'enumerate'});assert len(r['candidates'])==2
r=ok('distinct',{'op':'distinct','identity':'entity','input':u},query={'intent':'unique'});assert vals(r)==[(0,2,'uses')] and r['decision']=='ProvenTrue'
r=ok('unknown-true',target,src=unknown);assert (r['coverage'],r['decision'],r['unknown_rows'])==('Partial','Undetermined',1)
r=ok('unknown-false',scan('method_defs',{'all':[{'name':'uses'},flag,missing]}),src=unknown);assert (r['coverage'],r['decision'],r['unknown_rows'])==('Complete','ProvenFalse',0)
r=ok('unknown-or-true',scan('method_defs',{'all':[{'name':'uses'},{'any':[flag,uses]}]}),src=unknown);assert vals(r)==[(0,2,'uses')] and r['coverage']=='Complete'
r=ok('unknown-not',scan('method_defs',{'all':[{'name':'uses'},{'not':flag},uses]}),src=unknown);assert r['coverage']=='Partial' and r['decision']=='Undetermined' and r['unknown_rows']==1
r=ok('scope-partial',target,partial=True);assert r['decision']=='Undetermined' and r['coverage']=='Partial'
r=ok('body-skip',scan('method_defs',{'all':[{'name':'uses'},{'flags':{'domain':'reflection','value':2}},uses]}),src=broken);assert r['decision']=='ProvenFalse' and r['query_profile']['methods_decoded']==0
v=call('body-corrupt',{**base,'relation':target},src=broken,code=2);assert v['execution_status'] in ('Unsupported','CorruptInput') and not v.get('candidates',[])
v=call('budget',{**base,'max_work':1},code=3);assert v['execution_status']=='BudgetExceeded' and not v.get('candidates',[])
bad=[('missing-v17',{**base,'required_capabilities':caps[:2]}),('missing-v14',{**base,'required_capabilities':[caps[0],caps[2]]}),('missing-reflection-cap',{**base,'required_capabilities':caps[1:]}),('no-reflection',{**base,'relation':scan('method_defs',uses)}),('no-body',{**base,'relation':scan('method_defs',flag)}),('direct',{**base,'relation':'method_defs','where':all3}),('event-scan',{**base,'relation':{'op':'join','on':'caller','left':scan('invoke_sites'),'right':scan('method_defs',{'all':[flag,uses]})}}),('advanced',{**base,'required_capabilities':caps+['numeric_literals']}),('v15-mix',{**base,'required_capabilities':caps+['reflection_method_uses']}),('target-symbol-mix',{**base,'required_capabilities':caps+['use_target_symbol']})]
for name,q in bad:
 v=call(name,q,code=2);assert v['execution_status']=='Unsupported',(name,v)
# Independent canonical bytes for a fixed Scan with reflection + string use.
u=lambda *x:struct.pack('<'+'I'*len(x),*x)
frame=lambda b:struct.pack('<Q',len(b))+b
flag_bytes=u(11,0,2,8,0xffffffff,0)
value='used-string';body_bytes=u(14,1,0,0)+struct.pack('<Q',len(value))+value.encode('utf-16le')+u(0,0,0xffffffff,0)
predicate=u(2,0,0,0,0xffffffff,2)+frame(flag_bytes)+frame(body_bytes)
top=struct.pack('<IIIQIIIIIIII',0,0,4096,100000000,7,1,0,39846439,0,100000,0,0)
encoded_scan=u(0,0,1)+frame(predicate)+u(0,1,0xffffffff,1,0,0,0,0,0,0)
canonical=b'DexMeguviz:QueryIR:reflection-body-relational-v17'+top+encoded_scan
assert len(canonical)==287 and hashlib.sha256(canonical).hexdigest()=='67e8c0fffefab86676aecfe4605199572005c9718d9325a64b4ee1317a51ca2e'
golden_query={'schema_version':1,'required_capabilities':caps,'relation':scan('method_defs',{'all':[flag,uses]})}
golden=call('canonical-golden',golden_query);assert golden['query_id']=='query:v17:'+hashlib.sha256(canonical).hexdigest()
reordered=copy.deepcopy(golden_query);reordered['relation']['where']['all'].reverse();assert call('canonical-reordered',reordered)['query_id']==golden['query_id']
limited={**golden_query,'max_work':99999999};assert call('canonical-limit',limited)['query_id']!=golden['query_id']
intent={**golden_query,'intent':'unique'};assert call('canonical-intent',intent)['query_id']!=golden['query_id']
legacy=[('v13',{'schema_version':1,'relation':'method_defs','where':flag,'required_capabilities':['reflection_flags_static']}),('v14',{'schema_version':1,'relation':scan('method_defs',flag),'required_capabilities':caps[:2]}),('v15',{'schema_version':1,'relation':'method_defs','where':{'all':[{'name':'uses'},flag,uses]},'required_capabilities':['reflection_flags_static','reflection_method_uses']}),('v16',{'schema_version':1,'relation':{'op':'join','on':'target_symbol','left':scan('invoke_sites'),'right':scan('method_refs')},'required_capabilities':['use_target_symbol']})]
for name,q in legacy:
 new=call('new-'+name,q);old=call('old-'+name,q,exe=a.old_exe);assert new['query_id']==old['query_id'] and new['profile']==old['profile'] and new['coverage']==old['coverage'] and new['decision']==old['decision']
assert sha(a.exe.read_bytes())==exe_before and sha(a.old_exe.read_bytes())==old_before and a.fixture.read_bytes()==data;(out/'summary.json').write_text(json.dumps({'outcome':'passed','fixture_sha256':sha(data),'exe_sha256':sha(a.exe.read_bytes()),'old_exe_sha256':sha(a.old_exe.read_bytes()),'cases':len(records),'commands':records,'scope':'fixed DEX byte oracle and CLI v17 graph controls; no Android or ART'},indent=2)+'\n',encoding='utf-8');print('PASS',len(records),'v17 cases')
