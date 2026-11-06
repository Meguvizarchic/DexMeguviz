"""Behavioral JSON QueryIR checks with authored expectations and raw PC verification."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess,time,zlib

def run(exe:Path,root:Path):
 out=root/'docs/evidence/query-ir'/('run-'+str(time.time_ns()));out.mkdir(parents=True)
 source=root/'tests/fixtures/generated/method_facts/method-uses.dex'
 minimal=root/'tests/fixtures/generated/minimal.dex';late=root/'tests/fixtures/generated/query-ir/late-better.dex'
 manifest=json.loads((source.parent/'expected.json').read_text());data=source.read_bytes();records=[];binary=hashlib.sha256(exe.read_bytes()).hexdigest()
 def call(name,where=None,*,input=source,extra=None,code=0,**options):
  query={'schema_version':1,'relation':'method_defs','where':where or {},'intent':'enumerate','max_results':32,**options}
  path=out/(name+'.query.json');path.write_text(json.dumps(query,ensure_ascii=True,indent=2),encoding='utf-8')
  command=[str(exe),'query',str(input),'--query',str(path),'--json',*(extra or [])]
  p=subprocess.run(command,capture_output=True,timeout=20)
  (out/(name+'.stdout.json')).write_bytes(p.stdout);(out/(name+'.stderr.log')).write_bytes(p.stderr)
  records.append({'name':name,'command':command,'exit_code':p.returncode,'stdout_sha256':hashlib.sha256(p.stdout).hexdigest()})
  (out/'commands.json').write_text(json.dumps(records,ensure_ascii=False,indent=2),encoding='utf-8')
  assert p.returncode==code,(name,p.returncode,p.stdout,p.stderr)
  value=json.loads(p.stdout.decode('utf-8'));assert value['profile']=='dex-query-method-v1'
  return value
 full={'name':'uses','using_strings':{'all':['used-string',{'op':'contains','value':'string'}]},'invokes':{'all':[{'owner':'Ljava/lang/Object;','name':'sink','parameters':[]}]},'field_access':{'all':[{'type':'I','access':'read'}]}}
 result=call('all-body',full,intent='unique');assert result['decision']=='ProvenTrue' and len(result['candidates'])==1
 candidate=result['candidates'][0];assert candidate['name']=='uses' and result['query_profile']['methods_decoded']==1
 for witness in candidate['evidence']:
  pc=witness['dex_pc']
  if pc is None:continue
  at=candidate['code_offset']+16+2*pc;word=struct.unpack_from('<H',data,at)[0]
  assert word&255==witness['opcode']
  expected={'string_use':(0,10),'invoke':(2,4),'field_use':(5,0)}[witness['kind']]
  assert (pc,witness['reference_index'])==expected
  assert struct.unpack_from('<H',data,at+2)[0]==witness['reference_index']
 assert len([w for w in candidate['evidence'] if w['kind']=='string_use'])==2
 a=call('canonical-a',{'all':[{'using_strings':{'all':['used-string']}},{'flags_contains':8},{'name':'uses'}]},intent='unique')
 b=call('canonical-b',{'name':{'op':'exact','u16':[117,115,101,115]},'flags':{'mode':'contains','domain':'dex','value':8},'using_strings':{'all':[{'value':'used-string','op':'exact'}]}},intent='unique')
 assert a['query_id']==b['query_id'] and a['candidates'][0]['evidence']==b['candidates'][0]['evidence']
 assert call('pool-only',{'using_strings':{'all':['only-in-pool']}},intent='unique')['reason']=='NoMatch'
 assert len(call('not-pool-only',{'not':{'using_strings':{'all':['only-in-pool']}}})['candidates'])==4
 assert call('ascii-fold',{'name':{'op':'exact','value':'USES','ascii_case_insensitive':True}},intent='unique')['decision']=='ProvenTrue'
 projection=call('identity-projection',{'name':'uses'},projection=['identity']);assert len(projection['candidates'])==1
 assert not {'owner','name','prototype'}&projection['candidates'][0].keys()
 assert projection['candidates'][0]['evidence']
 ranked=call('topn-late',input=minimal,extra=['--source',str(late)],intent='top_n',max_results=1,order_by=[{'field':'name','direction':'desc'}])
 assert ranked['decision']=='ProvenTrue' and ranked['candidates'][0]['name']=='zzzzzz' and ranked['candidates'][0]['source_index']==1 and ranked['query_profile']['order_verified']
 partial=call('topn-incomplete',input=minimal,extra=['--source',str(late),'--scope-incomplete'],intent='top_n',max_results=1,order_by=[{'field':'name','direction':'desc'}])
 assert partial['decision']=='Undetermined' and partial['coverage']=='Partial' and not partial['query_profile']['order_verified']
 scoped=call('explicit-subscope',{'name':'uses'},extra=['--source',str(source),'--scope-incomplete'],intent='unique',scope={'slots':['input:0:'+str(source)]})
 assert scoped['decision']=='ProvenTrue' and scoped['coverage']=='Complete' and scoped['query_scope']['sources']==[0] and scoped['scope_complete'] is False
 assert call('missing-scope',scope={'slots':['missing']},code=2)['execution_status']=='SourceMismatch'
 assert call('work-budget',max_work=1,code=3)['execution_status']=='BudgetExceeded'
 assert call('unknown-capability',required_capabilities=['invented'],code=2)['execution_status']=='Unsupported'
 bad=bytearray(data);bad[manifest['uses']['code_offset']+16]=0x73;bad[12:32]=hashlib.sha1(bad[32:]).digest();struct.pack_into('<I',bad,8,zlib.adler32(bad[12:]))
 bad_path=out/'bad-opcode.dex';bad_path.write_bytes(bad)
 assert call('metadata-does-not-decode',{'name':'uses'},input=bad_path)['query_profile']['methods_decoded']==0
 failed=call('negative-cannot-hide-corrupt',{'name':'uses','not':{'using_strings':{'all':['used-string']}}},input=bad_path,code=2)
 assert failed['execution_status']=='CorruptInput' and failed['decision']=='Undetermined'
 assert hashlib.sha256(exe.read_bytes()).hexdigest()==binary
 report={'passed':len(records),'failed':0,'executable_sha256':binary,'raw_PC_verification':True,'canonical_query_and_witness_equivalence':True,'result_directory':str(out),'scope':'Method-root QueryIR subset; not full relational IR, runtime binding or BIL33 acceptance'}
 (out/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');return report
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2]);a=p.parse_args()
 print(json.dumps(run(a.exe.resolve(),a.root.resolve()),indent=2))
