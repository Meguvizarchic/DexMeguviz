"""Compare Kotlin-generated IR with independently authored CLI JSON cases."""
import argparse,json,subprocess,tempfile
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('--exe',required=True,type=Path);p.add_argument('--fixture',required=True,type=Path);p.add_argument('--lines',required=True,type=Path);a=p.parse_args()
generated={}
for line in a.lines.read_text(encoding='utf-8').splitlines():
 name,query=line.split('\t',1);assert name not in generated;generated[name]=json.loads(query)
golden={
 'exact':({'name':{'op':'exact','value':'locate'}},'unique'),
 'fold':({'name':{'op':'exact','value':'LOCATE','ascii_case_insensitive':True}},'unique'),
 'empty':({'name':{'op':'contains','value':''}},'enumerate'),
 'flags':({'flags_contains':256},'enumerate'),
 'unicode':({'name':{'op':'exact','u16':[65,0,55296,88,57343]}},'unique'),
 'and-not':({'all':[{'name':{'op':'prefix','value':'lo'}},{'not':{'flags_any':8}}]},'enumerate')
}
assert set(generated)==set(golden)
with tempfile.TemporaryDirectory(prefix='dmg-kotlin-v1-') as temp:
 temp=Path(temp)
 def run(label,query):
  path=temp/(label+'.json');path.write_text(json.dumps(query,ensure_ascii=True),encoding='utf-8')
  result=subprocess.run([str(a.exe.resolve()),'query',str(a.fixture.resolve()),'--query',str(path),'--json'],capture_output=True,text=True,encoding='utf-8',timeout=30)
  assert result.returncode==0,(label,result.stdout,result.stderr);return json.loads(result.stdout)
 for name,(where,intent) in golden.items():
  expected={'schema_version':1,'relation':'method_defs','where':where,'intent':intent,'max_results':4096,'max_work':100000000}
  kt=run(name+'-kt',generated[name]);control=run(name+'-control',expected)
  assert kt['profile']=='dex-query-method-v1' and kt['query_id'].startswith('query:v1:')
  for key in ('query_id','coverage','decision','reason','execution_status'):assert kt[key]==control[key],(name,key,kt[key],control[key])
  def rows(result):return [(r['source_index'],r['method_index'],r['owner'],r['name'],r['prototype'],r['access_flags']) for r in result['candidates']]
  assert rows(kt)==rows(control),name
print('PASS Kotlin-generated QueryIR vs independently authored CLI controls: text, raw flags, UTF-16 and boolean forms')
