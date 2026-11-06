"""Fixed-domain cross-occurrence comparisons using independent raw DEX parsers."""
from pathlib import Path
from collections import Counter
import argparse,hashlib,importlib.util,json,subprocess

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def main():
 a=argparse.ArgumentParser();a.add_argument('--root',type=Path,required=True);a.add_argument('--exe',type=Path,required=True);a.add_argument('--output',type=Path,required=True);x=a.parse_args();x.output.mkdir(parents=True,exist_ok=False)
 raw=load('use_oracle',x.root/'tests/integration/use_query_test.py');meta=load('entity_oracle',x.root/'tests/integration/entity_query_test.py');sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs=[];records=[]
 cases=[('field-ref','field-read-write.dex','field_uses','field_refs'),('field-def','field-read-write.dex','field_uses','field_defs'),('string','string-normal-jumbo.dex','string_uses','string_values'),('poly','invoke-domains-038.dex','invoke_sites','method_refs')]
 for name,file,relation,target in cases:
  path=x.root/'tests/fixtures/generated'/('method_facts' if name=='poly' else 'use_relations')/file;inputs.append(path)
  events=[e for e in raw.raw_fixture(path) if e[0]==relation and e[3]!='call_site'];entries=meta.raw_entities(path,x.root)
  def symbol(row):return tuple(row[k] for k in (['string_value'] if target=='string_values' else ['owner','name','type_descriptor'] if target.startswith('field_') else ['owner','name','prototype']))
  refs=entries['string_values' if relation=='string_uses' else 'field_refs' if relation=='field_uses' else 'method_refs']
  expected=Counter((source,e[1],dest,row['local_index'],e[2],e[3],e[4],e[5],symbol(row)) for source in range(2) for e in events for dest in range(2) for row in entries[target] if symbol(row)==symbol(refs[e[4]]))
  for reverse in (False,True):
   left={'op':'scan','relation':relation};right={'op':'scan','relation':target}
   if reverse:left,right=right,left
   q={'schema_version':1,'required_capabilities':['use_target_symbol'],'relation':{'op':'join','left':left,'right':right,'on':'target_symbol'},'max_results':100}
   name2=name+('-reverse' if reverse else '-forward');qp=x.output/(name2+'.query.json');qp.write_text(json.dumps(q),encoding='utf-8')
   cmd=[str(x.exe),'query',str(path),'--source',str(path),'--query',str(qp),'--json'];result=subprocess.run(cmd,capture_output=True,timeout=60)
   (x.output/(name2+'.stdout.json')).write_bytes(result.stdout);(x.output/(name2+'.stderr.log')).write_bytes(result.stderr);v=json.loads(result.stdout)
   assert result.returncode==0 and v['profile']=='dex-query-use-target-symbol-v16' and v['coverage']=='Complete',(name2,result.returncode,result.stderr)
   assert v['sources'][0]['content_id']==v['sources'][1]['content_id'] and v['sources'][0]['occurrence_id']!=v['sources'][1]['occurrence_id']
   actual=[]
   for row in v['candidates']:
    assert len(row['links'])==1 and row['links'][0]['key']=='target_symbol'
    event=next(b for b in row['bindings'] if b['relation']==relation);obj=next(b for b in row['bindings'] if b['relation']==target)
    keys=['string_value'] if target=='string_values' else ['owner','name','type_descriptor'] if target.startswith('field_') else ['owner','name','prototype']
    actual.append((event['source_index'],event['dex_pc'],obj['source_index'],obj['local_index'],event['opcode'],event['target_domain'],event['target_index'],event['extra_proto'],tuple(obj[k] for k in keys)))
   assert Counter(actual)==expected,(name2,actual,expected)
   records.append({'name':name2,'count':len(actual),'stdout_sha256':sha(x.output/(name2+'.stdout.json'))})
 result={'passed':len(records),'failed':0,'records':records,'exe_sha256':sha(x.exe),'inputs_sha256':{str(p):sha(p) for p in inputs},'scope':'fixed duplicate DEX occurrences; raw fixture opcodes and reference/definition symbols; no runtime binding or ART'}
 (x.output/'summary.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps({'passed':len(records)}))
if __name__=='__main__':main()
