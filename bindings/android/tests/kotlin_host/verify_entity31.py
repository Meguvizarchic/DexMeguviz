"""Compare Kotlin entity writer with independently authored core CLI queries."""
import argparse, json, struct, subprocess, tempfile
from pathlib import Path

p=argparse.ArgumentParser()
for name in ('exe','fixture','lines'): p.add_argument('--'+name,required=True,type=Path)
a=p.parse_args()
values={}
for line in a.lines.read_text(encoding='utf-8').splitlines():
    name,doc=line.split('\t',1);assert name not in values;values[name]=json.loads(doc)
relations={'METHOD_DEFS':'method_defs','CLASS_DEFS':'class_defs','FIELD_DEFS':'field_defs',
           'METHOD_REFS':'method_refs','FIELD_REFS':'field_refs','TYPE_REFS':'type_refs','STRING_VALUES':'string_values'}
golden={'all-'+k:(v,True) for k,v in relations.items()}
golden.update({
 'class':('class_defs',{'descriptor':'Lcatalog/Child;'}),
 'field':('field_defs',{'all':[{'type':'J'},{'flags_contains':8}]}),
 'external-field':('field_refs',{'has_local_definition':False}),
 'unknown-flags':('field_refs',{'flags_contains':0}),
 'owner-flags':('field_refs',{'owner_flags':{'domain':'dex','mode':'contains','value':1}}),
 'method-ref':('method_refs',{'name':'abstractMethod'}),
 'external-type':('type_refs',{'descriptor':'Lexternal/External;'}),
 'string':('string_values',{'value':'shared'}),
 'method-kind':('method_defs',{'kind':'normal'}),
 'not-unknown':('field_refs',{'not':{'flags_contains':0}}),
 'class-owner':('class_defs',{'superclass':'Lcatalog/Base;'}),
 'absent-utf16':('string_values',{'value':{'op':'exact','u16':[0,55296,34,92,57343]}}),
 'absent-utf16-value':('string_values',{'value':{'op':'exact','u16':[0,55296,34,92,57343]}}),
 'method-param':('method_refs',{'param_count':0}),
 'method-param-range':('method_refs',{'param_count':{'min':0,'max':0}}),
 'method-param-absent':('method_refs',{'parameter':{'index':0,'type':'I'}})})
assert set(values)==set(golden),(set(values)^set(golden))
fixture=a.fixture.read_bytes();u32=lambda offset:struct.unpack_from('<I',fixture,offset)[0]
counts={'method_defs':1,'class_defs':5,'field_defs':3,'method_refs':u32(88),'field_refs':u32(80),'type_refs':u32(64),'string_values':u32(56)}
with tempfile.TemporaryDirectory(prefix='dmg-kotlin-entities-') as temp:
    temp=Path(temp)
    def run(label,query):
        path=temp/(label+'.json');path.write_text(json.dumps(query,ensure_ascii=True),encoding='utf-8')
        result=subprocess.run([str(a.exe.resolve()),'query',str(a.fixture.resolve()),'--query',str(path),'--json'],capture_output=True,text=True,encoding='utf-8',timeout=30)
        assert result.returncode==0,(label,result.returncode,result.stdout,result.stderr)
        return json.loads(result.stdout)
    for name,(relation,where) in golden.items():
        expected={'schema_version':1,'relation':relation,'where':where,'intent':'enumerate','max_results':4096,'max_work':100000000}
        actual=run(name+'-kotlin',values[name]);control=run(name+'-manual',expected)
        for key in ('query_id','coverage','decision','reason','execution_status','candidates'):
            assert actual[key]==control[key],(name,key,actual.get(key),control.get(key))
        if name.startswith('all-'):assert len(actual['candidates'])==counts[relation],(name,len(actual['candidates']),counts[relation])
        if name in ('class','field','external-field','method-ref','external-type','string','method-kind','class-owner','method-param','method-param-range'):
            assert len(actual['candidates'])==1,(name,actual['candidates'])
        if name in ('absent-utf16','absent-utf16-value','method-param-absent'):assert not actual['candidates']
        if name=='unknown-flags':assert len(actual['candidates'])==3 and actual['unknown_rows']==1 and actual['coverage']=='Partial'
        if name=='owner-flags':assert len(actual['candidates'])==3 and actual['unknown_rows']==1 and actual['coverage']=='Partial'
        if name=='not-unknown':assert not actual['candidates'] and actual['unknown_rows']==1 and actual['coverage']=='Partial'
print('PASS 23 entity Kotlin JSON queries vs independently authored CLI; Unknown and root counts checked')
