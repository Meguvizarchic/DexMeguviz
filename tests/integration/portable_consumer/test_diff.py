"""Fixed independent DEX and APK checks for the static diff consumer."""
import argparse, contextlib, hashlib, importlib.util, io, json, struct, subprocess, sys, zlib
from pathlib import Path
if not __debug__: raise SystemExit('test requires assertions enabled')
p=argparse.ArgumentParser()
for name in ('tool','exe','root','out'):p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args(); root=a.root.resolve(); exe=a.exe.resolve(); tool=a.tool.resolve(); out=a.out.resolve()
if out.exists():raise SystemExit('output exists')
fixture=root/'tests/fixtures/generated/graph'; apk=root/'tests/fixtures/generated/multisource'
oracle_path=root/'tests/integration/raw_graph_oracle.py'
entity_oracle_path=root/'tests/integration/entity_query_test.py'
parser_path=root/'tools/evidence_verifier/verify.py'
catalog=root/'tests/fixtures/generated/definition_catalog/definitions.dex'
spec=importlib.util.spec_from_file_location('raw_oracle',oracle_path);oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
inputs=[Path(__file__).resolve(),Path(sys.executable).resolve(),tool,exe,oracle_path,entity_oracle_path,parser_path,catalog,*[fixture/n for n in ('amb-a.dex','amb-b1.dex','amb-b2.dex','amb-overload.dex')],apk/'reverse-stored.apk',apk/'resource-only.apk']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
before={str(x):sha(x) for x in inputs}
parsed={n:oracle.parse(fixture/n) for n in ('amb-a.dex','amb-b1.dex','amb-b2.dex','amb-overload.dex')}
assert tuple(parsed['amb-b1.dex']['definition'])==('Lamb/B;','b','()V')
assert tuple(parsed['amb-b2.dex']['definition'])==('Lamb/B;','b','()V')
assert tuple(parsed['amb-overload.dex']['definition'])==('Lamb/B;','b','(I)V')
assert tuple(parsed['amb-a.dex']['calls'][0]['symbol'])==('Lamb/B;','b','()V')
out.mkdir(parents=True); records=[]
def run(name,args,success=True):
 cmd=[sys.executable,'-B',str(tool),'--exe',str(exe),*map(str,args)]
 r=subprocess.run(cmd,capture_output=True,timeout=300); (out/(name+'.stdout.json')).write_bytes(r.stdout); (out/(name+'.stderr.log')).write_bytes(r.stderr)
 assert (r.returncode==0)==success,(name,r.returncode,r.stderr)
 if not success: assert not r.stdout,(name,'partial output')
 records.append({'name':name,'exit_code':r.returncode,'stdout_sha256':hashlib.sha256(r.stdout).hexdigest()})
 return json.loads(r.stdout) if success else r

def symbol(result, key):
 rows=[x for x in result['symbols'] if x['symbol']==list(key)]
 assert len(rows)==1,(key,len(rows)); return rows[0]
A=fixture/'amb-a.dex'; B=fixture/'amb-b1.dex'; C=fixture/'amb-b2.dex'; O=fixture/'amb-overload.dex'
# Independent raw-byte directories for class/type and field definitions/refs.
assert sha(catalog)=='e1059582b6c893690880403d00f6b5be8dfceb7be282793e2117bdf15b14e77a'
spec=importlib.util.spec_from_file_location('entity_oracle',entity_oracle_path); entity_oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(entity_oracle)
raw=entity_oracle.raw_entities(catalog,root)
result=run('catalog-byte-oracle',['--before',catalog,'--after',catalog,'--before-complete','--after-complete'])
for relation,kind in (('class_defs','class'),('type_refs','class'),('field_defs','field'),('field_refs','field'),('method_refs','method')):
    for row in raw[relation]:
        key=(kind,row['type_descriptor']) if kind=='class' else ((kind,row['owner'],row['name'],row['type_descriptor']) if kind=='field' else (kind,row['owner'],row['name'],row['prototype']))
        group=symbol(result,key)['before']; entity_records=group['definitions' if relation.endswith('_defs') else 'references']
        matching=[x for x in entity_records if x['local_index']==row['local_index']]
        assert len(matching)==1,(relation,key,row['local_index'])
        value=matching[0]
        for field in ('reference_index','record_offset','has_local_definition','definition_offset'):
            assert value[field]==row[field],(relation,key,field,value[field],row[field])
result=run('external-to-one',['--before',A,'--after',A,B,'--before-complete','--after-complete'])
b=symbol(result,('method','Lamb/B;','b','()V'))
assert (b['before']['definition_count'],b['before']['reference_count'],b['before']['observed_resolution'])==(0,1,'no_observed_definition')
assert (b['after']['definition_count'],b['after']['reference_count'],b['after']['observed_resolution'])==(1,2,'one_observed_definition')
assert b['before']['local_definition_count']==0 and b['after']['local_definition_count']==1
result=run('ambiguous-overload',['--before',A,B,'--after',A,B,C,O,'--before-complete','--after-complete'])
b=symbol(result,('method','Lamb/B;','b','()V')); overload=symbol(result,('method','Lamb/B;','b','(I)V'))
assert b['before']['definition_count']==1 and b['after']['definition_count']==2 and b['after']['observed_resolution']=='multiple_observed_definitions'
assert overload['before']['definition_count']==0 and overload['after']['definition_count']==1
assert b['after']['definitions'][0]['occurrence_id']!=b['after']['definitions'][1]['occurrence_id']
result=run('duplicate-occurrences',['--before',B,'--after',B,B])
b=symbol(result,('method','Lamb/B;','b','()V'))
assert not result['before']['scope_complete'] and not result['after']['scope_complete']
assert b['after']['definition_count']==2 and b['after']['definitions'][0]['source_sha256']==b['after']['definitions'][1]['source_sha256']
assert b['after']['definitions'][0]['occurrence_id']!=b['after']['definitions'][1]['occurrence_id']
# Preserve exact symbol/count while changing an encoded method access flag.
changed=bytearray(B.read_bytes()); class_off=struct.unpack_from('<I',changed,100)[0]
class_data=struct.unpack_from('<I',changed,class_off+24)[0]
assert changed[class_data:class_data+6]==bytes([0,0,1,0,0,9])
changed[class_data+5]=0x19  # public static -> public static final; width unchanged
changed[12:32]=hashlib.sha1(changed[32:]).digest()
struct.pack_into('<I',changed,8,zlib.adler32(changed[12:])&0xffffffff)
flagged=out/'flags-changed.dex'; flagged.write_bytes(changed)
result=run('flag-change',['--before',B,'--after',flagged,'--before-complete','--after-complete'])
row=symbol(result,('method','Lamb/B;','b','()V'))
assert not row['count_changed'] and row['attributes_changed']
assert row['before']['definitions'][0]['access_flags']==9 and row['after']['definitions'][0]['access_flags']==25
assert row['before']['definitions'][0]['has_code'] is True and row['after']['definitions'][0]['has_code'] is True
result=run('resource-input',['--before',A,'--after',A,'--after-resource',apk/'resource-only.apk'])
assert len(result['after']['inputs'])==2 and len(result['after']['sources'])==1
assert result['after']['inputs'][1]['allow_no_dex'] is True and result['after']['inputs'][1]['source_count']==0
result=run('apk-expansion',['--before',A,'--after',apk/'reverse-stored.apk'])
assert len(result['after']['sources'])==3 and [x['archive_entry_name'] for x in result['after']['sources']]==['classes.dex','classes2.dex','classes10.dex']
assert b'BudgetExceeded/ResultLimit' in run('result-limit',['--before',A,'--after',A,'--max-results','1'],False).stderr
assert b'BudgetExceeded' in run('work-limit',['--before',A,'--after',A,'--max-work','1'],False).stderr
large=out/'over-limit.dex'; large.write_bytes(bytes(1024*1024+1))
assert b'inputs exceed configured byte limit' in run('input-limit',['--before',large,'--after',A,'--max-input-mib','1'],False).stderr
# Mutate a private before-input after the after-side scan completes.
# The tool must detect it before it emits any JSON.
race_before=out/'race-before.dex'; race_before.write_bytes(A.read_bytes())
spec=importlib.util.spec_from_file_location('diff_under_test',tool); diff=importlib.util.module_from_spec(spec);spec.loader.exec_module(diff)
original_source_set=diff.source_set; calls=[]
def changed_between_sides(*args,**kwargs):
    value=original_source_set(*args,**kwargs); calls.append(1)
    if len(calls)==2: race_before.write_bytes(race_before.read_bytes()+b'\x00')
    return value
diff.source_set=changed_between_sides
class Capture:
    def __init__(self):self.buffer=io.BytesIO()
    def write(self,text):return len(text)
    def flush(self):pass
captured=Capture(); errors=io.StringIO()
with contextlib.redirect_stdout(captured),contextlib.redirect_stderr(errors):
    code=diff.main(['--exe',str(exe),'--before',str(race_before),'--after',str(B)])
assert code==2 and captured.buffer.getvalue()==b'' and 'input bytes changed before output' in errors.getvalue()
(out/'race.stderr.log').write_text(errors.getvalue(),encoding='utf-8')
records.append({'name':'before-changed-after-scan','exit_code':code,'stdout_sha256':hashlib.sha256(captured.buffer.getvalue()).hexdigest()})
after={str(x):sha(x) for x in inputs};assert before==after
(out/'summary.json').write_text(json.dumps({'outcome':'passed','scope':'fixed project-original fixtures, static input comparison only','input_sha256_before':before,'input_sha256_after':after,'records':records},indent=2)+'\n',encoding='utf-8')
print('PASS static symbol diff, provenance, incomplete scope and failure controls')






