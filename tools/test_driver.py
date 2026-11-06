"""Behavioral integration checks. Uses independent original-byte evidence oracle."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--cli',type=Path,required=True)
    parser.add_argument('--root',type=Path,required=True)
    args=parser.parse_args()
    root=args.root.resolve()
    spec=importlib.util.spec_from_file_location('independent_oracle',root/'tools/evidence_verifier/verify.py')
    oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
    fixture_root=root/'tests/fixtures'
    manifest=json.loads((fixture_root/'manifest.json').read_text(encoding='utf-8'))
    passed=0
    def call(arguments,expected_code=0):
        result=subprocess.run([str(args.cli),*map(str,arguments)],capture_output=True,text=True,encoding='utf-8',timeout=10)
        assert result.returncode==expected_code,(arguments,result.returncode,result.stdout,result.stderr)
        document=json.loads(result.stdout)
        assert document['schema_version']==1
        return document
    for entry in manifest['entries']:
        path=fixture_root/entry['path']
        assert hashlib.sha256(path.read_bytes()).hexdigest()==entry['sha256']
        valid=entry['expected']=='valid'
        result=call(['inspect',path,'--json'],0 if valid else 2)
        if valid:
            assert result['source_sha256']==entry['sha256']
            assert result['counts']['method_defs']==2 and result['counts']['method_refs']==3
        else:
            expected='Unsupported' if entry['expected']=='Unsupported' else 'CorruptInput'
            assert result['execution_status']==expected,(entry,result)
            assert result['decision']=='Undetermined'
        passed+=1
    cases=json.loads((fixture_root/'queries/declaration-cases.json').read_text())
    input_file=fixture_root/cases['fixture']
    (root/'build/test-work').mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(dir=root/'build/test-work') as directory:
        query_path=Path(directory)/'query.json'
        def query(document,code=0):
            query_path.write_text(json.dumps(document,ensure_ascii=True),encoding='utf-8')
            result=call(['query',input_file,'--query',query_path,'--json'],code)
            oracle.verify_result(input_file,result,document)
            return result
        for case in cases['cases']:
            result=query(case['query'])
            assert sorted(row['name'] for row in result['candidates'])==sorted(case['expected_names'])
            assert result['decision']==case['decision'] and result['reason']==case['reason']
            passed+=1
        base={'schema_version':1,'relation':'method_defs','where':{},'intent':'enumerate','max_results':10}
        for intent,limit,code in [('enumerate',10,0),('unique',1,3),('enumerate',1,3),('exists',1,0)]:
            query({**base,'intent':intent,'max_results':limit},code);passed+=1
        query({**base,'where':{'name':{'op':'exact','u16':[108,111,99,97,116,101]}}});passed+=1
        query({**base,'where':{'name':{'op':'contains','value':'oca'}}});passed+=1
        query({**base,'where':{'owner':{'op':'exact','value':'Lsample/Example;'},'flags_contains':8}});passed+=1
        query({**base,'where':{'flags_contains':0x408}});passed+=1
        query({**base,'where':{'name':{'op':'exact','u16':[0xd800]}}});passed+=1
        bad_queries=[
            b'{"schema_version":1,"schema_version":1}',
            json.dumps({**base,'unsupported':True}).encode(),
            json.dumps({**base,'where':{'using_strings':['fixture']}}).encode(),
            json.dumps({**base,'where':{'name':{'op':'regex','value':'.*'}}}).encode(),
            b'{"schema_version":1,"relation":"method_defs","where":{"name":{"op":"exact","value":"\xff"}}}',
            b'['*40+b'0'+b']'*40,
            b'{"schema_version":1} trailing',
            json.dumps({**base,'max_results':0}).encode(),
            json.dumps({**base,'where':{'name':{'op':'exact','u16':[65536]}}}).encode(),
        ]
        for data in bad_queries:
            query_path.write_bytes(data)
            result=call(['query',input_file,'--query',query_path,'--json'],2)
            assert result['execution_status'] in ['InvalidArgument','Unsupported']
            assert result['coverage']=='Partial' and result['decision']=='Undetermined'
            passed+=1
        query_path.write_bytes(b' '*65537)
        assert call(['query',input_file,'--query',query_path,'--json'],3)['execution_status']=='BudgetExceeded';passed+=1
        apk=Path(directory)/'sample.apk';apk.write_bytes(b'PK\x03\x04'+b'\0'*40)
        assert call(['inspect',apk,'--json'],2)['execution_status']=='CorruptInput';passed+=1
        broken=subprocess.Popen([str(args.cli),'inspect',str(input_file),'--json'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        broken.stdout.close()
        diagnostic=broken.stderr.read()
        assert broken.wait(timeout=10)!=0,diagnostic
        passed+=1
    print(json.dumps({'suite':'cli_integration','passed':passed,'failed':0,'skipped':0,'evidence_verifier':'independent Python raw-byte parser','scope':'raw metadata only'},ensure_ascii=False))

if __name__=='__main__':main()
