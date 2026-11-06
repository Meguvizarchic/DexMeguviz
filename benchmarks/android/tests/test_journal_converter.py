"""Bounded synthetic controls for append-only benchmark journal recovery."""
import argparse,hashlib,importlib.util,json,subprocess,sys
from pathlib import Path

def main():
 p=argparse.ArgumentParser();p.add_argument('--converter',type=Path,required=True);p.add_argument('--analyzer',type=Path,required=True);p.add_argument('--protocol',type=Path,required=True);p.add_argument('--samples',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(exist_ok=False)
 sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();paths=[a.converter,a.analyzer,a.protocol,*[a.samples/(x+'.jsonl') for x in ('complete','partial','failed','budget','mismatch','malformed-header','host-probe','fatal')]];before={str(x):sha(x) for x in paths}
 commands=[]
 def call(src,name,code):
  out=a.out/(name+'.json');p=subprocess.run([sys.executable,'-B',str(a.converter),'--journal',str(src),'--output',str(out)],capture_output=True,text=True,timeout=60);commands.append({'case':name,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr});assert p.returncode==code,(name,p.returncode,p.stdout,p.stderr);return out
 complete=call(a.samples/'complete.jsonl','complete',0);raw=json.loads(complete.read_text(encoding='utf8'));assert raw['journal_integrity']['status']=='complete' and len(raw['records'])==2 and raw['records'][0]['complete'] is True and raw['records'][1]['complete'] is False and raw['records'][0]==json.loads((a.samples/'expected-record.json').read_text(encoding='utf8'))
 partial=call(a.samples/'partial.jsonl','partial',2);raw=json.loads(partial.read_text(encoding='utf8'));assert raw['journal_integrity']['status']=='incomplete_or_invalid' and raw['records'][0]['complete'] is True and raw['records'][-1]['status']=='journal_incomplete_or_invalid'
 failed=call(a.samples/'failed.jsonl','failed',2);raw=json.loads(failed.read_text(encoding='utf8'));assert raw['records'][0]['status']=='journal_serialization_error' and raw['records'][-1]['status']=='journal_incomplete_or_invalid'
 budget=call(a.samples/'budget.jsonl','budget',2);raw=json.loads(budget.read_text(encoding='utf8'));assert len(raw['records'])==1 and raw['records'][0]['status']=='journal_incomplete_or_invalid'
 fatal=call(a.samples/'fatal.jsonl','fatal',2);raw=json.loads(fatal.read_text(encoding='utf8'));assert len(raw['records'])==1 and raw['records'][0]['status']=='journal_incomplete_or_invalid'
 mismatch=call(a.samples/'mismatch.jsonl','mismatch',2);raw=json.loads(mismatch.read_text(encoding='utf8'));assert 'identity_digest_mismatch' in raw['journal_integrity']['failures'] and raw['records'][-1]['complete'] is False
 host=call(a.samples/'host-probe.jsonl','host-probe',0);raw=json.loads(host.read_text(encoding='utf8'));assert raw['data_kind']=='synthetic_control' and len(raw['records'])==1 and raw['records'][0]['probe_evidence']['task_invoked'] is True and raw['records'][0]['probe_evidence']['task_returned'] is True
 invalid=a.out/'malformed-header.json';p=subprocess.run([sys.executable,'-B',str(a.converter),'--journal',str(a.samples/'malformed-header.jsonl'),'--output',str(invalid)],capture_output=True,timeout=60);assert p.returncode==1 and not invalid.exists()
 data=(a.samples/'complete.jsonl').read_bytes();lines=data.splitlines(keepends=True);assert len(lines)==4
 torn=a.out/'torn.jsonl';torn.write_bytes(data[:-7]);out=call(torn,'torn',2);raw=json.loads(out.read_text(encoding='utf8'));assert len(raw['records'])==3 and raw['records'][-1]['unverified_tail_bytes']>0
 line=json.loads(lines[1]);line['sha256']=('0' if line['sha256'][0]!='0' else '1')+line['sha256'][1:];mut=a.out/'tampered.jsonl';mut.write_bytes(lines[0]+(json.dumps(line,separators=(',',':'))+'\n').encode()+b''.join(lines[2:]));out=call(mut,'tampered',2);raw=json.loads(out.read_text(encoding='utf8'));assert raw['records'][-1]['status']=='journal_incomplete_or_invalid' and raw['journal_integrity']['failures'][0].startswith('invalid_frame:frame hash mismatch')
 duplicate=a.out/'duplicate-key.jsonl';duplicate.write_bytes(lines[0]+lines[1].replace(b'{',b'{"seq":1,',1)+b''.join(lines[2:]));out=call(duplicate,'duplicate-key',2);raw=json.loads(out.read_text(encoding='utf8'));assert 'duplicate JSON key' in raw['journal_integrity']['failures'][0]
 original=sha(complete);p=subprocess.run([sys.executable,'-B',str(a.converter),'--journal',str(a.samples/'complete.jsonl'),'--output',str(complete)],capture_output=True,timeout=60);assert p.returncode==1 and sha(complete)==original
 spec=importlib.util.spec_from_file_location('analyzer',a.analyzer);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);protocol,protocol_hash=m.read_json(a.protocol)
 for path in (complete,partial,failed,budget,mismatch,host,fatal,a.out/'torn.json',a.out/'tampered.json',a.out/'duplicate-key.json'):
  raw,_=m.read_json(path);result=m.analyze(protocol,raw,protocol_hash,path.parent);assert result['overall_acceptance']=='not_passed_or_unverified' and result['record_accounting']['input_records_retained']==len(raw['records'])
 after={k:sha(k) for k in before};assert before==after
 (a.out/'receipt.json').write_text(json.dumps({'status':'passed','cases':[x['case'] for x in commands]+['existing_output_not_overwritten','analyzer_fail_closed'],'commands':commands,'inputs':before,'unchanged':before==after,'scope':'synthetic host controls, no formal campaign or device data'},indent=2)+'\n');print('PASS journal framing, partial/tamper recovery, no overwrite, analyzer rejects incomplete synthetic input')
if __name__=='__main__':main()
