"""Check exact publication name against real artifact bytes and prior parser."""
import argparse,copy,importlib.util,json,sys
from pathlib import Path
from verify_aar import check_publication

sys.dont_write_bytecode=True
p=argparse.ArgumentParser()
for name in ('prior','aar','pom','module','out'):p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args()
spec=importlib.util.spec_from_file_location('prior_aar_audit',a.prior)
prior=importlib.util.module_from_spec(spec);spec.loader.exec_module(prior)
aar=a.aar.read_bytes();pom=a.pom.read_bytes();original=json.loads(a.module.read_text(encoding='utf-8'))
prior.check_publication(pom,json.dumps(original).encode(),aar);check_publication(pom,json.dumps(original).encode(),aar)
good=original['variants'][0]['files'][0]['name'];records=[]
for label,name,url,prior_expected in [
 ('encoded-traversal','%2e%2e%2fghost.aar','%2e%2e%2fghost.aar',True),
 ('encoded-slash','ghost%2fapp.aar','ghost%2fapp.aar',True),
 ('different-safe-name','ghost-1.aar','ghost-1.aar',True),
 ('query',good,good+'?x=1',False),
 ('fragment',good,good+'#part',False),
 ('unicode','caf\u00e9-1.aar','caf\u00e9-1.aar',True),
 ('double-dot','ghost..-1.aar','ghost..-1.aar',True)]:
 changed=copy.deepcopy(original)
 for variant in changed['variants']:
  variant['files'][0]['name']=name;variant['files'][0]['url']=url
 data=json.dumps(changed).encode()
 try:prior.check_publication(pom,data,aar);old=True
 except ValueError:old=False
 try:check_publication(pom,data,aar);new=True
 except ValueError:new=False
 if old!=prior_expected or new:raise SystemExit('unexpected path result '+label)
 records.append({'case':label,'name':name,'url':url,'prior_accepted':old,'new_accepted':new})
a.out.parent.mkdir(parents=True,exist_ok=True)
with a.out.open('x',encoding='utf-8') as f:json.dump({'real_metadata_positive':True,'cases':records},f,indent=2);f.write('\n')
print('PASS real metadata positive and',len(records),'name/URL negatives; prior accepted',sum(x['prior_accepted'] for x in records))
