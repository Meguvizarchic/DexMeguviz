"""Fixed legacy QueryID and candidate comparisons against the existing core binary."""
from pathlib import Path
import argparse,hashlib,json,subprocess

def main():
 a=argparse.ArgumentParser();a.add_argument('--old',type=Path,required=True);a.add_argument('--new',type=Path,required=True);a.add_argument('--fixture',type=Path,required=True);a.add_argument('--out',type=Path,required=True);x=a.parse_args();x.out.mkdir(parents=True,exist_ok=False)
 scans=[('v1',{'relation':'method_defs'}),('v3',{'relation':{'op':'join','on':'symbol','left':{'op':'scan','relation':'method_refs'},'right':{'op':'scan','relation':'method_defs'}}}),('v4',{'relation':{'op':'join','on':'target_ref','left':{'op':'scan','relation':'invoke_sites'},'right':{'op':'scan','relation':'method_refs'}}})];rows=[]
 for name,content in scans:
  q={'schema_version':1,**content,'max_results':100};p=x.out/(name+'.query.json');p.write_text(json.dumps(q),encoding='utf-8');values=[]
  for label,exe in [('old',x.old),('new',x.new)]:
   proc=subprocess.run([str(exe),'query',str(x.fixture),'--query',str(p),'--json'],capture_output=True,timeout=60);(x.out/(name+'-'+label+'.stdout.json')).write_bytes(proc.stdout);(x.out/(name+'-'+label+'.stderr.log')).write_bytes(proc.stderr);assert proc.returncode==0,(name,label,proc.stderr);values.append(json.loads(proc.stdout))
  old,new=values;assert old['query_id']==new['query_id'] and old['profile']==new['profile'] and old['candidates']==new['candidates'],name
  rows.append({'name':name,'query_id':old['query_id'],'candidates':len(old['candidates'])})
 sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();(x.out/'summary.json').write_text(json.dumps({'passed':len(rows),'rows':rows,'old_sha256':sha(x.old),'new_sha256':sha(x.new),'fixture_sha256':sha(x.fixture),'scope':'three fixed legacy plans only'},indent=2)+'\n',encoding='utf-8');print(json.dumps({'passed':len(rows)}))
if __name__=='__main__':main()
