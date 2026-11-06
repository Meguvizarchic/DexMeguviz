"""Independent raw DEX/ordinary SQLite comparison through resident CLI."""
import argparse,hashlib,importlib.util,json,sqlite3,subprocess
from pathlib import Path
if not __debug__:raise SystemExit('assertions required')
p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--root',type=Path,required=True);a=p.parse_args();root=a.root.resolve();fixture=root/'tests/fixtures/generated/multisource/raw-a.dex'
spec=importlib.util.spec_from_file_location('raw_oracle',root/'tools/evidence_verifier/verify.py');o=importlib.util.module_from_spec(spec);spec.loader.exec_module(o);raw=o.parse_dex(fixture);defs=sorted(raw['definitions'],key=lambda row:row['declaration_offset']);assert [(x['method_index'],x['name']) for x in defs]==[(2,'second'),(1,'locate')]
db=sqlite3.connect(':memory:');db.execute('CREATE TABLE mirror(ordinal INTEGER, name TEXT)');db.executemany('INSERT INTO mirror VALUES(?,?)',[(i,x['name']) for i,x in enumerate(defs)])
requests=[];query='SELECT ordinal,name FROM dmg_method_defs WHERE ordinal=?1 ORDER BY ordinal'
for i,index in enumerate((0,1,99),1):requests.extend([{'op':'submit','sql':query,'params':[{'integer':str(index)}],'max_bytes':1024},{'op':'run'},{'op':'final','id':str(i)},{'op':'ack','id':str(i)}])
requests.append({'op':'close'});payload=b''.join(json.dumps(x,separators=(',',':')).encode()+b'\n' for x in requests);r=subprocess.run([str(a.exe),str(fixture)],input=payload,capture_output=True,timeout=60);assert r.returncode==0,(r.returncode,r.stderr)
rows=[json.loads(line) for line in r.stdout.splitlines()];assert len(rows)==len(requests)+1 and rows[0]['op']=='ready'
for i,index in enumerate((0,1,99)):
 submitted,ran,final,ack=rows[1+i*4:5+i*4];assert submitted['status']==ran['status']==ack['status']==0 and submitted['id']==str(i+1)
 assert final['execution_status']==0 and final['result']['source_scope']=='partial';expected=[[{'integer':str(ordinal)},name] for ordinal,name in db.execute('SELECT ordinal,name FROM mirror WHERE ordinal=? ORDER BY ordinal',(index,))];assert final['result']['rows']==expected,(index,final,expected)
 if i:assert int(final['reuse']['cache_hits'])>=i
assert rows[-1]['status']==0;db.close();print('PASS raw DEX and ordinary SQLite resident CLI',hashlib.sha256(fixture.read_bytes()).hexdigest())
