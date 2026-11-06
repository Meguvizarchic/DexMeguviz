import argparse, json, subprocess, tempfile, sys
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--exe',required=True,type=Path);p.add_argument('--fixture',required=True,type=Path);p.add_argument('--lines',required=True,type=Path);a=p.parse_args()
exe=a.exe.resolve();fixture=a.fixture.resolve()
lines=a.lines.read_text(encoding='utf-8').splitlines()
documents=dict(line.split('\t',1) for line in lines)
assert set(documents)=={'incomparable','nested','nested-composite','surrogate'}
def value(s): return {'name':{'op':'exact','value':s,'ascii_case_insensitive':False}}
def array(s): return {'name':{'op':'exact','u16':[ord(c) for c in s],'ascii_case_insensitive':False}}
def wrap(where, n):
    for _ in range(n): where={'not':where}
    return where
long_high='\uffff'*10404
nulls='\0'*600
unusual='x'*397+chr(0xd800)+'Q'+chr(0xdfff)
expected={
  'incomparable':wrap({'all':[value('x'*200),value('\0'*1000)]},27),
  'nested':wrap({'all':[value(long_high),value('x'*400),array(nulls)]},1),
  'nested-composite':{'all':[{'all':[value(long_high),value('x'*400),array(nulls)]}]},
  'surrogate':{'all':[value(long_high),value(unusual),array(nulls)]},
}
def bounds(x,depth=0):
    children=x.values() if isinstance(x,dict) else x if isinstance(x,list) else ()
    data=[bounds(y,depth+1) for y in children]
    return 1+sum(x[0] for x in data),max([depth]+[x[1] for x in data])
mixed={'all':[value('x'*200),array('\0'*1000)]}
all_value={'all':[value('x'*200),value('\0'*1000)]}
assert len(json.dumps(mixed,separators=(',',':'))) < len(json.dumps(all_value,separators=(',',':')))
assert bounds(mixed)[0] > bounds(all_value)[0] and bounds(mixed)[1] > bounds(all_value)[1]
with tempfile.TemporaryDirectory(prefix='dmg-mixed-extra-') as tmp:
    def run(name, payload):
        path=Path(tmp)/(name+'.json');path.write_bytes(payload)
        r=subprocess.run([str(exe),'query',str(fixture),'--query',str(path),'--json'],capture_output=True,text=True,encoding='utf-8',timeout=60)
        assert r.returncode==0,(name,r.returncode,r.stdout,r.stderr)
        return json.loads(r.stdout)
    for name,raw in documents.items():
        decoded=json.loads(raw)
        assert len(raw.encode('ascii'))<=65536
        nodes,depth=bounds(decoded)
        assert nodes<=16384 and depth<=32,(name,nodes,depth)
        control={'schema_version':1,'relation':'method_defs','where':expected[name],
                 'intent':'enumerate','max_results':4096,'max_work':100000000}
        actual=run(name+'-candidate',raw.encode('ascii'))
        manual=run(name+'-control',json.dumps(control,ensure_ascii=True,separators=(',',':')).encode('ascii'))
        for key in ('query_id','execution_status','coverage','decision','reason','candidates'):
            assert actual[key]==manual[key],(name,key,actual[key],manual[key])
        print(name,'nodes',nodes,'depth',depth,'bytes',len(raw),'query_id',actual['query_id'])
