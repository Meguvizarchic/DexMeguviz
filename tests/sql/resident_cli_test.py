"""Bounded resident CLI protocol against an authored raw DEX."""
import argparse,json,subprocess,uuid,hashlib
from pathlib import Path
if not __debug__:raise SystemExit('assertions required')
p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--dex',type=Path,required=True);a=p.parse_args()
def line(v):return json.dumps(v,ensure_ascii=True,separators=(',',':')).encode()+b'\n'
def run(requests,expected_exit=0,dex=None):
 r=subprocess.run([str(a.exe),str(dex or a.dex)],input=b''.join(requests),capture_output=True,timeout=60)
 assert r.returncode==expected_exit,(r.returncode,r.stdout[-2000:],r.stderr[-2000:]);return [json.loads(x) for x in r.stdout.splitlines()],r.stderr
text='a\x00\u00e9\U0001f600'
cmds=[{'op':'submit','sql':'SELECT ?1','params':[text],'max_bytes':1024},
      {'op':'submit','sql':'SELECT ?1','params':['cancelled'],'max_bytes':1024},
      {'op':'final','id':'1'},{'op':'close'},{'op':'cancel','id':'2'},{'op':'final','id':'2'},
      {'op':'run'},{'op':'final','id':'1'},{'op':'final','id':'1'},{'op':'stats'},
      {'op':'ack','id':'2'},{'op':'ack','id':'1'},
      {'op':'submit','sql':'SELECT ?1','params':['next'],'max_bytes':1024},{'op':'run'},{'op':'final','id':'3'},{'op':'ack','id':'3'},
      {'op':'submit','sql':'DROP TABLE dmg_method_defs','max_bytes':1024},{'op':'run'},{'op':'final','id':'4'},{'op':'ack','id':'4'},
      {'op':'submit','sql':'SELECT \x00'},{'op':'submit','sql':'SELECT ?1','params':[{}]},
      {'op':'unknown'}, {'op':'stats'}, {'op':'close'}]
rows,err=run([line(x) for x in cmds]);assert not err and len(rows)==len(cmds)+1,rows
assert rows[0]['op']=='ready' and rows[0]['source_scope']=='partial'
r=rows[1:];assert (r[0]['id'],r[1]['id'])==('1','2')
assert r[2]['status']==5 and r[3]['status']==5 and 'close_us' not in r[3] and r[4]['status']==0
assert r[5]['status']==0 and r[5]['execution_status']==9 and r[5]['result'] is None
assert r[6]['status']==0 and r[7]['execution_status']==0 and r[7]['result']['rows']==[[text]]
assert r[7]['result']['source_scope']=='partial' and r[7]['result']['snapshot_id'] and r[7]['profile']['prepare_attempted']
assert r[7]==r[8] and r[9]['terminal']==2 and r[9]['input_bytes']=='0' and r[9]['reserved_result_bytes']=='2048'
assert r[10]['status']==r[11]['status']==0 and r[12]['id']=='3' and r[13]['status']==0
assert r[14]['execution_status']==0 and r[14]['result']['rows']==[['next']] and int(r[14]['reuse']['cache_hits'])>=1 and not r[14]['profile']['prepare_attempted']
assert r[15]['status']==0 and r[16]['id']=='4' and r[17]['status']==0 and r[18]['execution_status']!=0 and r[18]['result'] is None and r[19]['status']==0
assert all(r[i]['status']==21 for i in (20,21,22)) and r[23]['terminal']==0 and r[24]['status']==0 and r[24]['close_us'].isdigit()
# A real DEX path with supplementary CJK and emoji must round-trip via Windows wide argv.
unicode_dir=Path(a.exe).resolve().parent/('resident-unicode-'+uuid.uuid4().hex);unicode_dir.mkdir();unicode_dex=unicode_dir/('中\U00020000\U0001f4c2.dex')
with unicode_dex.open('xb') as f:f.write(a.dex.read_bytes())
assert hashlib.sha256(unicode_dex.read_bytes()).digest()==hashlib.sha256(a.dex.read_bytes()).digest()
rows,err=run([line({'op':'close'})],dex=unicode_dex);assert not err and rows[0]['op']=='ready' and rows[1]['status']==0 and rows[1]['close_us'].isdigit()
# Per-connection capacity and unacknowledged terminal preservation.
submit=[line({'op':'submit','sql':'SELECT 1','max_bytes':64}) for _ in range(17)]
cleanup=[item for i in range(1,17) for item in (line({'op':'cancel','id':str(i)}),line({'op':'ack','id':str(i)}))]
rows,err=run(submit+cleanup+[line({'op':'close'})]);assert not err
assert [x['id'] for x in rows[1:17]]==[str(i) for i in range(1,17)] and rows[17]['status']==13 and all(x['status']==0 for x in rows[18:])
# Duplicate key, invalid UTF-8 and oversized lines fail without poisoning the next command.
rows,err=run([b'{"op":"stats","op":"stats"}\n',b'{"op":"stats","x":"\xff"}\n',b' '+b'x'*65536+b'\n',line({'op':'stats'}),line({'op':'close'})]);assert not err and [x['status'] for x in rows[1:]]==[21,21,18,0,0]
# Exact signed 64-bit integers use explicit decimal text; identifiers stay text.
rows,err=run([line({'op':'submit','sql':'SELECT ?1,?2','params':[{'integer':'9223372036854775807'},{'integer':'-9223372036854775808'}],'max_bytes':1024}),line({'op':'run'}),line({'op':'final','id':'1'}),line({'op':'ack','id':'1'}),line({'op':'close'})]);assert not err and rows[3]['result']['rows']==[[{'integer':'9223372036854775807'},{'integer':'-9223372036854775808'}]]
rows,err=run([line({'op':'submit','sql':'SELECT ?1','params':[{'integer':'9223372036854775808'}]}),line({'op':'final','id':1}),line({'op':'final','id':'01'}),line({'op':'close'})]);assert not err and [x['status'] for x in rows[1:]]==[21,21,21,0]
# A valid UTF-8 TEXT result may exceed the per-request JSON input bound.
long_text='a'*40000+'é😀';rows,err=run([line({'op':'submit','sql':'SELECT ?1 || ?1','params':[long_text],'max_bytes':200000}),line({'op':'run'}),line({'op':'final','id':'1'}),line({'op':'ack','id':'1'}),line({'op':'close'})]);assert not err and rows[3]['status']==0 and rows[3]['result']['rows']==[[long_text+long_text]]
# Invalid UTF-8 result is refused without consuming the retained terminal.
rows,err=run([line({'op':'submit','sql':"SELECT CAST(X'EDA080' AS TEXT)",'max_bytes':1024}),line({'op':'run'}),line({'op':'final','id':'1'}),line({'op':'final','id':'1'}),line({'op':'stats'}),line({'op':'ack','id':'1'}),line({'op':'close'})]);assert not err and rows[3]['status']==20 and rows[4]['status']==20 and rows[5]['terminal']==1 and rows[6]['status']==0
# EOF with an accepted but unacknowledged job must not report a clean exit.
rows,err=run([line({'op':'submit','sql':'SELECT 1','max_bytes':64})],2);assert rows[1]['id']=='1' and b'unacknowledged' in err
print('PASS resident CLI lifecycle, terminal retention, quotas, malformed input and EOF')
