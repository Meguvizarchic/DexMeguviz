"""NUL and isolated surrogate raw byte controls for symbol equality."""
from pathlib import Path
from collections import Counter
import argparse,hashlib,json,struct,subprocess,zlib

def units(text):return tuple(struct.unpack('<'+'H'*(len(text.encode('utf-16le','surrogatepass'))//2),text.encode('utf-16le','surrogatepass')))
def main():
 a=argparse.ArgumentParser();a.add_argument('--root',type=Path,required=True);a.add_argument('--exe',type=Path,required=True);a.add_argument('--out',type=Path,required=True);x=a.parse_args();x.out.mkdir(parents=True,exist_ok=False);fix=x.root/'tests/fixtures/generated/target-symbol-utf16';names=['nul-high-d800.dex','nul-high-d801.dex']; pins=['20b71ba9dba5f265ca8f2a847ce007d3bd153b004f3faf21aadef72eb4396530','7c1c5ac05f0234cf7aecd04c1b1b90df6550f0fdab9221cb1c9c9b252b65a193'];expected=[(117,115,101,100,0,0xd800,120,121),(117,115,101,100,0,0xd801,120,121)]
 for i,name in enumerate(names):
  d=(fix/name).read_bytes();assert len(d)==608 and hashlib.sha256(d).hexdigest()==pins[i] and d[12:32]==hashlib.sha1(d[32:]).digest() and struct.unpack_from('<I',d,8)[0]==zlib.adler32(d[12:])&0xffffffff
  payload=b'\x08used\xc0\x80\xed\xa0'+bytes([0x80+i])+b'xy\x00';assert d.count(payload)==1
  assert struct.unpack_from('<H',d,432)[0]&255==0x1a and struct.unpack_from('<H',d,434)[0]==10 and struct.unpack_from('<H',d,436)[0]&255==0x1b and struct.unpack_from('<H',d,438)[0]==10
 records=[]
 for name,files in [('equal',[names[0],names[0]]),('different',names)]:
  for reverse in (False,True):
   left={'op':'scan','relation':'string_uses'};right={'op':'scan','relation':'string_values'}
   if reverse:left,right=right,left
   q={'schema_version':1,'required_capabilities':['use_target_symbol'],'relation':{'op':'join','left':left,'right':right,'on':'target_symbol'},'max_results':100};label=name+('-reverse' if reverse else '-forward');p=x.out/(label+'.query.json');p.write_text(json.dumps(q));cmd=[str(x.exe),'query',str(fix/files[0]),'--source',str(fix/files[1]),'--query',str(p),'--json'];r=subprocess.run(cmd,capture_output=True,timeout=60);(x.out/(label+'.stdout.json')).write_bytes(r.stdout);(x.out/(label+'.stderr.log')).write_bytes(r.stderr);v=json.loads(r.stdout);assert r.returncode==0 and v['profile']=='dex-query-use-target-symbol-v16'
   want=Counter((src,pc,dst,expected[0 if name=='equal' else dst]) for src in range(2) for pc in (0,2) for dst in range(2) if name=='equal' or src==dst);actual=[]
   for row in v['candidates']:
    event=next(b for b in row['bindings'] if b['relation']=='string_uses');target=next(b for b in row['bindings'] if b['relation']=='string_values');assert event['target_index']==10 and target['local_index']==10;actual.append((event['source_index'],event['dex_pc'],target['source_index'],units(target['string_value'])))
   assert Counter(actual)==want,(label,actual,want);records.append({'name':label,'count':len(actual)})
 (x.out/'summary.json').write_text(json.dumps({'passed':len(records),'records':records,'fixture_sha256':dict(zip(names,pins)),'scope':'fixed embedded NUL and isolated high-surrogate string targets; not complete Unicode/ART'},indent=2)+'\n',encoding='utf-8');print(json.dumps({'passed':len(records)}))
if __name__=='__main__':main()
