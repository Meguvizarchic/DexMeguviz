from pathlib import Path
import argparse,hashlib,json,struct,subprocess,zlib
p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();assert not a.out.exists();a.out.mkdir(parents=True);m=json.loads((a.fixtures/'expected.json').read_text());events=[]
for name in ('good-039','good-040','nonzero-039'):
 data=(a.fixtures/(name+'.dex')).read_bytes();assert hashlib.sha256(data).hexdigest()==m['fixtures'][name]['sha256'] and data[12:32]==hashlib.sha1(data[32:]).digest() and struct.unpack_from('<I',data,8)[0]==zlib.adler32(data[12:])&0xffffffff;off=m['nonzero_code_offset'] if name=='nonzero-039' else m['code_offset'];expected=m['nonzero_words'] if name=='nonzero-039' else m['words'];words=struct.unpack_from('<' + str(len(expected)) + 'H',data,off+16);assert list(words)==expected
 if name=='nonzero-039':
  assert struct.unpack_from('<H',data,off)[0]==2 and struct.unpack_from('<I',data,72)[0]==2
  mapat=struct.unpack_from('<I',data,52)[0];n=struct.unpack_from('<I',data,mapat)[0];handles=[struct.unpack_from('<HHII',data,mapat+4+12*i) for i in range(n) if struct.unpack_from('<H',data,mapat+4+12*i)[0]==8];assert len(handles)==1 and handles[0][2]==2 and data[handles[0][3]:handles[0][3]+16]==struct.pack('<HHHHHHHH',4,0,0,0,4,0,0,0)
 pc=0
 while pc<len(words):
  word=words[pc];opcode=word&255
  if opcode in (0xfe,0xff):events.append([name+'.dex',pc,words[pc+1],word>>8,opcode,0 if opcode==0xfe else 1]);pc+=2
  elif opcode in (0,0x0e):pc+=1
  else:raise AssertionError(('unexpected opcode',opcode,pc))
 assert pc==len(words)
r=subprocess.run([str(a.exe),str(a.fixtures)],capture_output=True,timeout=120);(a.out/'test.stdout').write_bytes(r.stdout);(a.out/'test.stderr').write_bytes(r.stderr);assert r.returncode==0,(r.returncode,r.stdout,r.stderr);actual=[]
for line in r.stdout.decode().splitlines():
 part=line.split()
 if part and part[0]=='EVENT':actual.append([part[1],*map(int,part[2:])])
assert actual==events,(actual,events)
(a.out/'expected-events.json').write_text(json.dumps(events,indent=2)+'\n');(a.out/'results.json').write_text(json.dumps({'outcome':'passed','expected_events':len(events),'scope':'authored bytes and fixed local table indices; no ART','events':events},indent=2)+'\n');print('PASS independent method-constant bytes',len(events))
