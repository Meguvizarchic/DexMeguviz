"""Independent DEX bytes vs string reverse C ABI differential test output."""
from pathlib import Path
import argparse,copy,hashlib,importlib.util,json,struct,subprocess,sys,zlib
if not __debug__:raise SystemExit('assertions required')
p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--root',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();root=a.root.resolve();out=a.out.resolve();assert not out.exists();out.mkdir(parents=True);fixture=root/'tests/fixtures/generated';normal=fixture/'use_relations/string-normal-jumbo.dex';q03=fixture/'q03/q03-domains.dex';utf0=fixture/'target-symbol-utf16/nul-high-d800.dex';utf1=fixture/'target-symbol-utf16/nul-high-d801.dex';broken=fixture/'use_relations/valid-then-corrupt.dex';metadata=root/'tools/evidence_verifier/verify.py';q03_oracle=root/'tests/integration/test_q03.py';source_oracle=root/'tests/integration/q_source_oracle.py';h=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();inputs=[Path(__file__),a.exe,normal,q03,utf0,utf1,broken,metadata,q03_oracle,source_oracle];before={str(p):h(p) for p in inputs}
def load(n,path):
 spec=importlib.util.spec_from_file_location(n,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
raw=load('raw',metadata);sys.path.insert(0,str(root/'tests/integration'));q3=load('q03_independent',q03_oracle);strings=q3.verify_raw(q03.read_bytes());assert strings[6]=='annotation-only-q03' and strings[7]=='code-use-q03' and strings[10]=='static-only-q03'
events=[]
for source,path in enumerate([normal,normal,q03,utf0,utf1]):
 data=path.read_bytes();assert data[12:32]==hashlib.sha1(data[32:]).digest() and struct.unpack_from('<I',data,8)[0]==zlib.adler32(data[12:])&0xffffffff;d=raw.parse_dex(data);definitions=sorted(d['definitions'],key=lambda x:x['declaration_offset'])
 if source in (3,4):
  units=d['strings'][10].encode('utf-16-le','surrogatepass');assert list(struct.unpack('<8H',units))==[117,115,101,100,0,0xd800+(source-3),120,121]
 for ordinal,method in enumerate(definitions):
  off=method['code_offset'];count=struct.unpack_from('<I',data,off+12)[0] if off else 0
  if not count:continue
  words=struct.unpack_from('<'+'H'*count,data,off+16);pc=0
  while pc<count:
   opcode=words[pc]&255
   if opcode in (0x1a,0x1b):
    target=words[pc+1] if opcode==0x1a else words[pc+1]|words[pc+2]<<16;assert target<len(d['strings']);events.append([source,ordinal,method['method_index'],pc,opcode,off,0,target,0xffffffff]);pc+=2 if opcode==0x1a else 3
   elif opcode in (0,0x0e):pc+=1
   else:raise AssertionError((path,pc,opcode))
assert len(events)==9 and [x[-2] for x in events if x[0]==2]==[7] and all(x[-2] not in (6,10) for x in events if x[0]==2)
cmd=[str(a.exe),str(normal),str(q03),str(utf0),str(utf1),str(broken)];proc=subprocess.run(cmd,capture_output=True,timeout=180);(out/'consumer.stdout').write_bytes(proc.stdout);(out/'consumer.stderr').write_bytes(proc.stderr);assert proc.returncode==0,(proc.stdout.decode('utf8','replace')[-3000:],proc.stderr.decode('utf8','replace'))
actual={0:[],1:[]}
for line in proc.stdout.decode().splitlines():
 parts=line.split()
 if parts and parts[0]=='EVENT':actual[int(parts[1])].append(list(map(int,parts[2:])))
def compare(rows):assert rows==events,(rows,events)
for mode in (0,1):compare(actual[mode])
mutants=[]
for field in range(9):
 x=copy.deepcopy(actual[1]);x[0][field]+=1;mutants.append(x)
mutants.extend([actual[1][:-1],list(reversed(actual[1])),actual[1]+[actual[1][0]]])
for x in mutants:
 try:compare(x)
 except AssertionError:pass
 else:raise AssertionError('forged event accepted')
assert all(h(p)==v for p,v in before.items());(out/'expected-events.json').write_text(json.dumps(events,indent=2)+'\n');outputs={str(p):h(p) for p in out.rglob('*') if p.is_file()};(out/'summary.json').write_text(json.dumps({'outcome':'passed','scope':'fixed independently parsed DEX string code units, five occurrences; no ART','inputs_before':before,'inputs_after':before,'outputs_sha256':outputs,'expected_events':len(events),'mutants_rejected':len(mutants),'commands':[cmd]},indent=2)+'\n');print('PASS independent string reference/PC byte oracle')
