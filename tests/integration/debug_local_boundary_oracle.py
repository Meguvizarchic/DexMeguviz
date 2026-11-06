"""Independent code-unit/debug-byte oracle for one authored DEX fixture.
No runtime debugger or native decoder is used to derive expected events.
"""
from pathlib import Path
import argparse,copy,hashlib,importlib.util,json,struct,subprocess
if not __debug__:raise SystemExit('assertions required')
p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--root',type=Path,required=True);p.add_argument('--out',type=Path);a=p.parse_args();root=a.root.resolve();fixture=root/'tests/fixtures/generated/debug-local-boundary.dex';generator=root/'tests/fixtures/generators/debug_local_boundary.py';metadata=root/'tools/evidence_verifier/verify.py';h=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();data=fixture.read_bytes();assert h(fixture)=='72ae48c940cb0ec87e860f9c0a328ce2ae3263e8110d7e47dc4f938516fa03ee'
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);obj=importlib.util.module_from_spec(spec);spec.loader.exec_module(obj);return obj
assert load('boundary_generator',generator).build_double(1)==data
parsed=load('independent_metadata',metadata).parse_dex(data);defs=sorted(parsed['definitions'],key=lambda x:x['declaration_offset']);assert len(defs)==1;code=defs[0]['code_offset'];units=struct.unpack_from('<I',data,code+12)[0];assert units==8 and struct.unpack_from('<8H',data,code+16)==(0x0013,1,0x0300,1,1,0,0xff,0x000e)
# Decode only this fixture's explicit forms from bytes, including the payload extent.
words=struct.unpack_from('<8H',data,code+16);pc=0;ranges=[]
while pc<units:
 op=words[pc]
 if op==0x0013:width=2;kind=0
 elif op==0x0300:
  element_width=words[pc+1];count=words[pc+2]|words[pc+3]<<16;assert element_width==1 and count==1;width=4+(element_width*count+1)//2;kind=2
 elif op==0x000e:width=1;kind=0
 else:raise AssertionError(('unsupported oracle opcode',pc,op))
 assert pc+width<=units;ranges.append((pc,pc+width,kind));pc+=width
assert ranges==[(0,2,0),(2,7,2),(7,8,0)]
def boundary(pc):
 if pc==units:return 4
 matches=[(start,end,kind) for start,end,kind in ranges if start<=pc<end];assert len(matches)==1;start,_,kind=matches[0];return kind if pc==start else kind+1
def uleb(at):
 value=0
 for n in range(5):
  byte=data[at];at+=1;value|=(byte&127)<<(7*n)
  if byte<128:return value,at
 raise ValueError('unsupported leb')
offset=struct.unpack_from('<I',data,code+8)[0];line,pos=uleb(offset);count,pos=uleb(pos);assert (line,count)==(1,1)
for _ in range(count):unused,pos=uleb(pos);assert unused==0
pc=0;events=[]
while True:
 at=pos;op=data[pos];pos+=1
 if op==0:break
 if op==1:advance,pos=uleb(pos);pc+=advance;continue
 assert op in (3,4,5,6);reg,pos=uleb(pos)
 if op in (3,4):
  name,pos=uleb(pos);typ,pos=uleb(pos)
  if op==4:sig,pos=uleb(pos)
 events.append([pc,boundary(pc),{3:0,4:1,5:2,6:3}[op],reg,at])
assert [r[:4] for r in events]==[[0,0,0,0],[1,1,2,0],[2,2,3,0],[3,3,2,0],[7,0,0,0],[8,4,2,0]]
r=subprocess.run([str(a.exe),str(fixture)],capture_output=True,text=True,timeout=60);assert r.returncode==0,(r.returncode,r.stdout,r.stderr);actual=[list(map(int,line.split()[1:])) for line in r.stdout.splitlines() if line.startswith('EVENT ')]
def check(rows):assert rows==events,(rows,events)
check(actual);mutants=[]
for field in range(5):
 x=copy.deepcopy(actual);x[0][field]+=1;mutants.append(x)
mutants.extend([actual[:-1],list(reversed(actual)),actual+[actual[0]]])
for x in mutants:
 try:check(x)
 except AssertionError:pass
 else:raise AssertionError('forged event accepted')
receipt={'outcome':'passed','scope':'single authored DEX, independent raw code/debug bytes; not ART or full verifier','fixture_sha256':h(fixture),'events':events,'mutants_rejected':len(mutants),'inputs_sha256':{str(p):h(p) for p in (Path(__file__),a.exe,fixture,generator,metadata)}}
if a.out:
 a.out.mkdir(parents=True,exist_ok=False);(a.out/'consumer.stdout').write_text(r.stdout,encoding='utf8');(a.out/'consumer.stderr').write_text(r.stderr,encoding='utf8');(a.out/'summary.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf8')
print(json.dumps(receipt,indent=2))
