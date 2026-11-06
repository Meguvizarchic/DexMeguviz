"""Independent DEX code-unit oracle for the restricted experimental join."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,struct,subprocess,copy
if not __debug__:raise SystemExit('assertions required')
p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--root',type=Path,required=True);p.add_argument('--out',type=Path);a=p.parse_args();root=a.root.resolve();fixture=root/'tests/fixtures/generated';files=[fixture/'use_relations/two-invokes.dex',fixture/'use_relations/two-invokes.dex',fixture/'method_facts/invoke-domains-038.dex',fixture/'reverse-join-multi-caller.dex',fixture/'reverse-join-poly-two-proto.dex'];h=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();assert h(files[-1])=='0cf1add7e8f573531f158d9df1083ca32d338bb7b2cdad356aca873e82336f32' and h(files[3])=='7efdabe3a1183bb2d4bc502de793d006fc2420ee87fc45d91b6165230dd8a14d'
poly_generator=root/'tests/fixtures/generators/reverse_join_poly_generator.py';multi_generator=root/'tests/fixtures/generators/reverse_fixture_base.py'
def load_module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
target=('Lfixture/Target;','sink','V',[])
assert load_module('poly_gen',poly_generator).build('Lfixture/Poly;','caller','V',[],targets=[target,target],extra_native=[('other','I',[],0x109)],static=True)==files[4].read_bytes()
assert load_module('multi_gen',multi_generator).build('Lfixture/Multi;','first','V',[],targets=[target],extra_bodies=[('second','V',[],[],[target,target],9)],static=True)==files[3].read_bytes()
metadata=root/'tools/evidence_verifier/verify.py';m=load_module('independent_metadata',metadata);events=[]
for source,path in enumerate(files):
 data=path.read_bytes();d=m.parse_dex(data);definitions=sorted(d['definitions'],key=lambda x:x['declaration_offset']);seen_poly=[]
 for ordinal,definition in enumerate(definitions):
  offset=definition['code_offset']
  if not offset:continue
  size=struct.unpack_from('<I',data,offset+12)[0];assert offset+16+2*size<=len(data);words=struct.unpack_from('<'+str(size)+'H',data,offset+16);pc=0
  while pc<size:
   unit=words[pc];opcode=unit&255
   if unit in (0,14):width=1
   elif opcode in (0x71,0xfc):width=3
   elif opcode==0xfa:width=4
   else:raise ValueError(f'unsupported fixture opcode {opcode:#x} at {path} pc {pc}')
   assert pc+width<=size
   if opcode in (0x71,0xfa):
    target=words[pc+1];extra=words[pc+3] if opcode==0xfa else 0xffffffff;domain=3 if opcode==0xfa else 2
    assert target<struct.unpack_from('<I',data,88)[0]
    if opcode==0xfa:assert extra<struct.unpack_from('<I',data,72)[0];seen_poly.append((target,extra))
    events.append([source,ordinal,definition['method_index'],pc,opcode,offset,domain,target,extra])
   pc+=width
 if source==4:assert len(seen_poly)==2 and seen_poly[0][0]==seen_poly[1][0] and {x[1] for x in seen_poly}=={0,1}
assert len(events)==10
result=subprocess.run([str(a.exe),str(files[0]),str(files[2]),str(files[3]),str(files[4]),str(fixture/'use_relations/valid-then-corrupt.dex'),str(fixture/'reverse-index-many.dex')],capture_output=True,timeout=120);assert result.returncode==0,(result.returncode,result.stdout.decode('utf8','replace')[-5000:],result.stderr.decode('utf8','replace')[-5000:]);lines=result.stdout.decode().splitlines();actual={0:[],1:[]};infos={0:[],1:[]}
for line in lines:
 pieces=line.split()
 if pieces[0]=='EVENT':actual[int(pieces[1])].append(list(map(int,pieces[2:])))
 elif pieces[0]=='RESULT':infos[int(pieces[1])].append(list(map(int,pieces[2:])))
def verify_events(rows,expected):
 assert rows==expected,(rows,expected)
for complete in (0,1):
 verify_events(actual[complete],events)
 assert len(infos[complete])==8 and infos[complete][0][0]==10 and infos[complete][4][0]==0 and infos[complete][7][0]==1
 assert infos[complete][3][1]>0,infos[complete]
mutants=[]
for field in range(9):
 candidate=copy.deepcopy(actual[1]);candidate[0][field]+=1;mutants.append(candidate)
mutants.extend([actual[1][:-1],list(reversed(actual[1])),actual[1]+[actual[1][0]]])
for candidate in mutants:
 try:verify_events(candidate,events)
 except AssertionError:pass
 else:raise AssertionError('forged candidate unexpectedly accepted')
receipt={'outcome':'passed','scope':'independent fixed DEX opcode forms, experimental join vs legacy and batch C API; no full DEX/ART','expected_events':len(events),'source_occurrences':len(files),'negative_controls':len(mutants),'inputs_sha256':{str(x):h(x) for x in [Path(__file__),a.exe,metadata,poly_generator,multi_generator,fixture/'use_relations/valid-then-corrupt.dex',fixture/'reverse-index-many.dex',*set(files)]}}
if a.out:
 a.out.mkdir(parents=True,exist_ok=False);(a.out/'consumer.stdout').write_bytes(result.stdout);(a.out/'consumer.stderr').write_bytes(result.stderr);(a.out/'expected-events.json').write_text(json.dumps(events,indent=2)+'\n');receipt['outputs_sha256']={str(x):h(x) for x in a.out.iterdir() if x.is_file()};(a.out/'summary.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt,indent=2))
