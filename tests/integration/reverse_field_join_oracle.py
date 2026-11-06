"""Independent DEX bytes vs field reverse C ABI differential test output."""
from pathlib import Path
import argparse,copy,hashlib,importlib.util,json,struct,subprocess,sys,zlib
if not __debug__:raise SystemExit('assertions required')
p=argparse.ArgumentParser();p.add_argument('--exe',type=Path,required=True);p.add_argument('--root',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();root=a.root.resolve();out=a.out.resolve();assert not out.exists();out.mkdir(parents=True);fixture=root/'tests/fixtures/generated';normal=fixture/'q08/q08.dex';external=fixture/'reverse-field-external/field-external.dex';broken=fixture/'use_relations/valid-then-corrupt.dex';gen=root/'tests/fixtures/generators/reverse_field_external.py';metadata=root/'tools/evidence_verifier/verify.py';h=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();inputs=[Path(__file__),a.exe,normal,external,broken,gen,metadata];before={str(p):h(p) for p in inputs};spec=importlib.util.spec_from_file_location('raw',metadata);raw=importlib.util.module_from_spec(spec);spec.loader.exec_module(raw)
cmd=[sys.executable,'-B',str(gen),'--output',str(out/'rebuilt')];built=subprocess.run(cmd,capture_output=True,timeout=60);(out/'generator.stdout').write_bytes(built.stdout);(out/'generator.stderr').write_bytes(built.stderr);assert built.returncode==0 and (out/'rebuilt/field-external.dex').read_bytes()==external.read_bytes()
events=[];descriptors=[]
for source,path in enumerate([normal,normal,external]):
 data=path.read_bytes();assert data[12:32]==hashlib.sha1(data[32:]).digest() and struct.unpack_from('<I',data,8)[0]==zlib.adler32(data[12:])&0xffffffff;d=raw.parse_dex(data);u=lambda pos:struct.unpack_from('<I',data,pos)[0];types=[d['strings'][u(u(68)+i*4)] for i in range(u(64))];fields=[]
 for i in range(u(80)):
  owner,typ,name=struct.unpack_from('<HHI',data,u(84)+8*i);fields.append((types[owner],d['strings'][name],types[typ]))
 descriptors.append(fields);definitions=sorted(d['definitions'],key=lambda x:x['declaration_offset'])
 for ordinal,method in enumerate(definitions):
  off=method['code_offset'];count=u(off+12) if off else 0
  if not count:continue
  words=struct.unpack_from('<'+'H'*count,data,off+16);pc=0
  while pc<count:
   opcode=words[pc]&255
   if opcode in (0x60,0x67):
    target=words[pc+1];assert target<len(fields);events.append([source,ordinal,method['method_index'],pc,opcode,off,1,target,0xffffffff]);pc+=2
   elif opcode==0x0e:pc+=1
   else:raise AssertionError((path,pc,opcode))
assert len(events)==14 and descriptors[0][1]==descriptors[1][1]==descriptors[2][1] and descriptors[2][-1]==('Ljava/lang/Object;','external','I')
cmd=[str(a.exe),str(normal),str(external),str(broken)];proc=subprocess.run(cmd,capture_output=True,timeout=180);(out/'consumer.stdout').write_bytes(proc.stdout);(out/'consumer.stderr').write_bytes(proc.stderr);assert proc.returncode==0,(proc.stdout.decode('utf8','replace')[-3000:],proc.stderr.decode('utf8','replace'))
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
assert all(h(p)==v for p,v in before.items());(out/'expected-events.json').write_text(json.dumps(events,indent=2)+'\n');outputs={str(p):h(p) for p in out.rglob('*') if p.is_file()};(out/'summary.json').write_text(json.dumps({'outcome':'passed','scope':'fixed independently parsed DEX field units, 3 occurrences and local-reference joins; not ART','inputs_before':before,'inputs_after':before,'outputs_sha256':outputs,'expected_events':len(events),'mutants_rejected':len(mutants),'commands':[cmd]},indent=2)+'\n');print('PASS independent field reference/PC byte oracle')
