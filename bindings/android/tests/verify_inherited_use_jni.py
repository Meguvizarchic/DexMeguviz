from pathlib import Path
import argparse,collections,hashlib,json,os,re,subprocess,sys,zipfile
if not __debug__:raise SystemExit('assertions required')
p=argparse.ArgumentParser();p.add_argument('--base',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--cli',type=Path,required=True);p.add_argument('--core-summary',type=Path,required=True);p.add_argument('--core-root',type=Path,required=True);p.add_argument('--jdk-home',type=Path,required=True);a=p.parse_args();base=a.base.resolve();root=base/'src';out=a.out.resolve();assert not out.exists();out.mkdir();sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
sources=json.loads((base/'source-before.json').read_text(encoding='utf-8'));build=json.loads((base/'evidence-v2/summary.json').read_text(encoding='utf-8'));jni=json.loads((base/'jni-evidence/summary.json').read_text(encoding='utf-8'));assert build['outcome']==jni['outcome']=='passed' and build['source_before']==build['source_after']==sources and jni['source_manifest_sha256']==sha(base/'source-before.json')
for rel,h in sources.items():assert sha(root/rel)==h,rel
aar=Path(build['aar']);dll=Path(jni['dll']);assert sha(aar)==build['aar_sha256'] and sha(dll)==jni['dll_sha256'];cli=a.cli.resolve();cli_summary=a.core_summary.resolve();cs=json.loads(cli_summary.read_text(encoding='utf-8'));assert cs['outcome']=='passed' and cs['inputs_before']==cs['inputs_after'];assert cs.get('artifacts_sha256',{}).get(str(cli))==sha(cli) or (cs.get('cli')==str(cli) and cs.get('cli_sha256')==sha(cli))
core_root=a.core_root.resolve();selected=set()
for path,h in cs['inputs_after'].items():
 path=Path(path)
 try:rel=path.relative_to(core_root)
 except ValueError:continue
 if rel.parts[0] in ('src','include','cmake') or rel.as_posix() in ('CMakeLists.txt','cli/main.cpp','cli/json.hpp') or rel.parts[:2]==('third_party','miniz'):
  assert sha(path)==h and sha(root/rel)==h,rel;selected.add(rel.as_posix())
required={p.relative_to(core_root).as_posix() for d in ('src','include','cmake','third_party/miniz') for p in (core_root/d).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc'}
required.update(('CMakeLists.txt','cli/main.cpp','cli/json.hpp'));assert required and required<=selected,(len(required),len(selected),sorted(required-selected)[:5])
jdk=a.jdk_home.resolve()/'bin';java=jdk/'java.exe';javac=jdk/'javac.exe';test=root/'bindings/android/tests/jni_host/InheritedTargetUseGraphTest.java';fixture=root/'tests/fixtures/generated/inherited-use/local-target.dex';parent=root/'tests/fixtures/generated/inherited/root.dex';inputs=[aar,dll,cli,cli_summary,java,javac,test,fixture,parent,base/'source-before.json',base/'jni-evidence/summary.json',base/'evidence-v2/summary.json',Path(__file__)];inputs.extend(root/rel for rel in sources);inputs.extend(core_root/rel for rel in required);before={str(q):sha(q) for q in inputs}
with zipfile.ZipFile(aar) as z:data=z.read('classes.jar')
jar=out/'classes.jar';jar.write_bytes(data);compiled=out/'test-classes';records=[]
def run(name,cmd):
 r=subprocess.run(list(map(str,cmd)),capture_output=True,timeout=120);(out/(name+'.stdout.log')).write_bytes(r.stdout);(out/(name+'.stderr.log')).write_bytes(r.stderr);records.append({'name':name,'argv':list(map(str,cmd)),'exit_code':r.returncode});(out/'commands.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8');print(name,r.returncode,flush=True)
 if r.returncode:raise SystemExit('FAILED '+name)
 return r.stdout.decode('utf-8')
run('javac',[javac,'-encoding','UTF-8','-cp',jar,'-d',compiled,test]);raw=run('host',[java,'-ea','-Xcheck:jni','-Xlog:class+load=info:file='+str(out/'class-load.log'),'-Djava.library.path='+str(dll.parent),'-cp',os.pathsep.join(map(str,[compiled,jar])),'io.github.jichuo1.dexmeguviz.InheritedTargetUseGraphTest',fixture,parent,out]);lines=raw.splitlines();head=next(x.split() for x in lines if x.startswith('RESULT '));assert len(head)==7 and 'PASS v18 use-graph JNI' in raw
values=[tuple(map(int,line.split()[1:])) for line in lines if line.startswith('INHERITED ')];native=run('cli',[cli,'query',fixture,'--source',fixture,'--source',parent,'--query',out/'query.json','--scope-incomplete','--json']);j=json.loads(native);assert j['query_id']==head[1] and len(j['candidates'])==int(head[2])==8 and j['coverage']=='Complete' and int(head[3])==0 and int(head[5])==0 and j['query_scope']['complete'] and j['query_scope']['explicit'] and len(j['query_scope']['sources'])==int(head[6]);assert [int(x.split()[1]) for x in lines if x.startswith('SCOPE ')]==j['query_scope']['sources']
convert=lambda v:0xffffffff if v is None else int(v);relations={'class_defs':1,'field_defs':2,'method_defs':0,'method_refs':3,'field_refs':4,'type_refs':6,'string_values':5,'invoke_sites':8,'field_uses':9,'string_uses':7};expected=[]
for row in j['candidates']:
 link=row['links'][0];l=link['left'];r=link['right']
 for w in row['evidence']:
  if w['kind']!='inherited':continue
  h=w['inherited'];expected.append((l['source_index'],l['dex_pc'],r['source_index'],w['node_id'],int(w['matched']),h['item'],convert(h['path']),convert(h['aux']),convert(h['branch']),h['detail'],h['source_index'],relations[h['relation']],h['local_index']))
assert collections.Counter(values)==collections.Counter(expected),(len(values),len(expected));log=(out/'class-load.log').read_text(encoding='utf-8',errors='replace');assert 'io.github.jichuo1.dexmeguviz.UseGraphResult source:' in log and 'classes.jar' in log
assert before=={str(q):sha(q) for q in inputs};outputs={str(q):sha(q) for q in out.rglob('*') if q.is_file()};(out/'summary.json').write_text(json.dumps({'outcome':'passed','scope':'v18 explicit-scope use-graph JNI vs CLI inherited evidence; host only','inputs_before':before,'inputs_after':before,'outputs_sha256':outputs,'commands':records,'candidate_rows':len(j['candidates']),'inherited_items':len(expected)},indent=2)+'\n',encoding='utf-8');print('PASS v18 JNI and CLI inherited path parity',len(expected),flush=True)
