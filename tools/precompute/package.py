"""Opt-in offline candidate package library and CLI; only standard library code."""
from __future__ import annotations
import argparse,hashlib,io,json,os,re,struct,subprocess,threading,time,zipfile
from pathlib import Path
try:from .local_dex import Dex,LocalError,Unsupported
except ImportError:from local_dex import Dex,LocalError,Unsupported

MAGIC=b'DMGPRE01';VERSION=1;HEADER=struct.Struct('<8sIIQ32s');MAX_PACKAGE=16*1024*1024
VERIFIER='dex-local-bytes-v1'
PROFILES={'dex-query-method-v1','dex-query-entity-v2','dex-query-relational-v3','dex-query-use-v4','dex-query-expand-v5','dex-query-use-target-symbol-v16','dex-query-type-uses-v21','dex-query-method-type-uses-v22'}
class PackageError(ValueError):
    def __init__(self,status,message):super().__init__(message);self.status=status
def need(value,message,status='InvalidPackage'):
    if not value:raise PackageError(status,message)
def sha(data):return hashlib.sha256(data).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def unique(pairs):
    out={}
    for k,v in pairs:
        need(k not in out,'duplicate JSON key');out[k]=v
    return out
def bounded(value,depth=0,counter=None):
    if counter is None:counter=[0]
    counter[0]+=1;need(counter[0]<=200000 and depth<=64,'JSON structural limit','BudgetExceeded')
    if isinstance(value,str):need(len(value)<=1048576,'JSON string limit','BudgetExceeded')
    elif isinstance(value,dict):
        for k,v in value.items():need(isinstance(k,str),'JSON key');bounded(k,depth+1,counter);bounded(v,depth+1,counter)
    elif isinstance(value,list):
        for v in value:bounded(v,depth+1,counter)
    else:need(value is None or type(value) in (int,bool),'non-integral JSON value')
def parse(data):
    need(len(data)<=MAX_PACKAGE,'JSON byte limit','BudgetExceeded')
    try:v=json.loads(data,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(PackageError('InvalidPackage','JSON constant')))
    except (json.JSONDecodeError,UnicodeDecodeError,RecursionError) as e:raise PackageError('InvalidPackage','invalid bounded JSON') from e
    bounded(v);return v
def read_bounded(path,limit):
    with Path(path).open('rb') as f:
        data=f.read(limit+1)
    need(len(data)<=limit,'file byte limit','BudgetExceeded');return data
def write_new(path,data):
    # Exclusive publication: readers reject an incomplete length/digest. No overwrite.
    p=Path(path);p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
def bounded_run(command,timeout=180):
    """Bound stdout/stderr while the child runs; never buffer an unbounded reply."""
    process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    buffers=[bytearray(),bytearray()];overflow=threading.Event();failed=threading.Event()
    def stop():
        try:process.kill()
        except OSError:pass
    def drain(index,stream,cap):
        try:
            while True:
                chunk=stream.read(65536)
                if not chunk:break
                room=cap-len(buffers[index]);buffers[index].extend(chunk[:room])
                if len(chunk)>room:overflow.set();stop();break
        except OSError:failed.set();stop()
        finally:stream.close()
    readers=[threading.Thread(target=drain,args=(0,process.stdout,MAX_PACKAGE),daemon=True),threading.Thread(target=drain,args=(1,process.stderr,1048576),daemon=True)]
    for reader in readers:reader.start()
    expired=False
    try:process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:expired=True;stop();process.wait()
    for reader in readers:reader.join(timeout=5)
    if any(reader.is_alive() for reader in readers):failed.set()
    status='OutputLimit' if overflow.is_set() else 'Deadline' if expired else 'PipeFailure' if failed.is_set() else 'Complete'
    return process.returncode,bytes(buffers[0]),bytes(buffers[1]),status
def load_sources(spec):
    need(spec.get('namespace')=='cli-v1','unsupported source namespace','Unsupported')
    need(type(spec.get('scope_complete')) is bool,'scope completeness required')
    inputs=spec.get('inputs');need(isinstance(inputs,list) and 1<=len(inputs)<=64,'input count','BudgetExceeded')
    sources=[];keys=[];total=0;expanded=0;seen=set()
    for i,item in enumerate(inputs):
        need(set(item)<= {'path','slot','role','format'},'unknown source option')
        path=Path(item['path']).resolve();role=item.get('role','base' if i==0 else 'code-split');need(role==('base' if i==0 else role) and role in ('base','code-split','resource-split'),'source role')
        need(i==0 or role!='base','only first input is base');slot=item.get('slot',f'input:{i}:{path}')
        need(isinstance(slot,str) and len(slot)<=32767 and '\0' not in slot and slot not in seen,'source slot');seen.add(slot)
        raw=read_bounded(path,256*1024*1024);total+=len(raw);need(total<=512*1024*1024,'total source limit','BudgetExceeded')
        kind=item.get('format','raw' if raw.startswith(b'dex\n') else 'apk');need(kind in ('raw','apk'),'source format','Unsupported');entries=[]
        if kind=='raw':
            expanded+=len(raw);need(expanded<=512*1024*1024,'expanded DEX limit','BudgetExceeded');entries=[(None,None,raw)]
        else:
            try:
                with zipfile.ZipFile(io.BytesIO(raw)) as z:
                    names=set();pending=[]
                    for central,entry in enumerate(z.infolist()):
                        need(len(names)<100000,'archive entry limit','BudgetExceeded');need(entry.filename not in names,'duplicate archive entry');names.add(entry.filename)
                        if not re.fullmatch(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex',entry.filename):
                            need(not re.fullmatch(r'classes[^/]*\.dex',entry.filename),'noncanonical DEX entry');continue
                        need(not entry.flag_bits&1 and entry.compress_type in (0,8),'archive encoding','Unsupported');need(entry.file_size<=64*1024*1024,'DEX size','BudgetExceeded')
                        order=1 if entry.filename=='classes.dex' else int(entry.filename[7:-4]);pending.append((order,central,entry))
                    need(pending or role=='resource-split','archive has no DEX')
                    for _,central,entry in sorted(pending):
                        expanded+=entry.file_size;need(expanded<=512*1024*1024,'expanded DEX limit','BudgetExceeded');entries.append((entry.filename,central,z.read(entry)))
            except (zipfile.BadZipFile,RuntimeError,EOFError) as e:raise PackageError('CorruptInput','archive parse/CRC failure') from e
        key={'slot':slot,'role':role,'format':kind,'sha256':sha(raw),'bytes':len(raw)};keys.append(key)
        for entry,central,data in entries:
            need(len(sources)<1024 and len(data)<=64*1024*1024,'DEX source limit','BudgetExceeded')
            sources.append({'source_index':len(sources),'input_index':i,'entry':entry,'central_index':central,'sha256':sha(data),'bytes':len(data),'data':data})
    need(sum(s['bytes'] for s in sources)<=512*1024*1024,'expanded DEX limit','BudgetExceeded')
    identity={'namespace':spec['namespace'],'scope_complete':spec['scope_complete'],'inputs':keys,'sources':[{k:v for k,v in s.items() if k!='data'} for s in sources]}
    return identity,sources
def widths(root):
    data=read_bounded(Path(root)/'tests/fixtures/generated/instructions/opcode_widths.json',MAX_PACKAGE);v=parse(data)
    return {row['opcode']:row['width'] for row in v['rows']},sha(data)
def certificates(result,sources,width_map,previous=None):
    dex={};out=[];old={c['pointer']:c for c in previous or []};visited=set()
    def get(i):
        need(type(i)==int and 0<=i<len(sources),'evidence source')
        if i not in dex:dex[i]=Dex(sources[i]['data'])
        return dex[i]
    def certify(obj,pointer,context=None,depth=0):
        need(depth<=48 and len(out)<=100000,'evidence limit','BudgetExceeded')
        if isinstance(obj,list):
            for i,v in enumerate(obj):certify(v,pointer+'/'+str(i),context,depth+1)
            return
        if not isinstance(obj,dict):return
        relation=obj.get('relation');source=obj.get('source_index',context[0] if context else None);ordinal=None;cert=None;d=get(source) if source is not None else None
        if source is not None and 'source_sha256' in obj:need(obj['source_sha256']==sources[source]['sha256'],'candidate source digest','SourceMismatch')
        if source is not None and 'input_index' in obj:need(obj['input_index']==sources[source]['input_index'],'candidate input occurrence','SourceMismatch')
        if 'method_index' in obj and 'declaration_offset' in obj and relation is None:
            relation='method_defs'
            if previous is not None:need(pointer in old,'missing method locator');ordinal=old[pointer]['value']['local_index']
            else:ordinal=d.method_from_ref(obj['method_index'],obj['declaration_offset'])
        elif relation in ('method_defs','class_defs','field_defs','method_refs','field_refs','type_refs','string_values') and 'local_index' in obj:ordinal=obj['local_index']
        if ordinal is not None:
            need(type(ordinal)==int and ordinal>=0,'local index');value=d.describe(relation,ordinal)
            aliases={'method_index':'reference_index','definition_offset':'declaration_offset','descriptor':'type_descriptor'}
            for key,raw in obj.items():
                k=aliases.get(key,key)
                if k in value and raw is not None and key not in ('relation',):need(raw==value[k],'candidate '+k+' differs from bytes','EvidenceMismatch')
            cert={'pointer':pointer,'source_index':source,'value':value}
            if relation=='method_defs':context=(source,ordinal)
        elif relation in ('string_uses','invoke_sites','field_uses','type_uses') and 'dex_pc' in obj:
            ordinal=obj.get('caller_ordinal',obj.get('local_index'))
            need(type(ordinal)==int and ordinal>=0 and type(obj['dex_pc'])==int and obj['dex_pc']>=0,'use caller/PC identity','EvidenceMismatch')
            if 'local_index' in obj:need(type(obj['local_index'])==int and obj['local_index']==ordinal,'use caller ordinal disagreement','EvidenceMismatch')
            caller=d.describe('method_defs',ordinal);value=d.event(ordinal,obj['dex_pc'],width_map)
            domain={'string_uses':'string_value','invoke_sites':'method_ref','field_uses':'field_ref','type_uses':'type_ref'}[relation]
            need(value['target_domain']==domain,'use relation differs from opcode family','EvidenceMismatch')
            if 'caller_method_ref' in obj:need(type(obj['caller_method_ref'])==int and obj['caller_method_ref']==caller['reference_index'],'use caller method reference','EvidenceMismatch')
            for key in ('owner','name','prototype'):
                if key in obj and obj[key] is not None:need(obj[key]==caller[key],'use caller '+key,'EvidenceMismatch')
            if 'extra_proto' in obj:need(obj['extra_proto'] is None,'ordinary use extra prototype','EvidenceMismatch')
            if 'instruction_offset' in obj:need(type(obj['instruction_offset'])==int and obj['instruction_offset']==value['code_offset']+16+obj['dex_pc']*2,'use instruction offset','EvidenceMismatch')
            if 'target_descriptor' in obj:need(value['target_domain']=='type_ref' and obj['target_descriptor']==value['target']['type_descriptor'],'type use descriptor','EvidenceMismatch')
            for key in ('opcode','target_index','target_domain','code_offset'):
                if key in obj:need(type(obj[key])==type(value[key]) and obj[key]==value[key],'use '+key+' differs from bytes','EvidenceMismatch')
            cert={'pointer':pointer,'source_index':source,'event':value};context=(source,ordinal)
        elif all(k in obj for k in ('caller','resolved','dex_pc','target_method_ref')):
            caller=obj['caller'];resolved=obj['resolved'];need(caller.get('relation')=='method_defs' and resolved.get('relation')=='method_defs','hop endpoint domain','EvidenceMismatch')
            need(type(caller.get('local_index'))==int and caller['local_index']>=0 and type(resolved.get('local_index'))==int and resolved['local_index']>=0 and type(obj['dex_pc'])==int and obj['dex_pc']>=0,'hop index/PC','EvidenceMismatch')
            source=caller['source_index'];ordinal=caller['local_index'];d=get(source);value=d.event(ordinal,obj['dex_pc'],width_map)
            need(value['target_domain']=='method_ref' and value['target_index']==obj['target_method_ref'] and value['opcode']==obj['opcode'],'path hop mismatch','EvidenceMismatch')
            resolved=obj['resolved'];target=get(resolved['source_index']).describe('method_defs',resolved['local_index'])
            need(all(target[k]==value['target'][k] for k in ('owner','name','prototype')),'resolved hop symbol mismatch','EvidenceMismatch')
            cert={'pointer':pointer,'source_index':source,'event':value}
        elif 'kind' in obj and 'node_id' in obj:
            kind=obj['kind'];need(kind in ('metadata','string_use','invoke','field_use','type_use','instruction_scope','no_body'),'unsupported local witness '+str(kind),'Unsupported')
            if kind!='metadata':
                witness_context=context
                e=obj.get('entity')
                if e and e.get('relation')=='method_defs':witness_context=(e['source_index'],e['local_index'])
                need(witness_context is not None,'witness method context','Unsupported');source,ordinal=witness_context;d=get(source)
                if kind=='no_body':need(d.describe('method_defs',ordinal)['code_offset']==0,'no-body mismatch','EvidenceMismatch');value=d.code_certificate(ordinal)
                elif kind=='instruction_scope':value=d.code_certificate(ordinal);need(obj.get('code_units')==value['code_units'],'code size mismatch','EvidenceMismatch')
                else:
                    value=d.event(ordinal,obj['dex_pc'],width_map);need(obj.get('opcode')==value['opcode'] and obj.get('reference_index')==value['target_index'],'instruction evidence mismatch','EvidenceMismatch')
                    expected={'string_use':'string_value','invoke':'method_ref','field_use':'field_ref','type_use':'type_ref'}[kind];need(value['target_domain']==expected,'witness reference domain','EvidenceMismatch')
                    if 'target_descriptor' in obj:need(obj['target_descriptor']==value['target']['type_descriptor'],'type descriptor mismatch','EvidenceMismatch')
                cert={'pointer':pointer,'source_index':source,'local_bytes':value}
        if cert:
            out.append(cert);visited.add(pointer)
            if previous is not None:need(old.get(pointer)==cert,'local certificate mismatch','EvidenceMismatch')
        for key,v in obj.items():
            if key not in ('source_index','relation'):
                child_context=context
                if key=='seed_witnesses' and 'seed' in obj:child_context=(obj['seed']['source_index'],obj['seed']['local_index'])
                certify(v,pointer+'/'+key,child_context,depth+1)
    certify(result['candidates'],'/candidates');certify(result.get('frontiers',[]),'/frontiers')
    need(all('/candidates/'+str(i) in visited for i in range(len(result['candidates']))),'candidate identity coverage','Unsupported')
    if previous is not None:need(len(old)==len(previous) and visited==set(old),'certificate coverage mismatch','EvidenceMismatch')
    return out,sum(d.work for d in dex.values())
def build_package(config,cli,output,root,workdir):
    started=time.perf_counter_ns();need(config.get('schema_version')==1,'config version','Unsupported');need(isinstance(config.get('model_version'),str),'model version')
    identity,sources=load_sources(config);source_ns=time.perf_counter_ns()-started;wm,wh=widths(root);rules=config.get('rules');need(isinstance(rules,list) and 1<=len(rules)<=128,'rule count')
    run=Path(workdir);run.mkdir(parents=True,exist_ok=False);executable=Path(cli).resolve();need(executable.is_file(),'CLI missing');engine_hash=sha(read_bounded(executable,64*1024*1024));records=[];seen=set()
    for index,rule in enumerate(rules):
        need(set(rule)=={'id','version','profile','query','roles'},'rule fields');need(isinstance(rule['id'],str) and rule['id'] not in seen,'rule identity');seen.add(rule['id']);need(rule['profile'] in PROFILES,'local profile unsupported','Unsupported')
        query=canonical(rule['query']);need(len(query)<=65536,'query limit','BudgetExceeded');qp=run/(str(index)+'.query.json');write_new(qp,query)
        cmd=[str(executable),'query',str(Path(config['inputs'][0]['path']).resolve()),'--query',str(qp),'--json']
        for item in config['inputs'][1:]:cmd += ['--resource-source' if item.get('role')=='resource-split' else '--source',str(Path(item['path']).resolve())]
        if not config['scope_complete']:cmd += ['--scope-incomplete']
        returncode,stdout,stderr,process_status=bounded_run(cmd);write_new(run/(str(index)+'.stdout.json'),stdout);write_new(run/(str(index)+'.stderr.log'),stderr)
        write_new(run/(str(index)+'.command.json'),canonical({'argv':cmd,'returncode':returncode,'capture_status':process_status,'stdout_limit':MAX_PACKAGE,'stderr_limit':1048576}))
        need(process_status=='Complete','generation child '+process_status,'BudgetExceeded' if process_status=='OutputLimit' else 'QueryFailed')
        need(returncode==0,'generation query failed','QueryFailed');actual=parse(stdout);need(actual.get('execution_status')=='Complete','incomplete generation','QueryFailed');need(actual.get('profile')==rule['profile'],'profile mismatch','VersionMismatch')
        need(len(actual.get('candidates',[]))<=4096,'candidate limit','BudgetExceeded');need(len(actual['sources'])==len(sources) and len(actual['inputs'])==len(identity['inputs']),'source enumeration mismatch','SourceMismatch')
        for a,b in zip(actual['inputs'],identity['inputs']):need(a['source_sha256']==b['sha256'] and a['slot_key']==b['slot'] and a['role']==b['role'],'CLI source identity','SourceMismatch')
        for a,b in zip(actual['sources'],sources):need(a['source_sha256']==b['sha256'] and a['input_index']==b['input_index'],'CLI DEX identity','SourceMismatch')
        cert,work=certificates(actual,sources,wm);need(cert or not actual['candidates'],'no verifiable candidate identity','Unsupported')
        need(isinstance(rule['roles'],dict),'role mapping');roles={}
        for role,indices in rule['roles'].items():
            need(isinstance(role,str) and 1<=len(role)<=128 and isinstance(indices,list),'role');need(all(type(i)==int and 0<=i<len(actual['candidates']) for i in indices),'role candidate index');roles[role]=indices
        records.append({'id':rule['id'],'version':rule['version'],'profile':rule['profile'],'query':rule['query'],'query_id':actual['query_id'],'query_sha256':sha(query),'roles':roles,'local_verifier':VERIFIER,'result':actual,'certificates':cert})
    current,_=load_sources(config);need(current==identity,'sources changed during generation','SourceMismatch');need(sha(read_bounded(executable,64*1024*1024))==engine_hash,'CLI changed during generation','VersionMismatch')
    payload={'format_version':VERSION,'model_version':config['model_version'],'source_identity':identity,'engine_sha256':engine_hash,'local_verifier':VERIFIER,'opcode_table_sha256':wh,'rules':records};raw=canonical(payload);need(len(raw)<=MAX_PACKAGE,'package limit','BudgetExceeded');binary=HEADER.pack(MAGIC,VERSION,HEADER.size,len(raw),bytes.fromhex(sha(raw)))+raw;write_new(output,binary)
    return {'schema_version':1,'package_sha256':sha(binary),'model_version':payload['model_version'],'source_identity':identity,'engine_sha256':engine_hash,'local_verifier':VERIFIER,'opcode_table_sha256':wh,'rules':[{k:v for k,v in r.items() if k not in ('result','certificates','query','roles')}|{'roles_sha256':sha(canonical(r['roles']))} for r in records],'timing_ns':{'generation':time.perf_counter_ns()-started,'initial_source_read_hash':source_ns},'authenticity':'Caller must retain this expectation independently; digest is not publisher authentication'}
def load_candidates(path,expected,current,root):
    start=time.perf_counter_ns();binary=read_bounded(path,MAX_PACKAGE+HEADER.size);need(expected.get('schema_version')==1,'expectation version','Unsupported');need(sha(binary)==expected.get('package_sha256'),'caller package digest mismatch','DigestMismatch')
    need(len(binary)>=HEADER.size,'truncated header');magic,version,size,n,digest=HEADER.unpack_from(binary);need(magic==MAGIC and version==VERSION and size==HEADER.size,'package format','Unsupported');need(n==len(binary)-size and n<=MAX_PACKAGE,'package length');raw=binary[size:];need(hashlib.sha256(raw).digest()==digest,'payload checksum','DigestMismatch');p=parse(raw)
    need(set(p)=={'format_version','model_version','source_identity','engine_sha256','local_verifier','opcode_table_sha256','rules'},'payload fields');need(p['format_version']==VERSION and p['local_verifier']==VERIFIER,'verifier version','Unsupported')
    for key in ('model_version','engine_sha256','local_verifier','opcode_table_sha256','source_identity'):need(p[key]==expected.get(key),'caller expectation mismatch: '+key,'VersionMismatch')
    package_ns=time.perf_counter_ns()-start;at=time.perf_counter_ns();need(current.get('model_version')==expected['model_version'],'current model version mismatch','VersionMismatch');identity,sources=load_sources(current);need(identity==expected['source_identity'],'current ordered source identity mismatch','SourceMismatch');source_ns=time.perf_counter_ns()-at
    wm,wh=widths(root);need(wh==expected['opcode_table_sha256'],'trusted local verifier table changed','VersionMismatch');need(len(p['rules'])==len(expected['rules']),'rule count mismatch','VersionMismatch');at=time.perf_counter_ns();reports=[];work=0
    for r,e in zip(p['rules'],expected['rules']):
        need(r['profile'] in PROFILES and r['local_verifier']==VERIFIER,'unsupported local profile','Unsupported')
        key={k:v for k,v in r.items() if k not in ('result','certificates','query','roles')}|{'roles_sha256':sha(canonical(r['roles']))};need(key==e and sha(canonical(r['query']))==e['query_sha256'],'caller rule/query/roles mismatch','VersionMismatch')
        need(r['result']['query_id']==e['query_id'] and r['result']['profile']==e['profile'],'result identity mismatch','VersionMismatch')
        _,units=certificates(r['result'],sources,wm,r['certificates']);work+=units
        result=r['result'];profile=result.get('query_profile') if isinstance(result.get('query_profile'),dict) else {};v1=result.get('profile_v1') if isinstance(result.get('profile_v1'),dict) else {};runtime=v1.get('runtime') if isinstance(v1.get('runtime'),dict) else {};plan=v1.get('plan') if isinstance(v1.get('plan'),dict) else {};scope=result.get('query_scope') if isinstance(result.get('query_scope'),dict) else {}
        scalar=lambda value:value if type(value) in (str,int,bool) else None
        indices=scope.get('sources');indices=indices if isinstance(indices,list) and len(indices)==len(sources) and all(type(x) is int and x>=0 for x in indices) else None
        claim={k:scalar(result.get(k)) for k in ('coverage','decision','reason','unknown_rows')}
        claim.update({k:scalar(result.get(k)) for k in ('execution_status','visited_methods','total_methods','scope_complete')})
        claim.update({'unknown_rows_present':'unknown_rows' in result,'query_profile_unknown_rows':scalar(profile.get('unknown_rows')),'query_scope_complete':scalar(scope.get('complete')),'query_scope_explicit':scalar(scope.get('explicit')),'query_scope_sources':indices,'profile_v1_present':'profile_v1' in result,'profile_v1_producer':scalar(v1.get('producer')),'profile_v1_phase':scalar(v1.get('phase')),'profile_v1_query_id':scalar(plan.get('query_id')),'profile_v1_unknown_rows':scalar(runtime.get('unknown_rows')),'profile_v1_scope_complete':scalar(runtime.get('scope_complete'))})
        reports.append({'id':r['id'],'query_id':r['query_id'],'roles':r['roles'],'candidates':result['candidates'],'frontiers':result.get('frontiers',[]),'producer_claim':claim,'query_decision_verified':False,'runtime_binding':'NotPerformed'})
    return {'status':'CandidatesLocallyVerified','source_identity':identity,'rules':reports,'local_work_units':work,'full_locator_scans':0,'package_authenticated':False,'runtime_binding':'NotPerformed','timing_ns':{'package_read_check':package_ns,'source_read_hash':source_ns,'local_verification':time.perf_counter_ns()-at,'total':time.perf_counter_ns()-start}}
def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='command',required=True)
    a=sub.add_parser('build');a.add_argument('--config',type=Path,required=True);a.add_argument('--cli',type=Path,required=True);a.add_argument('--output',type=Path,required=True);a.add_argument('--expected-output',type=Path,required=True);a.add_argument('--workdir',type=Path,required=True)
    a=sub.add_parser('consume');a.add_argument('--package',type=Path,required=True);a.add_argument('--expected',type=Path,required=True);a.add_argument('--current',type=Path,required=True)
    for a in sub.choices.values():a.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2])
    args=p.parse_args()
    try:
        if args.command=='build':report=build_package(parse(read_bounded(args.config,MAX_PACKAGE)),args.cli,args.output,args.root,args.workdir);write_new(args.expected_output,canonical(report))
        else:report=load_candidates(args.package,parse(read_bounded(args.expected,MAX_PACKAGE)),parse(read_bounded(args.current,MAX_PACKAGE)),args.root)
        print(json.dumps(report,ensure_ascii=True,sort_keys=True));return 0
    except (PackageError,LocalError,OSError,KeyError,TypeError,struct.error,subprocess.TimeoutExpired) as e:
        print(json.dumps({'status':getattr(e,'status','Unsupported' if isinstance(e,Unsupported) else 'InvalidPackage'),'detail':str(e)},ensure_ascii=True));return 2
if __name__=='__main__':raise SystemExit(main())
