"""Pinned desktop SQL collector; produces observations, never A/B/C acceptance."""
from __future__ import annotations
import argparse,collections,datetime,hashlib,json,os,platform,re,sys,time
from pathlib import Path
try:from .process import Process,ProcessFailure
except ImportError:from process import Process,ProcessFailure

class Failure(ValueError):pass
def need(value,message):
    if not value:raise Failure(message)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def digest(data):return hashlib.sha256(data).hexdigest()
def read(path,limit=16<<20):
    with Path(path).open('rb') as file:data=file.read(limit+1)
    need(len(data)<=limit,'file limit: '+str(path));return data
def parse(data):
    def unique(pairs):
        out={}
        for key,value in pairs:need(key not in out,'duplicate JSON key');out[key]=value
        return out
    try:return json.loads(data.decode('utf-8'),object_pairs_hook=unique,parse_constant=lambda x:(_ for _ in ()).throw(Failure('invalid JSON constant')))
    except (UnicodeError,json.JSONDecodeError,RecursionError) as error:raise Failure('invalid JSON') from error
def file_hash(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        while chunk:=stream.read(1<<20):h.update(chunk)
    return h.hexdigest()
def write_new(path,value):
    data=value if isinstance(value,bytes) else canonical(value)+b'\n'
    with path.open('xb') as out:out.write(data);out.flush();os.fsync(out.fileno())
def rows_identity(rows,mode):
    need(isinstance(rows,list),'SQL rows missing')
    for row in rows:
        need(isinstance(row,list),'SQL row must be an array')
        for value in row:
            if value is None or isinstance(value,str):continue
            need(isinstance(value,dict) and len(value)==1,'unexpected SQL cell')
            key,text=next(iter(value.items()));need(isinstance(text,str),'SQL tagged value needs text')
            if key=='integer':need(re.fullmatch(r'0|-?[1-9][0-9]*',text) and -(1<<63)<=int(text)<(1<<63),'invalid integer tag')
            else:need(key=='blob_hex' and len(text)%2==0 and re.fullmatch('[0-9a-f]*',text) is not None,'invalid BLOB tag')
    if mode=='ordered':return digest(canonical(rows))
    need(mode=='bag','unknown result comparison');counts=collections.Counter(canonical(row).decode('ascii') for row in rows)
    return digest(canonical(sorted(counts.items())))
def number(value):
    if value is None:return None
    if type(value)==int:need(value>=0,'negative timing/counter');return value
    need(isinstance(value,str) and re.fullmatch(r'0|[1-9][0-9]*',value),'invalid timing/counter');return int(value)
def native_metrics(profile):
    if not isinstance(profile,dict):return {'statement_prepare_us':None,'first_step_us':None,'query_us':None}
    return {'statement_prepare_us':number(profile.get('prepare_us')) if profile.get('prepare_attempted') else None,
            'first_step_us':number(profile.get('first_step_us')) if profile.get('first_step_observed', 'first_step_us' in profile) else None,
            'query_us':number(profile.get('elapsed_us'))}
def pointer(value,path):
    try:
        for part in path.strip('/').split('/'):value=value[part]
        return value
    except (KeyError,TypeError):return None

class Campaign:
    def __init__(self,config_path,output,connectivity,preflight_only=False):
        self.config_path=config_path.resolve();self.base=self.config_path.parent;self.output=output.resolve()
        self.raw_config=read(self.config_path);write_new(self.output/'config.original.json',self.raw_config);self.config=parse(self.raw_config)
        self.connectivity=connectivity;self.preflight_only=preflight_only;self.pins={};self.records=(self.output/'records.jsonl').open('xb');self.record_count=0;self.completed=0
        self.identity={};self.identity_sha=None;self.parent_ready=False;self.config_sha=digest(self.raw_config)
    def append(self,value):
        value={'schema_version':1,'event_monotonic_ns':time.perf_counter_ns(),'event_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'campaign_id':self.config.get('campaign_id'),'identity_sha256':self.identity_sha,**value};self.records.write(canonical(value)+b'\n');self.records.flush();os.fsync(self.records.fileno());self.record_count+=1
    def pin(self,item,limit=None):
        need(isinstance(item,dict) and isinstance(item.get('path'),str),'pinned file required');path=(self.base/item['path']).resolve();need(path.is_file(),'missing pinned file: '+str(path));expected=item.get('sha256');need(isinstance(expected,str) and re.fullmatch('[0-9a-f]{64}',expected),'pinned lowercase SHA-256 required')
        size=path.stat().st_size;need(limit is None or size<=limit,'pinned input size limit');actual=file_hash(path);need(actual==expected,'pinned file drift: '+str(path));self.pins[str(path)]={'sha256':actual,'bytes':size};return path
    def prepare(self):
        c=self.config;need(c.get('schema_version')==1 and c.get('protocol_id')=='desktop-sql-observations-v1','desktop config version');need(re.fullmatch('[A-Za-z0-9_-]{1,80}',c.get('campaign_id','')),'campaign ID')
        protocol_path=self.pin(c['base_protocol'],16<<20);self.protocol=parse(read(protocol_path));need(self.protocol.get('protocol_id')=='bil-abc-net-value-v1','parent protocol identity')
        missing=[p for p in self.protocol['required_before_run'] if pointer(self.protocol,p) in (None,'',{})];self.parent_ready=self.protocol.get('formal_runner_ready') is True and not missing
        self.limits=c['limits'];bounds={'input_mib':4096,'owned_mib':4096,'sqlite_heap_mib':4096,'max_rows':100000,'max_result_bytes':1<<20,'max_progress_intervals':1000000,'workflow_timeout_seconds':3600}
        need(set(self.limits)==set(bounds),'resource envelope fields');
        for key,maximum in bounds.items():need(type(self.limits[key])==int and 1<=self.limits[key]<=maximum,'invalid limit '+key)
        need(type(c.get('scope_complete'))==bool,'explicit source scope required');self.scope='declared_complete' if c['scope_complete'] else 'partial'
        self.executables={};build_identity={}
        for mode in ('one_shot','resident'):
            item=c['builds'][mode];path=self.pin(item,512<<20);self.executables[mode]=path
            for key in ('source_revision','toolchain_identity','build_flags'):need(item.get(key) not in (None,'',{}),'build identity missing '+key)
            build_identity[mode]={**item,'path':str(path)}
        need(isinstance(c.get('inputs'),list) and 1<=len(c['inputs'])<=64,'source count');self.inputs=[]
        for i,item in enumerate(c['inputs']):
            need(item.get('role') in ('base','code-split','resource-split') and (i!=0 or item['role']=='base') and (i==0 or item['role']!='base'),'source role/order');path=self.pin(item,self.limits['input_mib']<<20);self.inputs.append({**item,'path':str(path),'bytes':path.stat().st_size})
        need(sum(x['bytes'] for x in self.inputs)<=self.limits['input_mib']<<20,'aggregate source cap')
        need(isinstance(c.get('cases'),list) and 1<=len(c['cases'])<=64,'case count');self.cases=[];ids=set()
        for item in c['cases']:
            need(re.fullmatch('[A-Za-z0-9_-]{1,64}',item.get('id','')) and item['id'] not in ids,'case ID');ids.add(item['id']);sql_path=self.pin(item['sql'],65536);sql=read(sql_path,65536).decode('utf-8');need(sql and '\0' not in sql,'invalid SQL text');params_path=self.pin(item['params'],65536);params=parse(read(params_path,65536));need(isinstance(params,list) and len(params)<=256,'parameter list');expected_path=self.pin(item['expected'],8<<20);expected=parse(read(expected_path,8<<20));need(set(expected)=={'rows'},'expected result must contain complete rows only');comparison=item.get('comparison');expected_id=rows_identity(expected['rows'],comparison)
            self.cases.append({**item,'sql_path':sql_path,'params_path':params_path,'sql_text':sql,'params_value':params,'expected_identity':expected_id})
        sampling=c['sampling'];need(sampling['measured_rounds']==self.protocol['sampling']['paired_triplets_per_case'] and sampling['warmup_rounds']==self.protocol['sampling']['warmup_triplets_per_case'] and sampling['queries_per_snapshot']==self.protocol['sampling']['warm_queries_per_snapshot'],'sampling differs from registered count policy')
        order=sampling['order'];need(len(order)==sampling['measured_rounds'] and all(sorted(x)==['one_shot','resident'] for x in order),'fixed paired order required');need(sum(x[0]=='one_shot' for x in order)*2==len(order),'paired order must be balanced')
        need(isinstance(c.get('environment'),dict) and all(c['environment'].get(k) for k in ('host_selection','power_temperature_policy','os_page_cache_policy','measurement_clock')),'environment policy required')
        observed_host={'platform':platform.platform(),'machine':platform.machine(),'node_sha256':digest(platform.node().encode('utf-8')),'python':sys.version,'python_executable_sha256':file_hash(Path(sys.executable))}
        need(c['environment'].get('host_fingerprint')==observed_host,'host/instrumentation identity differs from registration')
        own={p.name:file_hash(p) for p in [Path(__file__),Path(__file__).with_name('process.py')]};need(c.get('runner_files')==own,'runner revision not pinned')
        self.identity={'protocol_id':c['protocol_id'],'base_protocol_sha256':c['base_protocol']['sha256'],'builds':build_identity,'inputs':self.inputs,'cases':c['cases'],'scope_complete':c['scope_complete'],'limits':self.limits,'sampling':sampling,'environment':c['environment'],'runner_files':own,'observed_host':observed_host,'frontend_namespaces':{'one_shot':'cli-v1','resident':'resident-cli'}}
        self.identity_sha=digest(canonical(self.identity));gates=[]
        if not self.connectivity and not self.preflight_only:
            need(c.get('formal_runner_ready') is True and c.get('finalized_at_utc'),'desktop preregistration not frozen')
            for key in ('correctness','lifecycle'):
                gate=self.pin(c['gates'][key],16<<20);value=parse(read(gate));need(value.get('status')=='passed' and value.get('complete') is True and value.get('identity_sha256')==self.identity_sha,'unbound prerequisite gate: '+key);gates.append({'kind':key,'path':str(gate),'sha256':file_hash(gate)})
        elif self.connectivity:need(c.get('data_kind')=='synthetic_control','connectivity requires a self-built fixture label')
        self.drift_check();write_new(self.output/'identity.json',self.identity);write_new(self.output/'preflight.json',{'status':'passed','mode':'preflight_only' if self.preflight_only else 'connectivity' if self.connectivity else 'desktop_collection','parent_protocol_ready':self.parent_ready,'parent_readiness_check':'flag_and_required_fields_presence_only','parent_missing_fields':missing,'gates':gates,'observed_host':observed_host,'identity_sha256':self.identity_sha,'normalization':'none; full SQL cells and multiplicities preserved','performance_acceptance':'not_evaluated'})
    def drift_check(self):
        started=time.perf_counter_ns()
        need(digest(read(self.config_path))==self.config_sha,'campaign config changed')
        for path,pin in self.pins.items():need(Path(path).stat().st_size==pin['bytes'] and file_hash(path)==pin['sha256'],'source/build/query/expected identity drift: '+path)
        self.append({'kind':'identity_check','elapsed_ns':time.perf_counter_ns()-started,'pinned_files':len(self.pins),'outside_backend_query_timing':True})
    def source_args(self):
        args=[self.inputs[0]['path']]
        for source in self.inputs[1:]:args+=['--resource-source' if source['role']=='resource-split' else '--source',source['path']]
        return args
    def envelope_args(self):return ['--max-input-mib',str(self.limits['input_mib']),'--budget-mib',str(self.limits['owned_mib']),'--sqlite-heap-mib',str(self.limits['sqlite_heap_mib'])]
    def verify(self,rows,case):
        start=time.perf_counter_ns();observed=rows_identity(rows,case['comparison']);need(observed==case['expected_identity'],'SQL result mismatch; no row/value/namespace normalization allowed');return time.perf_counter_ns()-start,observed
    def once(self,case,base,count):
        mode_started=time.perf_counter_ns();deadline=time.monotonic()+self.limits['workflow_timeout_seconds'];process_times=[]
        for repeat in range(count):
            self.drift_check();argv=[str(self.executables['one_shot']),'sql',*self.source_args(),'--sql-file',str(case['sql_path']),'--params-file',str(case['params_path']),'--json',*self.envelope_args(),'--sql-max-rows',str(self.limits['max_rows']),'--sql-max-bytes',str(self.limits['max_result_bytes']),'--sql-max-progress',str(self.limits['max_progress_intervals'])]
            if not self.config['scope_complete']:argv+=['--scope-incomplete']
            need(time.monotonic()<deadline,'workflow timeout');directory=self.output/(base+'-one-shot-'+str(repeat));p=Process(argv,directory,deadline-time.monotonic());self.append({'kind':'process_start','base':base,'backend':'one_shot','repeat':repeat,'argv':argv,'directory':directory.name})
            try:
                response,stamp=p.response();need(response.get('command')=='sql' and response.get('execution_status')=='Complete' and response.get('sqlite_status')==0 and response.get('close_status')==0,'one-shot SQL failed');need(response.get('source_scope')==self.scope and response.get('input_count')==len(self.inputs),'one-shot source scope');actual_inputs=response.get('inputs');need(isinstance(actual_inputs,list) and len(actual_inputs)==len(self.inputs),'one-shot source inventory');need(all(a.get('sha256')==b['sha256'] and a.get('index')==i for i,(a,b) in enumerate(zip(actual_inputs,self.inputs))),'runtime source digest mismatch')
                verify_ns,row_id=self.verify(response['rows'],case);runtime=response.get('profile_v1',{}).get('runtime',{});metrics=native_metrics(runtime.get('query'));metrics.update({'source_prepare_us':number(runtime.get('source_prepare_us')),'session_open_us':number(runtime.get('session_open_us')),'close_us':number(runtime.get('close_us')),'external_query_ns':None,'prepare_to_ready_ns':None,'first_result_observed_ns':stamp-p.start_ns,'verify_ns':verify_ns,'first_result_verified_ns':time.perf_counter_ns()-p.start_ns,'first_answer_ns':None});total=p.finish();metrics['process_total_ns']=total;process_times.append(total)
                self.append({'kind':'query','base':base,'backend':'one_shot','repeat':repeat,'complete':True,'correctness_passed':True,'rows_identity':row_id,'environment_valid':None,'metrics':metrics,'raw_directory':directory.name,'snapshot_id':response.get('snapshot_id')})
            finally:p.abort()
        return {'backend':'one_shot','requests':count,'process_total_ns':sum(process_times),'workflow_wall_ns':time.perf_counter_ns()-mode_started,'process_count':count}
    def resident(self,case,base,count):
        mode_started=time.perf_counter_ns();deadline=time.monotonic()+self.limits['workflow_timeout_seconds']
        self.drift_check();argv=[str(self.executables['resident']),*self.source_args(),*self.envelope_args(),'--scope-complete' if self.config['scope_complete'] else '--scope-incomplete'];directory=self.output/(base+'-resident');need(time.monotonic()<deadline,'workflow timeout');p=Process(argv,directory,deadline-time.monotonic());self.append({'kind':'process_start','base':base,'backend':'resident','argv':argv,'directory':directory.name})
        def request(command,op):
            p.send(command);answer,stamp=p.response();need(answer.get('op')==op and answer.get('status')==0,'resident command failed: '+op);return answer,stamp
        def query(sql,params):
            started=time.perf_counter_ns();submit,_=request({'op':'submit','sql':sql,'params':params,'max_rows':self.limits['max_rows'],'max_bytes':self.limits['max_result_bytes'],'max_progress':self.limits['max_progress_intervals']},'submit');task=submit.get('id');need(isinstance(task,str) and re.fullmatch('[1-9][0-9]*',task),'invalid task ID');request({'op':'run'},'run');final,stamp=request({'op':'final','id':task},'final');need(final.get('id')==task and final.get('execution_status')==0 and isinstance(final.get('result'),dict),'resident SQL failed');return task,final,started,stamp
        try:
            ready,ready_stamp=p.response();need(ready.get('op')=='ready' and ready.get('status')==0 and ready.get('source_scope')==self.scope,'resident readiness');prepare_ns=ready_stamp-p.start_ns
            # This explicit, separately charged read verifies the runtime input
            # digests; it is not hidden in the measured application SQL.
            probe='SELECT input_index,source_sha256,input_bytes,slot,role FROM dmg_inputs ORDER BY input_index'
            task,identity,started,stamp=query(probe,[]);result=identity['result'];rows=result.get('rows');need(isinstance(rows,list) and len(rows)==len(self.inputs),'resident input inventory');need(result.get('source_scope')==self.scope and result.get('input_count')==len(self.inputs),'resident source scope');snapshot=result.get('snapshot_id');need(isinstance(snapshot,str) and snapshot,'resident snapshot missing')
            for i,(row,source) in enumerate(zip(rows,self.inputs)):
                expected_slot='main' if i==0 else 'input:'+str(i)+':'+source['path'];expected_role='raw' if i==0 else source['role'];need(row==[{'integer':str(i)},source['sha256'],{'integer':str(source['bytes'])},expected_slot,expected_role],'resident runtime source identity differs')
            request({'op':'ack','id':task},'ack');self.append({'kind':'identity_probe','base':base,'backend':'resident','elapsed_ns':stamp-started,'snapshot_id':snapshot,'raw_directory':directory.name,'not_application_query':True})
            for repeat in range(count):
                self.drift_check();task,answer,start,stamp=query(case['sql_text'],case['params_value']);result=answer['result'];need(result.get('snapshot_id')==snapshot and result.get('source_scope')==self.scope and result.get('input_count')==len(self.inputs),'resident snapshot changed');verify_ns,row_id=self.verify(result.get('rows'),case);metrics=native_metrics(answer.get('profile'));metrics.update({'source_prepare_us':None,'session_open_us':None,'close_us':None,'prepare_to_ready_ns':prepare_ns if repeat==0 else None,'external_query_ns':stamp-start,'verify_ns':verify_ns,'first_result_observed_ns':stamp-p.start_ns if repeat==0 else None,'first_result_verified_ns':time.perf_counter_ns()-p.start_ns if repeat==0 else None,'first_answer_ns':None,'process_total_ns':None});request({'op':'ack','id':task},'ack');self.append({'kind':'query','base':base,'backend':'resident','repeat':repeat,'complete':True,'correctness_passed':True,'rows_identity':row_id,'environment_valid':None,'metrics':metrics,'reuse':answer.get('reuse'),'snapshot_id':snapshot,'raw_directory':directory.name})
            stats,_=request({'op':'stats'},'stats');start=time.perf_counter_ns();closed,stamp=request({'op':'close'},'close');total=p.finish();result={'backend':'resident','requests':count,'identity_probe_queries':1,'process_total_ns':total,'workflow_wall_ns':time.perf_counter_ns()-mode_started,'process_count':1,'prepare_to_ready_ns':prepare_ns,'session_open_us':number(stats.get('open_us')),'close_us':number(closed.get('close_us')),'close_observed_ns':stamp-start,'stats':stats}
        finally:p.abort()
        result['workflow_wall_ns']=time.perf_counter_ns()-mode_started
        return result
    def run(self):
        self.prepare()
        if self.preflight_only:return {'status':'preflight_only','identity_sha256':self.identity_sha,'performance_acceptance':'not_evaluated','benchmark_conclusion':None,'gates_validated':False}
        sampling=self.config['sampling'];schedule=[('connectivity',0,sampling['order'][0])] if self.connectivity else [('warmup',i,sampling['order'][i]) for i in range(sampling['warmup_rounds'])]+[('measured',i,order) for i,order in enumerate(sampling['order'])];queries=2 if self.connectivity else sampling['queries_per_snapshot']
        for case in self.cases:
            for phase,index,order in schedule:
                base=case['id']+'-'+phase+'-'+str(index);self.append({'kind':'pair_start','base':base,'case':case['id'],'phase':phase,'round':index,'order':order,'requests_per_backend':queries})
                for mode in order:
                    value=self.once(case,base,queries) if mode=='one_shot' else self.resident(case,base,queries);self.append({'kind':'mode_complete','base':base,'case':case['id'],'phase':phase,'round':index,**value})
                self.drift_check();self.completed+=1
        return {'status':'connectivity_passed' if self.connectivity else 'desktop_collection_complete','completed_pairs':self.completed,'record_count':self.record_count,'performance_acceptance':'not_evaluated','benchmark_conclusion':None,'bil_abc_results':False,'parent_protocol_ready':self.parent_ready,'identity_sha256':self.identity_sha,'data_kind':'synthetic_control' if self.connectivity else 'desktop_observations','metrics_not_collected':['RSS','PSS','device/ART/Hook','business first-answer','OS page-cache clearing']}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);modes=parser.add_mutually_exclusive_group();modes.add_argument('--connectivity',action='store_true');modes.add_argument('--preflight',action='store_true');args=parser.parse_args();campaign=None;summary=None;created=False
    try:
        args.out=args.out.resolve();args.out.mkdir(exist_ok=False);created=True;campaign=Campaign(args.config,args.out,args.connectivity,args.preflight);summary=campaign.run();code=0
    except (Exception,KeyboardInterrupt) as error:
        summary={'status':'failed','error':type(error).__name__+': '+str(error),'performance_acceptance':'not_evaluated','benchmark_conclusion':None,'completed_pairs':campaign.completed if campaign else 0};code=2
        failure={'kind':'failure','complete':False,'correctness_passed':False,'error':summary['error']}
        if campaign:campaign.append(failure)
        elif created:
            with (args.out/'records.jsonl').open('ab') as log:log.write(canonical(failure)+b'\n');log.flush();os.fsync(log.fileno())
    finally:
        if campaign:campaign.records.close()
        if created and summary is not None:write_new(args.out/'summary.json',summary)
    print(json.dumps(summary,ensure_ascii=True,sort_keys=True));return code
if __name__=='__main__':raise SystemExit(main())
