#include "c_api/runtime.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace dexmeguviz;
namespace dexmeguviz::reference { extern std::atomic<void(*)()> test_result_limit_barrier; }
namespace dexmeguviz::runtime { extern std::atomic<void(*)(uint32_t)> test_job_commit_barrier; extern std::atomic<bool> test_job_cancel_lock_failure; extern std::atomic<void(*)()> test_job_queue_wait_barrier; extern std::atomic<void(*)(uint32_t)> test_job_scan_barrier; }
#define CHECK(x) do{if(!(x))throw std::runtime_error("Q09 check "+std::to_string(__LINE__)+": " #x);}while(0)
using Engine=std::unique_ptr<dmg_engine,decltype(&dmg_engine_release)>;
using Snapshot=std::unique_ptr<dmg_snapshot,decltype(&dmg_snapshot_release)>;
using Query=std::unique_ptr<dmg_query,decltype(&dmg_query_release)>;
using Job=std::unique_ptr<dmg_job,decltype(&dmg_job_release)>;
using Batch=std::unique_ptr<dmg_batch,decltype(&dmg_batch_release)>;
static std::mutex gate_mutex;
static std::condition_variable gate_cv;
static bool gate_entered=false,gate_open=false;
static uint32_t gate_count=UINT32_MAX;
static uint32_t scan_gate_target=UINT32_MAX;
static void scan_gate_callback(uint32_t count){
    if(count!=scan_gate_target)return;
    std::unique_lock lock(gate_mutex);gate_count=count;gate_entered=true;gate_cv.notify_all();
    gate_cv.wait(lock,[]{return gate_open;});
}
static void arm_scan(uint32_t target){
    std::lock_guard lock(gate_mutex);gate_entered=false;gate_open=false;gate_count=UINT32_MAX;scan_gate_target=target;
    runtime::test_job_scan_barrier.store(&scan_gate_callback,std::memory_order_release);
}
static void gate_callback(uint32_t count){
    std::unique_lock lock(gate_mutex);gate_count=count;gate_entered=true;gate_cv.notify_all();
    gate_cv.wait(lock,[]{return gate_open;});
}
static void arm(){
    std::lock_guard lock(gate_mutex);gate_entered=false;gate_open=false;gate_count=UINT32_MAX;
    runtime::test_job_commit_barrier.store(&gate_callback,std::memory_order_release);
}
static uint32_t entered(){
    std::unique_lock lock(gate_mutex);CHECK(gate_cv.wait_for(lock,std::chrono::seconds(15),[]{return gate_entered;}));return gate_count;
}
static void unblock(){
    {std::lock_guard lock(gate_mutex);gate_open=true;runtime::test_job_commit_barrier.store(nullptr,std::memory_order_release);runtime::test_job_scan_barrier.store(nullptr,std::memory_order_release);reference::test_result_limit_barrier.store(nullptr,std::memory_order_release);}
    gate_cv.notify_all();
}
struct GateGuard{~GateGuard(){unblock();}};
static std::mutex queue_gate_mutex;
static std::condition_variable queue_gate_cv;
static bool queue_gate_entered=false,queue_gate_open=false;
static void queue_gate_callback(){
    std::unique_lock lock(queue_gate_mutex);queue_gate_entered=true;queue_gate_cv.notify_all();
    queue_gate_cv.wait(lock,[]{return queue_gate_open;});
}
static void arm_queue_gate(){
    std::lock_guard lock(queue_gate_mutex);queue_gate_entered=false;queue_gate_open=false;
    runtime::test_job_queue_wait_barrier.store(&queue_gate_callback,std::memory_order_release);
}
static void await_queue_gate(){
    std::unique_lock lock(queue_gate_mutex);CHECK(queue_gate_cv.wait_for(lock,std::chrono::seconds(15),[]{return queue_gate_entered;}));
}
static void unblock_queue_gate(){
    {std::lock_guard lock(queue_gate_mutex);queue_gate_open=true;runtime::test_job_queue_wait_barrier.store(nullptr,std::memory_order_release);}
    queue_gate_cv.notify_all();
}
struct QueueGateGuard{~QueueGateGuard(){unblock_queue_gate();}};
static std::vector<uint8_t> load(const std::filesystem::path& path){
    std::ifstream in(path,std::ios::binary);CHECK(in.good());return {std::istreambuf_iterator<char>(in),{}};
}
enum class Profile {v1,v2,v3,v4};
static const char* label(Profile p){switch(p){case Profile::v1:return "v1";case Profile::v2:return "v2";case Profile::v3:return "v3";case Profile::v4:return "v4";}return "invalid";}
static std::string query_text(Profile p,int kind,bool limit=false){
    const char* relation=nullptr;const char* where="";
    switch(p){
    case Profile::v1:relation="\"method_defs\"";where=kind==1?",\"where\":{\"name\":\"quiet\"}":kind==2?",\"where\":{\"name\":\"never-q09\"}":"";break;
    case Profile::v2:relation="\"field_defs\"";where=kind==1?",\"where\":{\"name\":\"shared\",\"owner\":\"Lcatalog/Base;\"}":kind==2?",\"where\":{\"name\":\"never-q09\"}":"";break;
    case Profile::v3:relation=kind==1?"{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"name\":\"quiet\"}}":kind==2?"{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"name\":\"never-q09\"}}":"{\"op\":\"scan\",\"relation\":\"method_defs\"}";break;
    case Profile::v4:relation=kind==2?"{\"op\":\"scan\",\"relation\":\"invoke_sites\",\"where\":{\"caller_name\":\"never-q09\"}}":"{\"op\":\"scan\",\"relation\":\"invoke_sites\"}";break;
    }
    return std::string("{\"schema_version\":1,\"relation\":")+relation+where+",\"intent\":\"unique\",\"max_results\":"+(limit?"1":"100")+"}";
}
static Engine make_engine(){dmg_engine* raw=nullptr;dmg_error error{};CHECK(dmg_engine_create(nullptr,&raw,&error)==DMG_OK&&raw);return Engine(raw,&dmg_engine_release);}
static Snapshot snapshot(dmg_engine* engine,const std::vector<uint8_t>& bytes,Profile p,bool repeat){
    const auto expected=p==Profile::v2?"e1059582b6c893690880403d00f6b5be8dfceb7be282793e2117bdf15b14e77a":"8262d2b338e54a7965111b4cec1ef9e628ada9795ad2f6a555d717a2ba9546bc";
    std::vector<dmg_source_spec> specs;
    for(uint32_t i=0;i<(repeat?2u:1u);++i){dmg_source_spec s{};s.struct_size=sizeof(s);s.abi_version=DMG_ABI_VERSION;s.format=DMG_INPUT_RAW_DEX;s.data=bytes.data();s.size=bytes.size();s.slot_key=i?"second":"first";s.role=i?"code-split":"base";s.expected_sha256=expected;specs.push_back(s);}
    dmg_source_set_options options{sizeof(options),DMG_ABI_VERSION,"q09-unique",1,8,1u<<20};dmg_snapshot* raw=nullptr;dmg_error error{};
    CHECK(dmg_snapshot_open_sources(engine,specs.data(),static_cast<uint32_t>(specs.size()),&options,&raw,&error)==DMG_OK&&raw);return Snapshot(raw,&dmg_snapshot_release);
}
static Query compile(dmg_engine* engine,Profile p,int kind,bool limit=false){
    const auto text=query_text(p,kind,limit);dmg_query* raw=nullptr;dmg_error error{};
    CHECK(dmg_query_compile_json(engine,reinterpret_cast<const uint8_t*>(text.data()),text.size(),&raw,&error)==DMG_OK&&raw);return Query(raw,&dmg_query_release);
}
static Job start(dmg_snapshot* snapshot,dmg_query* query,uint32_t queued,uint64_t deadline_ms=0,uint32_t batch_size=1){
    dmg_job_options options{sizeof(options),DMG_ABI_VERSION,batch_size,queued,deadline_ms};dmg_job* raw=nullptr;dmg_error error{};
    CHECK(dmg_job_start(snapshot,query,&options,&raw,&error)==DMG_OK&&raw);return Job(raw,&dmg_job_release);
}
struct Outcome{uint32_t lifecycle,terminal,status,coverage,decision,reason,count;};
static Outcome get(dmg_job* job,Profile p,bool wait){
    if(p==Profile::v1){dmg_job_status s{};CHECK((wait?dmg_job_wait(job,15000,&s):dmg_job_get_status(job,&s))==DMG_OK);return {s.lifecycle,s.terminal,s.outcome.execution_status,s.outcome.coverage,s.outcome.decision,s.outcome.reason,s.outcome.candidates_count};}
    if(p==Profile::v4){dmg_relation_job_status_v2 s{};CHECK((wait?dmg_job_wait_relation_v2(job,15000,&s,sizeof(s)):dmg_job_get_relation_status_v2(job,&s,sizeof(s)))==DMG_OK);return {s.lifecycle,s.terminal,s.outcome.execution_status,s.outcome.coverage,s.outcome.decision,s.outcome.reason,s.outcome.candidates_count};}
    dmg_relation_job_status s{};CHECK((wait?dmg_job_wait_relation(job,15000,&s,sizeof(s)):dmg_job_get_relation_status(job,&s,sizeof(s)))==DMG_OK);return {s.lifecycle,s.terminal,s.outcome.execution_status,s.outcome.coverage,s.outcome.decision,s.outcome.reason,s.outcome.candidates_count};
}
static bool wait_limited(dmg_job* job,Profile p,uint32_t timeout,Outcome& out){
    if(p==Profile::v1){dmg_job_status s{};const auto code=dmg_job_wait(job,timeout,&s);if(code==DMG_NOT_READY)return false;CHECK(code==DMG_OK);out={s.lifecycle,s.terminal,s.outcome.execution_status,s.outcome.coverage,s.outcome.decision,s.outcome.reason,s.outcome.candidates_count};return true;}
    if(p==Profile::v4){dmg_relation_job_status_v2 s{};const auto code=dmg_job_wait_relation_v2(job,timeout,&s,sizeof(s));if(code==DMG_NOT_READY)return false;CHECK(code==DMG_OK);out={s.lifecycle,s.terminal,s.outcome.execution_status,s.outcome.coverage,s.outcome.decision,s.outcome.reason,s.outcome.candidates_count};return true;}
    dmg_relation_job_status s{};const auto code=dmg_job_wait_relation(job,timeout,&s,sizeof(s));if(code==DMG_NOT_READY)return false;CHECK(code==DMG_OK);out={s.lifecycle,s.terminal,s.outcome.execution_status,s.outcome.coverage,s.outcome.decision,s.outcome.reason,s.outcome.candidates_count};return true;
}
static void expect(const Outcome& actual,uint32_t lifecycle,uint32_t status,uint32_t coverage,uint32_t decision,uint32_t reason,uint32_t count){
    if(!(actual.terminal==1&&actual.lifecycle==lifecycle&&actual.status==status&&actual.coverage==coverage&&actual.decision==decision&&actual.reason==reason&&actual.count==count))
        std::cerr<<"actual terminal/lifecycle/status/coverage/decision/reason/count="<<actual.terminal<<'/'<<actual.lifecycle<<'/'<<actual.status<<'/'<<actual.coverage<<'/'<<actual.decision<<'/'<<actual.reason<<'/'<<actual.count<<" expected="<<1<<'/'<<lifecycle<<'/'<<status<<'/'<<coverage<<'/'<<decision<<'/'<<reason<<'/'<<count<<'\n';
    CHECK(actual.terminal==1&&actual.lifecycle==lifecycle&&actual.status==status&&actual.coverage==coverage&&actual.decision==decision&&actual.reason==reason&&actual.count==count);
}
static void await_one(dmg_job* job,Profile p){
    const auto end=std::chrono::steady_clock::now()+std::chrono::seconds(15);
    for(;;){const auto value=get(job,p,false);CHECK(!value.terminal);if(value.count==1)return;CHECK(std::chrono::steady_clock::now()<end);std::this_thread::yield();}
}
struct Evidence{uint32_t source,local,reference,pc;std::string content,occurrence,snapshot;};
static Evidence read_batch(dmg_batch* batch,Profile p){
    dmg_source_info origin{};CHECK(dmg_result_get_origin(batch,0,&origin)==DMG_OK&&origin.dex.content_id&&origin.dex.occurrence_id&&origin.dex.snapshot_id);
    Evidence e{origin.source_index,0,0,UINT32_MAX,origin.dex.content_id,origin.dex.occurrence_id,origin.dex.snapshot_id};
    if(p==Profile::v1){dmg_result_info info{};dmg_method_row row{};CHECK(dmg_batch_get_info(batch,&info)==DMG_OK&&info.candidates_count==1&&info.coverage==DMG_COVERAGE_PARTIAL&&info.decision==DMG_NOT_APPLICABLE);CHECK(dmg_batch_get_method(batch,0,&row)==DMG_OK);e.local=e.reference=row.method_index;}
    else if(p==Profile::v4){dmg_relation_info_v2 info{};dmg_value_row_v2 row{};CHECK(dmg_result_get_relation_info_v2(batch,&info,sizeof(info))==DMG_OK&&info.candidates_count==1&&info.coverage==DMG_COVERAGE_PARTIAL&&info.decision==DMG_NOT_APPLICABLE);CHECK(dmg_result_get_value_v2(batch,0,&row,sizeof(row))==DMG_OK&&row.kind==DMG_VALUE_USE);e.local=row.use.caller_ordinal;e.reference=row.use.caller_method_ref;e.pc=row.use.dex_pc;CHECK(row.use.source_index==e.source);}
    else{dmg_relation_info info{};dmg_entity_row row{};CHECK(dmg_result_get_relation_info(batch,&info,sizeof(info))==DMG_OK&&info.candidates_count==1&&info.coverage==DMG_COVERAGE_PARTIAL&&info.decision==DMG_NOT_APPLICABLE);CHECK(dmg_result_get_entity(batch,0,&row,sizeof(row))==DMG_OK);e.local=row.local_index;e.reference=row.reference_index;CHECK(row.source_index==e.source);}
    return e;
}
static std::vector<Evidence> drain(dmg_job* job,Profile p){
    std::vector<Evidence> rows;
    for(unsigned attempt=0;attempt<10;++attempt){dmg_batch* raw=nullptr;dmg_error error{};const auto status=dmg_job_next(job,1000,&raw,&error);if(status==DMG_END_OF_STREAM){CHECK(raw==nullptr);return rows;}CHECK(status==DMG_OK&&raw);Batch batch(raw,&dmg_batch_release);
        rows.push_back(read_batch(batch.get(),p));
    }
    throw std::runtime_error("Q09 batch drain did not reach EOF");
}
static void scenario(dmg_engine* engine,const std::vector<uint8_t>& bytes,Profile p,int kind){
    // kind: 0 one published before cancellation, 1 two before cancellation,
    // 2 complete zero, 3 duplicate occurrences, 4 output limit first,
    // 5 deadline made expired at the test-only precommit gate,
    // 6 injected cancel-lock exception falls back to atomic cancellation,
    // 7 first provisional Batch consumed before cancel and terminal commit.
    const bool repeat=p==Profile::v4||kind==3;auto snap=snapshot(engine,bytes,p,repeat);auto q=compile(engine,p,kind==2?2:kind==3?1:0,kind==4);
    arm();auto job=start(snap.get(),q.get(),(kind==0||kind==7)?1:2);GateGuard guard;Batch early(nullptr,&dmg_batch_release);
    if(kind==0){await_one(job.get(),p);dmg_job_cancel(job.get());CHECK(entered()==1);}
    else if(kind==7){await_one(job.get(),p);dmg_batch* raw=nullptr;dmg_error error{};CHECK(dmg_job_next(job.get(),1000,&raw,&error)==DMG_OK&&raw);early.reset(raw);(void)read_batch(early.get(),p);CHECK(entered()==2);CHECK(!get(job.get(),p,false).terminal);dmg_job_cancel(job.get());}
    else {CHECK(entered()==(kind==2?0u:kind==4?1u:2u));CHECK(!get(job.get(),p,false).terminal);
        if(kind==5){std::lock_guard lock(job->state->mutex);job->state->control.deadline=std::chrono::steady_clock::now()-std::chrono::milliseconds(1);}
        else if(kind==6){runtime::test_job_cancel_lock_failure.store(true,std::memory_order_release);dmg_job_cancel(job.get());CHECK(!runtime::test_job_cancel_lock_failure.load(std::memory_order_acquire));}
        else if(kind!=2)dmg_job_cancel(job.get());}
    unblock();const auto final=get(job.get(),p,true);
    if(kind==0)expect(final,DMG_JOB_CANCELLED,DMG_CANCELLED,DMG_COVERAGE_PARTIAL,DMG_UNDETERMINED,DMG_REASON_NONE,1);
    else if(kind==2)expect(final,DMG_JOB_COMPLETED,DMG_OK,DMG_COVERAGE_COMPLETE,DMG_PROVEN_FALSE,DMG_NO_MATCH,0);
    else if(kind==4)expect(final,DMG_JOB_FAILED,DMG_BUDGET_EXCEEDED,DMG_COVERAGE_PARTIAL,DMG_UNDETERMINED,DMG_RESULT_LIMIT,1);
    else if(kind==5)expect(final,DMG_JOB_FAILED,DMG_DEADLINE_EXCEEDED,DMG_COVERAGE_PARTIAL,DMG_PROVEN_FALSE,DMG_AMBIGUOUS,2);
    else expect(final,DMG_JOB_CANCELLED,DMG_CANCELLED,DMG_COVERAGE_PARTIAL,DMG_PROVEN_FALSE,DMG_AMBIGUOUS,2);
    auto rows=drain(job.get(),p);CHECK(rows.size()+static_cast<size_t>(early!=nullptr)==final.count);
    if(early){const auto first=read_batch(early.get(),p);CHECK(rows.size()==1&&(first.source!=rows[0].source||first.local!=rows[0].local||first.pc!=rows[0].pc));}
    if(kind==1){CHECK(rows.size()==2);CHECK(rows[0].source!=rows[1].source||rows[0].local!=rows[1].local||rows[0].pc!=rows[1].pc);}
    if(kind==3){CHECK(rows.size()==2&&rows[0].source==0&&rows[1].source==1);CHECK(rows[0].local==rows[1].local&&rows[0].reference==rows[1].reference&&rows[0].pc==rows[1].pc);CHECK(rows[0].content==rows[1].content&&rows[0].occurrence!=rows[1].occurrence&&rows[0].snapshot==rows[1].snapshot);}
    if(kind==2)runtime::test_job_cancel_lock_failure.store(true,std::memory_order_release);
    dmg_job_cancel(job.get());if(kind==2)CHECK(!runtime::test_job_cancel_lock_failure.load(std::memory_order_acquire));
    const auto stable=get(job.get(),p,false);expect(stable,final.lifecycle,final.status,final.coverage,final.decision,final.reason,final.count);
    if(early){job.reset();(void)read_batch(early.get(),p);}
    std::cout<<label(p)<<" scenario "<<kind<<" passed\n";
}
static void shutdown_before_commit(const std::vector<uint8_t>& bytes){
    auto engine=make_engine();auto snap=snapshot(engine.get(),bytes,Profile::v1,false);auto q=compile(engine.get(),Profile::v1,0);
    arm();auto job=start(snap.get(),q.get(),2);GateGuard guard;CHECK(entered()==2);CHECK(!get(job.get(),Profile::v1,false).terminal);
    CHECK(dmg_engine_shutdown(engine.get(),1)==DMG_OK);unblock();const auto final=get(job.get(),Profile::v1,true);
    expect(final,DMG_JOB_CANCELLED,DMG_CANCELLED,DMG_COVERAGE_PARTIAL,DMG_PROVEN_FALSE,DMG_AMBIGUOUS,2);
    CHECK(drain(job.get(),Profile::v1).size()==2);std::cout<<"shutdown before commit passed\n";
}
static void queue_window(const std::vector<uint8_t>& bytes,Profile p,bool shutdown,bool with_deadline){
    auto engine=make_engine();auto snap=snapshot(engine.get(),bytes,p,p==Profile::v4);auto q=compile(engine.get(),p,0);
    arm_queue_gate();auto job=start(snap.get(),q.get(),1,with_deadline?8000:0);QueueGateGuard guard;await_queue_gate();
    // The worker holds job->mutex and is stopped after check(), before wait().
    // Both operations below notify without that mutex in these paths.
    if(shutdown)CHECK(dmg_engine_shutdown(engine.get(),1)==DMG_OK);
    else{runtime::test_job_cancel_lock_failure.store(true,std::memory_order_release);dmg_job_cancel(job.get());CHECK(!runtime::test_job_cancel_lock_failure.load(std::memory_order_acquire));}
    const auto started=std::chrono::steady_clock::now();unblock_queue_gate();Outcome final{};
    if(!wait_limited(job.get(),p,2500,final)){
        // Bounded rescue allows the old missed-notification control to exit.
        job->state->changed.notify_all();dmg_job_cancel(job.get());
        (void)get(job.get(),p,true);
        throw std::runtime_error("queue cancellation notification lost");
    }
    expect(final,DMG_JOB_CANCELLED,DMG_CANCELLED,DMG_COVERAGE_PARTIAL,DMG_UNDETERMINED,DMG_REASON_NONE,1);
    CHECK(drain(job.get(),p).size()==1);
    const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count();
    std::cout<<label(p)<<" queue-window "<<(shutdown?"shutdown":"fallback")<<' '<<(with_deadline?"deadline":"none")<<" passed "<<elapsed<<"ms\n";
}
static void queue_deadline(const std::vector<uint8_t>& bytes){
    auto engine=make_engine();auto snap=snapshot(engine.get(),bytes,Profile::v1,false);auto q=compile(engine.get(),Profile::v1,0);
    arm_queue_gate();auto job=start(snap.get(),q.get(),1,3000);QueueGateGuard guard;await_queue_gate();
    const auto deadline=job->state->control.deadline;const auto now=std::chrono::steady_clock::now();
    if(deadline>now+std::chrono::milliseconds(20))std::this_thread::sleep_until(deadline-std::chrono::milliseconds(20));
    unblock_queue_gate();Outcome final{};CHECK(wait_limited(job.get(),Profile::v1,3000,final));
    expect(final,DMG_JOB_FAILED,DMG_DEADLINE_EXCEEDED,DMG_COVERAGE_PARTIAL,DMG_UNDETERMINED,DMG_REASON_NONE,1);
    CHECK(drain(job.get(),Profile::v1).size()==1);
    std::cout<<"queue deadline passed; post-deadline completion ms="<<std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-deadline).count()<<'\n';
}
// The extra 33-row fixture lets us cancel while the scan has more methods
// remaining, rather than merely interrupting already completed materialization.
static void result_limit_gate(){gate_callback(1);}
static void arm_result_limit(){
    std::lock_guard lock(gate_mutex);gate_entered=false;gate_open=false;gate_count=UINT32_MAX;
    reference::test_result_limit_barrier.store(&result_limit_gate,std::memory_order_release);
}
static void scan_interrupt(const std::vector<uint8_t>& bytes,uint32_t witnesses){
    auto engine=make_engine();dmg_open_options options{sizeof(options),DMG_ABI_VERSION,0,"q09-scan","slot",nullptr};
    dmg_snapshot* raw=nullptr;dmg_error error{};CHECK(dmg_snapshot_open_copy_in(engine.get(),bytes.data(),bytes.size(),&options,&raw,&error)==DMG_OK&&raw);
    Snapshot snap(raw,&dmg_snapshot_release);auto q=compile(engine.get(),Profile::v1,0);
    arm_scan(witnesses);auto job=start(snap.get(),q.get(),2,0,8);GateGuard guard;
    CHECK(entered()==witnesses);dmg_job_status before{};CHECK(dmg_job_get_status(job.get(),&before)==DMG_OK);
    CHECK(!before.terminal&&before.outcome.candidates_count==witnesses&&before.outcome.total_methods==33&&before.outcome.visited_methods==witnesses);
    dmg_job_cancel(job.get());unblock();const auto final=get(job.get(),Profile::v1,true);
    expect(final,DMG_JOB_CANCELLED,DMG_CANCELLED,DMG_COVERAGE_PARTIAL,witnesses==1?DMG_UNDETERMINED:DMG_PROVEN_FALSE,witnesses==1?DMG_REASON_NONE:DMG_AMBIGUOUS,witnesses);
    const auto rows=drain(job.get(),Profile::v1);CHECK(rows.size()==witnesses);
    CHECK(rows[0].source==0&&!rows[0].content.empty()&&!rows[0].occurrence.empty()&&!rows[0].snapshot.empty());
    if(witnesses==2){
        CHECK(rows[0].source==rows[1].source&&rows[0].content==rows[1].content&&
              rows[0].occurrence==rows[1].occurrence&&rows[0].snapshot==rows[1].snapshot);
        CHECK(rows[0].local!=rows[1].local&&rows[0].reference!=rows[1].reference);
    }
    std::cout<<"scan-interrupt witnesses="<<witnesses<<" passed\n";
}
static void limit_then_cancel(const std::vector<uint8_t>& bytes){
    auto engine=make_engine();dmg_open_options options{sizeof(options),DMG_ABI_VERSION,0,"q09-limit","slot",nullptr};
    dmg_snapshot* raw=nullptr;dmg_error error{};CHECK(dmg_snapshot_open_copy_in(engine.get(),bytes.data(),bytes.size(),&options,&raw,&error)==DMG_OK&&raw);
    Snapshot snap(raw,&dmg_snapshot_release);auto q=compile(engine.get(),Profile::v1,0,true);
    arm_result_limit();auto job=start(snap.get(),q.get(),2,0,8);GateGuard guard;CHECK(entered()==1);
    dmg_job_cancel(job.get());unblock();const auto final=get(job.get(),Profile::v1,true);
    expect(final,DMG_JOB_FAILED,DMG_BUDGET_EXCEEDED,DMG_COVERAGE_PARTIAL,DMG_UNDETERMINED,DMG_RESULT_LIMIT,1);
    CHECK(drain(job.get(),Profile::v1).size()==1);std::cout<<"result limit before cancel passed\n";
}
static void graph_scan_interrupt(const std::vector<uint8_t>& bytes,Profile p,uint32_t witnesses){
    auto engine=make_engine();dmg_open_options options{sizeof(options),DMG_ABI_VERSION,0,"graph-scan","slot",nullptr};
    dmg_snapshot* raw=nullptr;dmg_error error{};CHECK(dmg_snapshot_open_copy_in(engine.get(),bytes.data(),bytes.size(),&options,&raw,&error)==DMG_OK&&raw);
    Snapshot snap(raw,&dmg_snapshot_release);auto q=compile(engine.get(),p,0);
    arm_scan(witnesses);auto job=start(snap.get(),q.get(),2,0,8);GateGuard guard;
    CHECK(entered()==witnesses);const auto before=get(job.get(),p,false);CHECK(!before.terminal&&before.count==witnesses);
    if(p==Profile::v3){
        dmg_relation_job_status state{};CHECK(dmg_job_get_relation_status(job.get(),&state,sizeof(state))==DMG_OK);
        CHECK(state.outcome.total_rows==33&&state.outcome.visited_rows==witnesses);
        dmg_operator_profile op{};CHECK(dmg_job_get_operator_profile(job.get(),0,&op,sizeof(op))==DMG_OK&&op.output_rows==witnesses&&!op.complete);
    }else{
        dmg_relation_job_status_v2 state{};CHECK(dmg_job_get_relation_status_v2(job.get(),&state,sizeof(state))==DMG_OK);
        CHECK(state.outcome.method_total==4&&state.outcome.method_visited<4);
        dmg_operator_profile_v2 op{};CHECK(dmg_job_get_operator_profile_v2(job.get(),0,&op,sizeof(op))==DMG_OK&&op.output_rows==witnesses&&!op.complete);
    }
    dmg_job_cancel(job.get());unblock();const auto final=get(job.get(),p,true);
    expect(final,DMG_JOB_CANCELLED,DMG_CANCELLED,DMG_COVERAGE_PARTIAL,witnesses==1?DMG_UNDETERMINED:DMG_PROVEN_FALSE,witnesses==1?DMG_REASON_NONE:DMG_AMBIGUOUS,witnesses);
    const auto rows=drain(job.get(),p);CHECK(rows.size()==witnesses);
    if(witnesses==2){CHECK(rows[0].source==rows[1].source&&rows[0].occurrence==rows[1].occurrence);
        if(p==Profile::v4)CHECK(rows[0].local==2&&rows[1].local==2&&rows[0].pc==0&&rows[1].pc==3);
        else CHECK(rows[0].local!=rows[1].local);}
    std::cout<<"graph scan "<<label(p)<<" witnesses="<<witnesses<<" passed\n";
}
static void graph_join_atomic(const std::vector<uint8_t>& bytes,bool by_tuple){
    auto engine=make_engine();dmg_open_options options{sizeof(options),DMG_ABI_VERSION,0,"graph-join","slot",nullptr};
    dmg_snapshot* raw=nullptr;dmg_error error{};CHECK(dmg_snapshot_open_copy_in(engine.get(),bytes.data(),bytes.size(),&options,&raw,&error)==DMG_OK&&raw);
    Snapshot snap(raw,&dmg_snapshot_release);
    const std::string text=std::string(R"({"schema_version":1,"relation":{"op":"join","on":"caller","left":{"op":"scan","relation":"method_defs","where":{"name":"uses"}},"right":{"op":"scan","relation":"invoke_sites"}},"intent":"unique","unique_by":")")+(by_tuple?"tuple":"entity")+"\"}";
    dmg_query* raw_query=nullptr;CHECK(dmg_query_compile_json(engine.get(),reinterpret_cast<const uint8_t*>(text.data()),text.size(),&raw_query,&error)==DMG_OK&&raw_query);
    Query q(raw_query,&dmg_query_release);const uint32_t n=by_tuple?2u:1u;
    arm_scan(1);auto job=start(snap.get(),q.get(),2,0,8);GateGuard guard;const auto final=get(job.get(),Profile::v4,true);
    CHECK(!gate_entered);expect(final,DMG_JOB_COMPLETED,DMG_OK,DMG_COVERAGE_COMPLETE,by_tuple?DMG_PROVEN_FALSE:DMG_PROVEN_TRUE,by_tuple?DMG_AMBIGUOUS:DMG_REASON_NONE,n);
    dmg_batch* raw_batch=nullptr;CHECK(dmg_job_next(job.get(),1000,&raw_batch,&error)==DMG_OK&&raw_batch);Batch batch(raw_batch,&dmg_batch_release);
    std::vector<uint32_t> pcs;
    for(uint32_t i=0;i<n;++i){dmg_value_row_v2 row{};CHECK(dmg_result_get_value_v2(batch.get(),i,&row,sizeof(row))==DMG_OK&&row.kind==DMG_VALUE_ENTITY);
        uint32_t count=0;CHECK(dmg_result_get_binding_count(batch.get(),i,&count)==DMG_OK&&count>=2);
        bool event=false;for(uint32_t j=0;j<count;++j){dmg_binding_row_v2 binding{};CHECK(dmg_result_get_binding_v2(batch.get(),i,j,&binding,sizeof(binding))==DMG_OK);if(binding.value.kind==DMG_VALUE_USE){pcs.push_back(binding.value.use.dex_pc);event=true;}}
        CHECK(event);CHECK(dmg_result_get_link_count(batch.get(),i,&count)==DMG_OK&&count==1);
    }
    if(by_tuple)CHECK(pcs.size()==2&&pcs[0]==0&&pcs[1]==3);else CHECK(pcs.size()==1&&pcs[0]==0);
    std::cout<<"graph join atomic unique_by="<<(by_tuple?"tuple":"entity")<<" passed\n";
}
static void graph_corrupt_method(const std::vector<uint8_t>& bytes){
    auto engine=make_engine();dmg_open_options options{sizeof(options),DMG_ABI_VERSION,0,"graph-corrupt","slot",nullptr};
    dmg_snapshot* raw=nullptr;dmg_error error{};CHECK(dmg_snapshot_open_copy_in(engine.get(),bytes.data(),bytes.size(),&options,&raw,&error)==DMG_OK&&raw);
    Snapshot snap(raw,&dmg_snapshot_release);auto q=compile(engine.get(),Profile::v4,0);auto job=start(snap.get(),q.get(),2,0,8);
    const auto final=get(job.get(),Profile::v4,true);expect(final,DMG_JOB_FAILED,DMG_CORRUPT_INPUT,DMG_COVERAGE_PARTIAL,DMG_UNDETERMINED,DMG_REASON_NONE,0);
    dmg_batch* batch=nullptr;CHECK(dmg_job_next(job.get(),1000,&batch,&error)==DMG_END_OF_STREAM&&batch==nullptr);
    std::cout<<"graph corrupt method emits no partial event passed\n";
}
static void graph_sorted_fallback(const std::vector<uint8_t>& bytes){
    auto engine=make_engine();dmg_open_options options{sizeof(options),DMG_ABI_VERSION,0,"graph-sorted","slot",nullptr};
    dmg_snapshot* raw=nullptr;dmg_error error{};CHECK(dmg_snapshot_open_copy_in(engine.get(),bytes.data(),bytes.size(),&options,&raw,&error)==DMG_OK&&raw);
    Snapshot snap(raw,&dmg_snapshot_release);
    const std::string text=R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"intent":"unique","order_by":[{"field":"pc","direction":"desc"}]})";
    dmg_query* raw_query=nullptr;CHECK(dmg_query_compile_json(engine.get(),reinterpret_cast<const uint8_t*>(text.data()),text.size(),&raw_query,&error)==DMG_OK&&raw_query);Query q(raw_query,&dmg_query_release);
    arm_scan(1);auto job=start(snap.get(),q.get(),2,0,8);GateGuard guard;
    const auto final=get(job.get(),Profile::v4,true);expect(final,DMG_JOB_COMPLETED,DMG_OK,DMG_COVERAGE_COMPLETE,DMG_PROVEN_FALSE,DMG_AMBIGUOUS,2);
    CHECK(!gate_entered);dmg_batch* raw_batch=nullptr;CHECK(dmg_job_next(job.get(),1000,&raw_batch,&error)==DMG_OK&&raw_batch);Batch batch(raw_batch,&dmg_batch_release);
    dmg_value_row_v2 first{},second{};CHECK(dmg_result_get_value_v2(batch.get(),0,&first,sizeof(first))==DMG_OK&&dmg_result_get_value_v2(batch.get(),1,&second,sizeof(second))==DMG_OK);
    CHECK(first.kind==DMG_VALUE_USE&&second.kind==DMG_VALUE_USE&&first.use.dex_pc==3&&second.use.dex_pc==0);
    std::cout<<"graph sorted fallback passed\n";
}
static Query compile_json(dmg_engine* engine,const std::string& text){
    dmg_query* q=nullptr;dmg_error error{};CHECK(dmg_query_compile_json(engine,reinterpret_cast<const uint8_t*>(text.data()),text.size(),&q,&error)==DMG_OK&&q);return Query(q,&dmg_query_release);
}
static void graph_budget_boundary(const std::vector<uint8_t>& bytes,const std::string& relation,Profile profile,const std::string& intent,const std::string& identity={}){
    auto engine=make_engine();dmg_open_options options{sizeof(options),DMG_ABI_VERSION,0,"graph-budget","slot",nullptr};dmg_snapshot* raw=nullptr;dmg_error error{};
    CHECK(dmg_snapshot_open_copy_in(engine.get(),bytes.data(),bytes.size(),&options,&raw,&error)==DMG_OK&&raw);Snapshot snap(raw,&dmg_snapshot_release);
    const auto text=[&](uint64_t limit){return std::string("{\"schema_version\":1,\"relation\":")+relation+",\"intent\":\""+intent+"\",\"max_results\":100"+(identity.empty()?"":",\"unique_by\":\""+identity+"\"")+(limit?",\"max_work\":"+std::to_string(limit):"")+"}";};
    auto baseline=compile_json(engine.get(),text(0));dmg_result* result=nullptr;CHECK(dmg_query_execute(snap.get(),baseline.get(),&result,&error)==DMG_OK&&result);
    dmg_query_profile p{};CHECK(dmg_result_get_profile(result,&p)==DMG_OK&&p.work_units>1);dmg_result_release(result);const auto work=p.work_units;
    for(uint64_t limit:{work-1,work}){
        auto q=compile_json(engine.get(),text(limit));result=nullptr;const auto sync=dmg_query_execute(snap.get(),q.get(),&result,&error);
        if(limit==work){CHECK(sync==DMG_OK&&result);dmg_query_profile measured{};CHECK(dmg_result_get_profile(result,&measured)==DMG_OK&&measured.work_units==work);dmg_result_release(result);}
        else CHECK(sync==DMG_BUDGET_EXCEEDED&&result==nullptr);
        auto job=start(snap.get(),q.get(),2,0,8);const auto actual=get(job.get(),profile,true);
        if(limit==work){if(actual.status!=DMG_OK)std::cerr<<"budget diff complete work="<<work<<" status="<<actual.status<<'\n';CHECK(actual.status==DMG_OK);}
        else {if(actual.status!=DMG_BUDGET_EXCEEDED)std::cerr<<"budget diff short work="<<work<<" status="<<actual.status<<'\n';CHECK(actual.status==DMG_BUDGET_EXCEEDED);}
    }
    std::cout<<"graph budget "<<label(profile)<<' '<<intent<<" exact="<<work<<" passed\n";
}
static void graph_metadata_unary(const std::vector<uint8_t>& bytes){
    auto engine=make_engine();dmg_open_options options{sizeof(options),DMG_ABI_VERSION,0,"unary","slot",nullptr};dmg_snapshot* raw=nullptr;dmg_error error{};
    CHECK(dmg_snapshot_open_copy_in(engine.get(),bytes.data(),bytes.size(),&options,&raw,&error)==DMG_OK&&raw);Snapshot snap(raw,&dmg_snapshot_release);
    const std::string text=R"({"schema_version":1,"relation":{"op":"label","label":"selected","input":{"op":"filter","input":{"op":"scan","relation":"method_defs"},"where":{"flags_contains":1}}},"intent":"unique","unique_by":"tuple"})";
    auto q=compile_json(engine.get(),text);arm_scan(2);auto job=start(snap.get(),q.get(),2,0,8);GateGuard guard;CHECK(entered()==2);
    dmg_relation_job_status before{};CHECK(dmg_job_get_relation_status(job.get(),&before,sizeof(before))==DMG_OK&&before.outcome.visited_rows==33&&before.outcome.total_rows==33);
    dmg_job_cancel(job.get());unblock();const auto final=get(job.get(),Profile::v3,true);expect(final,DMG_JOB_CANCELLED,DMG_CANCELLED,DMG_COVERAGE_PARTIAL,DMG_PROVEN_FALSE,DMG_AMBIGUOUS,2);
    for(uint32_t i=0;i<2;++i){dmg_batch* raw_batch=nullptr;CHECK(dmg_job_next(job.get(),1000,&raw_batch,&error)==DMG_OK&&raw_batch);Batch batch(raw_batch,&dmg_batch_release);
        uint32_t count=0;CHECK(dmg_result_get_binding_count(batch.get(),0,&count)==DMG_OK&&count==1);dmg_binding_row binding{};CHECK(dmg_result_get_binding(batch.get(),0,0,&binding,sizeof(binding))==DMG_OK&&std::string(binding.label)=="selected");}
    std::cout<<"metadata filter/label root evidence passed\n";
}
static void graph_metadata_join_exists(const std::vector<uint8_t>& bytes){
    auto engine=make_engine();dmg_open_options options{sizeof(options),DMG_ABI_VERSION,0,"metadata-join","slot",nullptr};dmg_snapshot* raw=nullptr;dmg_error error{};
    CHECK(dmg_snapshot_open_copy_in(engine.get(),bytes.data(),bytes.size(),&options,&raw,&error)==DMG_OK&&raw);Snapshot snap(raw,&dmg_snapshot_release);
    const std::string text=R"({"schema_version":1,"relation":{"op":"join","on":"local_definition","left":{"op":"scan","relation":"method_defs"},"right":{"op":"scan","relation":"method_refs"}},"intent":"exists"})";
    auto q=compile_json(engine.get(),text);arm_scan(1);auto job=start(snap.get(),q.get(),2,0,8);GateGuard guard;CHECK(entered()==1);
    dmg_job_cancel(job.get());unblock();const auto final=get(job.get(),Profile::v3,true);expect(final,DMG_JOB_CANCELLED,DMG_CANCELLED,DMG_COVERAGE_PARTIAL,DMG_PROVEN_TRUE,DMG_WITNESS,1);
    dmg_batch* raw_batch=nullptr;CHECK(dmg_job_next(job.get(),1000,&raw_batch,&error)==DMG_OK&&raw_batch);Batch batch(raw_batch,&dmg_batch_release);
    uint32_t count=0;CHECK(dmg_result_get_link_count(batch.get(),0,&count)==DMG_OK&&count==1);dmg_relation_link link{};
    CHECK(dmg_result_get_link(batch.get(),0,0,&link,sizeof(link))==DMG_OK&&link.left_source==link.right_source&&link.key==DMG_JOIN_LOCAL_DEFINITION);
    std::cout<<"metadata join Exists evidence passed\n";
}
static void graph_metadata_sorted_atomic(const std::vector<uint8_t>& bytes){
    auto engine=make_engine();dmg_open_options options{sizeof(options),DMG_ABI_VERSION,0,"metadata-sorted","slot",nullptr};dmg_snapshot* raw=nullptr;dmg_error error{};
    CHECK(dmg_snapshot_open_copy_in(engine.get(),bytes.data(),bytes.size(),&options,&raw,&error)==DMG_OK&&raw);Snapshot snap(raw,&dmg_snapshot_release);
    auto q=compile_json(engine.get(),R"({"schema_version":1,"relation":{"op":"scan","relation":"method_defs"},"intent":"unique","order_by":[{"field":"name","direction":"desc"}]})");
    arm_scan(1);auto job=start(snap.get(),q.get(),2,0,8);GateGuard guard;const auto final=get(job.get(),Profile::v3,true);CHECK(!gate_entered);
    expect(final,DMG_JOB_COMPLETED,DMG_OK,DMG_COVERAGE_COMPLETE,DMG_PROVEN_FALSE,DMG_AMBIGUOUS,2);
    dmg_batch* raw_batch=nullptr;CHECK(dmg_job_next(job.get(),1000,&raw_batch,&error)==DMG_OK&&raw_batch);Batch batch(raw_batch,&dmg_batch_release);
    dmg_entity_row a{},b{};CHECK(dmg_result_get_entity(batch.get(),0,&a,sizeof(a))==DMG_OK&&dmg_result_get_entity(batch.get(),1,&b,sizeof(b))==DMG_OK&&a.local_index==32&&b.local_index==31);
    std::cout<<"metadata sorted atomic fallback passed\n";
}
static void graph_use_atomic(const std::vector<uint8_t>& bytes){
    auto engine=make_engine();dmg_open_options options{sizeof(options),DMG_ABI_VERSION,0,"use-atomic","slot",nullptr};dmg_snapshot* raw=nullptr;dmg_error error{};
    CHECK(dmg_snapshot_open_copy_in(engine.get(),bytes.data(),bytes.size(),&options,&raw,&error)==DMG_OK&&raw);Snapshot snap(raw,&dmg_snapshot_release);
    auto q=compile(engine.get(),Profile::v4,0);arm_scan(1);auto job=start(snap.get(),q.get(),2,0,8);GateGuard guard;const auto outcome=get(job.get(),Profile::v4,true);
    CHECK(!gate_entered);expect(outcome,DMG_JOB_COMPLETED,DMG_OK,DMG_COVERAGE_COMPLETE,DMG_PROVEN_FALSE,DMG_AMBIGUOUS,2);
    dmg_batch* raw_batch=nullptr;CHECK(dmg_job_next(job.get(),1000,&raw_batch,&error)==DMG_OK&&raw_batch);Batch batch(raw_batch,&dmg_batch_release);
    dmg_value_row_v2 a{},b{};CHECK(dmg_result_get_value_v2(batch.get(),0,&a,sizeof(a))==DMG_OK&&dmg_result_get_value_v2(batch.get(),1,&b,sizeof(b))==DMG_OK);
    CHECK(a.kind==DMG_VALUE_USE&&b.kind==DMG_VALUE_USE&&a.use.dex_pc==0&&b.use.dex_pc==3);
    std::cout<<"graph use scan atomic fallback passed\n";
}
static void graph_union_behavior(const std::vector<uint8_t>& bytes,bool exists){
    auto engine=make_engine();dmg_open_options options{sizeof(options),DMG_ABI_VERSION,0,"graph-union","slot",nullptr};dmg_snapshot* raw=nullptr;dmg_error error{};
    CHECK(dmg_snapshot_open_copy_in(engine.get(),bytes.data(),bytes.size(),&options,&raw,&error)==DMG_OK&&raw);Snapshot snap(raw,&dmg_snapshot_release);
    const std::string relation=R"({"op":"union","semantics":"bag","inputs":[{"op":"scan","relation":"method_defs"},{"op":"scan","relation":"method_defs"}]})";
    auto q=compile_json(engine.get(),std::string("{\"schema_version\":1,\"relation\":")+relation+",\"intent\":\""+(exists?"exists":"unique")+"\"}");
    arm_scan(1);auto job=start(snap.get(),q.get(),2,0,8);GateGuard guard;
    if(exists){
        CHECK(entered()==1);dmg_relation_job_status running{};CHECK(dmg_job_get_relation_status(job.get(),&running,sizeof(running))==DMG_OK);
        CHECK(running.outcome.candidates_count==1&&running.outcome.total_rows==66&&running.outcome.visited_rows==33);
        dmg_job_cancel(job.get());unblock();const auto outcome=get(job.get(),Profile::v3,true);
        expect(outcome,DMG_JOB_CANCELLED,DMG_CANCELLED,DMG_COVERAGE_PARTIAL,DMG_PROVEN_TRUE,DMG_WITNESS,1);
        const auto rows=drain(job.get(),Profile::v3);CHECK(rows.size()==1&&rows[0].local==0);
    }else{
        const auto outcome=get(job.get(),Profile::v3,true);CHECK(!gate_entered);
        expect(outcome,DMG_JOB_COMPLETED,DMG_OK,DMG_COVERAGE_COMPLETE,DMG_PROVEN_FALSE,DMG_AMBIGUOUS,2);
        dmg_batch* raw_batch=nullptr;CHECK(dmg_job_next(job.get(),1000,&raw_batch,&error)==DMG_OK&&raw_batch);Batch batch(raw_batch,&dmg_batch_release);
        dmg_entity_row a{},b{};CHECK(dmg_result_get_entity(batch.get(),0,&a,sizeof(a))==DMG_OK&&dmg_result_get_entity(batch.get(),1,&b,sizeof(b))==DMG_OK);
        CHECK(a.local_index==0&&b.local_index==1);
    }
    std::cout<<"graph union bag "<<(exists?"exists streaming":"unique atomic dedup")<<" passed\n";
}
int main(int argc,char** argv){try{
    CHECK(argc==3||argc==4);auto methods=load(argv[1]);auto fields=load(argv[2]);
    if(argc==4&&std::string(argv[3])=="scan-interrupt"){scan_interrupt(methods,1);scan_interrupt(methods,2);limit_then_cancel(methods);return 0;}
    if(argc==4&&std::string(argv[3])=="graph-stream"){
        for(uint32_t n:{1u,2u})graph_scan_interrupt(methods,Profile::v3,n);graph_use_atomic(fields);
        graph_join_atomic(fields,false);graph_join_atomic(fields,true);
        graph_sorted_fallback(fields);graph_corrupt_method(load(std::filesystem::path(argv[2]).parent_path()/"valid-then-corrupt.dex"));
        const std::string scan_methods=R"({"op":"scan","relation":"method_defs"})";
        const std::string scan_uses=R"({"op":"scan","relation":"invoke_sites"})";
        const std::string joined=R"({"op":"join","on":"caller","left":{"op":"scan","relation":"method_defs","where":{"name":"uses"}},"right":{"op":"scan","relation":"invoke_sites"}})";
        graph_budget_boundary(methods,scan_methods,Profile::v3,"unique");graph_budget_boundary(fields,scan_uses,Profile::v4,"unique");
        graph_budget_boundary(fields,joined,Profile::v4,"unique");graph_budget_boundary(fields,joined,Profile::v4,"unique","tuple");
        graph_budget_boundary(fields,joined,Profile::v4,"exists");graph_union_behavior(methods,false);graph_union_behavior(methods,true);
        const std::string unary=R"({"op":"label","label":"selected","input":{"op":"filter","input":{"op":"scan","relation":"method_defs"},"where":{"flags_contains":1}}})";
        const std::string metadata_join=R"({"op":"join","on":"local_definition","left":{"op":"scan","relation":"method_defs"},"right":{"op":"scan","relation":"method_refs"}})";
        graph_budget_boundary(methods,scan_methods,Profile::v3,"exists");graph_budget_boundary(methods,metadata_join,Profile::v3,"exists");
        graph_budget_boundary(methods,unary,Profile::v3,"unique","tuple");graph_metadata_unary(methods);graph_metadata_join_exists(methods);graph_metadata_sorted_atomic(methods);return 0;
    }
    if(argc==4){const auto mode=std::string(argv[3]);CHECK(mode=="queue-only"||mode=="queue-only-deadline");queue_window(methods,Profile::v1,true,mode=="queue-only-deadline");return 0;}
    auto engine=make_engine();
    for(auto p:{Profile::v1,Profile::v2,Profile::v3,Profile::v4})for(int kind=0;kind<8;++kind)scenario(engine.get(),p==Profile::v2?fields:methods,p,kind);
    shutdown_before_commit(methods);
    for(auto p:{Profile::v1,Profile::v2,Profile::v3,Profile::v4})for(bool shutdown:{false,true})for(bool deadline:{false,true})queue_window(p==Profile::v2?fields:methods,p,shutdown,deadline);
    queue_deadline(methods);
    std::cout<<"PASS Q09: four profiles, provisional batches, cancel/commit, distinct occurrences and result limits\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
