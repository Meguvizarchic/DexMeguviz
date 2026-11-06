#include "c_api/runtime.hpp"
#include "source/sha256.hpp"
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
#include <vector>

using namespace dexmeguviz;
namespace dexmeguviz::reference { extern std::atomic<void(*)(uint32_t,uint64_t)> test_graph_reduce_barrier; }
namespace dexmeguviz::runtime {
extern std::atomic<void(*)(uint32_t)> test_job_scan_barrier;
extern std::atomic<void(*)(uint32_t)> test_job_commit_barrier;
extern std::atomic<void(*)(uint32_t)> test_unique_one_publish_barrier;
extern std::atomic<bool> test_unique_one_queue_allocation_failed;
extern std::atomic<bool> test_unique_one_binding_allocation_failed;
extern std::atomic<void(*)()> test_unique_one_terminal_locked;
extern std::atomic<void(*)()> test_unique_one_cancel_enter;
}
#define CHECK(x) do { if(!(x)) throw std::runtime_error("unique-one line "+std::to_string(__LINE__)+": " #x); } while(0)
using Engine=std::unique_ptr<dmg_engine,decltype(&dmg_engine_release)>;
using Snapshot=std::unique_ptr<dmg_snapshot,decltype(&dmg_snapshot_release)>;
using Query=std::unique_ptr<dmg_query,decltype(&dmg_query_release)>;
using Job=std::unique_ptr<dmg_job,decltype(&dmg_job_release)>;
using Batch=std::unique_ptr<dmg_batch,decltype(&dmg_batch_release)>;
using Result=std::unique_ptr<dmg_result,decltype(&dmg_result_release)>;

static std::mutex gate_mutex;
static std::condition_variable gate_cv;
static std::atomic<int> selected{0},fault{0},offers{0};
static std::atomic<runtime::EngineState*> budget_engine{nullptr};
static std::atomic<uint64_t> budget_reservation{0};
static bool entered=false,opened=false;
static bool cancel_entered=false;
static void gate(int point){
    if(selected.load(std::memory_order_acquire)!=point)return;
    std::unique_lock lock(gate_mutex);entered=true;gate_cv.notify_all();
    gate_cv.wait(lock,[]{return opened;});
}
static void publish_hook(uint32_t point){
    if(fault.load(std::memory_order_acquire)==6&&point==2){
        auto* engine=budget_engine.load(std::memory_order_acquire);CHECK(engine);
        constexpr uint64_t limit=256ull<<20;const auto used=engine->account.total();CHECK(used<limit);
        const auto reserve=limit-used;engine->account.reserve(reserve,MemoryKind::control);budget_reservation.store(reserve);
        return;
    }
    if(fault.load(std::memory_order_acquire)==static_cast<int>(point)){
        test_fail_allocation_after(0);return;
    }
    gate(100+static_cast<int>(point));
}
static void scan_hook(uint32_t count){offers.fetch_add(1);if(count==1)gate(301);}
static void reduce_hook(uint32_t point,uint64_t){gate(200+static_cast<int>(point));}
static void commit_hook(uint32_t){gate(401);}
static void terminal_locked_hook(){gate(402);}
static void cancel_enter_hook(){std::lock_guard lock(gate_mutex);cancel_entered=true;gate_cv.notify_all();}
static void install_hooks(){
    runtime::test_unique_one_publish_barrier.store(&publish_hook);
    runtime::test_job_scan_barrier.store(&scan_hook);
    reference::test_graph_reduce_barrier.store(&reduce_hook);
    runtime::test_job_commit_barrier.store(&commit_hook);
    runtime::test_unique_one_terminal_locked.store(&terminal_locked_hook);
}
static void arm(int point){std::lock_guard lock(gate_mutex);entered=false;opened=false;selected.store(point);fault.store(0);install_hooks();}
static void await_gate(){std::unique_lock lock(gate_mutex);CHECK(gate_cv.wait_for(lock,std::chrono::seconds(15),[]{return entered;}));}
static void unblock(){
    {std::lock_guard lock(gate_mutex);opened=true;selected.store(0);fault.store(0);}
    gate_cv.notify_all();
}
static void clear_hooks(){unblock();runtime::test_unique_one_publish_barrier.store(nullptr);runtime::test_job_scan_barrier.store(nullptr);reference::test_graph_reduce_barrier.store(nullptr);runtime::test_job_commit_barrier.store(nullptr);runtime::test_unique_one_terminal_locked.store(nullptr);runtime::test_unique_one_cancel_enter.store(nullptr);}
struct ReleaseGate { ~ReleaseGate(){clear_hooks();} };
static std::vector<uint8_t> load(const std::filesystem::path& path){std::ifstream in(path,std::ios::binary);CHECK(in.good());return {std::istreambuf_iterator<char>(in),{}};}
static Engine engine(){dmg_engine* value=nullptr;dmg_error error{};CHECK(dmg_engine_create(nullptr,&value,&error)==DMG_OK&&value);return Engine(value,&dmg_engine_release);}
static uint64_t owned(dmg_engine* engine){dmg_engine_stats stats{};CHECK(dmg_engine_get_stats(engine,&stats)==DMG_OK);return stats.owned_bytes;}
static Snapshot snapshot(dmg_engine* e,const std::vector<uint8_t>& first,const std::vector<uint8_t>* second=nullptr,bool complete=true){
    std::vector<dmg_source_spec> sources;
    const auto add=[&](const auto& bytes,const char* slot){sources.push_back({sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,bytes.data(),bytes.size(),slot,"code-split",nullptr});};
    add(first,"first");if(second)add(*second,"second");
    const dmg_source_set_options options{sizeof(options),DMG_ABI_VERSION,"unique-one-test",complete?1u:0u,8,1u<<20};
    dmg_snapshot* value=nullptr;dmg_error error{};CHECK(dmg_snapshot_open_sources(e,sources.data(),static_cast<uint32_t>(sources.size()),&options,&value,&error)==DMG_OK&&value);
    return Snapshot(value,&dmg_snapshot_release);
}
static Query compile(dmg_engine* e,uint64_t work=0,int pc=-1,bool experimental=true,const char* capability="use_streaming"){
    if(experimental&&std::string_view(capability)=="use_streaming")capability="unique_one_stream";
    std::string relation=R"({"op":"scan","relation":"invoke_sites")";
    if(pc>=0)relation+=",\"where\":{\"pc\":"+std::to_string(pc)+"}";
    relation+='}';
    std::string text=R"({"schema_version":1,"relation":)"+relation+R"(,"intent":"unique","max_results":1,"required_capabilities":[")"+capability+R"("]})";
    if(work)text.insert(text.size()-1,",\"max_work\":"+std::to_string(work));
    dmg_query* value=nullptr;dmg_error error{};CHECK(dmg_query_compile_json(e,reinterpret_cast<const uint8_t*>(text.data()),text.size(),&value,&error)==DMG_OK&&value);
    return Query(value,&dmg_query_release);
}
static Job start(dmg_snapshot* s,dmg_query* q){dmg_job_options options{sizeof(options),DMG_ABI_VERSION,1,4,0};dmg_job* value=nullptr;dmg_error error{};CHECK(dmg_job_start(s,q,&options,&value,&error)==DMG_OK&&value);return Job(value,&dmg_job_release);}
static dmg_relation_job_status_v2 wait(dmg_job* job){dmg_relation_job_status_v2 status{};CHECK(dmg_job_wait_relation_v2(job,15000,&status,sizeof(status))==DMG_OK&&status.terminal);return status;}
static Batch next(dmg_job* job){dmg_batch* value=nullptr;dmg_error error{};CHECK(dmg_job_next(job,1000,&value,&error)==DMG_OK&&value);return Batch(value,&dmg_batch_release);}
static uint32_t check_batch(dmg_batch* batch){
    dmg_relation_info_v2 info{};CHECK(dmg_result_get_relation_info_v2(batch,&info,sizeof(info))==DMG_OK&&info.coverage==DMG_COVERAGE_PARTIAL&&info.decision==DMG_NOT_APPLICABLE&&info.candidates_count==1);
    dmg_value_row_v2 row{};CHECK(dmg_result_get_value_v2(batch,0,&row,sizeof(row))==DMG_OK&&row.kind==DMG_VALUE_USE);
    CHECK(row.use.relation==DMG_INVOKE_SITES&&row.use.source_index==0&&row.use.caller_ordinal==1&&row.use.caller_method_ref==2&&row.use.dex_pc==0&&row.use.target_index==4);
    dmg_source_info origin{};CHECK(dmg_result_get_origin(batch,0,&origin)==DMG_OK&&origin.dex.occurrence_id&&origin.dex.snapshot_id);
    uint32_t bindings=UINT32_MAX;CHECK(dmg_result_get_binding_count(batch,0,&bindings)==DMG_OK&&bindings==0);
    uint32_t n=0;CHECK(dmg_result_get_witness_count(batch,0,&n)==DMG_OK&&n>0);bool found=false;
    for(uint32_t i=0;i<n;++i){dmg_relation_witness_v2 w{};CHECK(dmg_result_get_relation_witness_v2(batch,0,i,&w,sizeof(w))==DMG_OK);if(w.witness.kind==DMG_WITNESS_INVOKE){CHECK(w.witness.dex_pc==0&&w.witness.reference_index==4);found=true;}}
    CHECK(found);return row.use.dex_pc;
}
static uint32_t drain(dmg_job* job){uint32_t count=0;for(;;){dmg_batch* raw=nullptr;dmg_error error{};const auto status=dmg_job_next(job,1000,&raw,&error);if(status==DMG_END_OF_STREAM)return count;CHECK(status==DMG_OK&&raw);Batch batch(raw,&dmg_batch_release);check_batch(batch.get());++count;}}
static void isolation(dmg_engine* engine){
    struct Case{const char* json;const char* prefix;};
    const Case cases[]{
      {R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"intent":"unique","max_results":1,"required_capabilities":["use_streaming","numeric_literals"]})","query:v10:"},
      {R"({"schema_version":1,"relation":"class_defs","intent":"unique","max_results":1,"required_capabilities":["interface_resolved"]})","query:v11:"},
      {R"({"schema_version":1,"relation":{"op":"filter","input":{"op":"scan","relation":"invoke_sites"},"where":{"pc":0}},"intent":"unique","max_results":1,"required_capabilities":["use_streaming"]})","query:v9:"},
      {R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"intent":"unique","max_results":1,"order_by":[{"field":"pc","direction":"asc"}],"required_capabilities":["use_streaming"]})","query:v9:"}
    };
    for(const auto& test:cases){dmg_query* raw=nullptr;dmg_error error{};
        CHECK(dmg_query_compile_json(engine,reinterpret_cast<const uint8_t*>(test.json),std::char_traits<char>::length(test.json),&raw,&error)==DMG_OK&&raw);
        Query compiled(raw,&dmg_query_release);dmg_query_info info{};CHECK(dmg_query_get_info(compiled.get(),&info)==DMG_OK);
        CHECK(!reference::unique_one_stream_shape(*compiled->query->plan)&&std::string(info.query_id).starts_with(test.prefix));
    }
    const char* rejected[]{
      R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"intent":"exists","max_results":1,"required_capabilities":["unique_one_stream"]})",
      R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"intent":"unique","max_results":2,"required_capabilities":["unique_one_stream"]})",
      R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"intent":"unique","max_results":1,"required_capabilities":["unique_one_stream","string_uses"]})",
      R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"intent":"unique","max_results":1,"required_capabilities":["unique_one_stream","field_uses"]})",
      R"({"schema_version":1,"relation":{"op":"filter","input":{"op":"scan","relation":"invoke_sites"},"where":{"pc":0}},"intent":"unique","max_results":1,"required_capabilities":["unique_one_stream"]})",
      R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"intent":"unique","max_results":1,"order_by":[{"field":"pc","direction":"asc"}],"required_capabilities":["unique_one_stream"]})",
      R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"intent":"unique","max_results":1,"required_capabilities":["unique_one_stream","order"]})",
      R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"intent":"unique","max_results":1,"unique_by":"tuple","required_capabilities":["unique_one_stream"]})",
      R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"intent":"unique","max_results":1,"required_capabilities":["unique_one_stream","numeric_literals"]})",
      R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"intent":"unique","max_results":1,"required_capabilities":["unique_one_stream","inherited_fields"]})",
      R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"intent":"unique","max_results":1,"required_capabilities":["unique_one_stream","interface_fields"]})",
      R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"intent":"unique","max_results":1,"required_capabilities":["unique_one_stream","composite"]})",
      R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"intent":"unique","max_results":1,"required_capabilities":["unique_one_stream","join"]})",
      R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"intent":"unique","max_results":1,"required_capabilities":["unique_one_stream","owner_groups"]})",
      R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"intent":"unique","max_results":1,"required_capabilities":["unique_one_stream","interface_resolved"]})"
    };
    for(const auto* text:rejected){dmg_query* raw=nullptr;dmg_error error{};CHECK(dmg_query_compile_json(engine,reinterpret_cast<const uint8_t*>(text),std::char_traits<char>::length(text),&raw,&error)==DMG_UNSUPPORTED&&!raw);}
    for(const auto* root:{"string_uses","field_uses"})for(const auto* capability:{"invoke_sites","string_uses","field_uses"}){
        if(std::string_view(root)==capability)continue;
        const auto text=std::string(R"({"schema_version":1,"relation":{"op":"scan","relation":")")+root+R"("},"intent":"unique","max_results":1,"required_capabilities":["unique_one_stream",")"+capability+R"("]})";
        dmg_query* raw=nullptr;dmg_error error{};CHECK(dmg_query_compile_json(engine,reinterpret_cast<const uint8_t*>(text.data()),text.size(),&raw,&error)==DMG_UNSUPPORTED&&!raw);
    }
}
static void compare_budgets(const std::vector<uint8_t>& good){
    auto e=engine();auto s=snapshot(e.get(),good);auto old=compile(e.get(),0,-1,false);auto candidate=compile(e.get());
    isolation(e.get());
    dmg_query_info a{},b{};CHECK(dmg_query_get_info(old.get(),&a)==DMG_OK&&dmg_query_get_info(candidate.get(),&b)==DMG_OK);
    CHECK(std::string(a.query_id).starts_with("query:v9:")&&std::string(b.query_id).starts_with("query:v12:")&&std::string(a.query_id)!=b.query_id);
    CHECK((b.required_capabilities&(1048576u|131072u))==(1048576u|131072u));
    const std::string alias=R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"intent":"unique","max_results":1,"required_capabilities":["use_streaming","unique_one_stream"]})";
    dmg_query* alias_raw=nullptr;dmg_error alias_error{};CHECK(dmg_query_compile_json(e.get(),reinterpret_cast<const uint8_t*>(alias.data()),alias.size(),&alias_raw,&alias_error)==DMG_OK&&alias_raw);
    Query alias_query(alias_raw,&dmg_query_release);dmg_query_info alias_info{};CHECK(dmg_query_get_info(alias_query.get(),&alias_info)==DMG_OK&&std::string(alias_info.query_id)==b.query_id);
    CHECK(!reference::can_stream(*old->query->plan)&&reference::can_stream(*candidate->query->plan));
    // Handcrafted internal Plans cannot bypass the execution-side guard.
    for(const uint32_t bit:{32u,128u}){auto forged=compile(e.get());auto& plan=const_cast<query::Plan&>(*forged->query->plan);plan.required_capabilities|=bit;
        CHECK(!reference::unique_one_stream_shape(plan)&&!reference::can_stream(plan));
        dmg_result* rejected=nullptr;dmg_error error{};CHECK(dmg_query_execute(s.get(),forged.get(),&rejected,&error)==DMG_UNSUPPORTED&&!rejected);
        auto job=start(s.get(),forged.get());const auto done=wait(job.get());CHECK(done.outcome.execution_status==DMG_UNSUPPORTED&&done.outcome.candidates_count==0&&drain(job.get())==0);
    }
    uint32_t without_result=0,limited=0,provisional_on_failure=0;
    for(uint64_t work=1;work<=100;++work){auto q=compile(e.get(),work);dmg_result* raw=nullptr;dmg_error error{};const auto status=dmg_query_execute(s.get(),q.get(),&raw,&error);Result sync(raw,&dmg_result_release);
        uint32_t expected=status,reason=UINT32_MAX;if(sync){dmg_relation_info_v2 info{};CHECK(dmg_result_get_relation_info_v2(sync.get(),&info,sizeof(info))==DMG_OK);expected=info.execution_status;reason=info.reason;}
        auto job=start(s.get(),q.get());const auto done=wait(job.get());const auto rows=drain(job.get());
        CHECK(done.outcome.execution_status==expected&&done.outcome.candidates_count==rows&&rows<=1);
        if(sync){CHECK(done.outcome.reason==reason);if(reason==DMG_RESULT_LIMIT){++limited;CHECK(rows==1&&done.outcome.decision==DMG_UNDETERMINED);}}
        else {++without_result;CHECK(done.outcome.reason!=DMG_RESULT_LIMIT);if(rows)++provisional_on_failure;}
        if(work>=36&&work<=42)std::cout<<"work="<<work<<" sync="<<expected<<" job="<<done.outcome.execution_status<<" reason="<<done.outcome.reason<<" provisional="<<rows<<"\n";
    }
    CHECK(without_result&&limited&&provisional_on_failure);
    offers.store(0);runtime::test_job_scan_barrier.store(&scan_hook);auto job=start(s.get(),old.get());(void)wait(job.get());(void)drain(job.get());runtime::test_job_scan_barrier.store(nullptr);CHECK(offers.load()==0);
    std::cout<<"100 work thresholds: sync/Job status checked; sync-without-result="<<without_result<<" limit="<<limited<<" provisional-on-failure="<<provisional_on_failure<<"; old atomic path checked\n";
}
static void cancellation(const std::vector<uint8_t>& good,int point,bool deadline){
    auto e=engine();const auto baseline=owned(e.get());auto s=snapshot(e.get(),good);auto q=compile(e.get());
    arm(point);ReleaseGate release;auto job=start(s.get(),q.get());await_gate();
    const bool published=point!=101;
    Batch retained(nullptr,&dmg_batch_release);
    if(published){
        if(point==301){dmg_relation_job_status_v2 live{};CHECK(dmg_job_get_relation_status_v2(job.get(),&live,sizeof(live))==DMG_OK&&!live.terminal&&live.outcome.candidates_count==1&&live.outcome.method_visited>=2&&live.outcome.events_collected==1);}
        retained=next(job.get());check_batch(retained.get());
    }
    if(deadline)job->state->control.deadline=std::chrono::steady_clock::time_point::min();else dmg_job_cancel(job.get());
    unblock();const auto done=wait(job.get());
    CHECK(done.outcome.execution_status==static_cast<uint32_t>(deadline?DMG_DEADLINE_EXCEEDED:DMG_CANCELLED));
    CHECK(done.outcome.candidates_count==(published?1u:0u)&&done.outcome.reason!=DMG_RESULT_LIMIT&&done.outcome.decision==DMG_UNDETERMINED);
    CHECK(drain(job.get())==0);job.reset();q.reset();s.reset();
    if(retained){check_batch(retained.get());retained.reset();}
    CHECK(owned(e.get())==baseline);
}
static void failure_stages(const std::vector<uint8_t>& good){
    auto e=engine();const auto initial=owned(e.get());auto s=snapshot(e.get(),good);auto q=compile(e.get());const auto baseline=owned(e.get());
    for(int point=1;point<=4;++point){fault.store(point);install_hooks();auto job=start(s.get(),q.get());const auto done=wait(job.get());clear_hooks();
        CHECK(done.outcome.execution_status==DMG_OUT_OF_MEMORY&&done.outcome.candidates_count==0&&done.outcome.reason!=DMG_RESULT_LIMIT&&done.outcome.decision==DMG_UNDETERMINED);
        if(point==4)CHECK(runtime::test_unique_one_queue_allocation_failed.exchange(false));
        CHECK(drain(job.get())==0);job.reset();CHECK(owned(e.get())==baseline);
    }
    budget_engine.store(e->owner.get());fault.store(6);install_hooks();
    {auto job=start(s.get(),q.get());const auto done=wait(job.get());clear_hooks();
     CHECK(done.outcome.execution_status==DMG_BUDGET_EXCEEDED&&done.outcome.candidates_count==0&&done.outcome.reason!=DMG_RESULT_LIMIT&&done.outcome.decision==DMG_UNDETERMINED);
     CHECK(drain(job.get())==0);job.reset();}
    const auto reservation=budget_reservation.exchange(0);CHECK(reservation>0);e->owner->account.release(reservation,MemoryKind::control);budget_engine.store(nullptr);CHECK(owned(e.get())==baseline);
    {
        const std::string text=R"({"schema_version":1,"relation":{"op":"label","label":"event","input":{"op":"filter","input":{"op":"scan","relation":"invoke_sites"},"where":{"pc":0}}},"intent":"unique","max_results":2,"unique_by":"tuple","required_capabilities":["use_streaming"]})";
        dmg_query* raw=nullptr;dmg_error error{};CHECK(dmg_query_compile_json(e.get(),reinterpret_cast<const uint8_t*>(text.data()),text.size(),&raw,&error)==DMG_OK&&raw);
        Query label(raw,&dmg_query_release);CHECK(reference::can_stream(*label->query->plan));const auto label_baseline=owned(e.get());
        fault.store(5);install_hooks();auto job=start(s.get(),label.get());const auto done=wait(job.get());clear_hooks();
        CHECK(done.outcome.execution_status==DMG_OUT_OF_MEMORY&&done.outcome.candidates_count==0&&done.outcome.reason!=DMG_RESULT_LIMIT&&drain(job.get())==0);
        CHECK(runtime::test_unique_one_binding_allocation_failed.exchange(false));
        job.reset();CHECK(owned(e.get())==label_baseline);
    }
    q.reset();s.reset();CHECK(owned(e.get())==initial);
    std::cout<<"publication allocation failures including deque push, v9 binding copy and managed budget failure: no rows committed, Engine account restored\n";
}
static void cancellation_after_locked_commit(const std::vector<uint8_t>& good){
    auto e=engine();auto s=snapshot(e.get(),good);auto q=compile(e.get());
    {std::lock_guard lock(gate_mutex);cancel_entered=false;}
    arm(402);ReleaseGate release;auto job=start(s.get(),q.get());await_gate();
    runtime::test_unique_one_cancel_enter.store(&cancel_enter_hook);
    std::thread cancelling([&]{dmg_job_cancel(job.get());});
    bool observed=false;
    {std::unique_lock lock(gate_mutex);observed=gate_cv.wait_for(lock,std::chrono::seconds(15),[]{return cancel_entered;});}
    unblock();cancelling.join();CHECK(observed);
    const auto done=wait(job.get());CHECK(done.outcome.execution_status==DMG_BUDGET_EXCEEDED&&done.outcome.reason==DMG_RESULT_LIMIT&&done.outcome.candidates_count==1&&done.outcome.decision==DMG_UNDETERMINED);
    CHECK(drain(job.get())==1);
}
static void basic_results(const std::vector<uint8_t>& good,const std::vector<uint8_t>& bad){
    auto e=engine();auto s=snapshot(e.get(),good);
    for(int pc:{0,42}){auto q=compile(e.get(),0,pc);auto job=start(s.get(),q.get());const auto done=wait(job.get());
        CHECK(done.outcome.execution_status==DMG_OK&&done.outcome.coverage==DMG_COVERAGE_COMPLETE&&done.outcome.candidates_count==(pc==0?1u:0u));
        CHECK(done.outcome.decision==static_cast<uint32_t>(pc==0?DMG_PROVEN_TRUE:DMG_PROVEN_FALSE));CHECK(drain(job.get())==(pc==0?1u:0u));}
    {auto partial=snapshot(e.get(),good,nullptr,false);auto q=compile(e.get(),0,0);auto job=start(partial.get(),q.get());const auto done=wait(job.get());CHECK(done.outcome.coverage==DMG_COVERAGE_PARTIAL&&done.outcome.decision==DMG_UNDETERMINED&&drain(job.get())==1);}
    {auto broken=snapshot(e.get(),bad);auto q=compile(e.get());dmg_result* raw=nullptr;dmg_error error{};CHECK(dmg_query_execute(broken.get(),q.get(),&raw,&error)==DMG_CORRUPT_INPUT&&!raw);auto job=start(broken.get(),q.get());const auto done=wait(job.get());CHECK(done.outcome.execution_status==DMG_CORRUPT_INPUT&&done.outcome.candidates_count==1&&done.outcome.decision==DMG_UNDETERMINED&&drain(job.get())==1);}
    {auto multi=snapshot(e.get(),good,&good);auto q=compile(e.get());auto job=start(multi.get(),q.get());const auto done=wait(job.get());CHECK(done.outcome.execution_status==DMG_BUDGET_EXCEEDED&&done.outcome.reason==DMG_RESULT_LIMIT&&done.outcome.candidates_count==1&&drain(job.get())==1);dmg_job_cancel(job.get());dmg_relation_job_status_v2 after{};CHECK(dmg_job_get_relation_status_v2(job.get(),&after,sizeof(after))==DMG_OK&&after.terminal&&after.outcome.reason==DMG_RESULT_LIMIT);}
    struct PredicateCase{const char* predicate;uint32_t status,count,decision;};
    const PredicateCase predicates[]{
      {R"({"caller_name":"quiet"})",DMG_OK,1,DMG_PROVEN_TRUE},
      {R"({"all":[{"pc":0},{"opcode":113}]})",DMG_OK,1,DMG_PROVEN_TRUE},
      {R"({"target_index":4})",DMG_BUDGET_EXCEEDED,1,DMG_UNDETERMINED},
      {R"({"target_domain":"method_ref"})",DMG_BUDGET_EXCEEDED,1,DMG_UNDETERMINED}
    };
    for(const auto& test:predicates){const std::string text=std::string(R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites","where":)")+test.predicate+R"(},"intent":"unique","max_results":1,"required_capabilities":["unique_one_stream"]})";
        dmg_query* raw=nullptr;dmg_error error{};CHECK(dmg_query_compile_json(e.get(),reinterpret_cast<const uint8_t*>(text.data()),text.size(),&raw,&error)==DMG_OK&&raw);Query q(raw,&dmg_query_release);auto job=start(s.get(),q.get());const auto done=wait(job.get());
        CHECK(done.outcome.execution_status==test.status&&done.outcome.candidates_count==test.count&&done.outcome.decision==test.decision&&drain(job.get())==test.count);
    }
}
static Query root_query(dmg_engine* e,const char* relation,uint64_t work=0,const char* extra=""){
    std::string text=std::string(R"({"schema_version":1,"relation":{"op":"scan","relation":")")+relation+R"("},"intent":"unique","max_results":1,"required_capabilities":["unique_one_stream")"+extra+"]}";
    if(work)text.insert(text.size()-1,",\"max_work\":"+std::to_string(work));
    dmg_query* value=nullptr;dmg_error error{};CHECK(dmg_query_compile_json(e,reinterpret_cast<const uint8_t*>(text.data()),text.size(),&value,&error)==DMG_OK&&value);return Query(value,&dmg_query_release);
}
static uint32_t root_batch(dmg_batch* batch,uint32_t relation,uint32_t target){
    dmg_relation_info_v2 info{};CHECK(dmg_result_get_relation_info_v2(batch,&info,sizeof(info))==DMG_OK&&info.coverage==DMG_COVERAGE_PARTIAL&&info.decision==DMG_NOT_APPLICABLE&&info.candidates_count==1);
    dmg_value_row_v2 row{};CHECK(dmg_result_get_value_v2(batch,0,&row,sizeof(row))==DMG_OK&&row.kind==DMG_VALUE_USE);
    CHECK(row.use.relation==relation&&row.use.source_index==0&&row.use.caller_ordinal==2&&row.use.caller_method_ref==3&&row.use.dex_pc==0&&row.use.target_index==target);
    dmg_source_info origin{};CHECK(dmg_result_get_origin(batch,0,&origin)==DMG_OK&&origin.dex.occurrence_id&&origin.dex.snapshot_id);
    uint32_t count=0;CHECK(dmg_result_get_witness_count(batch,0,&count)==DMG_OK&&count>0);return row.use.opcode;
}
static uint32_t drain_root(dmg_job* job,uint32_t relation,uint32_t target){uint32_t n=0;for(;;){dmg_batch* b=nullptr;dmg_error err{};auto st=dmg_job_next(job,1000,&b,&err);if(st==DMG_END_OF_STREAM)return n;CHECK(st==DMG_OK&&b);Batch x(b,&dmg_batch_release);root_batch(x.get(),relation,target);++n;}}
static void extended_root(const std::vector<uint8_t>& bytes,const char* kind,uint32_t relation,uint32_t target,uint32_t opcode,uint32_t own_bit,uint32_t other1,uint32_t other2){
    auto e=engine();const auto initial=owned(e.get());auto s=snapshot(e.get(),bytes);auto q=root_query(e.get(),kind);const auto baseline=owned(e.get());
    CHECK(reference::unique_one_stream_shape(*q->query->plan));
    for(auto bit:{other1,other2}){auto forged=root_query(e.get(),kind);auto& p=const_cast<query::Plan&>(*forged->query->plan);p.required_capabilities|=bit;CHECK(!reference::unique_one_stream_shape(p)&&!reference::can_stream(p));dmg_result* r=nullptr;dmg_error er{};CHECK(dmg_query_execute(s.get(),forged.get(),&r,&er)==DMG_UNSUPPORTED&&!r);}
    {auto explicit_q=root_query(e.get(),kind,0,own_bit==32u?",\"string_uses\"":",\"field_uses\"");dmg_query_info a{},b{};CHECK(dmg_query_get_info(q.get(),&a)==DMG_OK&&dmg_query_get_info(explicit_q.get(),&b)==DMG_OK&&std::string(a.query_id)==b.query_id);}
    for(int pc:{0,42}){
        const auto text=std::string(R"({"schema_version":1,"relation":{"op":"scan","relation":")")+kind+R"(","where":{"pc":)"+std::to_string(pc)+R"(}},"intent":"unique","max_results":1,"required_capabilities":["unique_one_stream"]})";
        dmg_query* raw=nullptr;dmg_error er{};CHECK(dmg_query_compile_json(e.get(),reinterpret_cast<const uint8_t*>(text.data()),text.size(),&raw,&er)==DMG_OK&&raw);Query single(raw,&dmg_query_release);
        auto j=start(s.get(),single.get());auto done=wait(j.get());CHECK(done.outcome.execution_status==DMG_OK&&done.outcome.coverage==DMG_COVERAGE_COMPLETE&&done.outcome.candidates_count==(pc==0?1u:0u)&&done.outcome.decision==static_cast<uint32_t>(pc==0?DMG_PROVEN_TRUE:DMG_PROVEN_FALSE));CHECK(drain_root(j.get(),relation,target)==(pc==0?1u:0u));
        if(pc==0){auto partial=snapshot(e.get(),bytes,nullptr,false);auto j2=start(partial.get(),single.get());auto d=wait(j2.get());CHECK(d.outcome.coverage==DMG_COVERAGE_PARTIAL&&d.outcome.decision==DMG_UNDETERMINED&&drain_root(j2.get(),relation,target)==1);}
    }
    uint32_t limited=0,unavailable=0,provisional=0;
    for(uint64_t work=1;work<=120;++work){auto x=root_query(e.get(),kind,work);dmg_result* raw=nullptr;dmg_error er{};const auto st=dmg_query_execute(s.get(),x.get(),&raw,&er);Result sync(raw,&dmg_result_release);uint32_t expected=st,reason=UINT32_MAX;if(sync){dmg_relation_info_v2 i{};CHECK(dmg_result_get_relation_info_v2(sync.get(),&i,sizeof(i))==DMG_OK);expected=i.execution_status;reason=i.reason;}
        auto j=start(s.get(),x.get());auto done=wait(j.get());auto n=drain_root(j.get(),relation,target);CHECK(done.outcome.execution_status==expected&&done.outcome.candidates_count==n&&n<=1);if(sync){CHECK(done.outcome.reason==reason);if(reason==DMG_RESULT_LIMIT){++limited;CHECK(n==1&&done.outcome.decision==DMG_UNDETERMINED);}}else{++unavailable;if(n)++provisional;}}
    CHECK(limited&&unavailable&&provisional);
    arm(301);{ReleaseGate release;auto j=start(s.get(),q.get());await_gate();auto b=next(j.get());CHECK(root_batch(b.get(),relation,target)==opcode);dmg_job_cancel(j.get());unblock();auto done=wait(j.get());CHECK(done.outcome.execution_status==DMG_CANCELLED&&done.outcome.candidates_count==1&&done.outcome.decision==DMG_UNDETERMINED);CHECK(drain_root(j.get(),relation,target)==0);}CHECK(owned(e.get())==baseline);
    arm(101);{ReleaseGate release;auto j=start(s.get(),q.get());await_gate();dmg_job_cancel(j.get());unblock();auto done=wait(j.get());CHECK(done.outcome.execution_status==DMG_CANCELLED&&done.outcome.candidates_count==0&&drain_root(j.get(),relation,target)==0);}CHECK(owned(e.get())==baseline);
    arm(401);{ReleaseGate release;auto j=start(s.get(),q.get());await_gate();auto b=next(j.get());root_batch(b.get(),relation,target);j->state->control.deadline=std::chrono::steady_clock::time_point::min();unblock();auto done=wait(j.get());CHECK(done.outcome.execution_status==DMG_DEADLINE_EXCEEDED&&done.outcome.candidates_count==1&&done.outcome.reason!=DMG_RESULT_LIMIT&&drain_root(j.get(),relation,target)==0);}CHECK(owned(e.get())==baseline);
    fault.store(4);install_hooks();{auto j=start(s.get(),q.get());auto done=wait(j.get());clear_hooks();CHECK(done.outcome.execution_status==DMG_OUT_OF_MEMORY&&done.outcome.candidates_count==0&&drain_root(j.get(),relation,target)==0);CHECK(runtime::test_unique_one_queue_allocation_failed.exchange(false));}CHECK(owned(e.get())==baseline);
    q.reset();s.reset();CHECK(owned(e.get())==initial);std::cout<<kind<<" 120 work thresholds, cancellation after provisional and real deque failure passed\n";
}
int main(int argc,char** argv){try{
    CHECK(argc==5);const auto good=load(argv[1]),bad=load(argv[2]);
    CHECK(sha256(good)=="cb9020777da008d67b856862068a7a23fd6483b599a18ead5f01a3b94ecde00b");
    CHECK(sha256(bad)=="9c86f51bfa689764b9d38e984e6c0ef80cf49122e8a209010477ccf2226b66f6");
    compare_budgets(good);basic_results(good,bad);failure_stages(good);
    auto str=load(argv[3]),field=load(argv[4]);
    CHECK(sha256(str)=="67e58385794f6bc1f8fe56a30bbcb4a4eb973e26b4e6449a52ed0c671668292a");
    CHECK(sha256(field)=="7558a8945c3a87f727de782d885c687539d839e460497f6d2e86c2a7c7f46e8d");
    extended_root(str,"string_uses",DMG_STRING_USES,10,0x1a,32,64,128);
    extended_root(field,"field_uses",DMG_FIELD_USES,0,0x60,128,32,64);
    for(int point:{101,301,203,204,401})cancellation(good,point,false);
    cancellation(good,401,true);
    cancellation_after_locked_commit(good);
    std::cout<<"PASS isolated v12 Unique/max_results=1 draft; old v9 unchanged\n";return 0;
}catch(const std::exception& e){clear_hooks();std::cerr<<e.what()<<'\n';return 1;}}
