#include "c_api/runtime.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace dexmeguviz;
namespace dexmeguviz::runtime {
extern std::atomic<void(*)(uint32_t)> test_job_scan_barrier;
extern std::atomic<void(*)()> test_job_queue_wait_barrier;
}
namespace dexmeguviz::reference { extern std::atomic<void(*)(uint32_t,uint64_t)> test_graph_reduce_barrier; }
#define CHECK(x) do { if (!(x)) throw std::runtime_error(std::to_string(__LINE__) + ": " #x); } while(0)
using Engine=std::unique_ptr<dmg_engine,decltype(&dmg_engine_release)>;
using Snapshot=std::unique_ptr<dmg_snapshot,decltype(&dmg_snapshot_release)>;
using Query=std::unique_ptr<dmg_query,decltype(&dmg_query_release)>;
using Job=std::unique_ptr<dmg_job,decltype(&dmg_job_release)>;
using Batch=std::unique_ptr<dmg_batch,decltype(&dmg_batch_release)>;
static std::mutex gate_mutex;
static std::condition_variable gate_cv;
static bool entered=false,open=false;
static std::atomic<bool> queue_wait{false};
static void scan_gate(uint32_t n){
    if(n!=1)return;
    std::unique_lock lock(gate_mutex);entered=true;gate_cv.notify_all();
    gate_cv.wait(lock,[]{return open;});
}
static void queue_gate(){queue_wait.store(true,std::memory_order_release);}
static void arm(){
    std::lock_guard lock(gate_mutex);entered=false;open=false;
    runtime::test_job_scan_barrier.store(&scan_gate,std::memory_order_release);
}
static void await_gate(){
    std::unique_lock lock(gate_mutex);
    CHECK(gate_cv.wait_for(lock,std::chrono::seconds(10),[]{return entered;}));
}
static void unblock(){
    {std::lock_guard lock(gate_mutex);open=true;runtime::test_job_scan_barrier.store(nullptr,std::memory_order_release);}
    runtime::test_job_queue_wait_barrier.store(nullptr,std::memory_order_release);gate_cv.notify_all();
}
struct Unblock {~Unblock(){unblock();}};
static dmg_engine_stats stats(dmg_engine* e){dmg_engine_stats s{};CHECK(dmg_engine_get_stats(e,&s)==DMG_OK);return s;}
static bool same(const dmg_engine_stats& a,const dmg_engine_stats& b){
    return a.owned_bytes==b.owned_bytes&&a.source_bytes==b.source_bytes&&a.fact_bytes==b.fact_bytes&&
        a.scratch_bytes==b.scratch_bytes&&a.query_bytes==b.query_bytes&&a.result_bytes==b.result_bytes&&
        a.control_bytes==b.control_bytes&&a.borrowed_bytes==b.borrowed_bytes&&a.active_jobs==b.active_jobs;
}
static Batch next(dmg_job* j){dmg_batch* b=nullptr;dmg_error e{};CHECK(dmg_job_next(j,10000,&b,&e)==DMG_OK&&b);return Batch(b,&dmg_batch_release);}
static dmg_relation_job_status status(dmg_job* j,bool wait=false){
    dmg_relation_job_status s{};CHECK((wait?dmg_job_wait_relation(j,10000,&s,sizeof(s)):dmg_job_get_relation_status(j,&s,sizeof(s)))==DMG_OK);return s;
}
static Job start(dmg_snapshot* s,dmg_query* q){
    const dmg_job_options options{sizeof(options),DMG_ABI_VERSION,16,1,0};dmg_job* j=nullptr;dmg_error e{};
    CHECK(dmg_job_start(s,q,&options,&j,&e)==DMG_OK);return Job(j,&dmg_job_release);
}
struct Reservation {
    std::pmr::memory_resource* resource=nullptr;void* pointer=nullptr;size_t size=0;
    ~Reservation(){release();}
    void release(){if(pointer){resource->deallocate(pointer,size,alignof(std::max_align_t));pointer=nullptr;}}
};
static std::mutex reduce_mutex;
static std::condition_variable reduce_cv;
static std::atomic<uint64_t> reduce_work1{UINT64_MAX},reduce_work2{UINT64_MAX},reduce_work3{UINT64_MAX};
static uint32_t reduce_target=0;
static bool reduce_entered=false,reduce_open=false;
static void reduce_gate(uint32_t phase,uint64_t work){
    if(phase==1)reduce_work1.store(work,std::memory_order_release);
    if(phase==2)reduce_work2.store(work,std::memory_order_release);
    if(phase==3)reduce_work3.store(work,std::memory_order_release);
    std::unique_lock lock(reduce_mutex);if(phase!=reduce_target)return;
    reduce_entered=true;reduce_cv.notify_all();reduce_cv.wait(lock,[]{return reduce_open;});
}
static void open_reduce(){
    {std::lock_guard lock(reduce_mutex);reduce_open=true;reference::test_graph_reduce_barrier.store(nullptr,std::memory_order_release);}
    reduce_cv.notify_all();
}
struct ReduceGuard{~ReduceGuard(){open_reduce();}};
static void graph_reduce_test(const char* path,uint32_t target,bool cancel_after_gate){
    std::ifstream f(path,std::ios::binary);CHECK(f.good());std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)),{});
    const dmg_engine_options eo{sizeof(eo),DMG_ABI_VERSION,8u<<20,8u<<20,1u<<20,1,0};dmg_error error{};dmg_engine* raw_engine=nullptr;
    CHECK(dmg_engine_create(&eo,&raw_engine,&error)==DMG_OK&&raw_engine);Engine engine(raw_engine,&dmg_engine_release);
    const dmg_open_options oo{sizeof(oo),DMG_ABI_VERSION,0,"reduce-proof","slot","6419a7b0b6f792efbd43fc53d8d991d7b5b2b1fad971de0f9a47509e124d9413"};
    dmg_snapshot* raw_snapshot=nullptr;CHECK(dmg_snapshot_open_copy_in(engine.get(),bytes.data(),bytes.size(),&oo,&raw_snapshot,&error)==DMG_OK&&raw_snapshot);Snapshot snapshot(raw_snapshot,&dmg_snapshot_release);
    auto compile=[&](uint64_t work){
        auto text=std::string(R"({"schema_version":1,"relation":{"op":"scan","relation":"field_refs","where":{"flags_contains":1}},"intent":"unique","max_results":)")+(target==3?"1":"100");
        if(work)text+=",\"max_work\":"+std::to_string(work);text+='}';
        dmg_query* raw_query=nullptr;CHECK(dmg_query_compile_json(engine.get(),reinterpret_cast<const uint8_t*>(text.data()),text.size(),&raw_query,&error)==DMG_OK&&raw_query);return Query(raw_query,&dmg_query_release);
    };
    auto start_two=[&](dmg_query* query){const dmg_job_options options{sizeof(options),DMG_ABI_VERSION,16,2,0};dmg_job* raw_job=nullptr;
        CHECK(dmg_job_start(snapshot.get(),query,&options,&raw_job,&error)==DMG_OK&&raw_job);return Job(raw_job,&dmg_job_release);};
    reduce_work1.store(UINT64_MAX);reduce_work2.store(UINT64_MAX);reduce_work3.store(UINT64_MAX);
    {std::lock_guard lock(reduce_mutex);reduce_target=0;reduce_entered=false;reduce_open=false;}
    reference::test_graph_reduce_barrier.store(&reduce_gate,std::memory_order_release);
    {ReduceGuard guard;auto query=compile(0);auto job=start_two(query.get());const auto done=status(job.get(),true);
        if(target==3)CHECK(done.terminal&&done.outcome.execution_status==DMG_BUDGET_EXCEEDED&&done.outcome.reason==DMG_RESULT_LIMIT&&done.outcome.candidates_count==1);
        else CHECK(done.terminal&&done.outcome.execution_status==DMG_OK&&done.outcome.candidates_count==2);}
    const auto threshold=target==1?reduce_work1.load(std::memory_order_acquire):target==2?reduce_work2.load(std::memory_order_acquire):reduce_work3.load(std::memory_order_acquire);
    CHECK(threshold>0&&threshold!=UINT64_MAX);
    {std::lock_guard lock(reduce_mutex);reduce_target=target;reduce_entered=false;reduce_open=false;}
    reference::test_graph_reduce_barrier.store(&reduce_gate,std::memory_order_release);
    auto query=compile(threshold);auto job=start_two(query.get());ReduceGuard guard;
    {std::unique_lock lock(reduce_mutex);CHECK(reduce_cv.wait_for(lock,std::chrono::seconds(10),[]{return reduce_entered;}));}
    auto first=next(job.get());Batch second(nullptr,&dmg_batch_release);if(target!=3)second=next(job.get());
    dmg_relation_info one{},two{};CHECK(dmg_result_get_relation_info(first.get(),&one,sizeof(one))==DMG_OK&&one.unknown_rows==1);
    dmg_graph_info first_graph{},second_graph{};CHECK(dmg_result_get_graph_info(first.get(),&first_graph,sizeof(first_graph))==DMG_OK&&first_graph.identity_count==1);
    if(second){CHECK(dmg_result_get_relation_info(second.get(),&two,sizeof(two))==DMG_OK&&two.unknown_rows==1);
        CHECK(dmg_result_get_graph_info(second.get(),&second_graph,sizeof(second_graph))==DMG_OK&&second_graph.identity_count==2);}
    dmg_graph_info running{};CHECK(dmg_job_get_graph_info(job.get(),&running,sizeof(running))==DMG_OK&&running.identity_count==(target==3?1u:2u));
    if(cancel_after_gate)dmg_job_cancel(job.get());open_reduce();const auto terminal=status(job.get(),true);
    CHECK(terminal.terminal&&terminal.outcome.execution_status==DMG_BUDGET_EXCEEDED&&terminal.outcome.coverage==DMG_COVERAGE_PARTIAL&&terminal.outcome.candidates_count==(target==3?1u:2u));
    dmg_graph_info final_graph{};CHECK(dmg_job_get_graph_info(job.get(),&final_graph,sizeof(final_graph))==DMG_OK);
    std::cout<<"phase="<<target<<" cancel="<<cancel_after_gate<<" max_work="<<threshold<<" batch_unknown="<<one.unknown_rows<<" final_unknown="<<terminal.outcome.unknown_rows<<" published="<<(target==3?1:2)<<" final_identities="<<final_graph.identity_count<<" reason="<<terminal.outcome.reason<<'\n';
    CHECK(terminal.outcome.unknown_rows>=one.unknown_rows);
    CHECK(final_graph.identity_count>=(target==3?1u:2u));
    if(target==3)CHECK(terminal.outcome.reason==DMG_RESULT_LIMIT&&terminal.outcome.decision==DMG_UNDETERMINED);
}
int main(int argc,char** argv){try{
    if(argc==3){const std::string mode(argv[2]);CHECK(mode=="reduce-unknown"||mode=="reduce-identity"||mode=="reduce-limit-cancel"||mode=="reduce-limit-budget");
        graph_reduce_test(argv[1],mode=="reduce-unknown"?1u:mode=="reduce-identity"?2u:3u,mode=="reduce-limit-cancel");return 0;}
    CHECK(argc==2);std::ifstream f(argv[1],std::ios::binary);CHECK(f.good());
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)),{});
    constexpr uint64_t limit=8u<<20;
    const dmg_engine_options eo{sizeof(eo),DMG_ABI_VERSION,limit,limit,1u<<20,1,0};dmg_error err{};dmg_engine* raw_e=nullptr;
    CHECK(dmg_engine_create(&eo,&raw_e,&err)==DMG_OK);Engine engine(raw_e,&dmg_engine_release);
    const auto baseline=stats(engine.get());
    const dmg_open_options oo{sizeof(oo),DMG_ABI_VERSION,0,"q09-extra","slot","6419a7b0b6f792efbd43fc53d8d991d7b5b2b1fad971de0f9a47509e124d9413"};
    dmg_snapshot* raw_s=nullptr;CHECK(dmg_snapshot_open_copy_in(engine.get(),bytes.data(),bytes.size(),&oo,&raw_s,&err)==DMG_OK);
    Snapshot snapshot(raw_s,&dmg_snapshot_release);
    const std::string input=R"({"schema_version":1,"relation":{"op":"scan","relation":"field_refs","where":{"flags_contains":1}},"intent":"unique","max_results":100})";
    dmg_query* raw_q=nullptr;CHECK(dmg_query_compile_json(engine.get(),reinterpret_cast<const uint8_t*>(input.data()),input.size(),&raw_q,&err)==DMG_OK);
    Query query(raw_q,&dmg_query_release);const auto prepared=stats(engine.get());
    {
        arm();auto job=start(snapshot.get(),query.get());Unblock safety;await_gate();
        const auto live=status(job.get());CHECK(!live.terminal&&live.outcome.candidates_count==1&&live.outcome.unknown_rows==1&&live.outcome.visited_rows==2);
        dmg_query_profile jp{};CHECK(dmg_job_get_profile(job.get(),&jp)==DMG_OK&&jp.matches_seen==1&&jp.work_units>0);
        auto first=next(job.get());dmg_relation_info info{};CHECK(dmg_result_get_relation_info(first.get(),&info,sizeof(info))==DMG_OK);
        CHECK(info.candidates_count==1&&info.unknown_rows==1&&info.visited_rows==live.outcome.visited_rows&&info.coverage==DMG_COVERAGE_PARTIAL);
        dmg_query_profile bp{};CHECK(dmg_result_get_profile(first.get(),&bp)==DMG_OK&&bp.matches_seen==jp.matches_seen&&bp.work_units==jp.work_units);
        dmg_entity_row row{};CHECK(dmg_result_get_entity(first.get(),0,&row,sizeof(row))==DMG_OK&&row.local_index==1);
        dmg_job_cancel(job.get());unblock();const auto done=status(job.get(),true);
        CHECK(done.terminal&&done.lifecycle==DMG_JOB_CANCELLED&&done.outcome.execution_status==DMG_CANCELLED&&
              done.outcome.candidates_count==1&&done.outcome.decision==DMG_UNDETERMINED&&
              done.outcome.coverage==DMG_COVERAGE_PARTIAL&&done.outcome.reason==DMG_REASON_NONE&&
              done.outcome.unknown_rows==1&&done.outcome.visited_rows>=2&&done.outcome.visited_rows<=3&&done.outcome.total_rows==4);
        // visited_rows counts an attempted next row before its cancellation check.
        job.reset();first.reset();CHECK(same(stats(engine.get()),prepared));
    }
    {
        queue_wait.store(false,std::memory_order_release);runtime::test_job_queue_wait_barrier.store(&queue_gate,std::memory_order_release);
        auto job=start(snapshot.get(),query.get());Unblock safety;
        const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(10);
        while(!queue_wait.load(std::memory_order_acquire)){CHECK(std::chrono::steady_clock::now()<until);std::this_thread::yield();}
        dmg_relation_job_status waiting{};CHECK(dmg_job_wait_relation(job.get(),50,&waiting,sizeof(waiting))==DMG_NOT_READY&&!waiting.terminal);
        auto first=next(job.get());auto second=next(job.get());const auto done=status(job.get(),true);
        CHECK(done.terminal&&done.outcome.execution_status==DMG_OK&&done.outcome.candidates_count==2&&done.outcome.decision==DMG_PROVEN_FALSE&&done.outcome.reason==DMG_AMBIGUOUS);
        dmg_entity_row a{},b{};CHECK(dmg_result_get_entity(first.get(),0,&a,sizeof(a))==DMG_OK&&dmg_result_get_entity(second.get(),0,&b,sizeof(b))==DMG_OK&&a.local_index==1&&b.local_index==2);
        job.reset();first.reset();second.reset();CHECK(same(stats(engine.get()),prepared));
    }
    {
        arm();auto job=start(snapshot.get(),query.get());Unblock safety;await_gate();auto first=next(job.get());
        const auto used=stats(engine.get()).owned_bytes;CHECK(used<limit);
        Reservation reservation{&job->state->engine->control_resource,nullptr,static_cast<size_t>(limit-used)};
        reservation.pointer=reservation.resource->allocate(reservation.size,alignof(std::max_align_t));
        unblock();const auto done=status(job.get(),true);
        CHECK(done.terminal&&done.outcome.execution_status==DMG_BUDGET_EXCEEDED&&done.outcome.candidates_count==1&&done.outcome.decision==DMG_UNDETERMINED);
        reservation.release();job.reset();CHECK(stats(engine.get()).result_bytes>prepared.result_bytes);
        dmg_entity_row row{};CHECK(dmg_result_get_entity(first.get(),0,&row,sizeof(row))==DMG_OK&&row.local_index==1);
        first.reset();CHECK(same(stats(engine.get()),prepared));
    }
    query.reset();snapshot.reset();CHECK(same(stats(engine.get()),baseline));
    std::cout<<"PASS Q09 stream unknown snapshot, queue backpressure and retained Batch budget recovery\n";return 0;
}catch(const std::exception& e){unblock();std::cerr<<e.what()<<'\n';return 1;}}
