#include "dexmeguviz/dexmeguviz.h"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>
namespace dexmeguviz::reference {extern std::atomic<void(*)(uint32_t,uint64_t)> test_graph_reduce_barrier;}
namespace dexmeguviz::runtime {extern std::atomic<void(*)(uint32_t)> test_job_commit_barrier;}
namespace r=dexmeguviz::reference;namespace j=dexmeguviz::runtime;
#define CHECK(x) do {if(!(x))throw std::runtime_error("line "+std::to_string(__LINE__)+": " #x);}while(false)
using Engine=std::unique_ptr<dmg_engine,decltype(&dmg_engine_release)>;
using Snapshot=std::unique_ptr<dmg_snapshot,decltype(&dmg_snapshot_release)>;
using Query=std::unique_ptr<dmg_query,decltype(&dmg_query_release)>;
using Job=std::unique_ptr<dmg_job,decltype(&dmg_job_release)>;
using Batch=std::unique_ptr<dmg_batch,decltype(&dmg_batch_release)>;
static std::mutex mutex;static std::condition_variable cv;static bool entered=false,opened=false;static uint32_t marker=0;
static void block(uint32_t value){std::unique_lock lock(mutex);marker=value;entered=true;cv.notify_all();cv.wait(lock,[]{return opened;});}
static void reduce_gate(uint32_t phase,uint64_t){if(phase==2)block(phase);}
static void commit_gate(uint32_t count){block(count);}
static void arm(bool reduce){std::lock_guard lock(mutex);entered=false;opened=false;marker=0;if(reduce)r::test_graph_reduce_barrier.store(&reduce_gate,std::memory_order_release);else j::test_job_commit_barrier.store(&commit_gate,std::memory_order_release);}
static uint32_t await_gate(){std::unique_lock lock(mutex);CHECK(cv.wait_for(lock,std::chrono::seconds(15),[]{return entered;}));return marker;}
static void unblock(){{std::lock_guard lock(mutex);opened=true;r::test_graph_reduce_barrier.store(nullptr,std::memory_order_release);j::test_job_commit_barrier.store(nullptr,std::memory_order_release);}cv.notify_all();}
struct GateGuard{~GateGuard(){unblock();}};
static dmg_relation_job_status_v2 status(dmg_job* job,bool wait){dmg_relation_job_status_v2 s{};CHECK((wait?dmg_job_wait_relation_v2(job,15000,&s,sizeof(s)):dmg_job_get_relation_status_v2(job,&s,sizeof(s)))==DMG_OK);return s;}
static Job start(dmg_snapshot* snap,dmg_query* query){dmg_job_options o{sizeof(o),DMG_ABI_VERSION,8,2,0};dmg_job* raw=nullptr;dmg_error e{};CHECK(dmg_job_start(snap,query,&o,&raw,&e)==DMG_OK&&raw);return Job(raw,&dmg_job_release);}
static dmg_engine_stats stats(dmg_engine* e){dmg_engine_stats s{};CHECK(dmg_engine_get_stats(e,&s)==DMG_OK);return s;}
static bool same(const dmg_engine_stats& a,const dmg_engine_stats& b){return a.owned_bytes==b.owned_bytes&&a.source_bytes==b.source_bytes&&a.fact_bytes==b.fact_bytes&&a.scratch_bytes==b.scratch_bytes&&a.query_bytes==b.query_bytes&&a.result_bytes==b.result_bytes&&a.control_bytes==b.control_bytes&&a.borrowed_bytes==b.borrowed_bytes&&a.active_jobs==b.active_jobs;}
static void no_batch(dmg_job* job){dmg_batch* b=reinterpret_cast<dmg_batch*>(1);dmg_error e{};CHECK(dmg_job_next(job,0,&b,&e)==DMG_NOT_READY&&b==nullptr);}
static Batch next(dmg_job* job){dmg_batch* b=nullptr;dmg_error e{};CHECK(dmg_job_next(job,10000,&b,&e)==DMG_OK&&b);return Batch(b,&dmg_batch_release);}
static void expect_batch(dmg_batch* b,uint32_t count){dmg_relation_info_v2 info{};CHECK(dmg_result_get_relation_info_v2(b,&info,sizeof(info))==DMG_OK);CHECK(info.coverage==DMG_COVERAGE_PARTIAL&&info.decision==DMG_NOT_APPLICABLE&&info.candidates_count==count);
 for(uint32_t i=0;i<count;++i){dmg_value_row_v2 row{};CHECK(dmg_result_get_value_v2(b,i,&row,sizeof(row))==DMG_OK&&row.kind==DMG_VALUE_USE);CHECK(row.use.source_index==0&&row.use.dex_pc==(i==0?3u:0u)&&row.use.opcode==0x71&&row.use.target_index==4&&row.use.target_domain==DMG_TARGET_METHOD_REF);}}
static void run_case(dmg_engine* engine,dmg_snapshot* snap,bool top,bool single,bool cancel_after_publish,bool stream){
 const std::string relation=std::string(R"({"op":"scan","relation":"invoke_sites")")+(single?R"(,"where":{"pc":3})":"")+"}";
 const std::string text=std::string(R"({"schema_version":1,"relation":)")+relation+R"(,"intent":")"+(top?"top_n":"unique")+R"(","max_results":)"+(top?"1":"2")+R"(,"order_by":[{"field":"pc","direction":"desc"}])"+(stream?R"(,"required_capabilities":["use_streaming"])":"")+"}";
 dmg_query* raw=nullptr;dmg_error e{};CHECK(dmg_query_compile_json(engine,reinterpret_cast<const uint8_t*>(text.data()),text.size(),&raw,&e)==DMG_OK&&raw);Query query(raw,&dmg_query_release);const auto prepared=stats(engine);const uint32_t expected=(top||single)?1:2;
 {arm(true);auto job=start(snap,query.get());GateGuard guard;CHECK(await_gate()==2);CHECK(!status(job.get(),false).terminal);no_batch(job.get());dmg_job_cancel(job.get());unblock();auto done=status(job.get(),true);CHECK(done.terminal&&done.lifecycle==DMG_JOB_CANCELLED&&done.outcome.execution_status==DMG_CANCELLED&&done.outcome.coverage==DMG_COVERAGE_PARTIAL&&done.outcome.decision==DMG_UNDETERMINED&&done.outcome.candidates_count==0);dmg_batch* b=reinterpret_cast<dmg_batch*>(1);CHECK(dmg_job_next(job.get(),0,&b,&e)==DMG_END_OF_STREAM&&b==nullptr);job.reset();CHECK(same(stats(engine),prepared));}
 {arm(false);auto job=start(snap,query.get());GateGuard guard;CHECK(await_gate()==expected);CHECK(!status(job.get(),false).terminal);auto batch=next(job.get());expect_batch(batch.get(),expected);CHECK(!status(job.get(),false).terminal);if(cancel_after_publish)dmg_job_cancel(job.get());unblock();const auto done=status(job.get(),true);
  CHECK(done.terminal&&done.outcome.candidates_count==expected);
  if(cancel_after_publish){CHECK(done.lifecycle==DMG_JOB_CANCELLED&&done.outcome.execution_status==DMG_CANCELLED&&done.outcome.coverage==DMG_COVERAGE_PARTIAL);CHECK(done.outcome.decision==((top||single)?DMG_UNDETERMINED:DMG_PROVEN_FALSE));if(!top&&!single)CHECK(done.outcome.reason==DMG_AMBIGUOUS);}
  else {CHECK(done.lifecycle==DMG_JOB_COMPLETED&&done.outcome.execution_status==DMG_OK&&done.outcome.coverage==DMG_COVERAGE_COMPLETE);CHECK(done.outcome.decision==((top||single)?DMG_PROVEN_TRUE:DMG_PROVEN_FALSE));if(!top&&!single)CHECK(done.outcome.reason==DMG_AMBIGUOUS);}
  expect_batch(batch.get(),expected);job.reset();batch.reset();CHECK(same(stats(engine),prepared));}
 std::cout<<(top?"top_n":single?"unique_one":"unique_two")<<" stream="<<stream<<" commit_cancel="<<cancel_after_publish<<" reduce_no_batch=ok provisional_pc="<<((top||single)?"3":"3,0")<<"\n";
}
int main(int argc,char** argv){try{CHECK(argc==2);std::ifstream in(argv[1],std::ios::binary);CHECK(in.good());std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(in),{}};dmg_engine* e=nullptr;dmg_error error{};CHECK(dmg_engine_create(nullptr,&e,&error)==DMG_OK);Engine engine(e,&dmg_engine_release);dmg_open_options o{sizeof(o),DMG_ABI_VERSION,0,"sorted-q09","slot",nullptr};dmg_snapshot* s=nullptr;CHECK(dmg_snapshot_open_copy_in(engine.get(),bytes.data(),bytes.size(),&o,&s,&error)==DMG_OK);Snapshot snap(s,&dmg_snapshot_release);
 for(bool stream:{false,true})for(int kind=0;kind<3;++kind)for(bool cancel:{false,true})run_case(engine.get(),snap.get(),kind==2,kind==1,cancel,stream);
 std::cout<<"PASS sorted Q09 reduce cancellation and provisional commit windows\n";return 0;
}catch(const std::exception& e){unblock();std::cerr<<e.what()<<'\n';return 1;}}
