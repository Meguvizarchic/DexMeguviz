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
namespace dexmeguviz::reference{extern std::atomic<void(*)()> test_type_use_method_barrier;}
namespace dexmeguviz::runtime{extern std::atomic<void(*)(uint32_t)> test_job_commit_barrier;extern std::atomic<void(*)()> test_job_queue_wait_barrier;}
#define CHECK(x) do{if(!(x))throw std::runtime_error("type job line "+std::to_string(__LINE__)+": " #x);}while(0)
using Engine=std::unique_ptr<dmg_engine,decltype(&dmg_engine_release)>;using Snapshot=std::unique_ptr<dmg_snapshot,decltype(&dmg_snapshot_release)>;using Query=std::unique_ptr<dmg_query,decltype(&dmg_query_release)>;using Job=std::unique_ptr<dmg_job,decltype(&dmg_job_release)>;using Batch=std::unique_ptr<dmg_batch,decltype(&dmg_batch_release)>;
static std::mutex mutex;static std::condition_variable cv;static bool entered=false,open_gate=false;
static void gate(){std::unique_lock lock(mutex);entered=true;cv.notify_all();cv.wait(lock,[]{return open_gate;});}
static void commit(uint32_t){gate();}static void arm(){std::lock_guard lock(mutex);entered=false;open_gate=false;}
static void wait_gate(){std::unique_lock lock(mutex);CHECK(cv.wait_for(lock,std::chrono::seconds(15),[]{return entered;}));}
static void release_gate(){{std::lock_guard lock(mutex);open_gate=true;reference::test_type_use_method_barrier.store(nullptr);runtime::test_job_commit_barrier.store(nullptr);runtime::test_job_queue_wait_barrier.store(nullptr);}cv.notify_all();}
struct ReleaseGate{~ReleaseGate(){release_gate();}};
static Job start(dmg_snapshot* s,dmg_query* q,uint32_t queue,uint64_t deadline){dmg_job_options options{sizeof(options),DMG_ABI_VERSION,1,queue,deadline};dmg_job* p=nullptr;dmg_error e{};CHECK(dmg_job_start(s,q,&options,&p,&e)==DMG_OK&&p);return Job(p,&dmg_job_release);}
static dmg_relation_job_status_v3 wait(dmg_job* job){dmg_relation_job_status_v3 st{};CHECK(dmg_job_wait_relation_v3(job,15000,&st,sizeof(st))==DMG_OK&&st.terminal);return st;}
static Batch next(dmg_job* job){dmg_error e{};dmg_batch* p=nullptr;CHECK(dmg_job_next(job,15000,&p,&e)==DMG_OK&&p);return Batch(p,&dmg_batch_release);}
int main(int argc,char** argv){try{
 CHECK(argc==2);std::ifstream file(std::filesystem::path(argv[1]),std::ios::binary);CHECK(file.good());std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file),{}};dmg_error e{};dmg_engine* er=nullptr;CHECK(dmg_engine_create(nullptr,&er,&e)==DMG_OK);Engine engine(er,&dmg_engine_release);dmg_open_options open{sizeof(open),DMG_ABI_VERSION,0,"type-job","base",nullptr};dmg_snapshot* sr=nullptr;CHECK(dmg_snapshot_open_copy_in(engine.get(),bytes.data(),bytes.size(),&open,&sr,&e)==DMG_OK);Snapshot snapshot(sr,&dmg_snapshot_release);
 const std::string text=R"({"schema_version":1,"required_capabilities":["type_uses"],"relation":{"op":"scan","relation":"type_uses","where":{"all":[{"opcode":34},{"target_descriptor":"Lfixture/TypeUses$Parent;"}]}},"max_results":100})";dmg_query* qr=nullptr;CHECK(dmg_query_compile_json(engine.get(),reinterpret_cast<const uint8_t*>(text.data()),text.size(),&qr,&e)==DMG_OK);Query q(qr,&dmg_query_release);
 // First completely decoded method, before scan proceeds; no batch may have escaped.
 arm();reference::test_type_use_method_barrier.store(&gate);{auto job=start(snapshot.get(),q.get(),2,0);ReleaseGate guard;wait_gate();dmg_batch* empty=nullptr;CHECK(dmg_job_next(job.get(),0,&empty,&e)==DMG_NOT_READY&&!empty);dmg_job_cancel(job.get());release_gate();auto st=wait(job.get());CHECK(st.lifecycle==DMG_JOB_CANCELLED&&st.outcome.execution_status==DMG_CANCELLED&&st.outcome.coverage==DMG_COVERAGE_PARTIAL);CHECK(dmg_job_next(job.get(),0,&empty,&e)==DMG_END_OF_STREAM&&!empty);}
 // After scan and provisional publication, before terminal commit, cancellation wins.
 arm();runtime::test_job_commit_barrier.store(&commit);{auto job=start(snapshot.get(),q.get(),2,0);ReleaseGate guard;wait_gate();auto batch=next(job.get());dmg_relation_info_v3 info{};CHECK(dmg_result_get_relation_info_v3(batch.get(),&info,sizeof(info))==DMG_OK&&info.coverage==DMG_COVERAGE_PARTIAL&&info.decision==DMG_NOT_APPLICABLE);dmg_job_cancel(job.get());release_gate();auto st=wait(job.get());CHECK(st.lifecycle==DMG_JOB_CANCELLED&&st.outcome.execution_status==DMG_CANCELLED);job.reset();dmg_value_row_v3 value{};CHECK(dmg_result_get_value_v3(batch.get(),0,&value,sizeof(value))==DMG_OK&&value.value.use.relation==DMG_TYPE_USES);}
 // Queue capacity one: stop in backpressure until a deadline expires after one provisional batch.
 arm();runtime::test_job_queue_wait_barrier.store(&gate);{auto job=start(snapshot.get(),q.get(),1,3000);ReleaseGate guard;wait_gate();std::this_thread::sleep_until(job->state->control.deadline+std::chrono::milliseconds(10));release_gate();auto st=wait(job.get());CHECK(st.lifecycle==DMG_JOB_FAILED&&st.outcome.execution_status==DMG_DEADLINE_EXCEEDED&&st.outcome.coverage==DMG_COVERAGE_PARTIAL);auto batch=next(job.get());dmg_relation_info_v3 info{};CHECK(dmg_result_get_relation_info_v3(batch.get(),&info,sizeof(info))==DMG_OK&&info.candidates_count==1);}
 std::cout<<"PASS v21 Job scan cancellation, provisional commit cancellation, queue backpressure deadline\n";return 0;
 }catch(const std::exception& ex){release_gate();std::cerr<<ex.what()<<'\n';return 1;}}
