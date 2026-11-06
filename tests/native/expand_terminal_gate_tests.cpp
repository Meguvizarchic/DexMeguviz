#include "c_api/runtime.hpp"
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

using namespace dexmeguviz::runtime;
#define CHECK(x) do{if(!(x))throw std::runtime_error("expand terminal gate "+std::to_string(__LINE__)+": " #x);}while(0)
static std::mutex gate_mutex;
static std::condition_variable gate_changed;
static bool entered=false,released=false;
static void terminal_gate()noexcept{
 std::unique_lock lock(gate_mutex);entered=true;gate_changed.notify_all();gate_changed.wait(lock,[]{return released;});
}
struct ReleaseGate {~ReleaseGate(){std::lock_guard lock(gate_mutex);released=true;gate_changed.notify_all();}};
static std::vector<uint8_t> load(const char* path){std::ifstream in(path,std::ios::binary);CHECK(in.good());return {(std::istreambuf_iterator<char>(in)),{}};}
int main(int argc,char** argv){try{
 CHECK(argc==3);const bool old=std::string(argv[2])=="old";CHECK(old||std::string(argv[2])=="new");
 auto bytes=load(argv[1]);dmg_engine* engine=nullptr;dmg_snapshot* snapshot=nullptr;dmg_query* query=nullptr;dmg_job* job=nullptr;dmg_batch* batch=nullptr;dmg_error error{};
 dmg_source_spec source{sizeof(source),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,bytes.data(),bytes.size(),"a","base","10d0ea04da45c7c021ba902ce90ea8f24415d44fd396916088ed55dc6518213b"};
 dmg_source_set_options source_options{sizeof(source_options),DMG_ABI_VERSION,"terminal-gate",1,4,DMG_MAX_SOURCE_BYTES};
 const char* text=R"({"schema_version":1,"relation":{"op":"bounded_expand","input":{"op":"scan","relation":"method_defs","where":{"name":"a"}},"min_depth":0,"max_depth":0}})";
 CHECK(dmg_engine_create(nullptr,&engine,&error)==DMG_OK);
 CHECK(dmg_snapshot_open_sources(engine,&source,1,&source_options,&snapshot,&error)==DMG_OK);
 CHECK(dmg_query_compile_json(engine,reinterpret_cast<const uint8_t*>(text),std::strlen(text),&query,&error)==DMG_OK);
 dmg_engine_stats before{};CHECK(dmg_engine_get_stats(engine,&before)==DMG_OK&&before.scratch_bytes==0&&before.result_bytes==0);
 test_expand_fail_materialization_after.store(0,std::memory_order_release);
 test_expand_after_terminal_hook.store(&terminal_gate,std::memory_order_release);
 ReleaseGate release_gate;
 dmg_job_options options{sizeof(options),DMG_ABI_VERSION,1,1,0};CHECK(dmg_job_start(snapshot,query,&options,&job,&error)==DMG_OK);
 dmg_expand_job_status status{};CHECK(dmg_job_wait_expand(job,30000,&status,sizeof(status))==DMG_OK&&status.terminal&&status.lifecycle==DMG_JOB_FAILED&&status.info.outcome.execution_status==DMG_OUT_OF_MEMORY);
 {
  std::unique_lock lock(gate_mutex);CHECK(gate_changed.wait_for(lock,std::chrono::seconds(30),[]{return entered;}));
 }
 CHECK(dmg_job_next(job,0,&batch,&error)==DMG_END_OF_STREAM&&batch==nullptr);
 dmg_engine_stats at_terminal{};CHECK(dmg_engine_get_stats(engine,&at_terminal)==DMG_OK&&at_terminal.active_jobs==0);
 std::cout<<"terminal while worker gated: result="<<at_terminal.result_bytes<<" scratch="<<at_terminal.scratch_bytes<<"\n";
 if(old)CHECK(at_terminal.result_bytes>before.result_bytes&&at_terminal.scratch_bytes>before.scratch_bytes);
 else CHECK(at_terminal.result_bytes==before.result_bytes&&at_terminal.scratch_bytes==before.scratch_bytes);
 {std::lock_guard lock(gate_mutex);released=true;}gate_changed.notify_all();dmg_job_release(job);job=nullptr;
 test_expand_after_terminal_hook.store(nullptr,std::memory_order_release);test_expand_fail_materialization_after.store(-1,std::memory_order_release);
 dmg_engine_stats after{};CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&after.owned_bytes==before.owned_bytes&&after.result_bytes==before.result_bytes&&after.scratch_bytes==before.scratch_bytes);
 dmg_query_release(query);dmg_snapshot_release(snapshot);dmg_engine_release(engine);
 std::cout<<"PASS terminal gate "<<(old?"old residual reproduced":"new resources reclaimed")<<"\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
