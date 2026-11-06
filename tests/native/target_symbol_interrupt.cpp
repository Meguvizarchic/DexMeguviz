#include "dexmeguviz/dexmeguviz.h"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>
namespace dexmeguviz::reference { extern std::atomic<void(*)(uint64_t)> test_target_symbol_barrier; }
#define CHECK(x) do{if(!(x))throw std::runtime_error(std::to_string(__LINE__)+": " #x);}while(0)
static std::mutex mutex;static std::condition_variable cv;static bool entered=false,opened=false;static uint64_t captured=0;
static void gate(uint64_t work){std::unique_lock lock(mutex);if(entered)return;captured=work;entered=true;cv.notify_all();cv.wait(lock,[]{return opened;});}
static void release_gate(){std::lock_guard lock(mutex);opened=true;dexmeguviz::reference::test_target_symbol_barrier.store(nullptr);cv.notify_all();}
static std::vector<unsigned char> read(const char* path){std::ifstream f(path,std::ios::binary);CHECK(f.good());return {std::istreambuf_iterator<char>(f),{}};}
static dmg_operator_profile_v2 root_profile(dmg_job* job){dmg_graph_info g{};CHECK(dmg_job_get_graph_info(job,&g,sizeof(g))==DMG_OK);for(uint32_t i=0;i<g.operator_count;++i){dmg_operator_profile_v2 op{};CHECK(dmg_job_get_operator_profile_v2(job,i,&op,sizeof(op))==DMG_OK);if(op.node_id==g.root_node)return op;}throw std::runtime_error("missing root profile");}
static std::string query(uint64_t budget){return "{\"schema_version\":1,\"required_capabilities\":[\"use_target_symbol\"],\"relation\":{\"op\":\"join\",\"on\":\"target_symbol\",\"left\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"},\"right\":{\"op\":\"scan\",\"relation\":\"method_defs\"}},\"max_results\":100,\"max_work\":"+std::to_string(budget)+"}";}
int main(int argc,char**argv){try{CHECK(argc==4);std::vector<std::vector<unsigned char>> data;for(int i=1;i<argc;++i)data.push_back(read(argv[i]));dmg_engine* engine=nullptr;dmg_snapshot* snapshot=nullptr;dmg_error error{};dmg_source_spec sources[3]{};dmg_source_set_options options{sizeof(options),DMG_ABI_VERSION,"symbol-interrupt",1,3,DMG_MAX_SOURCE_BYTES};CHECK(dmg_engine_create(nullptr,&engine,&error)==DMG_OK);for(int i=0;i<3;++i)sources[i]={sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,data[i].data(),data[i].size(),i==0?"a":i==1?"b1":"b2",i==0?"base":"code",nullptr};CHECK(dmg_snapshot_open_sources(engine,sources,3,&options,&snapshot,&error)==DMG_OK);
 auto start=[&](uint64_t budget,dmg_query** out,dmg_job** job){auto q=query(budget);CHECK(dmg_query_compile_json(engine,reinterpret_cast<const uint8_t*>(q.data()),q.size(),out,&error)==DMG_OK);dmg_job_options j{sizeof(j),DMG_ABI_VERSION,1,1,0};CHECK(dmg_job_start(snapshot,*out,&j,job,&error)==DMG_OK);};
 dmg_query* q=nullptr;dmg_job* job=nullptr;dexmeguviz::reference::test_target_symbol_barrier.store(&gate);start(100000000,&q,&job);{std::unique_lock lock(mutex);CHECK(cv.wait_for(lock,std::chrono::seconds(10),[]{return entered;}));}CHECK(captured>0);dmg_job_cancel(job);release_gate();dmg_batch* batch=nullptr;CHECK(dmg_job_next(job,10000,&batch,&error)==DMG_END_OF_STREAM&&batch==nullptr);dmg_relation_job_status_v2 status{};CHECK(dmg_job_wait_relation_v2(job,10000,&status,sizeof(status))==DMG_OK&&status.terminal&&status.lifecycle==DMG_JOB_CANCELLED&&status.outcome.execution_status==DMG_CANCELLED&&status.outcome.candidates_count==0);dmg_operator_profile_v2 op=root_profile(job);CHECK(op.op==DMG_REL_JOIN&&op.input_rows==7);dmg_job_release(job);dmg_query_release(q);
 q=nullptr;job=nullptr;start(captured,&q,&job);CHECK(dmg_job_next(job,10000,&batch,&error)==DMG_END_OF_STREAM&&batch==nullptr);CHECK(dmg_job_wait_relation_v2(job,10000,&status,sizeof(status))==DMG_OK&&status.terminal&&status.lifecycle==DMG_JOB_FAILED&&status.outcome.execution_status==DMG_BUDGET_EXCEEDED&&status.outcome.candidates_count==0);op=root_profile(job);CHECK(op.op==DMG_REL_JOIN&&op.input_rows==7);dmg_job_release(job);dmg_query_release(q);dmg_snapshot_release(snapshot);dmg_engine_release(engine);std::cout<<"target symbol comparison cancel/budget PASS work="<<captured<<"\n";return 0;
 }catch(const std::exception&e){release_gate();std::cerr<<e.what()<<"\n";return 1;}}
