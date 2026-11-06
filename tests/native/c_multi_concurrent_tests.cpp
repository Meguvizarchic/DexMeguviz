#include "dexmeguviz/dexmeguviz.h"
#include <atomic>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <cstring>
#define CHECK(x) do{if(!(x))throw std::runtime_error("multi concurrent line "+std::to_string(__LINE__)+": " #x);}while(0)
int main(int argc,char** argv){try{
 CHECK(argc==2);std::ifstream f(argv[1],std::ios::binary);CHECK(f.good());std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(f),{}};
 const char* one=R"({"schema_version":1,"relation":"method_defs","where":{"name":"uses","using_strings":{"all":["used-string"]}}})";
 const char* two=R"({"schema_version":1,"relation":"method_defs","where":{"name":"uses","using_strings":{"all":[{"op":"contains","value":"string"}]}}})";
 dmg_engine* engine=nullptr;dmg_snapshot* snap=nullptr;dmg_query *a=nullptr,*b=nullptr;dmg_error e{};
 CHECK(dmg_engine_create(nullptr,&engine,&e)==DMG_OK);dmg_open_options open{sizeof(open),DMG_ABI_VERSION,DMG_MAX_SOURCE_BYTES,"parallel","slot",nullptr};
 CHECK(dmg_snapshot_open_copy_in(engine,bytes.data(),bytes.size(),&open,&snap,&e)==DMG_OK);
 CHECK(dmg_query_compile_json(engine,reinterpret_cast<const uint8_t*>(one),strlen(one),&a,&e)==DMG_OK&&dmg_query_compile_json(engine,reinterpret_cast<const uint8_t*>(two),strlen(two),&b,&e)==DMG_OK);
 dmg_query* rules[]{a,b};dmg_multi_options_v1 options{sizeof(options),DMG_ABI_VERSION,1u<<20,1000000,0,0};dmg_engine_stats baseline{};CHECK(dmg_engine_get_stats(engine,&baseline)==DMG_OK);std::atomic<unsigned> failures{0};
 auto execute=[&]{for(int n=0;n<12;n++){dmg_multi_batch_v1* batch=nullptr;dmg_result* result=nullptr;uint32_t index;dmg_error error{};dmg_multi_profile_v1 p{};dmg_result_info info{};
  if(dmg_multi_execute_v1(snap,rules,2,&options,&batch,&index,&error)!=DMG_OK){++failures;continue;}
  if(dmg_multi_batch_profile_v1(batch,&p,sizeof(p))!=DMG_OK||p.cache_hits==0||dmg_multi_batch_get_result_v1(batch,0,&result)!=DMG_OK){++failures;dmg_multi_batch_release_v1(batch);continue;}
  dmg_multi_batch_release_v1(batch);if(dmg_result_get_info(result,&info)!=DMG_OK||info.candidates_count==0)++failures;dmg_result_release(result);
 }};
 std::thread t0(execute),t1(execute),t2(execute),t3(execute);t0.join();t1.join();t2.join();t3.join();CHECK(failures==0);
 dmg_multi_batch_v1* shared=nullptr;uint32_t index;CHECK(dmg_multi_execute_v1(snap,rules,2,&options,&shared,&index,&e)==DMG_OK);
 auto reader=[&]{dmg_multi_batch_retain_v1(shared);for(int i=0;i<100;i++){dmg_result* result=nullptr;dmg_result_info info{};if(dmg_multi_batch_get_result_v1(shared,i%2,&result)!=DMG_OK||dmg_result_get_info(result,&info)!=DMG_OK||info.candidates_count==0)++failures;dmg_result_release(result);}dmg_multi_batch_release_v1(shared);};
 std::thread r0(reader),r1(reader),r2(reader),r3(reader);r0.join();r1.join();r2.join();r3.join();dmg_multi_batch_release_v1(shared);CHECK(failures==0);dmg_engine_stats after{};CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&after.owned_bytes==baseline.owned_bytes&&after.result_bytes==baseline.result_bytes&&after.scratch_bytes==baseline.scratch_bytes);
 dmg_query_release(a);dmg_query_release(b);dmg_snapshot_release(snap);dmg_engine_release(engine);std::cout<<"PASS concurrent independent batches and retained readers; ledger restored\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
