#include "dexmeguviz/dexmeguviz.h"
#include "execution/budget/account.hpp"
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#define CHECK(x) do{if(!(x))throw std::runtime_error("multi fault line "+std::to_string(__LINE__)+": " #x);}while(0)
int main(int argc,char** argv){try{
 CHECK(argc==2);std::ifstream f(argv[1],std::ios::binary);CHECK(f.good());std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(f),{}};
 const char* one=R"({"schema_version":1,"relation":"method_defs","where":{"name":"uses","using_strings":{"all":["used-string"]}}})";
 const char* two=R"({"schema_version":1,"relation":"method_defs","where":{"name":"uses","using_strings":{"all":[{"op":"contains","value":"string"}]}}})";
 dmg_engine* engine=nullptr;dmg_snapshot* snap=nullptr;dmg_query *a=nullptr,*b=nullptr;dmg_error e{};CHECK(dmg_engine_create(nullptr,&engine,&e)==DMG_OK);
 dmg_open_options open{sizeof(open),DMG_ABI_VERSION,DMG_MAX_SOURCE_BYTES,"fault","slot",nullptr};CHECK(dmg_snapshot_open_copy_in(engine,bytes.data(),bytes.size(),&open,&snap,&e)==DMG_OK);
 CHECK(dmg_query_compile_json(engine,reinterpret_cast<const uint8_t*>(one),strlen(one),&a,&e)==DMG_OK&&dmg_query_compile_json(engine,reinterpret_cast<const uint8_t*>(two),strlen(two),&b,&e)==DMG_OK);
 dmg_query* rules[]{a,b};dmg_multi_options_v1 options{sizeof(options),DMG_ABI_VERSION,1u<<20,1000000,0,0};dmg_engine_stats baseline{};CHECK(dmg_engine_get_stats(engine,&baseline)==DMG_OK);
 unsigned fails=0,success=0,late_materialization=0;
 for(int n=0;n<512;n++){
  dmg_multi_batch_v1* batch=nullptr;uint32_t index=UINT32_MAX;dmg_error error{};dexmeguviz::test_fail_allocation_after(n);
  auto status=dmg_multi_execute_v1(snap,rules,2,&options,&batch,&index,&error);dexmeguviz::test_fail_allocation_after(-1);
  if(status==DMG_OK){CHECK(batch);++success;dmg_multi_batch_release_v1(batch);}else{CHECK(status==DMG_OUT_OF_MEMORY&&batch==nullptr);++fails;if(index==1&&std::strcmp(error.message,"allocation failed")==0)++late_materialization;}
  dmg_engine_stats after{};CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&after.owned_bytes==baseline.owned_bytes&&after.result_bytes==baseline.result_bytes&&after.scratch_bytes==baseline.scratch_bytes);
 }
 CHECK(fails>0&&success>0&&late_materialization>0);dmg_query_release(a);dmg_query_release(b);dmg_snapshot_release(snap);dmg_engine_release(engine);
 std::cout<<"PASS "<<fails<<" injected allocation failures, "<<success<<" successes, "<<late_materialization<<" second-result OOM cases; ledger restored\n";return 0;
}catch(const std::exception& e){dexmeguviz::test_fail_allocation_after(-1);std::cerr<<e.what()<<'\n';return 1;}}
