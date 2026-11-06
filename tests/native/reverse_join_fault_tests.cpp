#include "dexmeguviz/dexmeguviz.h"
#include "execution/budget/account.hpp"
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
namespace dexmeguviz::reference {extern std::atomic<void(*)()> test_reverse_join_page_barrier;}
namespace dexmeguviz::runtime {extern std::atomic<void(*)()> test_reverse_join_materialize_barrier;}
#define CHECK(x) do{if(!(x))throw std::runtime_error("line "+std::to_string(__LINE__)+": " #x);}while(false)
static void page_failure(){dexmeguviz::reference::test_reverse_join_page_barrier.store(nullptr);dexmeguviz::test_fail_allocation_after(0);}
static void materialize_failure(){dexmeguviz::runtime::test_reverse_join_materialize_barrier.store(nullptr);dexmeguviz::test_fail_allocation_after(0);}
int main(int argc,char** argv){try{
 CHECK(argc==2);std::ifstream file(std::filesystem::path(argv[1]),std::ios::binary);CHECK(file.good());std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file),{}};
 dmg_engine* engine=nullptr;dmg_snapshot* snap=nullptr;dmg_query* query=nullptr;dmg_error error{};CHECK(dmg_engine_create(nullptr,&engine,&error)==DMG_OK);
 dmg_engine_stats initial{},before{},after{};CHECK(dmg_engine_get_stats(engine,&initial)==DMG_OK);
 dmg_source_spec source{sizeof(source),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,bytes.data(),bytes.size(),"fault","raw",nullptr};dmg_source_set_options so{sizeof(so),DMG_ABI_VERSION,"reverse-join-fault",1,8,1u<<20};
 CHECK(dmg_snapshot_open_sources(engine,&source,1,&so,&snap,&error)==DMG_OK);
 const std::string text=R"({"schema_version":1,"relation":{"op":"join","on":"target_ref","left":{"op":"scan","relation":"invoke_sites"},"right":{"op":"scan","relation":"method_refs"}},"max_results":100})";
 CHECK(dmg_query_compile_json(engine,reinterpret_cast<const uint8_t*>(text.data()),text.size(),&query,&error)==DMG_OK);
 dmg_reverse_join_options_v1 options{sizeof(options),DMG_ABI_VERSION,1000000,1u<<20,1000000,100000,10000,0,0};CHECK(dmg_engine_get_stats(engine,&before)==DMG_OK);
 dmg_result* out=reinterpret_cast<dmg_result*>(uintptr_t(1));dexmeguviz::reference::test_reverse_join_page_barrier.store(page_failure);
 const auto first=dmg_query_execute_reverse_target_v1(snap,query,&options,&out,&error);dexmeguviz::test_fail_allocation_after(-1);
 CHECK(first==DMG_OUT_OF_MEMORY&&!out);dmg_reverse_profile_v1 profile{};CHECK(dmg_snapshot_reverse_profile_v1(snap,&profile,sizeof(profile))==DMG_OK&&profile.builds==0&&profile.build_failures==1&&profile.published_indexes==0);
 CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&after.owned_bytes==before.owned_bytes&&after.scratch_bytes==before.scratch_bytes&&after.result_bytes==before.result_bytes);
 out=reinterpret_cast<dmg_result*>(uintptr_t(1));dexmeguviz::runtime::test_reverse_join_materialize_barrier.store(materialize_failure);
 const auto second=dmg_query_execute_reverse_target_v1(snap,query,&options,&out,&error);dexmeguviz::test_fail_allocation_after(-1);
 CHECK(second==DMG_OUT_OF_MEMORY&&!out);CHECK(dmg_snapshot_reverse_profile_v1(snap,&profile,sizeof(profile))==DMG_OK&&profile.builds==1&&profile.published_indexes==1&&profile.published_records==2);
 CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&after.owned_bytes>=before.owned_bytes&&after.scratch_bytes==before.scratch_bytes&&after.result_bytes==before.result_bytes);
 CHECK(dmg_query_execute_reverse_target_v1(snap,query,&options,&out,&error)==DMG_OK&&out);dmg_relation_info_v2 info{};CHECK(dmg_result_get_relation_info_v2(out,&info,sizeof(info))==DMG_OK&&info.candidates_count==2);dmg_result_release(out);
 CHECK(dmg_snapshot_reverse_profile_v1(snap,&profile,sizeof(profile))==DMG_OK&&profile.reuses>0);
 dmg_query_release(query);dmg_snapshot_release(snap);CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&after.owned_bytes==initial.owned_bytes);dmg_engine_release(engine);
 std::cout<<"PASS injected page/materialization allocation failures and retained complete index\n";return 0;
}catch(const std::exception& e){dexmeguviz::test_fail_allocation_after(-1);dexmeguviz::reference::test_reverse_join_page_barrier.store(nullptr);dexmeguviz::runtime::test_reverse_join_materialize_barrier.store(nullptr);std::cerr<<e.what()<<'\n';return 1;}}
