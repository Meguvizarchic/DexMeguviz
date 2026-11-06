#include "dexmeguviz/persistent_cache_v1.h"
#include <atomic>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <thread>
#include <vector>
#include <string>

#define CHECK(x) do{if(!(x)){std::cerr<<"check failed at line "<<__LINE__<<": "<<#x<<'\n';return 1;}}while(0)
std::vector<uint8_t> read_file(const char* path){std::ifstream f(path,std::ios::binary);return {std::istreambuf_iterator<char>(f),std::istreambuf_iterator<char>()};}
int main(int argc,char** argv){
    CHECK(argc==5);auto base=read_file(argv[1]),resource=read_file(argv[2]),code=read_file(argv[3]);CHECK(!base.empty()&&!resource.empty()&&!code.empty());
    dmg_engine_options eopt{};eopt.struct_size=sizeof(eopt);eopt.abi_version=DMG_ABI_VERSION;eopt.owned_bytes_limit=256uLL<<20;eopt.max_source_bytes=64uLL<<20;eopt.max_jobs=1;
    dmg_engine* engine=nullptr;dmg_error error{};CHECK(dmg_engine_create(&eopt,&engine,&error)==DMG_OK);
    std::vector<dmg_source_spec> specs(3);const std::vector<std::vector<uint8_t>*> data{&base,&resource,&code};const char* slots[]={"base","resource","code"};const char* roles[]={"base","resource-split","code-split"};
    for(size_t i=0;i<3;++i){auto& s=specs[i];s.struct_size=sizeof(s);s.abi_version=DMG_ABI_VERSION;s.format=i==2?DMG_INPUT_RAW_DEX:DMG_INPUT_APK;s.allow_no_dex=i==1?1:0;s.data=data[i]->data();s.size=data[i]->size();s.slot_key=slots[i];s.role=roles[i];}
    dmg_source_set_options so{};so.struct_size=sizeof(so);so.abi_version=DMG_ABI_VERSION;so.source_namespace="cache-concurrency";so.scope_complete=1;so.max_sources=16;so.max_total_dex_bytes=64uLL<<20;
    dmg_snapshot* snapshot=nullptr;CHECK(dmg_snapshot_open_sources(engine,specs.data(),static_cast<uint32_t>(specs.size()),&so,&snapshot,&error)==DMG_OK);
    dmg_snapshot_overview overview{};CHECK(dmg_snapshot_get_overview(snapshot,&overview)==DMG_OK&&overview.input_count==3&&overview.source_count==4);
    const std::string q=R"({"schema_version":1,"relation":"method_defs","required_capabilities":["type_uses"],"where":{"using_types":{"any":[{"descriptor":{"op":"contains","value":"L"}}]}},"intent":"enumerate","max_results":100,"scope":{"slots":["code"]}})";
    dmg_query* query=nullptr;CHECK(dmg_query_compile_json(engine,reinterpret_cast<const uint8_t*>(q.data()),q.size(),&query,&error)==DMG_OK);
    dmg_result* baseline=nullptr;CHECK(dmg_query_execute(snapshot,query,&baseline,&error)==DMG_OK);dmg_result_info expected{};CHECK(dmg_result_get_info(baseline,&expected)==DMG_OK&&expected.candidates_count>0);
    for(uint32_t i=0;i<expected.candidates_count;++i){dmg_source_info source{};CHECK(dmg_result_get_origin(baseline,i,&source)==DMG_OK&&source.input_index==2&&source.source_index==3);}
    dmg_persistent_cache_options_v1 co{};co.struct_size=sizeof(co);co.abi_version=DMG_ABI_VERSION;co.directory_utf8=reinterpret_cast<const uint8_t*>(argv[4]);co.directory_length=std::string(argv[4]).size();dmg_persistent_cache_v1* cache=nullptr;CHECK(dmg_persistent_cache_open_v1(engine,&co,&cache,&error)==DMG_OK);
    std::atomic<int> failures{0};std::vector<std::thread> threads;
    for(int t=0;t<4;++t){dmg_persistent_cache_retain_v1(cache);dmg_snapshot_retain(snapshot);dmg_query_retain(query);threads.emplace_back([&]{for(int n=0;n<3;++n){dmg_result* result=nullptr;dmg_error e{};if(dmg_persistent_cache_execute_v1(cache,snapshot,query,&result,&e)!=DMG_OK||!result){++failures;break;}dmg_result_info info{};if(dmg_result_get_info(result,&info)!=DMG_OK||info.candidates_count!=expected.candidates_count||info.coverage!=expected.coverage)++failures;for(uint32_t i=0;i<info.candidates_count;++i){dmg_source_info src{};if(dmg_result_get_origin(result,i,&src)!=DMG_OK||src.input_index!=2||src.source_index!=3)++failures;}dmg_result_release(result);}dmg_query_release(query);dmg_snapshot_release(snapshot);dmg_persistent_cache_release_v1(cache);});}
    for(auto& t:threads)t.join();threads.clear();CHECK(failures.load()==0);dmg_persistent_cache_stats_v1 stats{};CHECK(dmg_persistent_cache_get_stats_v1(cache,&stats,sizeof(stats))==DMG_OK&&stats.hits>0);
    std::atomic<int> ready{0},done{0};std::atomic<bool> go{false};
    for(int t=0;t<4;++t){dmg_persistent_cache_retain_v1(cache);dmg_snapshot_retain(snapshot);dmg_query_retain(query);threads.emplace_back([&]{++ready;while(!go.load(std::memory_order_acquire))std::this_thread::yield();dmg_result* result=nullptr;dmg_error e{};const auto status=dmg_persistent_cache_execute_v1(cache,snapshot,query,&result,&e);if(status!=DMG_OK&&status!=DMG_CLOSED)++failures;if(status==DMG_OK&&!result)++failures;if(status==DMG_CLOSED&&result)++failures;if(result)dmg_result_release(result);++done;dmg_query_release(query);dmg_snapshot_release(snapshot);dmg_persistent_cache_release_v1(cache);});}
    while(ready.load()!=4)std::this_thread::yield();go.store(true,std::memory_order_release);CHECK(dmg_persistent_cache_close_v1(cache)==DMG_OK);for(auto& t:threads)t.join();CHECK(done.load()==4&&failures.load()==0);
    dmg_result* after=reinterpret_cast<dmg_result*>(uintptr_t(1));CHECK(dmg_persistent_cache_execute_v1(cache,snapshot,query,&after,&error)==DMG_CLOSED&&after==nullptr);
    dmg_snapshot_close(snapshot);dmg_snapshot_release(snapshot);dmg_query_release(query);dmg_persistent_cache_release_v1(cache);CHECK(dmg_result_get_info(baseline,&expected)==DMG_OK);dmg_result_release(baseline);dmg_engine_release(engine);
    std::cout<<"PASS persistent C ABI explicit input scope, shared-handle concurrency and close admission"<<std::endl;return 0;
}
