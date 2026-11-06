#include "dexmeguviz/dexmeguviz.h"
#include "execution/budget/account.hpp"
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

#define CHECK(x) do{if(!(x))throw std::runtime_error("C ABI query fault check "+std::to_string(__LINE__)+": " #x);}while(0)

static bool same(const dmg_engine_stats& a,const dmg_engine_stats& b){
 return a.owned_bytes==b.owned_bytes&&a.source_bytes==b.source_bytes&&a.fact_bytes==b.fact_bytes&&
 a.scratch_bytes==b.scratch_bytes&&a.query_bytes==b.query_bytes&&a.result_bytes==b.result_bytes&&
 a.control_bytes==b.control_bytes&&a.borrowed_bytes==b.borrowed_bytes&&a.active_jobs==b.active_jobs;
}
static void sweep(dmg_engine* engine,const char* json){
 dmg_engine_stats baseline{};CHECK(dmg_engine_get_stats(engine,&baseline)==DMG_OK);
 bool completed=false;unsigned failures=0;
 for(int64_t n=0;n<4096;++n){
  dmg_query* query=reinterpret_cast<dmg_query*>(uintptr_t(1));dmg_error error{};
  dexmeguviz::test_fail_allocation_after(n);
  const auto status=dmg_query_compile_json(engine,reinterpret_cast<const uint8_t*>(json),std::strlen(json),&query,&error);
  dexmeguviz::test_fail_allocation_after(-1);
  if(status==DMG_OK){CHECK(query!=nullptr);dmg_query_release(query);completed=true;}
  else{CHECK(status==DMG_OUT_OF_MEMORY&&query==nullptr);++failures;}
  dmg_engine_stats after{};CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&same(baseline,after));
  if(completed)break;
 }
 CHECK(completed&&failures>=5);
 std::cout<<"C ABI fail-at sweep: "<<failures<<" injected allocation failures, all reclaimed\n";
}
int main(){try{
 dmg_engine* engine=nullptr;dmg_error error{};CHECK(dmg_engine_create(nullptr,&engine,&error)==DMG_OK&&engine);
 sweep(engine,R"({"schema_version":1,"relation":"method_defs"})");
 sweep(engine,R"({"schema_version":1,"relation":{"op":"bounded_expand","input":{"op":"scan","relation":"method_defs"},"max_depth":2,"walk_where":{"name":"a"},"emit_where":{"name":"b"}}})");
 dmg_engine_release(engine);std::cout<<"PASS C ABI v1/v5 compiler fault sweep\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
