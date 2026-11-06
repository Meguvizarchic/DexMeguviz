#include "dexmeguviz/dexmeguviz.h"
#include "execution/budget/account.hpp"
#include "query_oom_cases.hpp"
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#define CHECK(x) do {if(!(x))throw std::runtime_error("C ABI check "+std::to_string(__LINE__)+": " #x);}while(0)
static bool same(const dmg_engine_stats& a,const dmg_engine_stats& b){return a.owned_bytes==b.owned_bytes&&a.source_bytes==b.source_bytes&&a.fact_bytes==b.fact_bytes&&a.scratch_bytes==b.scratch_bytes&&a.query_bytes==b.query_bytes&&a.result_bytes==b.result_bytes&&a.control_bytes==b.control_bytes&&a.borrowed_bytes==b.borrowed_bytes&&a.active_jobs==b.active_jobs;}
static void run_case(dmg_engine* engine,const Case& c){
 dmg_engine_stats baseline{};CHECK(dmg_engine_get_stats(engine,&baseline)==DMG_OK);bool completed=false;unsigned failures=0;
 for(int64_t i=0;i<4096;++i){dmg_query* q=reinterpret_cast<dmg_query*>(uintptr_t(1));dmg_error e{};std::cout<<"attempt "<<c.name<<" "<<i<<std::endl;
  dexmeguviz::test_fail_allocation_after(i);const auto status=dmg_query_compile_json(engine,reinterpret_cast<const uint8_t*>(c.input),std::strlen(c.input),&q,&e);dexmeguviz::test_fail_allocation_after(-1);
  if(status==DMG_OK){CHECK(q);dmg_query_info info{};CHECK(dmg_query_get_info(q,&info)==DMG_OK&&info.query_id&&!std::strcmp(info.query_id,c.id));dmg_query_release(q);completed=true;}
  else{CHECK(status==DMG_OUT_OF_MEMORY&&q==nullptr);++failures;}
  dmg_engine_stats after{};CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&same(baseline,after));if(completed)break;
 }
 CHECK(completed&&failures>5);std::cout<<c.name<<" "<<failures<<" failures reclaimed\n";
}
int main(){
 std::set_terminate([](){std::cerr<<"TERMINATE during C ABI allocation sweep\n";std::_Exit(86);});
 try{dmg_engine* engine=nullptr;dmg_error error{};CHECK(dmg_engine_create(nullptr,&engine,&error)==DMG_OK&&engine);for(const auto& c:cases)run_case(engine,c);dmg_engine_release(engine);std::cout<<"PASS C ABI v1-v4 OOM sweep\n";return 0;}
 catch(const std::exception& e){dexmeguviz::test_fail_allocation_after(-1);std::cerr<<e.what()<<'\n';return 1;}
}
