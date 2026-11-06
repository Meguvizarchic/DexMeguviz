#include "query/ir.hpp"
#include "query/json.hpp"
#include <iostream>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <type_traits>

using namespace dexmeguviz::query;
#define CHECK(x) do{if(!(x))throw std::runtime_error("query allocation sweep "+std::to_string(__LINE__)+": " #x);}while(0)
struct Counting final:std::pmr::memory_resource{
 size_t used=0,allocations=0,fail_at=std::numeric_limits<size_t>::max();
 void* do_allocate(size_t n,size_t alignment)override{
  const auto position=allocations++;if(position==fail_at)throw std::bad_alloc();
  auto p=std::pmr::new_delete_resource()->allocate(n,alignment);used+=n;return p;
 }
 void do_deallocate(void* p,size_t n,size_t alignment)override{used-=n;std::pmr::new_delete_resource()->deallocate(p,n,alignment);}
 bool do_is_equal(const std::pmr::memory_resource& other)const noexcept override{return this==&other;}
};
static void sweep(const char* input,const char* expected){
 Counting control;{auto plan=compile(input,&control,&control);CHECK(plan.id==expected);}
 CHECK(control.used==0&&control.allocations>5);const auto total=control.allocations;
 for(size_t i=0;i<total;++i){Counting memory;memory.fail_at=i;bool failed=false;
  try{auto plan=compile(input,&memory,&memory);(void)plan;}catch(const std::bad_alloc&){failed=true;}
  CHECK(failed&&memory.used==0);
 }
 std::cout<<"query fail-at sweep: "<<total<<" allocation points reclaimed\n";
}
int main(){try{
 static_assert(!std::is_nothrow_move_constructible_v<json::Json> || std::is_nothrow_move_constructible_v<decltype(json::Json::object)>);
 auto* previous=std::pmr::set_default_resource(std::pmr::null_memory_resource());
 try{
  sweep(R"({"schema_version":1,"relation":"method_defs","where":{"return_type":"I","parameters":[],"using_strings":{"all":[{"op":"exact","value":"quality settings:"}]}},"intent":"unique","max_results":2,"evidence_profile":"minimal"})","query:v1:283ae5fd16c5c58a2c7690abdb0b7cfb3a8edf7644c63cf5b43956967d8e4a63");
  sweep(R"({"schema_version":1,"relation":{"op":"bounded_expand","input":{"op":"scan","relation":"method_defs"},"max_depth":2}})","query:v5:3bfd47f1ef95bf8167c954a743f47cd418a26b65180d9a1864805498fcae288b");
 }catch(...){std::pmr::set_default_resource(previous);throw;}
 std::pmr::set_default_resource(previous);std::cout<<"PASS query allocation sweeps: v1/v5 exact IDs and cleanup\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
