#include "query/ir.hpp"
#include <iostream>
#include <limits>
#include <memory_resource>
#include <stdexcept>
using namespace dexmeguviz::query;
#define CHECK(x) do{if(!(x))throw std::runtime_error("query compile check "+std::to_string(__LINE__)+": " #x);}while(0)
struct Counter:std::pmr::memory_resource{
 size_t used=0,limit=SIZE_MAX;
 void* do_allocate(size_t n,size_t a)override{if(n>limit-used)throw std::bad_alloc();auto p=std::pmr::new_delete_resource()->allocate(n,a);used+=n;return p;}
 void do_deallocate(void* p,size_t n,size_t a)override{used-=n;std::pmr::new_delete_resource()->deallocate(p,n,a);}
 bool do_is_equal(const std::pmr::memory_resource& r)const noexcept override{return this==&r;}
};
template<class F>void rejects(ErrorCode code,F f){bool rejected=false;try{f();}catch(const Error& e){CHECK(e.code==code);rejected=true;}CHECK(rejected);}
int main(){try{
 Counter plans,temporary;auto* previous=std::pmr::set_default_resource(std::pmr::null_memory_resource());
 try{
  {
   auto a=compile(R"({"schema_version":1,"relation":"method_defs","where":{"all":[{"flags":{"domain":"dex","mode":"contains","value":8}},{"name":"ABC"}]}})",&plans,&temporary);
   auto b=compile(R"({"relation":"method_defs","schema_version":1,"where":{"name":{"op":"exact","u16":[65,66,67]},"flags_contains":8}})",&plans,&temporary);
   CHECK(a.id==b.id && a.id.starts_with("query:v1:") && a.demand_mask==0);
   SimpleQuery simple;simple.name_enabled=true;simple.name=u"ABC";simple.flags=8;auto c=compile_simple(simple,&plans);CHECK(c.id==a.id);
   auto body=compile(R"({"schema_version":1,"relation":"method_defs","where":{"using_strings":{"all":[{"op":"exact","u16":[55296,0]},{"op":"contains","value":"WiFi","ascii_case_insensitive":true}]},"invokes":{"any":[{"name":"foo","parameters":["I"]}]},"field_access":{"all":[{"type":"I","access":"read"}]}},"intent":"top_n","max_results":2,"order_by":[{"field":"name","direction":"desc"}],"projection":["identity"],"scope":{"slots":["split","base"]}})",&plans,&temporary);
   CHECK(body.demand_mask==7 && body.projection==0 && body.intent==Intent::top_n);
   CHECK(body.explicit_scope && body.scope_slots[0]=="base" && body.texts[0].text.get_allocator().resource()==&plans);
   CHECK(temporary.used==0);
  }
  CHECK(plans.used==0 && temporary.used==0);
  rejects(ErrorCode::unsupported,[&]{(void)compile(R"({"schema_version":1,"relation":"method_defs","where":{"flags":{"domain":"reflection","value":8}}})",&plans,&temporary);});
  rejects(ErrorCode::unsupported,[&]{(void)compile(R"({"schema_version":1,"relation":"method_defs","required_capabilities":["not_real"]})",&plans,&temporary);});
  rejects(ErrorCode::unsupported,[&]{(void)compile(R"({"schema_version":1,"relation":"method_defs","where":{"invokes":{"all":[{"reference_kind":"call_site","name":"foo"}]}}})",&plans,&temporary);});
  rejects(ErrorCode::invalid,[&]{(void)compile(R"({"schema_version":1,"schema_version":1,"relation":"method_defs"})",&plans,&temporary);});
  rejects(ErrorCode::invalid,[&]{(void)compile(R"({"schema_version":1,"relation":"method_defs","where":{"param_count":{"min":2,"max":1}}})",&plans,&temporary);});
  rejects(ErrorCode::invalid,[&]{(void)compile(R"({"schema_version":1,"relation":"method_defs","scope":{"slots":["same","same"]}})",&plans,&temporary);});
  CHECK(plans.used==0&&temporary.used==0);
  temporary.limit=1;bool limited=false;try{(void)compile(R"({"schema_version":1,"relation":"method_defs"})",&plans,&temporary);}catch(const std::bad_alloc&){limited=true;}CHECK(limited&&temporary.used==0&&plans.used==0);
 }catch(...){std::pmr::set_default_resource(previous);throw;}
 std::pmr::set_default_resource(previous);
 std::cout<<"PASS query compiler: typed predicates, canonical aliases/u16/hash, demand masks, scope/projection/order, strict rejection and PMR rollback\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
