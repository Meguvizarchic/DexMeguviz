#include "query/ir.hpp"
#include <iostream>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <string>
#include <string_view>
#ifdef _MSC_VER
#include <crtdbg.h>
#endif

using namespace dexmeguviz::query;
#define CHECK(x) do{if(!(x))throw std::runtime_error("expand compile check "+std::to_string(__LINE__)+": " #x);}while(0)
struct Counter final:std::pmr::memory_resource {
 size_t used=0,limit=std::numeric_limits<size_t>::max();
 void* do_allocate(size_t n,size_t a)override{if(n>limit-used)throw std::bad_alloc();auto p=std::pmr::new_delete_resource()->allocate(n,a);used+=n;return p;}
 void do_deallocate(void* p,size_t n,size_t a)override{used-=n;std::pmr::new_delete_resource()->deallocate(p,n,a);}
 bool do_is_equal(const std::pmr::memory_resource& r)const noexcept override{return this==&r;}
};
template<class F>void rejects(ErrorCode code,F f){bool rejected=false;try{f();}catch(const Error& e){CHECK(e.code==code);rejected=true;}CHECK(rejected);}
static std::string doc(std::string_view tail={},std::string_view top={}){
 return "{\"schema_version\":1,\"relation\":{\"op\":\"bounded_expand\",\"input\":{\"op\":\"scan\",\"relation\":\"method_defs\"},\"max_depth\":2"+std::string(tail)+"}"+std::string(top)+"}";
}
int main(){try{
#ifdef _MSC_VER
 _CrtSetReportMode(_CRT_ASSERT,_CRTDBG_MODE_FILE);_CrtSetReportFile(_CRT_ASSERT,_CRTDBG_FILE_STDERR);
 _set_abort_behavior(0,_WRITE_ABORT_MSG|_CALL_REPORTFAULT);
#endif
 Counter plans,temporary;auto* previous=std::pmr::set_default_resource(std::pmr::null_memory_resource());
 try{
  {
   auto base=compile(doc(),&plans,&temporary);
   CHECK(base.contains_expand&&!base.contains_uses&&base.id=="query:v5:3bfd47f1ef95bf8167c954a743f47cd418a26b65180d9a1864805498fcae288b");
   CHECK(base.required_capabilities==8771&&base.demand_mask==2&&base.unique_identity==Identity::tuple);
   const auto& e=base.relations[base.relation_root];CHECK(e.op==RelOp::bounded_expand&&e.relation==Relation::method_defs&&e.children.size()==1);
   CHECK(e.expand_direction==ExpandDirection::outgoing&&e.expand_output==ExpandOutput::paths&&e.expand_min_depth==1&&e.expand_max_depth==2);
   CHECK(e.expand_walk_predicate==none&&e.expand_emit_predicate==none&&e.expand_max_visited==100000&&e.expand_max_edges==100000&&e.expand_max_paths==100000);
   auto explicit_defaults=compile(doc(",\"edge\":\"invoke_method_ref\",\"direction\":\"outgoing\",\"resolution\":\"all_definitions\",\"cycle\":\"bounded_walk\",\"output\":\"paths\",\"min_depth\":1,\"max_visited\":100000,\"max_edges\":100000,\"max_paths\":100000"),&plans,&temporary);
   CHECK(base.id==explicit_defaults.id);
   auto ordered=compile(doc(",\"scope\":{\"slots\":[\"b\",\"a\"]}"),&plans,&temporary);
   auto reordered=compile(doc(",\"scope\":{\"slots\":[\"a\",\"b\"]}"),&plans,&temporary);
   CHECK(ordered.id==reordered.id&&ordered.id!=base.id&&ordered.relations[ordered.relation_root].scope_slots[0]=="a");
   for(const char* tail:{",\"direction\":\"incoming\"",",\"output\":\"endpoints\"",",\"min_depth\":0",",\"max_visited\":5",",\"max_edges\":5",",\"max_paths\":5",",\"walk_where\":{\"name\":\"A\"}",",\"emit_where\":{\"name\":\"A\"}"}){
    auto changed=compile(doc(tail),&plans,&temporary);CHECK(changed.id!=base.id);
   }
   auto walk=compile(doc(",\"walk_where\":{\"name\":\"A\"}"),&plans,&temporary);
   auto emit=compile(doc(",\"emit_where\":{\"name\":\"A\"}"),&plans,&temporary);CHECK(walk.id!=emit.id);
   auto large=compile(doc(",\"max_edges\":4294967296"),&plans,&temporary);CHECK(large.relations[large.relation_root].expand_max_edges==4294967296ULL);
   auto endpoints=compile(doc(",\"output\":\"endpoints\""),&plans,&temporary);CHECK(endpoints.unique_identity==Identity::entity);
   auto entity=compile(doc({},",\"unique_by\":\"entity\""),&plans,&temporary);CHECK(entity.unique_identity==Identity::entity&&entity.id!=base.id);
   auto zero=compile(R"({"schema_version":1,"relation":{"op":"bounded_expand","input":{"op":"scan","relation":"method_defs"},"min_depth":0,"max_depth":0}})",&plans,&temporary);
   CHECK(zero.relations[zero.relation_root].expand_min_depth==0&&zero.relations[zero.relation_root].expand_max_depth==0);
   auto body=compile(doc(",\"walk_where\":{\"using_strings\":{\"all\":[\"x\"]}},\"emit_where\":{\"field_access\":{\"any\":[{\"access\":\"read\"}]}}"),&plans,&temporary);
   CHECK(body.demand_mask==7&&body.stable_order.size()>=4);
   auto v1=compile(R"({"schema_version":1,"relation":"method_defs","where":{"return_type":"I","parameters":[],"using_strings":{"all":[{"op":"exact","value":"quality settings:"}]}},"intent":"unique","max_results":2,"evidence_profile":"minimal"})",&plans,&temporary);
   auto v2=compile(R"({"schema_version":1,"relation":"field_defs"})",&plans,&temporary);
   auto v3=compile(R"({"schema_version":1,"relation":{"op":"scan","relation":"method_defs"}})",&plans,&temporary);
   auto v4=compile(R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"}})",&plans,&temporary);
   CHECK(v1.id=="query:v1:283ae5fd16c5c58a2c7690abdb0b7cfb3a8edf7644c63cf5b43956967d8e4a63");
   CHECK(v2.id=="query:v2:6d119cc5d61d304582f915944e04db2a8b482aad25d7a694f6024907308a185a");
   CHECK(v3.id=="query:v3:d3b9d916113de0403046db0ee9b5b4247591d5ccc2904e17809eadace97eff23");
   CHECK(v4.id=="query:v4:c026266fb392c395224c2d8659d259303e4e112a62ee7d18a12dd725ae4ad90f");
  }
  CHECK(plans.used==0&&temporary.used==0);
  for(const char* tail:{",\"edge\":\"call_site\"",",\"resolution\":\"first\"",",\"cycle\":\"visited\"",",\"direction\":\"sideways\"",",\"output\":\"unknown\"",",\"future\":true"}){
   rejects(ErrorCode::unsupported,[&]{(void)compile(doc(tail),&plans,&temporary);});}
  for(const char* tail:{",\"min_depth\":3",",\"max_visited\":0",",\"max_edges\":0",",\"max_paths\":0",",\"scope\":{\"slots\":[\"x\",\"x\"]}"}){
   rejects(ErrorCode::invalid,[&]{(void)compile(doc(tail),&plans,&temporary);});}
  rejects(ErrorCode::invalid,[&]{(void)compile(R"({"schema_version":1,"relation":{"op":"bounded_expand","input":{"op":"scan","relation":"method_defs"}}})",&plans,&temporary);});
  rejects(ErrorCode::unsupported,[&]{(void)compile(R"({"schema_version":1,"relation":{"op":"bounded_expand","input":{"op":"scan","relation":"field_defs"},"max_depth":2}})",&plans,&temporary);});
  rejects(ErrorCode::unsupported,[&]{(void)compile(doc({},",\"where\":{\"name\":\"A\"}"),&plans,&temporary);});
  rejects(ErrorCode::unsupported,[&]{(void)compile(doc({},",\"semantics\":\"set\""),&plans,&temporary);});
  rejects(ErrorCode::unsupported,[&]{(void)compile(R"({"schema_version":1,"relation":{"op":"bounded_expand","input":{"op":"bounded_expand","input":{"op":"scan","relation":"method_defs"},"max_depth":1},"max_depth":2}})",&plans,&temporary);});
  rejects(ErrorCode::unsupported,[&]{(void)compile(doc(",\"walk_where\":{\"pc\":0}"),&plans,&temporary);});
  CHECK(plans.used==0&&temporary.used==0);
  temporary.limit=1;bool limited=false;try{(void)compile(R"({"schema_version":1,"relation":"method_defs"})",&plans,&temporary);}catch(const std::bad_alloc&){limited=true;}CHECK(limited&&temporary.used==0&&plans.used==0);
  limited=false;try{(void)compile(doc(),&plans,&temporary);}catch(const std::bad_alloc&){limited=true;}CHECK(limited&&temporary.used==0&&plans.used==0);
 }catch(...){std::pmr::set_default_resource(previous);throw;}
 std::pmr::set_default_resource(previous);
 std::cout<<"PASS expand compiler: v5 golden, typed fields, budgets, fail-closed wrapping, old IDs and PMR rollback\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
