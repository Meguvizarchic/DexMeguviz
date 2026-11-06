#include "planner/multi_rule.hpp"
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>
using namespace dexmeguviz;
#define CHECK(x) do{if(!(x))throw std::runtime_error("multi-rule line "+std::to_string(__LINE__)+": " #x);}while(0)
struct Memory:std::pmr::memory_resource{
 size_t used=0,peak=0,calls=0;size_t fail_at=SIZE_MAX;
 std::vector<std::pair<size_t,size_t>> requests,releases;
 void* do_allocate(size_t n,size_t a)override{requests.emplace_back(n,a);if(calls++==fail_at)throw std::bad_alloc();auto p=std::pmr::new_delete_resource()->allocate(n,a);used+=n;peak=std::max(peak,used);return p;}
 void do_deallocate(void* p,size_t n,size_t a)override{releases.emplace_back(n,a);CHECK(used>=n);used-=n;std::pmr::new_delete_resource()->deallocate(p,n,a);}
 bool do_is_equal(const std::pmr::memory_resource& o)const noexcept override{return this==&o;}
};
static std::vector<uint8_t> read(const std::filesystem::path& p){std::ifstream f(p,std::ios::binary);CHECK(f.good());return {std::istreambuf_iterator<char>(f),{}};}
static bool witness_equal(const reference::Witness& a,const reference::Witness& b){
 return a.kind==b.kind&&a.node==b.node&&a.matched==b.matched&&a.dex_pc==b.dex_pc&&a.opcode==b.opcode&&a.reference_index==b.reference_index&&a.reference_kind==b.reference_kind&&a.extra_proto==b.extra_proto&&a.code_units==b.code_units&&a.relation_node==b.relation_node&&a.source_index==b.source_index&&a.entity_ordinal==b.entity_ordinal&&a.entity_relation==b.entity_relation&&a.entity_pc==b.entity_pc&&a.numeric_bits==b.numeric_bits&&a.numeric_width==b.numeric_width&&a.numeric_kind==b.numeric_kind&&a.inherited_item==b.inherited_item&&a.inherited_path==b.inherited_path&&a.inherited_aux==b.inherited_aux&&a.inherited_branch==b.inherited_branch&&a.inherited_detail==b.inherited_detail;
}
static void same(const planner::Outcome& a,const planner::Outcome& b){
 CHECK(a.rule_id==b.rule_id&&a.code==b.code&&a.error_offset==b.error_offset&&a.error_pc==b.error_pc);
 CHECK(a.progress.visited==b.progress.visited&&a.progress.total==b.progress.total&&a.progress.scope_complete==b.progress.scope_complete&&a.progress.order_verified==b.progress.order_verified);
 CHECK(a.progress.scope_source_count==b.progress.scope_source_count&&a.progress.scope_derived_unknown==b.progress.scope_derived_unknown);
 CHECK(a.progress.profile.work_units==b.progress.profile.work_units&&a.progress.profile.fact_requests==b.progress.profile.fact_requests&&a.progress.profile.methods_decoded==b.progress.profile.methods_decoded&&a.progress.profile.code_units==b.progress.profile.code_units&&a.progress.profile.unknown_rows==b.progress.profile.unknown_rows&&a.progress.profile.string_pool_lookups==b.progress.profile.string_pool_lookups&&a.progress.profile.invoke_sites==b.progress.profile.invoke_sites&&a.progress.profile.field_uses==b.progress.profile.field_uses&&a.progress.profile.declared_fields==b.progress.profile.declared_fields&&a.progress.profile.matches_seen==b.progress.profile.matches_seen&&a.progress.profile.sort_comparisons==b.progress.profile.sort_comparisons);
 CHECK(bool(a.progress.graph)==bool(b.progress.graph));if(a.progress.graph){const auto& x=*a.progress.graph;const auto& y=*b.progress.graph;
  CHECK(x.identity_count==y.identity_count&&x.root_node==y.root_node&&x.entity_total==y.entity_total&&x.entity_visited==y.entity_visited&&x.method_total==y.method_total&&x.method_visited==y.method_visited&&x.events_collected==y.events_collected&&x.nodes.size()==y.nodes.size());
  for(size_t i=0;i<x.nodes.size();++i){const auto& u=x.nodes[i];const auto& v=y.nodes[i];CHECK(u.node==v.node&&u.op==v.op&&u.input_rows==v.input_rows&&u.output_rows==v.output_rows&&u.unknown_rows==v.unknown_rows&&u.visited_rows==v.visited_rows&&u.total_rows==v.total_rows&&u.scan_domain==v.scan_domain&&u.attempted_methods==v.attempted_methods&&u.no_body_methods==v.no_body_methods&&u.decoded_methods==v.decoded_methods&&u.emitted_events==v.emitted_events&&u.code_units==v.code_units&&u.complete==v.complete);}}
 CHECK(bool(a.result)==bool(b.result));if(!a.result)return;
 const auto& x=*a.result;const auto& y=*b.result;CHECK(x.result_limit==y.result_limit&&x.scope_sources==y.scope_sources&&x.rows.size()==y.rows.size());
 CHECK(x.uses.size()==y.uses.size());for(const auto& [key,u]:x.uses){auto it=y.uses.find(key);CHECK(it!=y.uses.end());const auto& v=it->second;CHECK(u.key==v.key&&u.caller_method_ref==v.caller_method_ref&&u.code_offset==v.code_offset&&u.target_index==v.target_index&&u.extra_proto==v.extra_proto&&u.opcode==v.opcode&&u.target_domain==v.target_domain);}
 for(size_t i=0;i<x.rows.size();++i){const auto& u=x.rows[i];const auto& v=y.rows[i];CHECK(u.key()==v.key()&&u.uncertain==v.uncertain&&u.bindings==v.bindings&&u.witnesses.size()==v.witnesses.size()&&u.links.size()==v.links.size()&&u.proof_bindings.size()==v.proof_bindings.size());
  for(size_t j=0;j<u.links.size();++j){const auto& l=u.links[j];const auto& r=v.links[j];CHECK(l.node==r.node&&l.key==r.key&&l.left==r.left&&l.right==r.right);}
  for(size_t j=0;j<u.proof_bindings.size();++j)CHECK(u.proof_bindings[j].node==v.proof_bindings[j].node&&u.proof_bindings[j].binding==v.proof_bindings[j].binding);
  for(size_t j=0;j<u.witnesses.size();++j)CHECK(witness_equal(u.witnesses[j],v.witnesses[j]));}
}
int main(int argc,char** argv){try{
 CHECK(argc==2);auto bytes=read(std::filesystem::path(argv[1])/"generated/method_facts/method-uses.dex");
 auto metadata=read_metadata(bytes);std::array<reference::SourceView,2> sources{{{0,0,&metadata,bytes},{1,1,&metadata,bytes}}};
 const std::array<std::string_view,2> slots{"left","right"};const reference::DatasetView data{sources,slots,true};
 Memory plan_mem,temp;auto compile=[&](const std::string& s){return query::compile(s,&plan_mem,&temp);};
 auto exact=compile(R"({"schema_version":1,"relation":"method_defs","where":{"name":"uses","using_strings":{"all":["used-string"]}}})");
 auto contains=compile(R"({"schema_version":1,"relation":"method_defs","where":{"name":"uses","using_strings":{"all":[{"op":"contains","value":"string"}]}}})");
 auto left=compile(R"({"schema_version":1,"relation":"method_defs","scope":{"slots":["left"]},"where":{"name":"uses","using_strings":{"all":["used-string"]}}})");
 auto other_profile=compile(R"({"schema_version":1,"relation":"method_defs","required_capabilities":["numeric_literals"],"where":{"name":"uses","using_strings":{"all":["used-string"]}}})");
 auto other_demand=compile(R"({"schema_version":1,"relation":"method_defs","where":{"name":"uses","using_strings":{"all":["used-string"]},"invokes":{"all":[{"name":"sink"}]}}})");
 auto metadata_only=compile(R"({"schema_version":1,"relation":"method_defs","where":{"name":"uses"}})");
 auto missing=compile(R"({"schema_version":1,"relation":"method_defs","scope":{"slots":["missing"]},"where":{"name":"uses"}})");
 auto graph=compile(R"({"schema_version":1,"relation":{"op":"scan","relation":"method_defs","where":{"name":"uses"}}})");
 auto graph_exact=compile(R"({"schema_version":1,"relation":{"op":"scan","relation":"method_defs","where":{"name":"uses","using_strings":{"all":["used-string"]}}}})");
 auto graph_contains=compile(R"({"schema_version":1,"relation":{"op":"scan","relation":"method_defs","where":{"name":"uses","using_strings":{"all":[{"op":"contains","value":"string"}]}}}})");
 auto graph_left=compile(R"({"schema_version":1,"relation":{"op":"scan","relation":"method_defs","scope":{"slots":["left"]},"where":{"name":"uses","using_strings":{"all":["used-string"]}}}})");
 auto graph_filter_different=compile(R"({"schema_version":1,"relation":{"op":"filter","input":{"op":"scan","relation":"method_defs","scope":{"slots":["left"]},"where":{"name":"uses"}},"where":{"using_strings":{"all":[{"op":"contains","value":"string"}]}}}})");
 auto graph_filter=compile(R"({"schema_version":1,"required_capabilities":["booleans"],"relation":{"op":"filter","input":{"op":"scan","relation":"method_defs","scope":{"slots":["left"]},"where":{"name":"uses"}},"where":{"using_strings":{"all":[{"op":"contains","value":"string"}]}}}})");
 auto join=compile(R"({"schema_version":1,"relation":{"op":"join","on":"same_entity","left":{"op":"label","label":"L","input":{"op":"scan","relation":"method_defs","where":{"name":"uses"}}},"right":{"op":"label","label":"R","input":{"op":"scan","relation":"method_defs","where":{"name":"uses"}}}}})");
 auto group=compile(R"({"schema_version":1,"relation":{"op":"group_by_owner","inputs":[{"op":"label","label":"member","input":{"op":"scan","relation":"method_defs","where":{"name":"uses"}}}],"min":1,"max":1,"required_roles":["member"]}})");
 auto group_shared=compile(R"({"schema_version":1,"relation":{"op":"group_by_owner","inputs":[{"op":"label","label":"A","input":{"op":"scan","relation":"method_defs","where":{"name":"uses","using_strings":{"all":["used-string"]}}}},{"op":"label","label":"B","input":{"op":"scan","relation":"method_defs","where":{"name":"uses","using_strings":{"all":[{"op":"contains","value":"string"}]}}}}],"min":1,"max":1,"required_roles":["A","B"],"role_policy":"shared"}})");
 auto group_distinct=compile(R"({"schema_version":1,"relation":{"op":"group_by_owner","inputs":[{"op":"label","label":"A","input":{"op":"scan","relation":"method_defs","where":{"name":"uses","using_strings":{"all":["used-string"]}}}},{"op":"label","label":"B","input":{"op":"scan","relation":"method_defs","where":{"name":"uses","using_strings":{"all":["used-string"]}}}}],"min":1,"max":2,"required_roles":["A","B"],"role_policy":"distinct"}})");
 auto group_mixed=compile(R"({"schema_version":1,"relation":{"op":"group_by_owner","inputs":[{"op":"scan","relation":"method_defs","scope":{"slots":["left"]},"where":{"name":"uses","using_strings":{"all":["used-string"]}}},{"op":"scan","relation":"method_defs","scope":{"slots":["right"]},"where":{"name":"uses","using_strings":{"all":["used-string"]}}}]}})");
 auto group_fields=compile(R"({"schema_version":1,"relation":{"op":"group_by_owner","inputs":[{"op":"scan","relation":"method_defs","where":{"name":"uses","using_strings":{"all":["used-string"]}}},{"op":"scan","relation":"field_defs"}]}})");
 auto union_bag=compile(R"({"schema_version":1,"relation":{"op":"union","semantics":"bag","inputs":[{"op":"label","label":"A","input":{"op":"scan","relation":"method_defs","where":{"name":"uses","using_strings":{"all":["used-string"]}}}},{"op":"label","label":"B","input":{"op":"scan","relation":"method_defs","where":{"name":"uses","using_strings":{"all":[{"op":"contains","value":"string"}]}}}}]}})");
 auto union_set=compile(R"({"schema_version":1,"relation":{"op":"distinct","identity":"entity","input":{"op":"union","semantics":"bag","inputs":[{"op":"scan","relation":"method_defs","where":{"name":"uses","using_strings":{"all":["used-string"]}}},{"op":"filter","input":{"op":"scan","relation":"method_defs","where":{"name":"uses"}},"where":{"using_strings":{"all":[{"op":"contains","value":"string"}]}}}]}}})");
 auto union_mixed=compile(R"({"schema_version":1,"relation":{"op":"union","semantics":"bag","inputs":[{"op":"scan","relation":"method_defs","scope":{"slots":["left"]},"where":{"name":"uses","using_strings":{"all":["used-string"]}}},{"op":"scan","relation":"method_defs","scope":{"slots":["right"]},"where":{"name":"uses","using_strings":{"all":["used-string"]}}}]}})");
 auto union_same_scope=compile(R"({"schema_version":1,"relation":{"op":"union","semantics":"bag","inputs":[{"op":"scan","relation":"method_defs","scope":{"slots":["left"]},"where":{"name":"uses","using_strings":{"all":["used-string"]}}},{"op":"scan","relation":"method_defs","scope":{"slots":["left"]},"where":{"name":"uses","using_strings":{"all":["used-string"]}}}]}})");
 auto filter_union=compile(R"({"schema_version":1,"relation":{"op":"filter","input":{"op":"union","semantics":"bag","inputs":[{"op":"scan","relation":"method_defs","where":{"name":"uses"}},{"op":"scan","relation":"method_defs","where":{"name":"uses"}}]},"where":{"using_strings":{"all":["used-string"]}}}})");
 std::vector<std::byte> cache_bytes(1u<<20);unsigned cases=0;
 // Internal guard remains conservative for malformed graph structures and
 // dissimilar leaf scopes. No published QueryIR may contain these mutations.
 {
  std::pmr::monotonic_buffer_resource arena(cache_bytes.data(),cache_bytes.size(),std::pmr::null_memory_resource());
  reference::FactsCache guard(sources,&arena,1000000);
  CHECK(guard.graph_scan_scope(union_bag)!=nullptr);
  CHECK(guard.graph_scan_scope(union_set)!=nullptr);
  CHECK(guard.graph_scan_scope(union_mixed)==nullptr);
  CHECK(guard.graph_scan_scope(join)==nullptr);
  CHECK(guard.graph_scan_scope(group_shared)!=nullptr);
  CHECK(guard.graph_scan_scope(group_distinct)!=nullptr);
  CHECK(guard.graph_scan_scope(group_mixed)==nullptr);
  CHECK(guard.graph_scan_scope(group_fields)==nullptr);
  auto& children=union_bag.relations[union_bag.relation_root].children;CHECK(children.size()==2);
  const auto saved=children[1];children[1]=children[0];CHECK(guard.graph_scan_scope(union_bag)==nullptr);
  children[1]=union_bag.relation_root;CHECK(guard.graph_scan_scope(union_bag)==nullptr);
  children[1]=static_cast<uint32_t>(union_bag.relations.size());CHECK(guard.graph_scan_scope(union_bag)==nullptr);
  children[1]=saved;CHECK(guard.graph_scan_scope(union_bag)!=nullptr);
 }
 // Empty plans perform no rule execution, cache construction or allocation;
 // normal coordinator and cache/input overlap validation still applies.
 {Memory coord;const auto before=cache_bytes;
  auto empty=planner::execute(data,{},&coord,cache_bytes,1000000);
  CHECK(empty.rules.empty()&&empty.shared.physical_collects==0&&empty.shared.cache_builds==0&&empty.shared.cache_hits==0&&empty.shared.cache_work_charged==0);
  CHECK(coord.calls==0&&coord.used==0&&cache_bytes==before);
  bool null_rejected=false;try{(void)planner::execute(data,{},nullptr,cache_bytes,1000000);}catch(const std::invalid_argument&){null_rejected=true;}
  CHECK(null_rejected);
  bool overlap_rejected=false;auto overlap=std::span<std::byte>(reinterpret_cast<std::byte*>(bytes.data()+1),16);
  try{(void)planner::execute(data,{},&coord,overlap,1000000);}catch(const std::invalid_argument&){overlap_rejected=true;}
  CHECK(overlap_rejected&&coord.calls==0);++cases;
 }
 auto compare=[&](const query::Plan& p,const query::Plan& q,reference::DatasetView dataset,reference::Cancel second_cancel={},size_t fail_at=SIZE_MAX){
  Memory s0,s1,o0,a0,a1,o1; s1.fail_at=a1.fail_at=fail_at;
  std::array<planner::Rule,2> scalar{{{"first",&p,&s0,{}},{"second",&q,&s1,second_cancel}}};
  std::array<planner::Rule,2> optimized{{{"first",&p,&a0,{},true},{"second",&q,&a1,second_cancel,true}}};
  {auto ref=planner::execute(dataset,scalar,&o0,{},0);auto actual=planner::execute(dataset,optimized,&o1,cache_bytes,1000000);
   CHECK(ref.rules.size()==2&&actual.rules.size()==2);same(ref.rules[0],actual.rules[0]);same(ref.rules[1],actual.rules[1]);
   CHECK(s1.calls==a1.calls);if(fail_at==SIZE_MAX && &p==&exact && &q==&contains && dataset.sources.size()==2 && !second_cancel.requested){CHECK(actual.shared.physical_collects==2&&actual.shared.cache_builds==2&&actual.shared.cache_hits==2);}
   if(fail_at==SIZE_MAX && &p==&exact && &q==&left)CHECK(actual.shared.cache_hits==0);
   if(fail_at==SIZE_MAX && &p==&exact && (&q==&other_profile||&q==&other_demand))CHECK(actual.shared.cache_hits==0);
   if(fail_at==SIZE_MAX&&!second_cancel.requested&&((&p==&graph_exact&&&q==&graph_contains)||(&p==&graph_left&&&q==&graph_filter))){std::cerr<<"graph pair "<<(&p==&graph_exact?"exact":"left")<<" hits "<<actual.shared.cache_hits<<" builds "<<actual.shared.cache_builds<<" collects "<<actual.shared.physical_collects<<" work "<<actual.shared.cache_work_charged<<"\n";CHECK(actual.shared.cache_hits>0);}
   if(fail_at==SIZE_MAX&&((&p==&graph_exact&&&q==&graph_left)||(&p==&graph_left&&&q==&graph_filter_different)))CHECK(actual.shared.cache_hits==0);
   if(fail_at==SIZE_MAX && &p==&metadata_only && &q==&metadata_only)CHECK(actual.shared.cache_hits==0&&actual.shared.physical_collects==0);
   if(fail_at==SIZE_MAX && &p==&missing)CHECK(actual.rules[0].code==planner::OutcomeCode::source_mismatch&&actual.rules[1].code==planner::OutcomeCode::result_available);
  }
  CHECK(s0.used==0&&s1.used==0&&o0.used==0&&a0.used==0&&a1.used==0&&o1.used==0);
  CHECK(s1.requests==a1.requests&&s1.peak==a1.peak);
  if(fail_at==SIZE_MAX)CHECK(s1.releases==a1.releases);
  ++cases;
 };
 compare(exact,contains,data);compare(exact,left,data);compare(exact,other_profile,data);compare(exact,other_demand,data);compare(metadata_only,metadata_only,data);compare(missing,contains,data);compare(graph,contains,data);compare(join,group,data);
 compare(graph_exact,graph_contains,data);compare(graph_exact,graph_left,data);compare(graph_left,graph_filter,data);compare(graph_left,graph_filter_different,data);
 compare(union_bag,union_bag,data);compare(union_set,union_set,data);compare(union_mixed,union_mixed,data);compare(union_same_scope,union_same_scope,data);compare(filter_union,filter_union,data);
 for(const auto* p:{&union_bag,&union_set,&union_mixed,&union_same_scope,&filter_union}){
  Memory a,b,coord;std::array<planner::Rule,2> rules{{{"first",p,&a,{},true},{"second",p,&b,{},true}}};
  {auto result=planner::execute(data,rules,&coord,cache_bytes,1000000);CHECK(result.rules.size()==2);
   CHECK(result.rules[0].code==planner::OutcomeCode::result_available&&result.rules[1].code==planner::OutcomeCode::result_available);
   if(p==&union_mixed)CHECK(result.shared.cache_hits==0&&result.shared.cache_builds==0);
   else CHECK(result.shared.cache_hits>0&&result.shared.cache_builds>0&&result.shared.physical_collects<result.rules[0].progress.profile.fact_requests+result.rules[1].progress.profile.fact_requests);
   CHECK(result.rules[0].result->rows.size()==((p==&union_bag||p==&filter_union)?4:2));
  }CHECK(a.used==0&&b.used==0&&coord.used==0);++cases;
 }
 // Owner grouping consumes identical checked facts but never caches role or
 // group decisions. Same member satisfies shared roles, not distinct roles.
 compare(group_shared,group_shared,data);compare(group_shared,group_distinct,data);compare(group_mixed,group_mixed,data);
 {
  Memory a,b,coord;std::array<planner::Rule,2> rules{{{"shared",&group_shared,&a,{},true},{"distinct",&group_distinct,&b,{},true}}};
  {auto result=planner::execute(data,rules,&coord,cache_bytes,1000000);
   CHECK(result.rules.size()==2&&result.rules[0].code==planner::OutcomeCode::result_available&&result.rules[1].code==planner::OutcomeCode::result_available);
   CHECK(result.shared.cache_hits>0&&result.shared.cache_builds>0);
   CHECK(result.rules[0].result->rows.size()==2&&result.rules[1].result->rows.empty());
  }CHECK(a.used==0&&b.used==0&&coord.used==0);
 }
 reference::DatasetView incomplete_graph{sources,slots,false};compare(graph_exact,graph_contains,incomplete_graph);
 compare(group_shared,group_shared,incomplete_graph);compare(group_shared,group_distinct,incomplete_graph);
 {
  Memory a,b,coord;std::array<planner::Rule,2> rules{{{"first",&group_shared,&a,{},true},{"second",&group_shared,&b,{},true}}};
  {auto result=planner::execute(incomplete_graph,rules,&coord,cache_bytes,1000000);
   CHECK(result.rules[0].code==planner::OutcomeCode::result_available&&result.shared.cache_hits>0);
   CHECK(result.rules[0].result->rows.empty()&&result.rules[0].progress.profile.unknown_rows==2);}
  CHECK(a.used==0&&b.used==0&&coord.used==0);
 }
 {
  Memory a,b,coord;std::array<planner::Rule,2> rules{{{"first",&group_mixed,&a,{},true},{"second",&group_mixed,&b,{},true}}};
  {auto result=planner::execute(data,rules,&coord,cache_bytes,1000000);CHECK(result.rules[0].code==planner::OutcomeCode::result_available);
   CHECK(result.shared.cache_hits==0&&result.shared.cache_builds==0);}
  CHECK(a.used==0&&b.used==0&&coord.used==0);
 }
 {const auto original=group_shared.max_work;for(uint64_t limit:{1u,20u,100u,500u}){group_shared.max_work=limit;compare(group_shared,group_distinct,data);}group_shared.max_work=original;}

 compare(union_bag,union_set,incomplete_graph);compare(union_same_scope,union_same_scope,incomplete_graph);
 reference::Cancel graph_cancel{[](void*)noexcept{return true;},nullptr};compare(graph_exact,graph_contains,data,graph_cancel);
 compare(group_shared,group_distinct,data,graph_cancel);
 compare(union_bag,union_set,data,graph_cancel);
 for(size_t n=0;n<100;++n)compare(union_bag,union_set,data,{},n);
 // Logical work limits are exercised across both leaf and union reduction.
 {const auto original=union_set.max_work;for(uint64_t limit:{1u,5u,20u,50u,100u,200u,500u,1000u}){
   union_set.max_work=limit;compare(union_bag,union_set,data);
  }union_set.max_work=original;}
 // Independent cancellation counters reproduce the same checkpoint in the
 // second rule for scalar and replay paths, including checks inside decode.
 for(unsigned threshold:{1u,3u,8u,16u,32u}){
  struct CancelState {unsigned calls=0,threshold=0;};CancelState a{0,threshold},b{0,threshold};
  const auto stop=[](void* p)noexcept{auto& s=*static_cast<CancelState*>(p);return ++s.calls>=s.threshold;};
  Memory s0,s1,o0,a0,a1,o1;std::array<planner::Rule,2> scalar{{{"first",&union_bag,&s0,{}},{"second",&union_set,&s1,{stop,&a}}}};
  std::array<planner::Rule,2> optimized{{{"first",&union_bag,&a0,{},true},{"second",&union_set,&a1,{stop,&b},true}}};
  {auto ref=planner::execute(data,scalar,&o0,{},0);auto actual=planner::execute(data,optimized,&o1,cache_bytes,1000000);
   same(ref.rules[0],actual.rules[0]);same(ref.rules[1],actual.rules[1]);CHECK(a.calls==b.calls);}
  CHECK(s0.used==0&&s1.used==0&&o0.used==0&&a0.used==0&&a1.used==0&&o1.used==0);++cases;
 }
 // Exhausting the separate cache arena must fall back to checked scalar facts.
 for(size_t bytes_available:{size_t(0),size_t(1),size_t(64),size_t(512),size_t(4096)}){
  Memory s0,s1,o0,a0,a1,o1;std::array<planner::Rule,2> scalar{{{"first",&union_bag,&s0,{}},{"second",&union_set,&s1,{}}}};
  std::array<planner::Rule,2> optimized{{{"first",&union_bag,&a0,{},true},{"second",&union_set,&a1,{},true}}};
  {auto ref=planner::execute(data,scalar,&o0,{},0);auto actual=planner::execute(data,optimized,&o1,std::span(cache_bytes).first(bytes_available),1000000);
   same(ref.rules[0],actual.rules[0]);same(ref.rules[1],actual.rules[1]);}
  CHECK(s0.used==0&&s1.used==0&&o0.used==0&&a0.used==0&&a1.used==0&&o1.used==0);++cases;
 }
 for(size_t n=0;n<50;++n)compare(graph_exact,graph_contains,data,{},n);
 // Newer v18 relation plans must stay on the scalar path while the cache is
 // deliberately restricted to its explicitly recognized direct profiles.
 {
  auto method_bytes=read(std::filesystem::path(argv[1])/"generated/inherited-use/local-target.dex");
  auto parent_bytes=read(std::filesystem::path(argv[1])/"generated/inherited/root.dex");
  auto method_facts=read_metadata(method_bytes);auto parent_facts=read_metadata(parent_bytes);
  std::array<reference::SourceView,2> v18_sources{{{0,0,&method_facts,method_bytes},{1,1,&parent_facts,parent_bytes}}};
  reference::DatasetView v18_data{v18_sources,slots,true};
  auto v18=compile(R"({"schema_version":1,"required_capabilities":["inherited_fields","use_target_symbol","inherited_target_symbol"],"relation":{"op":"join","on":"target_symbol","left":{"op":"scan","relation":"invoke_sites"},"right":{"op":"scan","relation":"method_defs","where":{"all":[{"name":"uses"},{"declares_fields":{"scope":"inherited","where":{"name":"unseen"},"min":0,"max":0}}]}}},"max_results":100})");
  Memory a,b,coord;std::array<planner::Rule,2> rules{{{"v18-a",&v18,&a,{},true},{"v18-b",&v18,&b,{},true}}};
  {auto result=planner::execute(v18_data,rules,&coord,cache_bytes,1000000);
   CHECK(result.rules.size()==2&&result.rules[0].code==planner::OutcomeCode::result_available&&result.rules[1].code==planner::OutcomeCode::result_available);
   CHECK(result.shared.cache_hits==0&&result.shared.cache_builds==0&&result.rules[0].result->rows.size()>0);
   // Independently compare with no cache; inherited evidence, use identities,
   // bindings, paths, profile and coverage are checked by same().
   Memory c,d,scalar_coord;auto baseline=planner::execute(v18_data,std::array<planner::Rule,2>{{{"v18-a",&v18,&c,{}},{"v18-b",&v18,&d,{}}}},&scalar_coord,{},0);
   same(result.rules[0],baseline.rules[0]);same(result.rules[1],baseline.rules[1]);
  }
  CHECK(a.used==0&&b.used==0&&coord.used==0);
  compare(v18,v18,v18_data);
  v18_data.scope_complete=false;compare(v18,v18,v18_data);
  reference::Cancel stopped{[](void*)noexcept{return true;},nullptr};compare(v18,v18,v18_data,stopped);
  ++cases;
 }
 // The public QueryIR cannot yet request array_data. Inject this demand only
 // into an internal test plan and use a checked DEX with two actual elements.
 // Both rules must execute the scalar collector, never cache incomplete facts.
 {
  auto array_bytes=read(std::filesystem::path(argv[1])/"generated/array-data-facts/array-data.dex");
  auto array_metadata=read_metadata(array_bytes);CHECK(array_metadata.methods.size()==1);
  auto actual_elements=facts::collect_method(array_bytes,array_metadata,0,instructions::Demand::array_data);
  CHECK(actual_elements.array_elements.size()==2&&actual_elements.array_elements[0].bits==0x12345678&&actual_elements.array_elements[1].bits==0x80000001);
  std::array<reference::SourceView,1> array_sources{{{0,0,&array_metadata,array_bytes}}};
  const reference::DatasetView array_data{array_sources,std::span(slots).first(1),true};
  auto array_plan=compile(R"({"schema_version":1,"relation":"method_defs","where":{"using_strings":{"all":[{"op":"contains","value":"run"}]}}})");
  array_plan.demand_mask|=instructions::Demand::array_data;
  CHECK((array_plan.demand_mask&instructions::Demand::array_data)!=0);
  std::pmr::monotonic_buffer_resource guard_arena(cache_bytes.data(),cache_bytes.size(),std::pmr::null_memory_resource());
  reference::FactsCache guard(array_sources,&guard_arena,1000000);
  CHECK(!guard.can_record(array_sources[0],array_plan));
  for(uint32_t bit:{uint32_t(instructions::Demand::array_data),uint32_t(instructions::Demand::switch_targets),uint32_t(instructions::Demand::branch_targets),uint32_t(instructions::Demand::method_constants),uint32_t(1u<<31)}){
   auto probe=compile(R"({"schema_version":1,"relation":{"op":"scan","relation":"method_defs","where":{"using_strings":{"all":["run"]}}}})");
   probe.demand_mask|=bit;const auto* graph_scope=reference::FactsCache::single_scan_scope(probe);CHECK(graph_scope&&!guard.can_record(array_sources[0],probe,graph_scope));
  }
  // New and unknown future demand bits may contain fields not copied by the cache.
  for(uint32_t bit:{uint32_t(instructions::Demand::switch_targets),uint32_t(instructions::Demand::branch_targets),uint32_t(instructions::Demand::method_constants),uint32_t(1u<<31)}){
   auto probe=compile(R"({"schema_version":1,"relation":"method_defs","where":{"using_strings":{"all":["run"]}}})");
   probe.demand_mask|=bit;
   CHECK(!guard.can_record(array_sources[0],probe));
  }
  Memory scalar0,scalar1,cache0,cache1,scalar_coord,cache_coord;
  std::array<planner::Rule,2> scalar{{{"a",&array_plan,&scalar0,{}},{"b",&array_plan,&scalar1,{}}}};
  std::array<planner::Rule,2> cached{{{"a",&array_plan,&cache0,{},true},{"b",&array_plan,&cache1,{},true}}};
  {
   auto expected=planner::execute(array_data,scalar,&scalar_coord,{},0);
   auto observed=planner::execute(array_data,cached,&cache_coord,cache_bytes,1000000);
   CHECK(expected.rules.size()==2&&observed.rules.size()==2);
   same(expected.rules[0],observed.rules[0]);same(expected.rules[1],observed.rules[1]);
   CHECK(observed.shared.physical_collects==2&&observed.shared.cache_builds==0&&observed.shared.cache_hits==0&&observed.shared.cache_rejections==0&&observed.shared.cache_work_charged==0);
   CHECK(scalar0.requests==cache0.requests&&scalar1.requests==cache1.requests);
  }
  CHECK(scalar0.used==0&&scalar1.used==0&&cache0.used==0&&cache1.used==0&&scalar_coord.used==0&&cache_coord.used==0);
  ++cases;
 }
 reference::Cancel cancel{[](void*)noexcept{return true;},nullptr};compare(exact,contains,data,cancel);
 // Tiny cache arena, no physical cache work and untrusted allocator attestation
 // are safe fallbacks, rather than failures or silent partial publication.
 {
  Memory scratch,coord;std::array<planner::Rule,2> rules{{{"x",&exact,&scratch,{},true},{"y",&contains,&scratch,{},true}}};
  std::array<std::byte,1> tiny{};
  {auto no_space=planner::execute(data,rules,&coord,tiny,1000000);CHECK(no_space.rules[0].code==planner::OutcomeCode::result_available&&no_space.rules[1].code==planner::OutcomeCode::result_available&&no_space.shared.cache_hits==0);}
  {auto no_work=planner::execute(data,rules,&coord,cache_bytes,1);CHECK(no_work.rules[0].code==planner::OutcomeCode::result_available&&no_work.rules[1].code==planner::OutcomeCode::result_available&&no_work.shared.cache_hits==0);}
  for(uint64_t limit:{2u,8u,32u,100u}){auto limited=planner::execute(data,rules,&coord,cache_bytes,limit);
   CHECK(limited.shared.cache_work_charged<=limit&&limited.rules[0].code==planner::OutcomeCode::result_available&&limited.rules[1].code==planner::OutcomeCode::result_available);}
  rules[1].allocation_replay_safe=false;
  {auto untrusted=planner::execute(data,rules,&coord,cache_bytes,1000000);CHECK(untrusted.rules[0].code==planner::OutcomeCode::result_available&&untrusted.rules[1].code==planner::OutcomeCode::result_available&&untrusted.shared.cache_hits==0);}
  CHECK(scratch.used==0&&coord.used==0);++cases;
 }
 {Memory m,c;std::array<planner::Rule,2> duplicate{{{"dup",&exact,&m,{},true},{"dup",&contains,&m,{},true}}};bool rejected=false;
  try{(void)planner::execute(data,duplicate,&c,cache_bytes,1000000);}catch(const std::invalid_argument&){rejected=true;}CHECK(rejected&&m.calls==0&&c.used==0);++cases;}
 {Memory m,c;std::array<planner::Rule,1> one{{{"overlap",&exact,&m,{},true}}};const auto before=bytes;bool rejected=false;
  auto overlap=std::span<std::byte>(reinterpret_cast<std::byte*>(bytes.data()+1),16);
  try{(void)planner::execute(data,one,&c,overlap,1000000);}catch(const std::invalid_argument&){rejected=true;}
  CHECK(rejected&&bytes==before&&m.calls==0&&c.used==0);++cases;}
 // Same underlying scratch allocation sequence, including deterministic OOM.
 for(size_t n=0;n<50;++n)compare(exact,contains,data,{},n);
 // max_work is part of each rule, never relaxed by a fact-cache hit.
 for(unsigned cap:{1u,10u,20u,40u,80u}){auto bounded=compile(std::string(R"({"schema_version":1,"relation":"method_defs","max_work":)")+std::to_string(cap)+R"(,"where":{"name":"uses","using_strings":{"all":[{"op":"contains","value":"string"}]}}})");compare(exact,bounded,data);}
 // Corrupt method body must not be cached as an empty/complete result.
 auto bad=bytes;uint32_t ordinal=0;while(metadata.methods[ordinal].name!=u"uses")++ordinal;bad[metadata.methods[ordinal].code_offset+16]=0x73;
 auto bad_metadata=read_metadata(bad);std::array<reference::SourceView,1> corrupt_sources{{{0,0,&bad_metadata,bad}}};const reference::DatasetView corrupt{corrupt_sources,std::span(slots).first(1),true};compare(exact,contains,corrupt);
 CHECK(temp.used==0);std::cout<<"PASS internal multirule differential "<<cases<<" cases, physical reuse, scope, budgets, OOM, cancellation and corruption\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}


