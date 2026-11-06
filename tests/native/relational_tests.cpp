#include "query/ir.hpp"
#include "execution/reference/evaluate.hpp"
#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <string>
#include <vector>

using namespace dexmeguviz;
#define CHECK(x) do{if(!(x))throw std::runtime_error("relational check "+std::to_string(__LINE__)+": " #x);}while(0)
struct Counter:std::pmr::memory_resource{
 size_t used=0,limit=std::numeric_limits<size_t>::max();
 void* do_allocate(size_t n,size_t a)override{if(n>limit-used)throw std::bad_alloc();auto p=std::pmr::new_delete_resource()->allocate(n,a);used+=n;return p;}
 void do_deallocate(void* p,size_t n,size_t a)override{used-=n;std::pmr::new_delete_resource()->deallocate(p,n,a);}
 bool do_is_equal(const std::pmr::memory_resource& r)const noexcept override{return this==&r;}
};
static std::vector<uint8_t> load(const std::filesystem::path& path){
 std::ifstream input(path,std::ios::binary);CHECK(input.good());return {(std::istreambuf_iterator<char>(input)),{}};
}
static std::string scan(std::string_view relation,std::string_view predicate={},std::string_view slot={}){
 std::string out="{\"op\":\"scan\",\"relation\":\""+std::string(relation)+"\"";
 if(!predicate.empty())out+=",\"where\":"+std::string(predicate);
 if(!slot.empty())out+=",\"scope\":{\"slots\":[\""+std::string(slot)+"\"]}";
 return out+"}";
}
static std::string inputs(std::initializer_list<std::string_view> branches){
 std::string out="[";bool comma=false;for(auto branch:branches){if(comma)out+=',';out+=branch;comma=true;}return out+"]";
}
static std::string unite(std::initializer_list<std::string_view> branches,std::string_view semantics="bag",std::string_view identity="tuple"){
 return "{\"op\":\"union\",\"inputs\":"+inputs(branches)+",\"semantics\":\""+std::string(semantics)+"\",\"identity\":\""+std::string(identity)+"\"}";
}
static std::string distinct(std::string_view input,std::string_view identity){
 return "{\"op\":\"distinct\",\"input\":"+std::string(input)+",\"identity\":\""+std::string(identity)+"\"}";
}
static std::string label(std::string_view input,std::string_view value){
 return "{\"op\":\"label\",\"input\":"+std::string(input)+",\"label\":\""+std::string(value)+"\"}";
}
static std::string filter(std::string_view input,std::string_view predicate){
 return "{\"op\":\"filter\",\"input\":"+std::string(input)+",\"where\":"+std::string(predicate)+"}";
}
static std::string group(std::initializer_list<std::string_view> branches,std::string_view options={}){
 return "{\"op\":\"group_by_owner\",\"inputs\":"+inputs(branches)+std::string(options)+"}";
}
static std::string query_json(std::string_view expression,std::string_view tail={}){
 return "{\"schema_version\":1,\"relation\":"+std::string(expression)+std::string(tail)+"}";
}
static void ordinals(const reference::Result& result,std::initializer_list<uint32_t> expected){
 CHECK(result.rows.size()==expected.size());size_t index=0;for(auto ordinal:expected)CHECK(result.rows[index++].method_ordinal==ordinal);
}
static bool bound(const query::Plan& plan,const reference::Candidate& row,std::string_view label_name,query::Relation relation,uint32_t source,uint32_t ordinal){
 return std::any_of(row.bindings.begin(),row.bindings.end(),[&](const auto& b){
  const bool role=label_name.empty()?b.label==query::none:b.label!=query::none&&plan.labels.at(b.label)==label_name;
  return role&&b.entity==reference::EntityKey{source,ordinal,relation};
 });
}
static void graph_checked(const query::Plan& plan,const reference::Progress& progress){
 CHECK(plan.id.starts_with("query:v3:")&&progress.graph.has_value());
 uint64_t visited=0,total=0;bool root=false;
 for(const auto& node:progress.graph->nodes){
  CHECK(node.unknown_rows<=node.output_rows);
  root|=node.node==progress.graph->root_node;
  if(node.op==query::RelOp::scan){visited+=node.visited_rows;total+=node.total_rows;}
 }
 CHECK(root&&visited==progress.visited&&total==progress.total);
}

int main(int argc,char** argv){try{
 CHECK(argc==2);const std::filesystem::path root(argv[1]);Counter facts_memory,plans,temporary,execution;
 const auto catalog_bytes=load(root/"generated/definition_catalog/definitions.dex");
 const auto method_bytes=load(root/"generated/method_facts/method-uses.dex");
 auto* previous=std::pmr::set_default_resource(std::pmr::null_memory_resource());unsigned cases=0;
 try{
  auto catalog=read_metadata(catalog_bytes,&facts_memory),methods=read_metadata(method_bytes,&facts_memory);
  const std::array<std::string_view,2> slots{"left","right"};
  const std::array<reference::SourceView,2> catalogs{{{0,0,&catalog,catalog_bytes},{1,1,&catalog,catalog_bytes}}};
  const std::array<reference::SourceView,2> method_sources{{{0,0,&methods,method_bytes},{1,1,&methods,method_bytes}}};
  const reference::DatasetView one{std::span(catalogs).first(1),std::span(slots).first(1),true},pair{catalogs,slots,true};
  const reference::DatasetView method_data{std::span(method_sources).first(1),std::span(slots).first(1),true},method_pair{method_sources,slots,true};
  auto run=[&](std::string_view name,const std::string& json,reference::DatasetView data,auto check){
   try{{auto plan=query::compile(json,&plans,&temporary);reference::Progress progress;auto result=reference::execute(data,plan,progress,&execution);
     graph_checked(plan,progress);for(const auto& row:result.rows)CHECK(!row.uncertain);check(plan,result,progress);}
    CHECK(plans.used==0&&temporary.used==0&&execution.used==0);++cases;
   }catch(...){std::cerr<<"case: "<<name<<'\n';throw;}
  };
  auto rejected=[&](const std::string& json){
   bool failed=false;try{(void)query::compile(json,&plans,&temporary);}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::unsupported||e.code==query::ErrorCode::invalid);failed=true;}
   CHECK(failed&&plans.used==0&&temporary.used==0);++cases;
  };
  auto limited=[&](const std::string& json,reference::DatasetView data){
   {auto plan=query::compile(json,&plans,&temporary);bool failed=false;
    {reference::Progress progress;try{(void)reference::execute(data,plan,progress,&execution);}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::budget);failed=true;}}
    CHECK(failed&&execution.used==0);}
   CHECK(plans.used==0&&temporary.used==0);++cases;
  };
  const auto uses=scan("method_defs",R"({"name":"uses"})"),quiet=scan("method_defs",R"({"name":"quiet"})");
  const auto a_uses=label(uses,"A"),b_uses=label(uses,"B"),a_quiet=label(quiet,"A");
  const auto same_bag=unite({uses,uses}),roles_bag=unite({a_uses,b_uses});
  run("scan expression",query_json(uses),method_data,[](const auto&,const auto& r,const auto& p){ordinals(r,{2});CHECK(p.profile.unknown_rows==0&&p.visited==4&&p.total==4);});
  run("post scan body filter",query_json(filter(scan("method_defs"),R"({"name":"uses","using_strings":{"all":["used-string"]}})")),method_data,[](const auto&,const auto& r,const auto& p){
   ordinals(r,{2});CHECK(p.profile.methods_decoded==1);bool pc=false;
   for(const auto& w:r.rows[0].witnesses){CHECK(w.relation_node!=UINT32_MAX&&w.source_index==0&&w.entity_relation==query::Relation::method_defs&&w.entity_ordinal==2);if(w.kind==reference::WitnessKind::string_use){CHECK(w.dex_pc==0&&w.reference_index==10);pc=true;}}
   CHECK(pc);
  });
  run("bag duplicates",query_json(same_bag),method_data,[](const auto&,const auto& r,const auto&){ordinals(r,{2,2});});
  run("union entity set",query_json(unite({uses,uses},"set","entity")),method_data,[](const auto&,const auto& r,const auto&){ordinals(r,{2});});
  run("union tuple set",query_json(unite({uses,uses},"set")),method_data,[](const auto&,const auto& r,const auto&){ordinals(r,{2});});
  run("root tuple set",query_json(same_bag,R"(,"semantics":"set")"),method_data,[](const auto&,const auto& r,const auto&){ordinals(r,{2});});
  run("distinct entity removes role alternatives",query_json(distinct(roles_bag,"entity")),method_data,[](const auto&,const auto& r,const auto&){ordinals(r,{2});});
  run("distinct tuple preserves role alternatives",query_json(distinct(roles_bag,"tuple")),method_data,[](const auto& plan,const auto& r,const auto&){
   ordinals(r,{2,2});CHECK(bound(plan,r.rows[0],"A",query::Relation::method_defs,0,2));CHECK(bound(plan,r.rows[1],"B",query::Relation::method_defs,0,2));
  });
  run("root set preserves different role tuples",query_json(roles_bag,R"(,"semantics":"set")"),method_data,[](const auto&,const auto& r,const auto&){ordinals(r,{2,2});});
  run("unique default identity ignores duplicate role tuples",query_json(roles_bag,R"(,"intent":"unique")"),method_data,[](const auto&,const auto& r,const auto& p){ordinals(r,{2});CHECK(p.profile.unknown_rows==0&&!r.result_limit);});
  run("unique entity does not spend cap on duplicate bag rows",query_json(same_bag,R"(,"intent":"unique","unique_by":"entity","max_results":1)"),method_data,[](const auto&,const auto& r,const auto&){ordinals(r,{2});CHECK(!r.result_limit);});
  run("unique tuple finds role ambiguity",query_json(roles_bag,R"(,"intent":"unique","unique_by":"tuple")"),method_data,[](const auto&,const auto& r,const auto&){ordinals(r,{2,2});CHECK(!r.result_limit);});
  run("unique tuple max one remains limited",query_json(roles_bag,R"(,"intent":"unique","unique_by":"tuple","max_results":1)"),method_data,[](const auto&,const auto& r,const auto&){CHECK(r.rows.size()==1&&r.result_limit);});
  run("bag preserves branch order",query_json(unite({uses,quiet})),method_data,[](const auto&,const auto& r,const auto&){ordinals(r,{2,1});});
  run("root limit follows complete relation",query_json(unite({uses,quiet}),R"(,"max_results":1)"),method_data,[](const auto&,const auto& r,const auto& p){ordinals(r,{2});CHECK(r.result_limit&&p.visited==8&&p.total==8);});
  run("top n sees a better later branch",query_json(unite({quiet,uses}),R"(,"intent":"top_n","max_results":1,"order_by":[{"field":"name","direction":"desc"}])"),method_data,[](const auto&,const auto& r,const auto& p){ordinals(r,{2});CHECK(!r.result_limit&&p.order_verified&&p.visited==8);});
  const auto left=scan("method_defs",R"({"name":"uses"})","left"),right=scan("method_defs",R"({"name":"uses"})","right");
  run("set identity keeps source occurrence",query_json(unite({left,right},"set","entity")),method_pair,[](const auto&,const auto& r,const auto& p){
   ordinals(r,{2,2});CHECK(r.rows[0].source_index==0&&r.rows[1].source_index==1&&p.scope_source_count==2);
  });
  run("cross source unique is ambiguous",query_json(unite({left,right},"set"),R"(,"intent":"unique")"),method_pair,[](const auto&,const auto& r,const auto&){CHECK(r.rows.size()==2&&r.rows[0].source_index!=r.rows[1].source_index);});
  run("unscoped relation keeps incomplete source coverage",query_json(uses),{method_sources,slots,false},[](const auto&,const auto& r,const auto& p){CHECK(r.rows.size()==2&&!p.scope_complete);});
  run("explicit leaf scope is complete within incomplete parent",query_json(left),{method_sources,slots,false},[](const auto&,const auto& r,const auto& p){ordinals(r,{2});CHECK(r.rows[0].source_index==0&&p.scope_complete&&r.scope_sources.size()==1&&r.scope_sources[0]==0);});

  const auto two_methods=group({label(quiet,"A"),b_uses},R"(,"min":2,"max":2,"required_roles":["A","B"],"role_policy":"distinct")");
  run("two methods grouped by one owner",query_json(two_methods),method_data,[&](const auto& plan,const auto& r,const auto& p){
   ordinals(r,{0});const auto& row=r.rows[0];CHECK(row.relation==query::Relation::class_defs&&row.source_index==0&&p.profile.unknown_rows==0);
   CHECK(reference::entity(method_sources[0],row.relation,row.method_ordinal).type_descriptor==u"Lfacts/Example;");
   CHECK(bound(plan,row,"",query::Relation::method_defs,0,1)&&bound(plan,row,"",query::Relation::method_defs,0,2));
   CHECK(bound(plan,row,"A",query::Relation::method_defs,0,1)&&bound(plan,row,"B",query::Relation::method_defs,0,2));
   CHECK(row.bindings.size()==4);for(const auto& w:row.witnesses)CHECK(w.entity_relation==query::Relation::method_defs&&(w.entity_ordinal==1||w.entity_ordinal==2)&&w.source_index==0);
  });
  run("owner grouping keeps source occurrence",query_json(two_methods),method_pair,[](const auto&,const auto& r,const auto&){ordinals(r,{0,0});CHECK(r.rows[0].source_index==0&&r.rows[1].source_index==1);});
  run("bag duplication is not a second group member",query_json(group({same_bag},R"(,"min":2)")),method_data,[](const auto&,const auto& r,const auto&){CHECK(r.rows.empty());});
  run("one member can share two roles",query_json(group({a_uses,b_uses},R"(,"min":1,"max":1,"required_roles":["A","B"],"role_policy":"shared")")),method_data,[](const auto& plan,const auto& r,const auto&){
   ordinals(r,{0});CHECK(r.rows[0].bindings.size()==3);CHECK(bound(plan,r.rows[0],"A",query::Relation::method_defs,0,2)&&bound(plan,r.rows[0],"B",query::Relation::method_defs,0,2));
  });
  run("distinct roles need distinct members",query_json(group({a_uses,b_uses},R"(,"min":1,"required_roles":["A","B"],"role_policy":"distinct")")),method_data,[](const auto&,const auto& r,const auto&){CHECK(r.rows.empty());});
  run("distinct role matching must find a non greedy assignment",query_json(group({a_uses,a_quiet,b_uses},R"(,"min":2,"max":2,"required_roles":["A","B"],"role_policy":"distinct")")),method_data,[](const auto& plan,const auto& r,const auto&){
   ordinals(r,{0});CHECK(bound(plan,r.rows[0],"A",query::Relation::method_defs,0,1)&&bound(plan,r.rows[0],"B",query::Relation::method_defs,0,2));CHECK(r.rows[0].bindings.size()==5);
  });
  const auto base_field=scan("field_defs",R"({"owner":"Lcatalog/Base;","name":"shared"})");
  const auto child_field=scan("field_defs",R"({"owner":"Lcatalog/Child;","name":"shared"})");
  run("roles from different owners cannot combine",query_json(group({label(base_field,"A"),label(child_field,"B")},R"(,"required_roles":["A","B"])")),one,[](const auto&,const auto& r,const auto&){CHECK(r.rows.empty());});
  const auto left_field=scan("field_defs",R"({"name":"shared"})","left"),right_field=scan("field_defs",R"({"name":"shared"})","right");
  run("roles from different sources cannot combine",query_json(group({label(left_field,"A"),label(right_field,"B")},R"(,"required_roles":["A","B"])")),pair,[](const auto&,const auto& r,const auto&){CHECK(r.rows.empty());});
  run("mixed member kinds preserve bindings",query_json(group({label(child_field,"F"),label(scan("method_defs"),"M")},R"(,"min":2,"max":2,"required_roles":["F","M"],"role_policy":"distinct")")),one,[](const auto& plan,const auto& r,const auto&){
   ordinals(r,{4});CHECK(r.rows[0].relation==query::Relation::class_defs);
   CHECK(bound(plan,r.rows[0],"F",query::Relation::field_defs,0,2)&&bound(plan,r.rows[0],"M",query::Relation::method_defs,0,0));
   CHECK(bound(plan,r.rows[0],"",query::Relation::field_defs,0,2)&&bound(plan,r.rows[0],"",query::Relation::method_defs,0,0));
  });
  run("late upper bound rejection cannot expose early owner",query_json(group({scan("field_defs")},R"(,"min":1,"max":1)"),R"(,"max_results":1)"),one,[](const auto&,const auto& r,const auto&){ordinals(r,{4});CHECK(!r.result_limit);});
  run("filter after group sees class schema",query_json(filter(group({scan("field_defs")}),R"({"descriptor":"Lcatalog/Base;"})")),one,[](const auto&,const auto& r,const auto&){ordinals(r,{3});});

  const auto unknown=scan("field_refs",R"({"flags_contains":8})"),external=scan("field_refs",R"({"has_local_definition":false})");
  run("unknown survives scan",query_json(unknown),one,[](const auto&,const auto& r,const auto& p){ordinals(r,{1});CHECK(p.profile.unknown_rows==1);});
  run("filter false removes incoming unknown",query_json(filter(unknown,R"({"name":"shared"})")),one,[](const auto&,const auto& r,const auto& p){ordinals(r,{1});CHECK(p.profile.unknown_rows==0);});
  run("filter true keeps incoming unknown",query_json(filter(unknown,R"({"name":"externalField"})")),one,[](const auto&,const auto& r,const auto& p){CHECK(r.rows.empty()&&p.profile.unknown_rows==1);});
  run("constant false removes all unknown rows",query_json(filter(unknown,"false")),one,[](const auto&,const auto& r,const auto& p){CHECK(r.rows.empty()&&p.profile.unknown_rows==0);});
  run("set true row dominates same unknown identity",query_json(unite({unknown,external},"set","entity")),one,[](const auto&,const auto& r,const auto& p){ordinals(r,{1,3});CHECK(p.profile.unknown_rows==0);});
  run("set dominance is independent of branch order",query_json(unite({external,unknown},"set","entity")),one,[](const auto&,const auto& r,const auto& p){CHECK(r.rows.size()==2&&p.profile.unknown_rows==0);});
  run("set merges duplicate unknown rows once",query_json(unite({unknown,unknown},"set","entity")),one,[](const auto&,const auto& r,const auto& p){ordinals(r,{1});CHECK(p.profile.unknown_rows==1);});
  run("bag retains duplicate unknown rows",query_json(unite({unknown,unknown})),one,[](const auto&,const auto& r,const auto& p){ordinals(r,{1,1});CHECK(p.profile.unknown_rows==2);});
  run("distinct handles unknown identities",query_json(distinct(unite({unknown,unknown}),"entity")),one,[](const auto&,const auto& r,const auto& p){ordinals(r,{1});CHECK(p.profile.unknown_rows==1);});
  run("same label tuple true dominates unknown",query_json(unite({label(unknown,"A"),label(external,"A")},"set","tuple")),one,[](const auto&,const auto& r,const auto& p){ordinals(r,{1,3});CHECK(p.profile.unknown_rows==0);});
  run("different role tuple cannot hide unknown",query_json(unite({label(unknown,"A"),label(external,"B")},"set","tuple")),one,[](const auto&,const auto& r,const auto& p){ordinals(r,{1,3});CHECK(p.profile.unknown_rows==1);});

  rejected(query_json(unite({scan("method_defs"),scan("field_defs")})));
  rejected(query_json(group({scan("method_refs")})));
  rejected(query_json(group({scan("class_defs")})));
  rejected(query_json(filter(group({scan("field_defs")}),R"({"name":"shared"})")));
  rejected(query_json(distinct(uses,"symbol")));
  rejected(query_json(group({a_uses},R"(,"role_policy":"unknown")")));
  rejected(query_json(group({a_uses},R"(,"min":3,"max":1)")));
  limited(query_json(scan("field_defs"),R"(,"intent":"exists","max_results":1,"max_intermediate_rows":2)"),one);
  limited(query_json(filter(scan("field_defs"),"false"),R"(,"max_intermediate_rows":2)"),one);
  limited(query_json(unite({uses,quiet}),R"(,"intent":"exists","max_results":1,"max_intermediate_rows":1)"),method_data);
  limited(query_json(group({scan("field_defs")},R"(,"max":1)"),R"(,"max_results":1,"max_intermediate_rows":2)"),one);
  limited(query_json(two_methods,R"(,"max_work":1)"),method_data);
  {
   auto plan=query::compile(query_json(scan("method_defs",{},"missing")),&plans,&temporary);bool absent=false;
   {reference::Progress progress;try{(void)reference::execute(method_data,plan,progress,&execution);}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::source_mismatch);absent=true;}}
   CHECK(absent&&execution.used==0);++cases;
  }
  {
   auto plan=query::compile(query_json(two_methods),&plans,&temporary);unsigned calls=0;bool cancelled=false;
   {reference::Progress progress;try{(void)reference::execute(method_pair,plan,progress,&execution,{[](void* context)noexcept{return ++*static_cast<unsigned*>(context)>=6;},&calls});}
    catch(const query::Error& e){CHECK(e.code==query::ErrorCode::cancelled);cancelled=true;}}
   CHECK(cancelled&&calls>=6&&execution.used==0);++cases;
  }
  {
   auto plan=query::compile(query_json(two_methods),&plans,&temporary);bool exhausted=false;execution.limit=16;
   {reference::Progress progress;try{(void)reference::execute(method_data,plan,progress,&execution);}catch(const std::bad_alloc&){exhausted=true;}}
   execution.limit=std::numeric_limits<size_t>::max();CHECK(exhausted&&execution.used==0);++cases;
  }
  {
   const auto old=query::compile(R"({"schema_version":1,"relation":"method_defs","where":{"return_type":"I","parameters":[],"using_strings":{"all":[{"op":"exact","value":"quality settings:"}]}},"intent":"unique","max_results":2,"evidence_profile":"minimal"})",&plans,&temporary);
   CHECK(old.id=="query:v1:283ae5fd16c5c58a2c7690abdb0b7cfb3a8edf7644c63cf5b43956967d8e4a63");
   const auto entity=query::compile(R"({"schema_version":1,"relation":"field_defs"})",&plans,&temporary);
   CHECK(entity.id=="query:v2:6d119cc5d61d304582f915944e04db2a8b482aad25d7a694f6024907308a185a");
   const auto forward=query::compile(query_json(unite({uses,quiet})),&plans,&temporary),reverse=query::compile(query_json(unite({quiet,uses})),&plans,&temporary);
   const auto entity_unique=query::compile(query_json(roles_bag,R"(,"intent":"unique","unique_by":"entity")"),&plans,&temporary),tuple_unique=query::compile(query_json(roles_bag,R"(,"intent":"unique","unique_by":"tuple")"),&plans,&temporary);
   const auto shared=query::compile(query_json(group({a_uses,b_uses},R"(,"required_roles":["A","B"],"role_policy":"shared")")),&plans,&temporary),separate=query::compile(query_json(group({a_uses,b_uses},R"(,"required_roles":["A","B"],"role_policy":"distinct")")),&plans,&temporary);
   const auto small_budget=query::compile(query_json(uses,R"(,"max_intermediate_rows":10)"),&plans,&temporary),large_budget=query::compile(query_json(uses,R"(,"max_intermediate_rows":11)"),&plans,&temporary);
   CHECK(forward.id.starts_with("query:v3:")&&forward.id!=reverse.id&&entity_unique.id!=tuple_unique.id&&shared.id!=separate.id&&small_budget.id!=large_budget.id);++cases;
  }
  CHECK(plans.used==0&&temporary.used==0&&execution.used==0);
 }catch(...){std::pmr::set_default_resource(previous);throw;}
 std::pmr::set_default_resource(previous);CHECK(facts_memory.used==0);
 std::cout<<"PASS relational QueryIR: "<<cases<<" cases; bag/set and tuple identities, owner/role binding, complete intermediate scans, unknown propagation, budgets, cancellation, PMR reclamation and QueryID compatibility\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
