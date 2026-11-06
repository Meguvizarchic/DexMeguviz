#include "query/ir.hpp"
#include "execution/reference/evaluate.hpp"
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory_resource>
#include <stdexcept>
#include <string>
#include <vector>

using namespace dexmeguviz;
#define CHECK(x) do{if(!(x))throw std::runtime_error("entity query check "+std::to_string(__LINE__)+": " #x);}while(0)
struct Counter:std::pmr::memory_resource{
 size_t used=0;
 void* do_allocate(size_t n,size_t a)override{auto p=std::pmr::new_delete_resource()->allocate(n,a);used+=n;return p;}
 void do_deallocate(void* p,size_t n,size_t a)override{used-=n;std::pmr::new_delete_resource()->deallocate(p,n,a);}
 bool do_is_equal(const std::pmr::memory_resource& r)const noexcept override{return this==&r;}
};
static std::vector<uint8_t> load(const std::filesystem::path& path){
 std::ifstream input(path,std::ios::binary);CHECK(input.good());return {(std::istreambuf_iterator<char>(input)),{}};
}
static uint32_t u32(const std::vector<uint8_t>& bytes,uint32_t at){
 return uint32_t(bytes.at(at))|(uint32_t(bytes.at(at+1))<<8)|(uint32_t(bytes.at(at+2))<<16)|(uint32_t(bytes.at(at+3))<<24);
}
static std::string query_json(std::string_view relation,std::string_view tail={}){
 return "{\"schema_version\":1,\"relation\":\""+std::string(relation)+"\""+std::string(tail)+"}";
}
static void ordinals(const reference::Result& result,std::initializer_list<uint32_t> expected){
 CHECK(result.rows.size()==expected.size());size_t index=0;
 for(auto ordinal:expected)CHECK(result.rows[index++].method_ordinal==ordinal);
}

int main(int argc,char** argv){try{
 CHECK(argc==2);const std::filesystem::path root(argv[1]);Counter facts_memory,plans,temporary,execution;
 const auto bytes=load(root/"generated/definition_catalog/definitions.dex");
 const auto method_bytes=load(root/"generated/method_facts/method-uses.dex");
 auto* previous=std::pmr::set_default_resource(std::pmr::null_memory_resource());
 unsigned cases=0;
 try{
  auto metadata=read_metadata(bytes,&facts_memory),methods=read_metadata(method_bytes,&facts_memory);
  std::array<reference::SourceView,2> sources{{{0,0,&metadata,bytes},{1,1,&metadata,bytes}}};
  std::array<reference::SourceView,1> method_sources{{{0,0,&methods,method_bytes}}};
  const std::array<std::string_view,2> slots{"left","right"};
  const reference::DatasetView one{std::span(sources).first(1),std::span(slots).first(1),true};
  const reference::DatasetView pair{sources,slots,true};
  const reference::DatasetView method_data{method_sources,std::span(slots).first(1),true};
  auto run=[&](std::string_view json,reference::DatasetView data,auto check){
   {auto plan=query::compile(json,&plans,&temporary);reference::Progress progress;auto result=reference::execute(data,plan,progress,&execution);check(plan,result,progress);}
   CHECK(plans.used==0&&temporary.used==0&&execution.used==0);++cases;
  };
  auto rejected=[&](std::string_view json){
   bool unsupported=false;try{(void)query::compile(json,&plans,&temporary);}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::unsupported);unsupported=true;}
   CHECK(unsupported&&plans.used==0&&temporary.used==0);++cases;
  };
  struct Root {const char* name;query::Relation relation;uint32_t count;};
  const std::array<Root,7> roots{{
   {"method_defs",query::Relation::method_defs,1},{"class_defs",query::Relation::class_defs,5},
   {"field_defs",query::Relation::field_defs,3},{"method_refs",query::Relation::method_refs,1},
   {"field_refs",query::Relation::field_refs,4},{"string_values",query::Relation::string_values,13},
   {"type_refs",query::Relation::type_refs,9}}};
  for(const auto& root_case:roots){
   reference::validate_entity_relation(root_case.relation);
   run(query_json(root_case.name),one,[&](const auto& plan,const auto& result,const auto& progress){
    CHECK(plan.relation==root_case.relation&&result.rows.size()==root_case.count);
    CHECK(progress.total==root_case.count&&progress.visited==root_case.count&&progress.scope_complete);
    CHECK(progress.profile.unknown_rows==0&&progress.profile.matches_seen==root_case.count&&progress.profile.methods_decoded==0);
    CHECK(plan.id.starts_with(root_case.relation==query::Relation::method_defs?"query:v1:":"query:v2:"));
    for(uint32_t i=0;i<root_case.count;++i){const auto& row=result.rows[i];CHECK(row.relation==root_case.relation&&row.source_index==0&&row.method_ordinal==i);}
   });
   run(query_json(root_case.name),pair,[&](const auto&,const auto& result,const auto& progress){
    CHECK(result.rows.size()==root_case.count*2&&progress.total==root_case.count*2&&progress.visited==progress.total);
    CHECK(result.scope_sources.size()==2&&progress.profile.unknown_rows==0);
    for(uint32_t source=0;source<2;++source)for(uint32_t i=0;i<root_case.count;++i){
     const auto& candidate=result.rows[source*root_case.count+i];CHECK(candidate.source_index==source&&candidate.method_ordinal==i&&candidate.relation==root_case.relation);
     const auto row=reference::entity(sources[source],candidate.relation,candidate.method_ordinal);
     CHECK(row.source_index==source&&row.ordinal==i&&row.kind==root_case.relation);
    }
   });
  }
  for(const uint32_t raw:{7u,UINT32_MAX}){
   const auto invalid=static_cast<query::Relation>(raw);bool validation_rejected=false,size_rejected=false,entity_rejected=false;
   try{reference::validate_entity_relation(invalid);}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::unsupported);validation_rejected=true;}
   try{(void)reference::relation_size(metadata,invalid);}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::unsupported);size_rejected=true;}
   try{(void)reference::entity(sources[0],invalid,0);}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::unsupported);entity_rejected=true;}
   CHECK(validation_rejected&&size_rejected&&entity_rejected&&execution.used==0);++cases;
  }
  {
   const reference::SourceView missing{0,0,nullptr,{}};bool rejected=false;
   try{(void)reference::entity(missing,query::Relation::method_defs,0);}
   catch(const query::Error& e){CHECK(e.code==query::ErrorCode::invalid);rejected=true;}
   CHECK(rejected&&execution.used==0);++cases;
  }
  {
   auto plan=query::compile(query_json("method_defs"),&plans,&temporary);plan.relation=static_cast<query::Relation>(UINT32_MAX);
   bool unsupported=false;
   {reference::Progress progress;try{(void)reference::execute(one,plan,progress,&execution);}
    catch(const query::Error& e){CHECK(e.code==query::ErrorCode::unsupported);unsupported=true;}}
   CHECK(unsupported&&execution.used==0);++cases;
  }
  CHECK(plans.used==0&&temporary.used==0&&execution.used==0);
  {
   const reference::DatasetView empty{std::span<const reference::SourceView>{},std::span<const std::string_view>{},true};
   for(bool graph:{false,true})for(unsigned test=0;test<3;++test){
    const bool use_empty_data=test!=1;const bool empty_scope=test!=0;
    const auto data=use_empty_data?empty:one;
    std::string input=graph?R"({"schema_version":1,"relation":{"op":"scan","relation":"method_defs"})":R"({"schema_version":1,"relation":"method_defs")";
    input+=empty_scope?R"(,"scope":{"slots":[]}})":"}";
    {auto plan=query::compile(input,&plans,&temporary);const auto invalid=static_cast<query::Relation>(UINT32_MAX);
     if(graph)plan.relations[plan.relation_root].relation=invalid;else plan.relation=invalid;
     bool unsupported=false;
     {reference::Progress progress;try{(void)reference::execute(data,plan,progress,&execution);}
      catch(const query::Error& e){CHECK(e.code==query::ErrorCode::unsupported);unsupported=true;}}
     CHECK(unsupported&&execution.used==0);}
    CHECK(plans.used==0&&temporary.used==0&&execution.used==0);++cases;
   }
  }
  {
   auto plan=query::compile(R"({"schema_version":1,"relation":{"op":"scan","relation":"method_defs"}})",&plans,&temporary);
   plan.relations[plan.relation_root].relation=query::Relation::string_uses;bool invalid=false;
   {reference::Progress progress;try{(void)reference::execute(one,plan,progress,&execution);}
    catch(const query::Error& e){CHECK(e.code==query::ErrorCode::invalid);invalid=true;}}
   CHECK(invalid&&execution.used==0);++cases;
  }
  CHECK(plans.used==0&&temporary.used==0&&execution.used==0);
  run(query_json("class_defs"),one,[&](const auto&,const auto& result,const auto&){
   const std::array<uint32_t,5> types{7,4,5,2,3},flags{1,0x601,0x601,1,0x401};
   for(size_t i=0;i<result.rows.size();++i){const auto row=reference::entity(sources[0],result.rows[i].relation,result.rows[i].method_ordinal);
    CHECK(row.reference_index==types[i]&&row.record_offset==252+i*32&&row.definition_offset==row.record_offset);
    CHECK(row.definition_known&&row.flags_known&&row.access_flags==flags[i]&&!row.code_known);
    CHECK(row.owner.empty()&&row.name.empty()&&row.owner_class&&row.owner_class->type_id==types[i]);
    CHECK(u32(bytes,row.record_offset)==row.reference_index&&u32(bytes,row.record_offset+4)==row.access_flags);
   }
  });
  run(query_json("field_defs"),one,[&](const auto&,const auto& result,const auto&){
   const std::array<uint32_t,3> refs{1,0,2},flags{9,1,1},offsets{611,613,619};
   const std::array<std::u16string_view,3> owners{u"Lcatalog/Base;",u"Lcatalog/Base;",u"Lcatalog/Child;"};
   const std::array<std::u16string_view,3> names{u"shared",u"instanceField",u"shared"},types{u"J",u"I",u"I"};
   for(size_t i=0;i<result.rows.size();++i){const auto row=reference::entity(sources[0],result.rows[i].relation,result.rows[i].method_ordinal);
    CHECK(row.reference_index==refs[i]&&row.record_offset==offsets[i]&&row.definition_offset==offsets[i]);
    CHECK(row.definition_known&&row.flags_known&&row.access_flags==flags[i]&&!row.code_known);
    CHECK(row.owner==owners[i]&&row.name==names[i]&&row.type_descriptor==types[i]&&row.owner_class);
   }
  });
  run(query_json("field_refs"),one,[&](const auto&,const auto& result,const auto&){
   const std::array<uint32_t,4> offsets{613,611,619,0},flags{1,9,1,0};
   for(uint32_t i=0;i<4;++i){const auto row=reference::entity(sources[0],result.rows[i].relation,result.rows[i].method_ordinal);
    CHECK(row.reference_index==i&&row.record_offset==u32(bytes,84)+i*8);
    CHECK(row.definition_known==(i!=3)&&row.flags_known==(i!=3)&&row.definition_offset==offsets[i]&&row.access_flags==flags[i]);
    CHECK(!row.code_known&&bool(row.owner_class)==(i!=3));
   }
   const auto external=reference::entity(sources[0],query::Relation::field_refs,3);
   CHECK(external.owner==u"Lexternal/External;"&&external.name==u"externalField"&&external.type_descriptor==u"I");
  });
  run(query_json("method_defs"),method_data,[&](const auto&,const auto& result,const auto& progress){
   CHECK(result.rows.size()==4&&progress.total==4);const std::array<uint32_t,4> refs{1,2,3,0};
   for(uint32_t i=0;i<4;++i){const auto row=reference::entity(method_sources[0],result.rows[i].relation,result.rows[i].method_ordinal);
    CHECK(row.reference_index==refs[i]&&row.definition_known&&row.flags_known&&row.code_known&&row.method);
    CHECK(row.definition_offset==row.record_offset&&row.owner==u"Lfacts/Example;"&&row.prototype==u"()V");
   }
   CHECK(reference::entity(method_sources[0],query::Relation::method_defs,0).code_offset==0);
   CHECK(reference::entity(method_sources[0],query::Relation::method_defs,3).code_offset==0);
  });
  run(query_json("method_refs"),method_data,[&](const auto&,const auto& result,const auto& progress){
   CHECK(result.rows.size()==5&&progress.total==5);
   for(uint32_t i=0;i<5;++i){const auto row=reference::entity(method_sources[0],result.rows[i].relation,result.rows[i].method_ordinal);
    CHECK(row.reference_index==i&&row.record_offset==u32(method_bytes,92)+i*8);
    CHECK(row.definition_known==(i!=4)&&row.flags_known==(i!=4)&&!row.code_known&&!row.method);
   }
   const auto external=reference::entity(method_sources[0],query::Relation::method_refs,4);
   CHECK(external.name==u"sink"&&external.owner==u"Ljava/lang/Object;"&&!external.owner_class&&external.definition_offset==0);
  });
  run(query_json("type_refs"),one,[&](const auto&,const auto& result,const auto&){
   const std::array<uint32_t,9> offsets{0,0,348,380,284,316,0,252,0};
   for(uint32_t i=0;i<9;++i){const auto row=reference::entity(sources[0],result.rows[i].relation,result.rows[i].method_ordinal);
    CHECK(row.reference_index==i&&row.record_offset==u32(bytes,68)+i*4&&row.definition_offset==offsets[i]);
    CHECK(row.definition_known==(offsets[i]!=0)&&row.flags_known==(offsets[i]!=0)&&!row.code_known);
   }
  });
  run(query_json("string_values",R"(,"where":{"value":"externalField"})"),one,[&](const auto&,const auto& result,const auto&){
   ordinals(result,{10});const auto row=reference::entity(sources[0],result.rows[0].relation,result.rows[0].method_ordinal);
   CHECK(row.reference_index==10&&row.record_offset==152&&row.value==u"externalField");
   CHECK(!row.definition_known&&!row.flags_known&&!row.code_known&&!row.owner_class&&row.owner_type==UINT32_MAX);
  });
  run(query_json("class_defs",R"(,"where":{"descriptor":"Lcatalog/Child;","superclass":"Lcatalog/Base;","direct_interface":"Lcatalog/InterfaceA;","flags_contains":1024})"),one,[](const auto&,const auto& result,const auto& progress){ordinals(result,{4});CHECK(progress.profile.unknown_rows==0);});
  run(query_json("field_defs",R"(,"where":{"type":"I"})"),one,[](const auto&,const auto& result,const auto&){ordinals(result,{1,2});});
  run(query_json("field_refs",R"(,"where":{"type":"I"})"),one,[](const auto&,const auto& result,const auto&){ordinals(result,{0,2,3});});
  run(query_json("field_defs",R"(,"where":{"name":"shared"})"),one,[](const auto&,const auto& result,const auto&){ordinals(result,{0,2});});

  auto field_truth=[&](std::string_view predicate,std::initializer_list<uint32_t> expected,uint64_t unknown){
   run(query_json("field_refs",",\"where\":"+std::string(predicate)),one,[&](const auto&,const auto& result,const auto& progress){
    ordinals(result,expected);CHECK(progress.profile.unknown_rows==unknown&&progress.visited==4&&progress.total==4);
    CHECK(progress.scope_complete&&progress.profile.matches_seen==expected.size());
   });
  };
  field_truth(R"({"flags_contains":8})",{1},1);
  field_truth(R"({"not":{"flags_contains":8}})",{0,2},1);
  field_truth(R"({"flags_contains":0})",{0,1,2},1);
  field_truth(R"({"has_local_definition":false})",{3},0);
  field_truth(R"({"all":[{"flags_contains":8},{"has_local_definition":true}]})",{1},0);
  field_truth(R"({"any":[{"flags_contains":8},{"has_local_definition":false}]})",{1,3},0);
  field_truth(R"({"all":[{"flags_contains":8},{"has_local_definition":false}]})",{},1);
  field_truth(R"({"any":[{"flags_contains":8},{"has_local_definition":true}]})",{0,1,2},1);
  field_truth(R"({"not":{"owner_flags":{"mode":"contains","value":1}}})",{},1);
  run(query_json("method_refs",R"(,"where":{"not":{"flags_contains":8}})"),method_data,[](const auto&,const auto& result,const auto& progress){ordinals(result,{0});CHECK(progress.profile.unknown_rows==1&&progress.visited==5);});
  run(query_json("method_refs",R"(,"where":{"has_local_definition":false})"),method_data,[](const auto&,const auto& result,const auto& progress){ordinals(result,{4});CHECK(progress.profile.unknown_rows==0);});
  run(query_json("type_refs",R"(,"where":{"flags_contains":1})"),one,[](const auto&,const auto& result,const auto& progress){ordinals(result,{2,3,4,5,7});CHECK(progress.profile.unknown_rows==4&&progress.scope_complete);});
  run(query_json("type_refs",R"(,"where":{"has_local_definition":false})"),one,[](const auto&,const auto& result,const auto& progress){ordinals(result,{0,1,6,8});CHECK(progress.profile.unknown_rows==0);});

  run(query_json("field_refs",R"(,"intent":"top_n","max_results":4,"order_by":[{"field":"flags","direction":"asc"}])"),one,[](const auto&,const auto& result,const auto& progress){ordinals(result,{3,0,2,1});CHECK(progress.order_verified&&progress.visited==4&&progress.profile.unknown_rows==0);});
  run(query_json("field_refs",R"(,"intent":"top_n","max_results":4,"order_by":[{"field":"flags","direction":"desc"}])"),one,[](const auto&,const auto& result,const auto& progress){ordinals(result,{1,0,2,3});CHECK(progress.order_verified&&progress.visited==4);});
  run(query_json("field_refs",R"(,"intent":"top_n","max_results":1,"order_by":[{"field":"flags"}])"),one,[](const auto&,const auto& result,const auto& progress){ordinals(result,{3});CHECK(progress.order_verified&&progress.visited==4&&!result.result_limit);});
  run(query_json("field_refs",R"(,"intent":"top_n","max_results":4,"where":{"flags_contains":1},"order_by":[{"field":"flags"}])"),one,[](const auto&,const auto& result,const auto& progress){ordinals(result,{0,2,1});CHECK(!progress.order_verified&&progress.profile.unknown_rows==1&&progress.scope_complete);});

  for(const auto* json:{
   R"({"schema_version":1,"relation":"class_defs","where":{"name":"Child"}})",
   R"({"schema_version":1,"relation":"class_defs","where":{"owner_flags":{"value":1}}})",
   R"({"schema_version":1,"relation":"field_defs","where":{"return_type":"I"}})",
   R"({"schema_version":1,"relation":"method_refs","where":{"using_strings":{"all":["used-string"]}}})",
   R"({"schema_version":1,"relation":"field_refs","where":{"invokes":{"all":[{"name":"sink"}]}}})",
   R"({"schema_version":1,"relation":"type_refs","where":{"field_access":{"any":[{"type":"I"}]}}})",
   R"({"schema_version":1,"relation":"string_values","where":{"flags_contains":0}})",
   R"({"schema_version":1,"relation":"method_defs","where":{"value":"uses"}})",
   R"({"schema_version":1,"relation":"method_defs","where":{"descriptor":"Lcatalog/Child;"}})",
   R"({"schema_version":1,"relation":"type_refs","where":{"type":"I"}})",
   R"({"schema_version":1,"relation":"field_defs","where":{"prototype":"()V"}})",
   R"({"schema_version":1,"relation":"string_values","projection":["name"]})",
   R"({"schema_version":1,"relation":"method_refs","projection":["value"]})",
   R"({"schema_version":1,"relation":"type_refs","order_by":[{"field":"name"}]})",
   R"({"schema_version":1,"relation":"field_refs","order_by":[{"field":"method_index"}]})",
   R"({"schema_version":1,"relation":"string_values","order_by":[{"field":"flags"}]})"
  })rejected(json);
  {
   const auto legacy=query::compile(R"({"schema_version":1,"relation":"method_defs","where":{"return_type":"I","parameters":[],"using_strings":{"all":[{"op":"exact","value":"quality settings:"}]}},"intent":"unique","max_results":2,"evidence_profile":"minimal"})",&plans,&temporary);
   CHECK(legacy.id=="query:v1:283ae5fd16c5c58a2c7690abdb0b7cfb3a8edf7644c63cf5b43956967d8e4a63");
   const auto definition=query::compile(query_json("field_defs",R"(,"where":{"name":"shared"})"),&plans,&temporary);
   const auto reference=query::compile(query_json("field_refs",R"(,"where":{"name":"shared"})"),&plans,&temporary);
   const auto extended=query::compile(query_json("method_defs",R"(,"where":{"has_local_definition":true})"),&plans,&temporary);
   CHECK(definition.id.starts_with("query:v2:")&&reference.id.starts_with("query:v2:")&&definition.id!=reference.id&&extended.id.starts_with("query:v2:"));++cases;
  }
  CHECK(plans.used==0&&temporary.used==0&&execution.used==0);
  {
   auto invalid_sources=sources;invalid_sources[1].source_index=0;
   auto plan=query::compile(query_json("field_refs"),&plans,&temporary);reference::Progress progress;bool invalid=false;
   try{(void)reference::execute({invalid_sources,slots,true},plan,progress,&execution);}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::invalid);invalid=true;}
   CHECK(invalid&&execution.used==0);++cases;
  }
 }catch(...){std::pmr::set_default_resource(previous);throw;}
 std::pmr::set_default_resource(previous);CHECK(facts_memory.used==0);
 std::cout<<"PASS entity QueryIR: "<<cases<<" cases; seven roots, independent fixture identities, definitions versus references, three-valued predicates, source multiplicity, NULL ordering, strict type rejection and QueryID compatibility\n";
 return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
