#include "query/ir.hpp"
#include "execution/reference/evaluate.hpp"
#include "source/sha256.hpp"
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
#define CHECK(x) do{if(!(x))throw std::runtime_error("join check "+std::to_string(__LINE__)+": " #x);}while(0)
struct Counter:std::pmr::memory_resource{
 size_t used=0,limit=std::numeric_limits<size_t>::max();
 void* do_allocate(size_t n,size_t a)override{if(n>limit-used)throw std::bad_alloc();auto p=std::pmr::new_delete_resource()->allocate(n,a);used+=n;return p;}
 void do_deallocate(void* p,size_t n,size_t a)override{used-=n;std::pmr::new_delete_resource()->deallocate(p,n,a);}
 bool do_is_equal(const std::pmr::memory_resource& r)const noexcept override{return this==&r;}
};
static std::vector<uint8_t> load(const std::filesystem::path& path){
 std::ifstream in(path,std::ios::binary);CHECK(in.good());return {(std::istreambuf_iterator<char>(in)),{}};
}
static std::string scan(std::string_view relation,std::string_view where={},std::string_view slot={}){
 std::string s="{\"op\":\"scan\",\"relation\":\""+std::string(relation)+"\"";
 if(!where.empty())s+=",\"where\":"+std::string(where);
 if(!slot.empty())s+=",\"scope\":{\"slots\":[\""+std::string(slot)+"\"]}";
 return s+"}";
}
static std::string label(std::string_view input,std::string_view name){return "{\"op\":\"label\",\"input\":"+std::string(input)+",\"label\":\""+std::string(name)+"\"}";}
static std::string unite(std::initializer_list<std::string_view> inputs,std::string_view semantics="bag"){
 std::string s="{\"op\":\"union\",\"semantics\":\""+std::string(semantics)+"\",\"inputs\":[";bool first=true;
 for(auto input:inputs){if(!first)s+=',';first=false;s+=input;}return s+"]}";
}
static std::string join(std::string_view left,std::string_view right,std::string_view key,std::string_view op="join"){
 return "{\"op\":\""+std::string(op)+"\",\"left\":"+std::string(left)+",\"right\":"+std::string(right)+",\"on\":\""+std::string(key)+"\"}";
}
static std::string distinct(std::string_view input,std::string_view identity="tuple"){
 return "{\"op\":\"distinct\",\"input\":"+std::string(input)+",\"identity\":\""+std::string(identity)+"\"}";
}
static std::string group(std::initializer_list<std::string_view> inputs,std::string_view tail={}){
 std::string s="{\"op\":\"group_by_owner\",\"inputs\":[";bool first=true;
 for(auto input:inputs){if(!first)s+=',';first=false;s+=input;}return s+"]"+std::string(tail)+"}";
}
static std::string query_json(std::string_view expression,std::string_view tail={}){
 return "{\"schema_version\":1,\"relation\":"+std::string(expression)+std::string(tail)+"}";
}
static bool binding(const query::Plan& plan,const reference::Candidate& row,std::string_view label_name,
                    reference::EntityKey entity,std::initializer_list<uint8_t> path){
 return std::any_of(row.bindings.begin(),row.bindings.end(),[&](const auto& b){
  const bool role=label_name.empty()?b.label==query::none:b.label!=query::none&&plan.labels.at(b.label)==label_name;
  return role&&b.entity==entity&&b.path_length==path.size()&&std::equal(path.begin(),path.end(),b.path.begin());
 });
}
static bool proof_binding(const query::Plan& plan,const reference::Candidate& row,uint32_t node,std::string_view label_name,
                          reference::EntityKey entity,std::initializer_list<uint8_t> path){
 return std::any_of(row.proof_bindings.begin(),row.proof_bindings.end(),[&](const auto& proof){const auto& b=proof.binding;
  const bool role=label_name.empty()?b.label==query::none:b.label!=query::none&&plan.labels.at(b.label)==label_name;
  return proof.node==node&&role&&b.entity==entity&&b.path_length==path.size()&&std::equal(path.begin(),path.end(),b.path.begin());
 });
}
static void paths_valid(const reference::Candidate& row){
 for(const auto& b:row.bindings){CHECK(b.path_length<=b.path.size());for(uint32_t i=0;i<b.path_length;++i)CHECK(b.path[i]<=1);}
 for(const auto& w:row.witnesses)CHECK(w.relation_node!=query::none&&w.source_index!=query::none&&w.entity_ordinal!=query::none);
}
int main(int argc,char** argv){try{
 CHECK(argc==2);const std::filesystem::path root(argv[1]);Counter facts_memory,plans,temporary,execution;
 const auto bytes=load(root/"generated/definition_catalog/definitions.dex");
 const auto method_bytes=load(root/"generated/method_facts/method-uses.dex");
 auto* previous=std::pmr::set_default_resource(std::pmr::null_memory_resource());unsigned cases=0;
 try{
  auto catalog=read_metadata(bytes,&facts_memory),methods=read_metadata(method_bytes,&facts_memory);
  const std::array<std::string_view,2> slots{"left","right"};
  const std::array<reference::SourceView,2> catalogs{{{0,0,&catalog,bytes},{1,1,&catalog,bytes}}};
  const std::array<reference::SourceView,2> mixed{{{0,0,&catalog,bytes},{1,1,&methods,method_bytes}}};
  const std::array<reference::SourceView,1> method_source{{{0,0,&methods,method_bytes}}};
  const reference::DatasetView one{std::span(catalogs).first(1),std::span(slots).first(1),true},pair{catalogs,slots,true};
  const reference::DatasetView mixed_data{mixed,slots,true},method_data{method_source,std::span(slots).first(1),true};
  auto run=[&](std::string_view name,const std::string& json,reference::DatasetView data,auto verify){
   try{{auto plan=query::compile(json,&plans,&temporary);reference::Progress progress;auto result=reference::execute(data,plan,progress,&execution);
      CHECK(progress.graph&&plan.id.starts_with("query:v3:"));for(const auto& row:result.rows){CHECK(!row.uncertain);paths_valid(row);}verify(plan,result,progress);}
    CHECK(plans.used==0&&temporary.used==0&&execution.used==0);++cases;
   }catch(...){std::cerr<<"case: "<<name<<'\n';throw;}
  };
  auto rejects=[&](const std::string& json){bool failed=false;
   try{(void)query::compile(json,&plans,&temporary);}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::unsupported||e.code==query::ErrorCode::invalid);failed=true;}
   CHECK(failed&&plans.used==0&&temporary.used==0);++cases;
  };
  auto limited=[&](const std::string& json,reference::DatasetView data){
   {auto plan=query::compile(json,&plans,&temporary);bool failed=false;
    {reference::Progress progress;try{(void)reference::execute(data,plan,progress,&execution);}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::budget);failed=true;}}
    CHECK(failed&&execution.used==0);}CHECK(plans.used==0&&temporary.used==0);++cases;
  };
  const auto method=scan("method_defs",R"({"name":"abstractMethod"})"),labeled=label(method,"x");
  const auto choices=unite({labeled,method});const auto pair_choices=join(choices,choices,"same_entity");
  run("same entity join",query_json(join(method,method,"same_entity")),one,[](const auto& p,const auto& r,const auto& progress){
   CHECK(r.rows.size()==1&&progress.profile.unknown_rows==0&&progress.graph->identity_count==1);
   const auto key=reference::EntityKey{0,0,query::Relation::method_defs};const auto& row=r.rows[0];
   CHECK(binding(p,row,"",key,{0})&&binding(p,row,"",key,{1}));CHECK(row.links.size()==1);
   CHECK(row.links[0].key==query::JoinKey::same_entity&&row.links[0].left==key&&row.links[0].right==key);
   CHECK(row.links[0].node==progress.graph->root_node&&row.witnesses.size()>=2);
  });
  run("four bag pairs preserve left right role provenance",query_json(pair_choices),one,[](const auto& p,const auto& r,const auto& progress){
   CHECK(r.rows.size()==4&&progress.graph->identity_count==1);const reference::EntityKey key{0,0,query::Relation::method_defs};unsigned mask=0;
   for(const auto& row:r.rows){CHECK(binding(p,row,"",key,{0})&&binding(p,row,"",key,{1})&&row.links.size()==1);
    const unsigned sides=(binding(p,row,"x",key,{0})?1u:0u)|(binding(p,row,"x",key,{1})?2u:0u);mask|=1u<<sides;}
   CHECK(mask==15);
  });
  run("four distinct tuples",query_json(distinct(pair_choices),R"(,"unique_by":"tuple")"),one,[](const auto&,const auto& r,const auto& progress){CHECK(r.rows.size()==4&&progress.graph->identity_count==4);});
  run("tuple unique recognizes two pair identities",query_json(pair_choices,R"(,"intent":"unique","unique_by":"tuple")"),one,[](const auto&,const auto& r,const auto& progress){CHECK(r.rows.size()==2&&progress.graph->identity_count==4&&!r.result_limit);});
  run("entity unique ignores four same-primary pairs",query_json(pair_choices,R"(,"intent":"unique","unique_by":"entity")"),one,[](const auto&,const auto& r,const auto& progress){CHECK(r.rows.size()==1&&progress.graph->identity_count==1&&!r.result_limit);});
  const auto simple_join=join(method,method,"same_entity");
  run("different operator nodes with same tuple deduplicate",query_json(unite({simple_join,simple_join},"set"),R"(,"unique_by":"tuple")"),one,[](const auto&,const auto& r,const auto& progress){CHECK(r.rows.size()==1&&progress.graph->identity_count==1&&r.rows[0].links.size()==1);});
  run("nested pair retains hierarchical sides",query_json(join(simple_join,method,"same_entity")),one,[](const auto& p,const auto& r,const auto&){
   CHECK(r.rows.size()==1);const reference::EntityKey key{0,0,query::Relation::method_defs};const auto& row=r.rows[0];
   CHECK(row.links.size()==2&&binding(p,row,"",key,{0,0})&&binding(p,row,"",key,{0,1})&&binding(p,row,"",key,{1}));
  });
  const auto twice=unite({method,method}),thrice=unite({method,method,method});
  run("bag join m times n",query_json(join(twice,thrice,"same_entity")),one,[](const auto&,const auto& r,const auto&){CHECK(r.rows.size()==6);});
  run("bag semijoin preserves only left multiplicity",query_json(join(twice,thrice,"same_entity","semi_join")),one,[](const auto&,const auto& r,const auto& progress){
   CHECK(r.rows.size()==2&&progress.profile.unknown_rows==0);for(const auto& row:r.rows)CHECK(row.links.size()==1&&row.bindings.empty());
  });
  run("root limit does not cut intermediate join",query_json(join(twice,thrice,"same_entity"),R"(,"max_results":5)"),one,[](const auto&,const auto& r,const auto& progress){CHECK(r.rows.size()==5&&r.result_limit&&progress.visited==progress.total);});
  run("field local definitions map the right table",query_json(join(scan("field_defs"),scan("field_refs"),"local_definition")),one,[](const auto&,const auto& r,const auto&){
   CHECK(r.rows.size()==3);const std::array<uint32_t,3> refs{1,0,2};for(size_t i=0;i<3;++i){const auto& row=r.rows[i];CHECK(row.method_ordinal==i&&row.links.size()==1&&row.links[0].right.ordinal==refs[i]);}
  });
  run("reverse field local definitions",query_json(join(scan("field_refs"),scan("field_defs"),"local_definition")),one,[](const auto&,const auto& r,const auto&){
   CHECK(r.rows.size()==3);for(const auto& row:r.rows)CHECK(row.method_ordinal!=3&&row.links[0].right.relation==query::Relation::field_defs);
  });
  run("class and type local definitions",query_json(join(scan("class_defs"),scan("type_refs"),"local_definition")),one,[](const auto&,const auto& r,const auto&){
   const std::array<uint32_t,5> types{7,4,5,2,3};CHECK(r.rows.size()==5);for(size_t i=0;i<5;++i)CHECK(r.rows[i].links[0].right.ordinal==types[i]);
  });
  run("method refs map definitions",query_json(join(scan("method_defs"),scan("method_refs"),"local_definition")),method_data,[](const auto&,const auto& r,const auto&){
   const std::array<uint32_t,4> refs{1,2,3,0};CHECK(r.rows.size()==4);for(size_t i=0;i<4;++i)CHECK(r.rows[i].links[0].right.ordinal==refs[i]);
  });
  run("local reference ids cannot cross sources",query_json(join(scan("method_defs",{},"left"),scan("method_refs",{},"right"),"local_definition")),mixed_data,[](const auto&,const auto& r,const auto& progress){CHECK(r.rows.empty()&&progress.scope_complete);});
  run("local owner binds matching declaration",query_json(join(scan("field_defs"),scan("class_defs"),"local_owner")),one,[](const auto&,const auto& r,const auto&){
   const std::array<uint32_t,3> owners{3,3,4};CHECK(r.rows.size()==3);for(size_t i=0;i<3;++i)CHECK(r.rows[i].links[0].right.ordinal==owners[i]);
  });
  run("owner id cannot cross sources",query_json(join(scan("field_defs",{},"left"),scan("class_defs",{},"right"),"local_owner")),pair,[](const auto&,const auto& r,const auto&){CHECK(r.rows.empty());});
  run("symbol matches preserve both occurrences",query_json(join(scan("method_defs"),scan("method_refs"),"symbol")),pair,[](const auto&,const auto& r,const auto&){
   CHECK(r.rows.size()==4);unsigned combinations=0;for(const auto& row:r.rows){CHECK(row.links.size()==1);combinations|=1u<<(2*row.links[0].left.source_index+row.links[0].right.source_index);}CHECK(combinations==15);
  });
  run("symbol owner and full member signature distinguish shared fields",query_json(join(scan("field_defs"),scan("field_refs"),"symbol")),one,[](const auto&,const auto& r,const auto&){
   const std::array<uint32_t,3> refs{1,0,2};CHECK(r.rows.size()==3);for(size_t i=0;i<3;++i)CHECK(r.rows[i].links[0].right.ordinal==refs[i]);
  });
  run("string symbols retain cross source pairs",query_json(join(scan("string_values",R"({"value":"shared"})"),scan("string_values",R"({"value":"shared"})"),"symbol")),pair,[](const auto&,const auto& r,const auto&){CHECK(r.rows.size()==4);});
  const auto external=scan("field_refs",R"({"has_local_definition":false})"),unknown=scan("field_refs",R"({"flags_contains":8})");
  run("semijoin matching unknown remains unknown",query_json(join(external,unknown,"same_entity","semi_join")),one,[](const auto&,const auto& r,const auto& progress){CHECK(r.rows.empty()&&progress.profile.unknown_rows==1&&progress.scope_complete&&!progress.scope_derived_unknown);});
  run("true right witness dominates unknown",query_json(join(external,unite({unknown,external}),"same_entity","semi_join")),one,[](const auto& plan,const auto& r,const auto& progress){
   CHECK(r.rows.size()==1&&progress.profile.unknown_rows==0&&r.rows[0].method_ordinal==3&&r.rows[0].links.size()>=1);
   const auto& root=plan.relations[plan.relation_root];const auto& right_union=plan.relations[root.children[1]];
   const auto right_true_node=plan.relations[right_union.children[1]].stable_id;
   CHECK(std::any_of(r.rows[0].witnesses.begin(),r.rows[0].witnesses.end(),[&](const auto& w){return w.relation_node==right_true_node&&w.entity_relation==query::Relation::field_refs&&w.entity_ordinal==3&&w.matched==1;}));
  });
  const auto scoped_external=scan("field_refs",R"({"has_local_definition":false})","left"),absent=scan("field_refs",R"({"name":"missing"})");
  run("missing right scope makes unmatched left unknown",query_json(join(scoped_external,absent,"same_entity","semi_join")),{std::span(catalogs).first(1),std::span(slots).first(1),false},[](const auto&,const auto& r,const auto& progress){CHECK(r.rows.empty()&&progress.profile.unknown_rows==1&&!progress.scope_complete&&progress.scope_derived_unknown);});
  run("known empty right scope proves unmatched",query_json(join(scoped_external,scan("field_refs",R"({"name":"missing"})","left"),"same_entity","semi_join")),{std::span(catalogs).first(1),std::span(slots).first(1),false},[](const auto&,const auto& r,const auto& progress){CHECK(r.rows.empty()&&progress.profile.unknown_rows==0&&progress.scope_complete&&!progress.scope_derived_unknown);});
  run("inner join missing right does not invent endpoint",query_json(join(scoped_external,absent,"same_entity")),{std::span(catalogs).first(1),std::span(slots).first(1),false},[](const auto&,const auto& r,const auto& progress){CHECK(r.rows.empty()&&!progress.scope_complete);});
  // The original fixture SHA-256 and the modified fixture's SHA-1, Adler-32 and
  // SHA-256 were precomputed independently with Python hashlib and zlib. The
  // metadata reader itself does not verify DEX checksums or ART loadability.
  CHECK(bytes.size()==804&&sha256<>(bytes)=="e1059582b6c893690880403d00f6b5be8dfceb7be282793e2117bdf15b14e77a");
  auto altered_bytes=bytes;
  const std::array<uint8_t,8> original_data{1,1,0,0,1,9,0,1},changed_data{2,0,0,0,0,9,1,9};
  CHECK(std::equal(original_data.begin(),original_data.end(),altered_bytes.begin()+607));
  std::copy(changed_data.begin(),changed_data.end(),altered_bytes.begin()+607);
  const std::array<uint8_t,24> checksum_and_signature{0xa7,0x79,0xfd,0x87,0xa6,0xdb,0x29,0x98,0x0f,0x96,0xbe,0xd2,0x87,0x44,0x6f,0x08,0x98,0x9d,0x64,0x5a,0xa5,0x43,0xf0,0xe4};
  std::copy(checksum_and_signature.begin(),checksum_and_signature.end(),altered_bytes.begin()+8);
  CHECK(sha256<>(altered_bytes)=="9f4589fa8667801cbbdc1f3247ecc17618645845517d5adb650a9ffe888c587a");
  auto altered=read_metadata(altered_bytes,&facts_memory);
  CHECK(altered.field_definitions.size()==3&&altered.field_definitions[0].field_ref_index==0&&altered.field_definitions[0].access_flags==9);
  const std::array<reference::SourceView,2> completed_sources{{{0,0,&catalog,bytes},{1,1,&altered,altered_bytes}}};
  const auto owner_base=scan("field_defs",R"({"owner":"Lcatalog/Base;"})","left");
  const auto matching_static=scan("field_defs",R"({"flags_contains":8})");
  const auto capped_owner=group({join(owner_base,matching_static,"symbol")},R"(,"max":1)");
  run("incomplete inner join cannot prove max-bounded group exists",query_json(capped_owner,R"(,"intent":"exists")"),
      {std::span(catalogs).first(1),std::span(slots).first(1),false},[](const auto&,const auto& r,const auto& progress){
   CHECK(r.rows.empty()&&progress.profile.unknown_rows==1&&!progress.scope_complete&&progress.scope_derived_unknown);
  });
  run("completed second source invalidates max-bounded group",query_json(capped_owner,R"(,"intent":"exists")"),
      {completed_sources,slots,true},[](const auto&,const auto& r,const auto& progress){
   CHECK(r.rows.empty()&&progress.profile.unknown_rows==0&&progress.scope_complete&&progress.visited==progress.total&&!progress.scope_derived_unknown);
  });
  run("unscoped incomplete group stays unknown",query_json(group({scan("field_defs",R"({"owner":"Lcatalog/Base;"})")},R"(,"min":2,"max":2)")),
      {std::span(catalogs).first(1),std::span(slots).first(1),false},[](const auto&,const auto& r,const auto& progress){CHECK(r.rows.empty()&&progress.profile.unknown_rows==1&&!progress.scope_complete&&progress.scope_derived_unknown);});
  run("explicit complete scan restores group certainty",query_json(group({owner_base},R"(,"min":2,"max":2)")),
      {std::span(catalogs).first(1),std::span(slots).first(1),false},[](const auto&,const auto& r,const auto& progress){CHECK(r.rows.size()==1&&r.rows[0].method_ordinal==3&&progress.profile.unknown_rows==0&&progress.scope_complete&&!progress.scope_derived_unknown);});
  run("known group above max is rejected even with incomplete scope",query_json(group({scan("field_defs",R"({"owner":"Lcatalog/Base;"})")},R"(,"min":0,"max":1)")),
      {std::span(catalogs).first(1),std::span(slots).first(1),false},[](const auto&,const auto& r,const auto& progress){CHECK(r.rows.empty()&&progress.profile.unknown_rows==0&&!progress.scope_complete&&!progress.scope_derived_unknown);});
  const auto uses=scan("method_defs",R"({"name":"uses"})"),quiet=scan("method_defs",R"({"name":"quiet"})");
  const auto grouped=group({label(join(uses,uses,"same_entity"),"A"),label(join(quiet,quiet,"same_entity"),"B")},R"(,"min":2,"max":2,"required_roles":["A","B"],"role_policy":"distinct")");
  run("group after join retains distinct roles and edges",query_json(grouped),method_data,[](const auto& p,const auto& r,const auto&){
   CHECK(r.rows.size()==1&&r.rows[0].relation==query::Relation::class_defs&&r.rows[0].links.size()==2);
   CHECK(binding(p,r.rows[0],"A",{0,2,query::Relation::method_defs},{})&&binding(p,r.rows[0],"B",{0,1,query::Relation::method_defs},{}));
  });
  const auto child_field=scan("field_defs",R"({"owner":"Lcatalog/Child;","name":"shared"})");
  const auto right_group=group({label(child_field,"F"),label(method,"M")},R"(,"min":2,"max":2,"required_roles":["F","M"],"role_policy":"distinct")");
  run("semijoin retains right group proof but not its tuple bindings",query_json(join(method,unite({right_group,right_group}),"local_owner","semi_join"),R"(,"unique_by":"tuple")"),one,[](const auto& plan,const auto& r,const auto& progress){
   CHECK(r.rows.size()==1&&progress.graph->identity_count==1&&progress.profile.unknown_rows==0);
   const auto& row=r.rows[0];const auto node=progress.graph->root_node;CHECK(row.bindings.empty()&&row.links.size()==1&&row.proof_bindings.size()==5);
   CHECK(row.links[0].node==node&&row.links[0].right==(reference::EntityKey{0,4,query::Relation::class_defs}));
   CHECK(proof_binding(plan,row,node,"",{0,4,query::Relation::class_defs},{1}));
   CHECK(proof_binding(plan,row,node,"",{0,2,query::Relation::field_defs},{1})&&proof_binding(plan,row,node,"F",{0,2,query::Relation::field_defs},{1}));
   CHECK(proof_binding(plan,row,node,"",{0,0,query::Relation::method_defs},{1})&&proof_binding(plan,row,node,"M",{0,0,query::Relation::method_defs},{1}));
  });
  const auto external_role=label(scan("method_refs",R"({"name":"abstractMethod"})"),"outside");
  run("group shared role cannot be supplied by joined nonmember reference",query_json(group({join(method,external_role,"local_definition")},R"(,"required_roles":["outside"],"role_policy":"shared")")),one,[](const auto&,const auto& r,const auto& progress){CHECK(r.rows.empty()&&progress.scope_complete&&progress.profile.unknown_rows==0);});
  const auto left_method=scan("method_defs",R"({"name":"abstractMethod"})","left"),other_method=label(scan("method_defs",R"({"name":"abstractMethod"})","right"),"outside");
  run("group role cannot be borrowed from another occurrence",query_json(group({join(left_method,other_method,"symbol")},R"(,"required_roles":["outside"],"role_policy":"shared")")),pair,[](const auto&,const auto& r,const auto& progress){CHECK(r.rows.empty()&&progress.scope_complete);});
  const auto inner_semi=join(method,method,"same_entity","semi_join");
  const auto nested_left_semi=join(inner_semi,method,"same_entity","semi_join");
  run("nested semijoin left proof keeps both sides",query_json(nested_left_semi,R"(,"unique_by":"tuple")"),one,[](const auto& plan,const auto& r,const auto& progress){
   CHECK(r.rows.size()==1&&progress.graph->identity_count==1&&r.rows[0].bindings.empty());const auto& row=r.rows[0];
   const auto& root=plan.relations[plan.relation_root];const auto inner=plan.relations[root.children[0]].stable_id;
   const reference::EntityKey key{0,0,query::Relation::method_defs};
   CHECK(row.proof_bindings.size()==2&&proof_binding(plan,row,inner,"",key,{0,1})&&proof_binding(plan,row,root.stable_id,"",key,{1}));
  });
  const auto nested_right_semi=join(method,inner_semi,"same_entity","semi_join");
  run("nested semijoin right proof keeps both sides",query_json(nested_right_semi),one,[](const auto& plan,const auto& r,const auto&){
   CHECK(r.rows.size()==1&&r.rows[0].bindings.empty());const auto& row=r.rows[0];const auto& root=plan.relations[plan.relation_root];
   const auto inner=plan.relations[root.children[1]].stable_id;const reference::EntityKey key{0,0,query::Relation::method_defs};
   CHECK(row.proof_bindings.size()==2&&proof_binding(plan,row,inner,"",key,{1,1})&&proof_binding(plan,row,root.stable_id,"",key,{1}));
  });
  run("join outside nested semijoin prefixes full proof tree",query_json(join(nested_left_semi,method,"same_entity")),one,[](const auto& plan,const auto& r,const auto&){
   CHECK(r.rows.size()==1);const auto& row=r.rows[0];const auto& outer=plan.relations[plan.relation_root];const auto& middle=plan.relations[outer.children[0]];
   const auto inner=plan.relations[middle.children[0]].stable_id;const reference::EntityKey key{0,0,query::Relation::method_defs};
   CHECK(row.proof_bindings.size()==2&&proof_binding(plan,row,inner,"",key,{0,0,1})&&proof_binding(plan,row,middle.stable_id,"",key,{0,1}));
  });
  rejects(query_json(join(scan("field_defs"),scan("method_defs"),"same_entity")));
  rejects(query_json(join(scan("field_defs"),scan("method_refs"),"local_definition")));
  rejects(query_json(join(scan("class_defs"),scan("field_defs"),"local_owner")));
  rejects(query_json(join(scan("string_values"),scan("type_refs"),"symbol")));
  rejects(query_json(join(method,method,"invented")));
  limited(query_json(join(twice,thrice,"same_entity"),R"(,"max_intermediate_rows":5)"),one);
  limited(query_json(join(twice,thrice,"same_entity"),R"(,"max_work":1)"),one);
  {
   auto plan=query::compile(query_json(join(twice,thrice,"same_entity")),&plans,&temporary);bool cancelled=false;unsigned checks=0;
   {reference::Progress progress;try{(void)reference::execute(pair,plan,progress,&execution,{[](void* c)noexcept{return ++*static_cast<unsigned*>(c)>=7;},&checks});}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::cancelled);cancelled=true;}}
   CHECK(cancelled&&execution.used==0);++cases;
  }
  {
   auto plan=query::compile(query_json(join(twice,thrice,"same_entity")),&plans,&temporary);bool exhausted=false;execution.limit=16;
   {reference::Progress progress;try{(void)reference::execute(one,plan,progress,&execution);}catch(const std::bad_alloc&){exhausted=true;}}
   execution.limit=std::numeric_limits<size_t>::max();CHECK(exhausted&&execution.used==0);++cases;
  }
  {
   const auto old=query::compile(R"({"schema_version":1,"relation":"method_defs","where":{"return_type":"I","parameters":[],"using_strings":{"all":[{"op":"exact","value":"quality settings:"}]}},"intent":"unique","max_results":2,"evidence_profile":"minimal"})",&plans,&temporary);
   CHECK(old.id=="query:v1:283ae5fd16c5c58a2c7690abdb0b7cfb3a8edf7644c63cf5b43956967d8e4a63");
   const auto entity=query::compile(R"({"schema_version":1,"relation":"field_defs"})",&plans,&temporary);
   CHECK(entity.id=="query:v2:6d119cc5d61d304582f915944e04db2a8b482aad25d7a694f6024907308a185a");
   const auto original_graph=query::compile(R"({"schema_version":1,"relation":{"op":"scan","relation":"method_defs"}})",&plans,&temporary);
   CHECK(original_graph.id=="query:v3:d3b9d916113de0403046db0ee9b5b4247591d5ccc2904e17809eadace97eff23");
   const auto a=query::compile(query_json(join(scan("field_defs"),scan("field_refs"),"local_definition")),&plans,&temporary);
   const auto b=query::compile(query_json(join(scan("field_defs"),scan("field_refs"),"symbol")),&plans,&temporary);
   const auto c=query::compile(query_json(join(scan("field_refs"),scan("field_defs"),"symbol")),&plans,&temporary);
   CHECK(a.id!=b.id&&b.id!=c.id);++cases;
  }
  CHECK(plans.used==0&&temporary.used==0&&execution.used==0);
 }catch(...){std::pmr::set_default_resource(previous);throw;}
 std::pmr::set_default_resource(previous);CHECK(facts_memory.used==0);
 std::cout<<"PASS Join/SemiJoin: "<<cases<<" cases; tuple sides, bag multiplicity, local/global identity, owner, unknown scope, grouping, PMR and QueryID compatibility\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
