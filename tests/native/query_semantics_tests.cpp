#include "query/ir.hpp"
#include "execution/reference/evaluate.hpp"
#include "format/instructions/decoder.hpp"
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>
using namespace dexmeguviz;
#define CHECK(x) do{if(!(x))throw std::runtime_error("reference check "+std::to_string(__LINE__)+": " #x);}while(0)
struct Counter:std::pmr::memory_resource{
 size_t used=0;
 void* do_allocate(size_t n,size_t a)override{auto p=std::pmr::new_delete_resource()->allocate(n,a);used+=n;return p;}
 void do_deallocate(void* p,size_t n,size_t a)override{used-=n;std::pmr::new_delete_resource()->deallocate(p,n,a);}
 bool do_is_equal(const std::pmr::memory_resource& r)const noexcept override{return this==&r;}
};
std::vector<uint8_t> load(const std::filesystem::path& p){std::ifstream f(p,std::ios::binary);CHECK(f.good());return {(std::istreambuf_iterator<char>(f)),{}};}
int main(int argc,char** argv){try{
 CHECK(argc==2);const std::filesystem::path root(argv[1]);Counter facts_memory,plans,temporary,execution;
 auto bytes=load(root/"generated/method_facts/method-uses.dex");auto metadata=read_metadata(bytes,&facts_memory);
 std::array<reference::SourceView,2> sources{{{0,0,&metadata,bytes},{1,1,&metadata,bytes}}};
 const std::array<std::string_view,2> slots{"left","right"};reference::DatasetView data{sources,slots,true};
 unsigned cases=0;
 auto run=[&](std::string_view json,reference::DatasetView view,auto check){
  {auto plan=query::compile(json,&plans,&temporary);reference::Progress progress;auto result=reference::execute(view,plan,progress,&execution);check(plan,result,progress);}
  CHECK(plans.used==0&&temporary.used==0&&execution.used==0);++cases;
 };
 const reference::DatasetView one{{sources.data(),1},{slots.data(),1},true};
 run(R"({"schema_version":1,"relation":"method_defs","where":{"name":"uses","using_strings":{"all":["used-string",{"op":"contains","value":"string"}]},"invokes":{"all":[{"name":"sink"}]},"field_access":{"all":[{"type":"I","access":"read"}]}},"intent":"unique"})",one,[&](const auto&,const auto& r,const auto& p){
  CHECK(r.rows.size()==1&&metadata.methods[r.rows[0].method_ordinal].name==u"uses");CHECK(p.profile.methods_decoded==1&&p.profile.code_units==8);
  unsigned string_witnesses=0;for(auto w:r.rows[0].witnesses)if(w.kind==reference::WitnessKind::string_use){CHECK(w.dex_pc==0&&w.reference_index==10);++string_witnesses;}CHECK(string_witnesses==2);
 });
 run(R"({"schema_version":1,"relation":"method_defs","where":{"using_strings":{"all":["only-in-pool"]}}})",one,[](const auto&,const auto& r,const auto& p){CHECK(r.rows.empty()&&p.visited==p.total);});
 run(R"({"schema_version":1,"relation":"method_defs","where":{"not":{"using_strings":{"all":["only-in-pool"]}}}})",one,[](const auto&,const auto& r,const auto& p){CHECK(r.rows.size()==4&&p.profile.methods_decoded==2);});
 run(R"({"schema_version":1,"relation":"method_defs","where":{"name":"uses","using_strings":{"any":["absent-string","used-string"]}}})",one,[](const auto&,const auto& r,const auto& p){CHECK(r.rows.size()==1&&p.profile.methods_decoded==1);});
 run(R"({"schema_version":1,"relation":"method_defs","where":{"name":"uses","flags_contains":8},"intent":"unique"})",data,[](const auto&,const auto& r,const auto&){CHECK(r.rows.size()==2&&r.rows[0].source_index!=r.rows[1].source_index);});
 run(R"({"schema_version":1,"relation":"method_defs","where":{"flags_exact":8}})",one,[](const auto&,const auto& r,const auto&){CHECK(r.rows.empty());});
 run(R"({"schema_version":1,"relation":"method_defs","where":{"declares_fields":{"where":{"type":"I"},"min":1,"max":1}}})",one,[](const auto&,const auto& r,const auto& p){CHECK(r.rows.size()==4&&p.profile.methods_decoded==0);});
 run(R"({"schema_version":1,"relation":"method_defs","scope":{"slots":["left"]},"where":{"name":"uses"},"intent":"unique"})",{sources,slots,false},[](const auto&,const auto& r,const auto& p){CHECK(r.rows.size()==1&&r.scope_sources.size()==1&&p.scope_complete&&p.visited==p.total);});
 run(R"({"schema_version":1,"relation":"method_defs","where":{"name":"uses"},"intent":"unique"})",{std::span(sources).first(1),std::span(slots).first(1),false},[](const auto&,const auto& r,const auto& p){CHECK(r.rows.size()==1&&!p.scope_complete);});
 run(R"({"schema_version":1,"relation":"method_defs","max_results":1})",one,[](const auto&,const auto& r,const auto&){CHECK(r.result_limit&&r.rows.size()==1);});
 run(R"({"schema_version":1,"relation":"method_defs","scope":{"slots":[]}})",data,[](const auto&,const auto& r,const auto& p){CHECK(r.rows.empty()&&p.total==0&&p.scope_complete);});
 auto first=load(root/"generated/minimal.dex"),late=load(root/"generated/query-ir/late-better.dex");auto first_facts=read_metadata(first,&facts_memory),late_facts=read_metadata(late,&facts_memory);
 std::array<reference::SourceView,2> ranking{{{0,0,&first_facts,first},{1,1,&late_facts,late}}};
 run(R"({"schema_version":1,"relation":"method_defs","intent":"top_n","max_results":1,"order_by":[{"field":"name","direction":"desc"}]})",{ranking,slots,true},[&](const auto&,const auto& r,const auto& p){CHECK(r.rows.size()==1&&r.rows[0].source_index==1);CHECK(late_facts.methods[r.rows[0].method_ordinal].name==u"zzzzzz"&&p.order_verified&&p.visited==4);});
 run(R"({"schema_version":1,"relation":"method_defs","intent":"top_n","max_results":1,"order_by":[{"field":"name","direction":"desc"}]})",{ranking,slots,false},[](const auto&,const auto& r,const auto& p){CHECK(r.rows.size()==1&&!p.order_verified);});
 for(auto json:{R"({"schema_version":1,"relation":"method_defs","scope":{"slots":["missing"]}})",R"({"schema_version":1,"relation":"method_defs","max_work":1})"}){
  auto plan=query::compile(json,&plans,&temporary);reference::Progress p;bool failed=false;try{(void)reference::execute(data,plan,p,&execution);}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::source_mismatch||e.code==query::ErrorCode::budget);failed=true;}CHECK(failed&&execution.used==0);++cases;
 }
 auto bad=bytes;uint32_t uses=0;while(metadata.methods[uses].name!=u"uses")++uses;bad[metadata.methods[uses].code_offset+16]=0x73;
 auto bad_facts=read_metadata(bad,&facts_memory);std::array<reference::SourceView,1> bad_source{{{0,0,&bad_facts,bad}}};reference::DatasetView bad_data{bad_source,std::span(slots).first(1),true};
 run(R"({"schema_version":1,"relation":"method_defs","where":{"name":"uses"}})",bad_data,[](const auto&,const auto& r,const auto& p){CHECK(r.rows.size()==1&&p.profile.methods_decoded==0);});
 {auto plan=query::compile(R"({"schema_version":1,"relation":"method_defs","where":{"name":"uses","not":{"using_strings":{"all":["used-string"]}}}})",&plans,&temporary);reference::Progress p;bool failed=false;try{(void)reference::execute(bad_data,plan,p,&execution);}catch(const instructions::DecodeError&){failed=true;}CHECK(failed&&execution.used==0);++cases;}
 {auto plan=query::compile(R"({"schema_version":1,"relation":"method_defs"})",&plans,&temporary);reference::Progress p;unsigned calls=0;bool stopped=false;try{(void)reference::execute(one,plan,p,&execution,{[](void* v)noexcept{return ++*static_cast<unsigned*>(v)>=3;},&calls});}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::cancelled);stopped=true;}CHECK(stopped&&execution.used==0);++cases;}
 CHECK(plans.used==0&&execution.used==0&&temporary.used==0);
 std::cout<<"PASS reference QueryIR: "<<cases<<" cases; same-method all/any/not, instruction evidence, no false absence, scope, duplicates, global TopN, quotas and cancellation\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
