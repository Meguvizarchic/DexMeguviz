#include "query/ir.hpp"
#include "execution/reference/evaluate.hpp"
#include "format/instructions/decoder.hpp"
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory_resource>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
using namespace dexmeguviz;
#define CHECK(x) do{if(!(x))throw std::runtime_error("use query check "+std::to_string(__LINE__)+": " #x);}while(0)
struct Counter:std::pmr::memory_resource{
 size_t used=0,limit=SIZE_MAX;
 void* do_allocate(size_t n,size_t a)override{if(n>limit-used)throw std::bad_alloc();auto p=std::pmr::new_delete_resource()->allocate(n,a);used+=n;return p;}
 void do_deallocate(void* p,size_t n,size_t a)override{used-=n;std::pmr::new_delete_resource()->deallocate(p,n,a);}
 bool do_is_equal(const std::pmr::memory_resource& x)const noexcept override{return this==&x;}
};
static std::vector<uint8_t> load(const std::filesystem::path& path){std::ifstream in(path,std::ios::binary);CHECK(in.good());return {(std::istreambuf_iterator<char>(in)),{}};}
static std::string scan(std::string_view relation,std::string_view where={}){
 return "{\"op\":\"scan\",\"relation\":\""+std::string(relation)+"\""+(where.empty()?"":",\"where\":"+std::string(where))+"}";
}
static std::string join(std::string_view a,std::string_view b,std::string_view key){return "{\"op\":\"join\",\"left\":"+std::string(a)+",\"right\":"+std::string(b)+",\"on\":\""+std::string(key)+"\"}";}
static std::string query_json(std::string_view relation,std::string_view options={}){return "{\"schema_version\":1,\"relation\":"+std::string(relation)+std::string(options)+"}";}
int main(int argc,char** argv){try{
 CHECK(argc==2);const std::filesystem::path root(argv[1]);Counter facts_memory,plan_memory,temporary,execution;unsigned cases=0;
 const auto twice=load(root/"generated/use_relations/two-invokes.dex"),fields=load(root/"generated/use_relations/field-read-write.dex"),
 strings=load(root/"generated/use_relations/string-normal-jumbo.dex"),bad=load(root/"generated/use_relations/valid-then-corrupt.dex"),
 domains=load(root/"generated/method_facts/invoke-domains-038.dex");
 auto* previous=std::pmr::set_default_resource(std::pmr::null_memory_resource());
 try{
  auto m_twice=read_metadata(twice,&facts_memory),m_fields=read_metadata(fields,&facts_memory),m_strings=read_metadata(strings,&facts_memory),m_bad=read_metadata(bad,&facts_memory),m_domains=read_metadata(domains,&facts_memory);
  const std::array<std::string_view,2> slots{"left","right"};
  std::array<reference::SourceView,2> a{{{0,0,&m_twice,twice},{1,1,&m_twice,twice}}};
  const reference::DatasetView one{std::span(a).first(1),std::span(slots).first(1),true},pair{a,slots,true};
  auto dataset=[&](const Facts& facts,const std::vector<uint8_t>& bytes,auto callback){std::array<reference::SourceView,1> src{{{0,0,&facts,bytes}}};callback(reference::DatasetView{src,std::span(slots).first(1),true});};
  auto run=[&](std::string_view name,const std::string& input,reference::DatasetView data,auto verify){
   try{{auto plan=query::compile(input,&plan_memory,&temporary);reference::Progress progress;auto result=reference::execute(data,plan,progress,&execution);CHECK(plan.contains_uses&&plan.id.starts_with("query:v4:")&&progress.graph);verify(plan,result,progress);}
    CHECK(plan_memory.used==0&&temporary.used==0&&execution.used==0);++cases;
   }catch(...){std::cerr<<"case: "<<name<<'\n';throw;}
  };
  const auto events=scan("invoke_sites");
  run("same caller distinct PCs",query_json(events),one,[](const auto&,const auto& result,const auto& progress){
   CHECK(result.rows.size()==2&&progress.total==4&&progress.visited==4&&progress.graph->method_total==4&&progress.graph->method_visited==4&&progress.graph->entity_total==0);
   CHECK(progress.graph->events_collected==2&&result.uses.size()==2);
   for(uint32_t i=0;i<2;++i){const auto& row=result.rows[i];CHECK(row.relation==query::Relation::invoke_sites&&row.method_ordinal==2&&row.dex_pc==3*i);
    const auto& event=reference::use_record(result,row.key());CHECK(event.key.source_index==0&&event.key.caller_ordinal==2&&event.key.dex_pc==3*i&&event.caller_method_ref==3&&event.code_offset==416&&event.target_index==4&&event.opcode==0x71);
    CHECK(event.target_domain==facts::TargetDomain::method_ref&&event.extra_proto==UINT32_MAX);}
  });
  run("two source occurrences",query_json(events),pair,[](const auto&,const auto& result,const auto& progress){CHECK(result.rows.size()==4&&result.uses.size()==4&&progress.graph->method_total==8);CHECK(result.rows[0].source_index==0&&result.rows[2].source_index==1);});
  run("event unique uses pc",query_json(events,R"(,"intent":"unique")"),one,[](const auto&,const auto& result,const auto& progress){CHECK(result.rows.size()==2&&result.rows[0].dex_pc!=result.rows[1].dex_pc&&progress.graph->identity_count==2);});
  run("event pc predicate",query_json(scan("invoke_sites",R"({"pc":3,"caller_name":"uses","opcode":113,"target_domain":"method_ref"})")),one,[](const auto&,const auto& r,const auto&){CHECK(r.rows.size()==1&&r.rows[0].dex_pc==3);});
  run("filtered scan counts all raw events",query_json(scan("invoke_sites",R"({"pc":3})")),one,[](const auto&,const auto& r,const auto& p){CHECK(r.rows.size()==1&&p.graph->events_collected==2);});
  const auto event_union="{\"op\":\"union\",\"semantics\":\"set\",\"inputs\":["+events+","+events+"]}";
  run("duplicate event scans deduplicate identity but count work",query_json(event_union),one,[](const auto&,const auto& r,const auto& p){CHECK(r.rows.size()==2&&r.uses.size()==2&&p.graph->method_total==8&&p.graph->method_visited==8&&p.graph->events_collected==4);});
  run("event pc sort",query_json(events,R"(,"intent":"top_n","max_results":1,"order_by":[{"field":"pc","direction":"desc"}])"),one,[](const auto&,const auto& r,const auto& p){CHECK(r.rows.size()==1&&r.rows[0].dex_pc==3&&p.order_verified);});
  dataset(m_fields,fields,[&](auto data){run("field read/write",query_json(scan("field_uses")),data,[](const auto&,const auto& r,const auto&){CHECK(r.rows.size()==2&&r.rows[0].dex_pc==0&&r.rows[1].dex_pc==2);CHECK(reference::use_record(r,r.rows[0].key()).opcode==0x60&&reference::use_record(r,r.rows[1].key()).opcode==0x67);});});
  dataset(m_strings,strings,[&](auto data){run("string normal/jumbo",query_json(scan("string_uses")),data,[](const auto&,const auto& r,const auto&){CHECK(r.rows.size()==2&&r.rows[0].dex_pc==0&&r.rows[1].dex_pc==2);CHECK(reference::use_record(r,r.rows[0].key()).target_index==10&&reference::use_record(r,r.rows[1].key()).target_index==10);});});
  dataset(m_domains,domains,[&](auto data){
   run("poly/custom domains",query_json(events),data,[](const auto&,const auto& r,const auto&){CHECK(r.rows.size()==2);const auto& p=reference::use_record(r,r.rows[0].key());const auto& c=reference::use_record(r,r.rows[1].key());CHECK(p.key.dex_pc==0&&p.target_domain==facts::TargetDomain::method_and_proto&&p.extra_proto==0);CHECK(c.key.dex_pc==4&&c.target_domain==facts::TargetDomain::call_site&&c.target_index==0);});
   run("custom not method_ref",query_json(join(events,scan("method_refs"),"target_ref")),data,[](const auto&,const auto& r,const auto&){CHECK(r.rows.size()==1&&r.rows[0].dex_pc==0&&r.rows[0].links.size()==1&&r.rows[0].links[0].right.ordinal==4);});
  });
  run("event target ref join",query_json(join(events,scan("method_refs"),"target_ref")),one,[](const auto&,const auto& r,const auto& p){CHECK(r.rows.size()==2&&r.rows[0].links[0].right.ordinal==4&&r.rows[1].links[0].right.ordinal==4);CHECK(p.graph->method_total==4&&p.graph->entity_total==5);});
  run("target local join never crosses source",query_json(join(events,scan("method_refs"),"target_ref")),pair,[](const auto&,const auto& r,const auto&){CHECK(r.rows.size()==4);for(const auto& row:r.rows)CHECK(row.links[0].left.source_index==row.links[0].right.source_index);});
  const auto callers=scan("method_defs",R"({"name":"uses"})");
  run("caller join preserves two pairs",query_json(join(callers,events,"caller")),one,[](const auto&,const auto& r,const auto&){CHECK(r.rows.size()==2&&r.rows[0].relation==query::Relation::method_defs&&r.rows[0].links[0].right.dex_pc==0&&r.rows[1].links[0].right.dex_pc==3);});
  run("caller unique entity",query_json(join(callers,events,"caller"),R"(,"intent":"unique","unique_by":"entity")"),one,[](const auto&,const auto& r,const auto& p){CHECK(r.rows.size()==1&&p.graph->identity_count==1);});
  run("caller unique tuple",query_json(join(callers,events,"caller"),R"(,"intent":"unique","unique_by":"tuple")"),one,[](const auto&,const auto& r,const auto& p){CHECK(r.rows.size()==2&&p.graph->identity_count==2);});
  dataset(m_bad,bad,[&](auto data){for(const auto& expr:{query_json(events),query_json(scan("string_uses","false"))}){auto plan=query::compile(expr,&plan_memory,&temporary);reference::Progress p;bool corrupt=false;try{(void)reference::execute(data,plan,p,&execution);}catch(const instructions::DecodeError& e){CHECK(e.code==instructions::DecodeCode::corrupt&&e.dex_pc==5);corrupt=true;}CHECK(corrupt);++cases;}});
  for(const auto& input:{query_json(events,R"(,"max_intermediate_rows":1)"),query_json(events,R"(,"max_work":1)")}){auto plan=query::compile(input,&plan_memory,&temporary);reference::Progress p;bool limited=false;try{(void)reference::execute(one,plan,p,&execution);}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::budget);limited=true;}catch(const facts::UseScanError& e){CHECK(e.code==facts::UseScanError::Code::budget);limited=true;}catch(const instructions::DecodeError& e){CHECK(e.code==instructions::DecodeCode::budget);limited=true;}CHECK(limited);++cases;}
  for(const auto& input:{R"({"schema_version":1,"relation":"invoke_sites"})",R"({"schema_version":1,"relation":{"op":"scan","relation":"field_uses","where":{"target_domain":"method_ref"}}})",R"({"schema_version":1,"relation":{"op":"join","on":"target_ref","left":{"op":"scan","relation":"string_uses"},"right":{"op":"scan","relation":"method_refs"}}})"}){
   bool rejected=false;try{(void)query::compile(input,&plan_memory,&temporary);}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::unsupported);rejected=true;}CHECK(rejected);++cases;
  }
  CHECK(plan_memory.used==0&&temporary.used==0&&execution.used==0);
 }catch(...){std::pmr::set_default_resource(previous);throw;}
 std::pmr::set_default_resource(previous);CHECK(facts_memory.used==0);
 std::cout<<"PASS use QueryIR: "<<cases<<" cases; PC identity, typed domains, source scope, caller/target joins, full method failure and budgets\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
