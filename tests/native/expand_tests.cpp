#include "execution/reference/evaluate.hpp"
#include "format/instructions/decoder.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <memory_resource>
#include <stdexcept>
#include <string>
#include <vector>
using namespace dexmeguviz;
namespace q=dexmeguviz::query;namespace r=dexmeguviz::reference;
#define CHECK(x) do{if(!(x))throw std::runtime_error("expand check " + std::to_string(__LINE__) + ": " #x);}while(0)
struct Data {
 std::vector<std::vector<uint8_t>> bytes;std::vector<std::unique_ptr<Facts>> facts;
 std::vector<std::string> names;std::vector<std::string_view> slots;std::vector<r::SourceView> sources;
 explicit Data(const std::filesystem::path& dir,std::initializer_list<const char*> files,bool corrupt=false){
  bytes.reserve(files.size());facts.reserve(files.size());names.reserve(files.size());slots.reserve(files.size());sources.reserve(files.size());
  for(const auto* file:files){std::ifstream in(dir/file,std::ios::binary);CHECK(in.good());bytes.emplace_back(std::istreambuf_iterator<char>(in),std::istreambuf_iterator<char>());}
  if(corrupt){CHECK(bytes[0].size()>282);bytes[0][282]=0x3e;}
  for(size_t i=0;i<bytes.size();++i){facts.push_back(std::make_unique<Facts>(read_metadata(bytes[i])));names.push_back("s"+std::to_string(i));}
  for(size_t i=0;i<bytes.size();++i){slots.push_back(names[i]);sources.push_back({static_cast<uint32_t>(i),static_cast<uint32_t>(i),facts[i].get(),bytes[i]});}
 }
 r::DatasetView view(bool complete=true)const{return {sources,slots,complete};}
};
static q::Plan plan(std::pmr::memory_resource* mem,uint32_t seed,uint32_t min,uint32_t max,q::ExpandOutput output=q::ExpandOutput::paths,q::ExpandDirection dir=q::ExpandDirection::outgoing){
 q::Plan p(mem);p.nodes.emplace_back(mem);p.nodes.back().kind=q::Kind::yes;
 p.relations.emplace_back(mem);auto& scan=p.relations.back();scan.op=q::RelOp::scan;scan.relation=q::Relation::method_defs;scan.predicate=0;scan.stable_id=0;scan.explicit_scope=true;scan.scope_slots.emplace_back("s"+std::to_string(seed));
 p.relations.emplace_back(mem);auto& ex=p.relations.back();ex.op=q::RelOp::bounded_expand;ex.relation=q::Relation::method_defs;ex.stable_id=1;ex.children.push_back(0);ex.expand_min_depth=min;ex.expand_max_depth=max;ex.expand_output=output;ex.expand_direction=dir;ex.expand_max_paths=1000;ex.expand_max_edges=1000;ex.expand_max_visited=1000;
 p.relation_root=1;p.relation=q::Relation::method_defs;p.contains_expand=true;p.demand_mask=2;p.unique_identity=q::Identity::tuple;p.max_work=10000000;return p;
}
int main(int argc,char** argv){try{
 CHECK(argc==2);std::pmr::unsynchronized_pool_resource mem;const std::filesystem::path dir(argv[1]);unsigned cases=0;
 Data amb(dir,{"amb-a.dex","amb-b1.dex","amb-b2.dex","amb-c1.dex","amb-c2.dex","amb-overload.dex"});
 {
  auto p=plan(&mem,0,2,2);r::Progress progress;auto out=r::execute(amb.view(),p,progress,&mem);CHECK(out.rows.size()==4&&out.frontiers.empty());
  unsigned first0=0,first3=0,c1=0,c2=0;for(const auto& row:out.rows){CHECK(row.expand_paths.size()==1&&row.expand_path_identity);const auto& path=row.expand_paths[0];CHECK(path.hops.size()==2&&path.seed.source_index==0&&path.endpoint==row.key());
   CHECK(path.hops[0].caller.source_index==0&&path.hops[0].target_method_ref==1&&path.hops[0].candidate_count==2&&path.hops[0].resolution_complete);
   CHECK(path.hops[0].dex_pc==0||path.hops[0].dex_pc==3);first0+=path.hops[0].dex_pc==0;first3+=path.hops[0].dex_pc==3;
   CHECK(path.hops[1].dex_pc==0&&path.hops[1].target_method_ref==1&&path.hops[1].candidate_count==1);c1+=row.source_index==3;c2+=row.source_index==4;}
  CHECK(first0==2&&first3==2&&c1==2&&c2==2&&progress.graph->identity_count==4);++cases;
 }
 {
  auto p=plan(&mem,0,2,2,q::ExpandOutput::endpoints);r::Progress progress;auto out=r::execute(amb.view(),p,progress,&mem);CHECK(out.rows.size()==2);
  for(const auto& row:out.rows)CHECK(!row.expand_path_identity&&row.expand_paths.size()==2);++cases;
 }
 {
  auto p=plan(&mem,0,0,1);p.relations[0].scope_slots.emplace_back("s1");r::Progress progress;auto out=r::execute(amb.view(),p,progress,&mem);CHECK(out.rows.size()==7);
  const std::array<uint32_t,7> seeds{0,0,0,0,0,1,1};const std::array<size_t,7> depths{0,1,1,1,1,0,1};
  for(size_t i=0;i<out.rows.size();++i){const auto& path=out.rows[i].expand_paths[0];CHECK(path.seed.source_index==seeds[i]&&path.hops.size()==depths[i]);}
  CHECK(out.rows[1].expand_paths[0].hops[0].dex_pc==0&&out.rows[2].expand_paths[0].hops[0].dex_pc==0&&out.rows[3].expand_paths[0].hops[0].dex_pc==3&&out.rows[4].expand_paths[0].hops[0].dex_pc==3);++cases;
 }
 {
  auto p=plan(&mem,0,0,1,q::ExpandOutput::endpoints);p.relations[0].scope_slots.emplace_back("s1");r::Progress progress;auto out=r::execute(amb.view(),p,progress,&mem);CHECK(out.rows.size()==4);
  CHECK(out.rows[0].source_index==0&&out.rows[1].source_index==1&&out.rows[2].source_index==2&&out.rows[3].source_index==3);
  const auto& paths=out.rows[1].expand_paths;CHECK(paths.size()==3&&paths[0].seed.source_index==0&&paths[0].hops[0].dex_pc==0&&paths[1].seed.source_index==0&&paths[1].hops[0].dex_pc==3&&paths[2].seed.source_index==1&&paths[2].hops.empty());++cases;
 }
 {
  auto p=plan(&mem,0,0,1);p.relations[0].scope_slots.emplace_back("s1");p.relations[1].expand_max_paths=5;r::Progress progress;bool rejected=false;
  try{(void)r::execute(amb.view(),p,progress,&mem);}catch(const q::Error& e){CHECK(e.code==q::ErrorCode::budget);rejected=true;}CHECK(rejected);++cases;
 }
 {
  auto p=plan(&mem,0,2,2);p.intent=q::Intent::unique;r::Progress progress;auto out=r::execute(amb.view(),p,progress,&mem);CHECK(out.rows.size()==2&&progress.graph->identity_count==4);++cases;
 }
 {
  auto p=plan(&mem,0,2,2);p.intent=q::Intent::unique;p.unique_identity=q::Identity::entity;r::Progress progress;auto out=r::execute(amb.view(),p,progress,&mem);CHECK(out.rows.size()==2&&progress.graph->identity_count==2);for(const auto& row:out.rows)CHECK(row.expand_paths.size()==2);++cases;
 }
 {
  auto p=plan(&mem,3,2,2,q::ExpandOutput::paths,q::ExpandDirection::incoming);r::Progress progress;auto out=r::execute(amb.view(),p,progress,&mem);CHECK(out.rows.size()==2);
  for(const auto& row:out.rows){CHECK(row.source_index==0&&row.expand_paths.size()==1);const auto& h=row.expand_paths[0].hops;CHECK(h.size()==2&&h[0].caller.source_index==1&&h[0].resolved.source_index==3&&h[1].caller.source_index==0&&h[1].resolved.source_index==1);}CHECK(progress.graph->expands[0].reverse_builds==1);++cases;
 }
 {
  Data cycle(dir,{"cycle-a.dex","cycle-b.dex"});auto p=plan(&mem,0,2,2);r::Progress progress;auto out=r::execute(cycle.view(),p,progress,&mem);CHECK(out.rows.size()==1&&out.rows[0].source_index==0&&out.rows[0].expand_paths[0].hops.size()==2);++cases;
 }
 {
  Data diamond(dir,{"diamond-a.dex","diamond-b.dex","diamond-c.dex","diamond-d.dex"});auto p=plan(&mem,0,2,2,q::ExpandOutput::endpoints);r::Progress progress;auto out=r::execute(diamond.view(),p,progress,&mem);CHECK(out.rows.size()==1&&out.rows[0].source_index==3&&out.rows[0].expand_paths.size()==2);++cases;
 }
 {
  Data diamond(dir,{"diamond-a.dex","diamond-b.dex","diamond-c.dex","diamond-d.dex"});auto& a=*diamond.facts[0];const auto owner=a.method_refs[a.methods[0].method_index].owner;const auto saved=a.class_definition_by_type[owner];a.class_definition_by_type[owner]=UINT32_MAX;
  auto p=plan(&mem,0,0,2,q::ExpandOutput::endpoints);p.nodes.emplace_back(&mem);p.nodes.back().kind=q::Kind::flags_contains;p.nodes.back().argument=1;p.nodes.back().minimum=1;p.relations[0].predicate=1;p.relations[0].scope_slots.emplace_back("s1");p.relations[0].scope_slots.emplace_back("s2");
  r::Progress progress;auto out=r::execute(diamond.view(),p,progress,&mem);CHECK(out.rows.size()==3&&out.rows[0].source_index==1&&out.rows[1].source_index==2&&out.rows[2].source_index==3);
  CHECK(out.rows[0].expand_paths.size()==2&&out.rows[1].expand_paths.size()==2&&out.rows[2].expand_paths.size()==4);
  CHECK(out.rows[2].expand_paths[0].uncertain&&out.rows[2].expand_paths[1].uncertain&&!out.rows[2].expand_paths[2].uncertain&&!out.rows[2].expand_paths[3].uncertain);
  a.class_definition_by_type[owner]=saved;++cases;
 }
 {
  Data diamond(dir,{"diamond-a.dex","diamond-b.dex","diamond-c.dex","diamond-d.dex"});auto& a=*diamond.facts[0];const auto owner=a.method_refs[a.methods[0].method_index].owner;const auto saved=a.class_definition_by_type[owner];a.class_definition_by_type[owner]=UINT32_MAX;
  auto p=plan(&mem,0,1,2,q::ExpandOutput::endpoints);p.nodes.emplace_back(&mem);p.nodes.back().kind=q::Kind::flags_contains;p.nodes.back().argument=1;p.nodes.back().minimum=1;p.relations[0].predicate=1;p.relations[0].scope_slots.emplace_back("s1");
  p.texts.emplace_back(&mem);p.texts.back().text=u"d";p.nodes.emplace_back(&mem);p.nodes.back().kind=q::Kind::name;p.nodes.back().text=0;p.relations[1].expand_emit_predicate=2;
  r::Progress progress;auto out=r::execute(diamond.view(),p,progress,&mem);CHECK(out.rows.size()==1&&out.rows[0].source_index==3&&out.rows[0].expand_paths.size()==3);
  CHECK(out.rows[0].expand_paths[0].uncertain&&out.rows[0].expand_paths[1].uncertain&&!out.rows[0].expand_paths[2].uncertain);
  CHECK(progress.profile.unknown_rows==2&&!progress.graph->nodes[1].complete);a.class_definition_by_type[owner]=saved;++cases;
 }
 {
  auto p=plan(&mem,0,0,0);r::Progress progress;auto out=r::execute(amb.view(),p,progress,&mem);CHECK(out.rows.size()==1&&out.rows[0].source_index==0&&out.rows[0].expand_paths[0].hops.empty()&&progress.graph->expands[0].decoded_methods==0);++cases;
 }
 {
  auto p=plan(&mem,0,2,2,q::ExpandOutput::endpoints);p.labels.emplace_back("seed");p.relations.emplace_back(&mem);
  auto& label=p.relations.back();label.op=q::RelOp::label;label.relation=q::Relation::method_defs;label.label=0;label.stable_id=2;label.children.push_back(0);p.relations[1].children[0]=2;
  r::Progress progress;auto out=r::execute(amb.view(),p,progress,&mem);CHECK(out.rows.size()==2);
  for(const auto& row:out.rows){CHECK(row.expand_paths.size()==2);for(const auto& path:row.expand_paths)CHECK(path.seed_bindings.size()==1&&path.seed_bindings[0].label==0&&!path.seed_witnesses.empty());}++cases;
 }
 {
  q::Plan p(&mem);p.nodes.emplace_back(&mem);p.nodes[0].kind=q::Kind::yes;p.labels.emplace_back("A");p.labels.emplace_back("B");
  for(int i=0;i<8;++i)p.relations.emplace_back(&mem);
  for(int i=0;i<2;++i){auto& scan=p.relations[2*i];scan.op=q::RelOp::scan;scan.relation=q::Relation::method_defs;scan.stable_id=2*i;scan.predicate=0;scan.explicit_scope=true;scan.scope_slots.emplace_back("s"+std::to_string(i));
   auto& label=p.relations[2*i+1];label.op=q::RelOp::label;label.relation=q::Relation::method_defs;label.stable_id=2*i+1;label.label=i;label.children.push_back(2*i);}
  auto& un=p.relations[4];un.op=q::RelOp::union_rows;un.relation=q::Relation::method_defs;un.stable_id=4;un.bag=true;un.children={1,3};
  auto& right=p.relations[5];right.op=q::RelOp::scan;right.relation=q::Relation::method_defs;right.stable_id=5;right.predicate=0;right.explicit_scope=true;right.scope_slots.emplace_back("s0");right.scope_slots.emplace_back("s1");
  auto& semi=p.relations[6];semi.op=q::RelOp::semi_join;semi.relation=q::Relation::method_defs;semi.stable_id=6;semi.join_key=q::JoinKey::same_entity;semi.children={4,5};
  auto& ex=p.relations[7];ex.op=q::RelOp::bounded_expand;ex.relation=q::Relation::method_defs;ex.stable_id=7;ex.children.push_back(6);ex.expand_min_depth=1;ex.expand_max_depth=2;ex.expand_output=q::ExpandOutput::endpoints;ex.expand_walk_predicate=0;ex.expand_emit_predicate=0;ex.expand_max_visited=1000;ex.expand_max_edges=1000;ex.expand_max_paths=1000;
  p.relation=q::Relation::method_defs;p.relation_root=7;p.demand_mask=2;p.contains_expand=true;p.max_work=10000000;
  r::Progress progress;auto out=r::execute(amb.view(),p,progress,&mem);CHECK(out.rows.size()==4);
  const auto found=std::find_if(out.rows.begin(),out.rows.end(),[](const auto& row){return row.source_index==3;});CHECK(found!=out.rows.end()&&found->expand_paths.size()==3);
  for(size_t i=0;i<3;++i){const auto& path=found->expand_paths[i];CHECK(path.seed_bindings.size()==1&&path.seed_bindings[0].label==(i==2?1u:0u)&&!path.seed_witnesses.empty());
   CHECK(path.seed_links.size()==1&&path.seed_proof_bindings.size()==1&&!path.emit_witnesses.empty());CHECK(path.walk_witnesses.size()==(i==2?0u:1u));}
  CHECK(found->expand_paths[0].seed.source_index==0&&found->expand_paths[0].hops[0].dex_pc==0&&found->expand_paths[1].seed.source_index==0&&found->expand_paths[1].hops[0].dex_pc==3&&found->expand_paths[2].seed.source_index==1);++cases;
 }
 {
  auto p=plan(&mem,0,1,2);p.nodes.emplace_back(&mem);p.nodes.back().kind=q::Kind::no;p.relations[1].expand_walk_predicate=1;
  r::Progress progress;auto out=r::execute(amb.view(),p,progress,&mem);CHECK(out.rows.size()==4&&progress.graph->expands[0].visited==5&&progress.graph->expands[0].edges==4);for(const auto& row:out.rows)CHECK(row.expand_paths[0].hops.size()==1);++cases;
 }
 {
  auto p=plan(&mem,0,1,2);p.nodes.emplace_back(&mem);p.nodes.back().kind=q::Kind::no;p.relations[1].expand_emit_predicate=1;
  r::Progress progress;auto out=r::execute(amb.view(),p,progress,&mem);CHECK(out.rows.empty()&&progress.graph->expands[0].visited==9&&progress.graph->expands[0].edges==8);++cases;
 }
 {
  auto& source=*amb.facts[1];const auto owner=source.method_refs[source.methods[0].method_index].owner;const auto saved=source.class_definition_by_type[owner];source.class_definition_by_type[owner]=UINT32_MAX;
  auto p=plan(&mem,0,2,2);p.nodes.emplace_back(&mem);p.nodes.back().kind=q::Kind::flags_contains;p.nodes.back().argument=1;p.nodes.back().minimum=1;p.relations[1].expand_walk_predicate=1;
  r::Progress progress;auto out=r::execute(amb.view(),p,progress,&mem);CHECK(out.rows.size()==2&&out.frontiers.size()==2&&progress.profile.unknown_rows==2&&!progress.graph->nodes[1].complete);
  for(const auto& front:out.frontiers)CHECK(front.reason==r::FrontierReason::unknown_walk&&!front.walk_witnesses.empty()&&front.prefix.size()==1);source.class_definition_by_type[owner]=saved;++cases;
 }
 {
  auto& source=*amb.facts[1];const auto owner=source.method_refs[source.methods[0].method_index].owner;const auto saved=source.class_definition_by_type[owner];source.class_definition_by_type[owner]=UINT32_MAX;
  auto p=plan(&mem,0,1,1);p.nodes.emplace_back(&mem);p.nodes.back().kind=q::Kind::flags_contains;p.nodes.back().argument=1;p.nodes.back().minimum=1;p.relations[1].expand_emit_predicate=1;
  r::Progress progress;auto out=r::execute(amb.view(),p,progress,&mem);CHECK(out.rows.size()==2&&out.frontiers.size()==2&&progress.profile.unknown_rows==2&&!progress.graph->nodes[1].complete);
  for(const auto& front:out.frontiers)CHECK(front.reason==r::FrontierReason::unknown_emit&&!front.emit_witnesses.empty()&&front.prefix.size()==1);source.class_definition_by_type[owner]=saved;++cases;
 }
 {
  auto p=plan(&mem,0,2,2);r::Progress progress;auto out=r::execute(amb.view(false),p,progress,&mem);CHECK(out.rows.size()==4&&!progress.scope_complete&&!out.frontiers.empty()&&progress.profile.unknown_rows>0);++cases;
 }
 {
  Data only(dir,{"amb-a.dex"});auto p=plan(&mem,0,1,1);r::Progress progress;auto out=r::execute(only.view(),p,progress,&mem);CHECK(out.rows.empty()&&out.frontiers.size()==2&&out.frontiers[0].reason==r::FrontierReason::unresolved&&progress.scope_complete&&progress.profile.unknown_rows==0);++cases;
 }
 {
  auto p=plan(&mem,0,1,1);auto& n=p.relations[1];n.explicit_scope=true;n.scope_slots.emplace_back("s0");r::Progress progress;auto out=r::execute(amb.view(false),p,progress,&mem);
  CHECK(out.rows.empty()&&out.frontiers.size()==2&&progress.scope_complete&&progress.profile.unknown_rows==0&&out.scope_sources.size()==1);++cases;
 }
 {
  auto p=plan(&mem,0,1,1);p.relations[0].explicit_scope=false;p.relations[0].scope_slots.clear();auto& n=p.relations[1];n.explicit_scope=true;
  for(int i=0;i<6;++i)n.scope_slots.emplace_back("s"+std::to_string(i));r::Progress progress;auto out=r::execute(amb.view(false),p,progress,&mem);
  CHECK(out.rows.size()==6&&!progress.scope_complete&&out.frontiers.empty()&&progress.profile.unknown_rows==0);
  for(const auto& row:out.rows)CHECK(row.expand_paths[0].hops[0].resolution_complete);++cases;
 }
 {
  auto p=plan(&mem,0,1,1);auto& n=p.relations[1];n.explicit_scope=true;n.scope_slots.emplace_back("missing");r::Progress progress;bool rejected=false;
  try{(void)r::execute(amb.view(),p,progress,&mem);}catch(const q::Error& e){CHECK(e.code==q::ErrorCode::source_mismatch);rejected=true;}CHECK(rejected);++cases;
 }
 {
  Data duplicate(dir,{"amb-a.dex","amb-b1.dex","amb-b2.dex","amb-c1.dex","amb-c2.dex","amb-b1.dex"});auto p=plan(&mem,0,2,2);r::Progress progress;auto out=r::execute(duplicate.view(),p,progress,&mem);CHECK(out.rows.size()==6);
  for(const auto& row:out.rows)CHECK(row.expand_paths[0].hops[0].candidate_count==3);++cases;
 }
 {
  Data empty(dir,{});auto p=plan(&mem,0,1,1);p.relations[0].explicit_scope=false;p.relations[0].scope_slots.clear();r::Progress progress;
  auto out=r::execute(empty.view(),p,progress,&mem);CHECK(out.rows.empty()&&out.frontiers.empty()&&progress.scope_complete);++cases;
 }
 {
  auto p=plan(&mem,0,1,1);p.max_work=1;r::Progress progress;bool rejected=false;
  try{(void)r::execute(amb.view(),p,progress,&mem);}catch(const q::Error& e){CHECK(e.code==q::ErrorCode::budget);rejected=true;}CHECK(rejected);++cases;
 }
 {
  auto p=plan(&mem,0,2,2);r::Progress progress;bool rejected=false;try{(void)r::execute(amb.view(),p,progress,std::pmr::null_memory_resource());}catch(const std::bad_alloc&){rejected=true;}CHECK(rejected);++cases;
 }
 for(int which=0;which<3;++which){auto p=plan(&mem,0,2,2);auto& n=p.relations[1];if(which==0)n.expand_max_visited=1;if(which==1)n.expand_max_edges=1;if(which==2)n.expand_max_paths=1;r::Progress progress;bool rejected=false;try{(void)r::execute(amb.view(),p,progress,&mem);}catch(const q::Error& e){CHECK(e.code==q::ErrorCode::budget);rejected=true;}CHECK(rejected);++cases;}
 {
  auto p=plan(&mem,0,2,2);r::Progress progress;bool rejected=false;auto cancel=[](void*)noexcept{return true;};try{(void)r::execute(amb.view(),p,progress,&mem,{cancel,nullptr});}catch(const q::Error& e){CHECK(e.code==q::ErrorCode::cancelled);rejected=true;}CHECK(rejected);++cases;
 }
 {
  Data bad(dir,{"amb-a.dex","amb-b1.dex"},true);auto p=plan(&mem,0,1,1);r::Progress progress;bool rejected=false;try{(void)r::execute(bad.view(),p,progress,&mem);}catch(const instructions::DecodeError& e){CHECK(e.code==instructions::DecodeCode::corrupt);rejected=true;}CHECK(rejected);++cases;
 }
 std::cout<<"PASS expand reference "<<cases<<" scenarios\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
