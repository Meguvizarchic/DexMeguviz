#include "planner/isolated_multi.hpp"
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string_view>
#include <vector>
using namespace dexmeguviz;
#define CHECK(x) do{if(!(x))throw std::runtime_error("materialized multi line "+std::to_string(__LINE__)+": " #x);}while(false)
namespace {
struct EngineDelete {void operator()(dmg_engine* p)const noexcept{if(p)dmg_engine_release(p);}};
struct SnapshotDelete {void operator()(dmg_snapshot* p)const noexcept{if(p)dmg_snapshot_release(p);}};
struct QueryDelete {void operator()(dmg_query* p)const noexcept{if(p)dmg_query_release(p);}};
struct ResultDelete {void operator()(dmg_result* p)const noexcept{if(p)dmg_result_release(p);}};
using Engine=std::unique_ptr<dmg_engine,EngineDelete>;using Snapshot=std::unique_ptr<dmg_snapshot,SnapshotDelete>;
using Query=std::unique_ptr<dmg_query,QueryDelete>;using Result=std::unique_ptr<dmg_result,ResultDelete>;
std::u16string_view text(const uint16_t* p,uint64_t n){return n?std::u16string_view(reinterpret_cast<const char16_t*>(p),n):std::u16string_view{};}
bool same_text(const char* a,const char* b){return (!a&&!b)||(a&&b&&std::string_view(a)==b);}
void compare_path(const dmg_binding_path& a,const dmg_binding_path& b){CHECK(a.length==b.length);for(uint32_t i=0;i<a.length;++i)CHECK(a.sides[i]==b.sides[i]);}
void compare_identity(const dmg_value_identity_v2& a,const dmg_value_identity_v2& b){CHECK(a.relation==b.relation&&a.source_index==b.source_index&&a.local_index==b.local_index&&a.dex_pc==b.dex_pc);}
void compare_witness(const dmg_relation_witness_v2& a,const dmg_relation_witness_v2& b){
 const auto& x=a.witness;const auto& y=b.witness;
 CHECK(a.operator_node==b.operator_node);compare_identity(a.entity,b.entity);
 CHECK(x.kind==y.kind&&x.node_id==y.node_id&&x.matched==y.matched&&x.dex_pc==y.dex_pc&&x.opcode==y.opcode&&x.reference_index==y.reference_index&&x.reference_kind==y.reference_kind&&x.extra_proto==y.extra_proto&&x.code_units==y.code_units);
}
void compare_value(const dmg_value_row_v2& a,const dmg_value_row_v2& b){
 CHECK(a.kind==b.kind);
 if(a.kind==DMG_VALUE_ENTITY){const auto& x=a.entity;const auto& y=b.entity;
  CHECK(x.relation==y.relation&&x.source_index==y.source_index&&x.local_index==y.local_index&&x.reference_index==y.reference_index&&x.record_offset==y.record_offset);
  CHECK(x.definition_known==y.definition_known&&x.definition_offset==y.definition_offset&&x.flags_known==y.flags_known&&x.access_flags==y.access_flags&&x.code_known==y.code_known&&x.code_offset==y.code_offset);
  CHECK(text(x.owner,x.owner_length)==text(y.owner,y.owner_length)&&text(x.name,x.name_length)==text(y.name,y.name_length));
  CHECK(text(x.prototype,x.prototype_length)==text(y.prototype,y.prototype_length)&&text(x.type_descriptor,x.type_descriptor_length)==text(y.type_descriptor,y.type_descriptor_length));
 }else{const auto& x=a.use;const auto& y=b.use;CHECK(x.relation==y.relation&&x.source_index==y.source_index&&x.caller_ordinal==y.caller_ordinal&&x.caller_method_ref==y.caller_method_ref&&x.dex_pc==y.dex_pc&&x.opcode==y.opcode&&x.code_offset==y.code_offset&&x.target_domain==y.target_domain&&x.target_index==y.target_index&&x.extra_proto==y.extra_proto);
  CHECK(text(x.owner,x.owner_length)==text(y.owner,y.owner_length)&&text(x.name,x.name_length)==text(y.name,y.name_length)&&text(x.prototype,x.prototype_length)==text(y.prototype,y.prototype_length));}
}
}
int main(int argc,char** argv){try{
 CHECK(argc==2);std::ifstream input(std::filesystem::path(argv[1])/"generated/method_facts/method-uses.dex",std::ios::binary);
 CHECK(input.good());const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input),{}};
 dmg_engine_options opts{sizeof(opts),DMG_ABI_VERSION,16u<<20,8u<<20,8u<<20,2,0};
 std::array<dmg_source_spec,2> sources{{{sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,bytes.data(),bytes.size(),"a","raw",nullptr},{sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,bytes.data(),bytes.size(),"b","raw",nullptr}}};
 dmg_source_set_options so{sizeof(so),DMG_ABI_VERSION,"multi-test",1,16,8u<<20};
 auto session=planner::IsolatedMultiSession::open(&opts,sources.data(),sources.size(),&so);
 constexpr auto one=R"({"schema_version":1,"relation":"method_defs","where":{"name":"uses","using_strings":{"all":["used-string"]}}})";
 constexpr auto two=R"({"schema_version":1,"relation":"method_defs","where":{"name":{"op":"contains","value":"use"},"using_strings":{"all":["used-string"]}}})";
 constexpr auto join=R"({"schema_version":1,"relation":{"op":"join","on":"same_entity","left":{"op":"label","label":"L","input":{"op":"scan","relation":"method_defs","where":{"name":"uses"}}},"right":{"op":"label","label":"R","input":{"op":"scan","relation":"method_defs","where":{"name":"uses"}}}}})";
 constexpr auto semi=R"({"schema_version":1,"relation":{"op":"semi_join","on":"same_entity","left":{"op":"label","label":"L","input":{"op":"scan","relation":"method_defs","where":{"name":"uses"}}},"right":{"op":"label","label":"R","input":{"op":"scan","relation":"method_defs","where":{"name":"uses"}}}}})";
 constexpr auto low=R"({"schema_version":1,"relation":"method_defs","where":true,"max_work":1})";
 constexpr auto limit=R"({"schema_version":1,"relation":"method_defs","where":{"name":"uses"},"max_results":1})";
 for(auto [id,json]:std::array<std::pair<std::string_view,std::string_view>,6>{{{"one",one},{"two",two},{"join",join},{"semi",semi},{"low",low},{"limit",limit}}})session->add(id,json);
 dmg_error error{};dmg_engine* e=nullptr;CHECK(dmg_engine_create(&opts,&e,&error)==DMG_OK);Engine engine(e);
 dmg_snapshot* snap=nullptr;CHECK(dmg_snapshot_open_sources(engine.get(),sources.data(),sources.size(),&so,&snap,&error)==DMG_OK);Snapshot snapshot(snap);
 auto compile=[&](std::string_view json){dmg_query* q=nullptr;CHECK(dmg_query_compile_json(engine.get(),reinterpret_cast<const uint8_t*>(json.data()),json.size(),&q,&error)==DMG_OK);return Query(q);};
 auto q1=compile(one),q2=compile(two),qj=compile(join),qs=compile(semi),qlow=compile(low),qlimit=compile(limit);
 for(auto entry:std::array<std::pair<std::string_view,dmg_query*>,4>{{{"one",q1.get()},{"two",q2.get()},{"join",qj.get()},{"semi",qs.get()}}}){
   auto a=session->stats();dmg_engine_stats b{};CHECK(dmg_engine_get_stats(engine.get(),&b)==DMG_OK);
   auto isolated=session->execute_one(entry.first);dmg_result* raw=nullptr;CHECK(dmg_query_execute(snapshot.get(),entry.second,&raw,&error)==DMG_OK);Result direct(raw);CHECK(bool(direct));
   dmg_relation_info ia{},ib{};CHECK(isolated.relation_info(ia)==DMG_OK&&dmg_result_get_relation_info(direct.get(),&ib,sizeof(ib))==DMG_OK);
   CHECK(ia.relation==ib.relation&&ia.execution_status==ib.execution_status&&ia.coverage==ib.coverage&&ia.decision==ib.decision&&ia.reason==ib.reason&&ia.candidates_count==ib.candidates_count&&ia.unknown_rows==ib.unknown_rows);
   dmg_query_info qa{},qb{};CHECK(isolated.query_info(qa)==DMG_OK&&dmg_result_get_query_info(direct.get(),&qb)==DMG_OK);CHECK(std::string_view(qa.query_id)==qb.query_id);
   dmg_snapshot_overview sa{},sb{};CHECK(isolated.overview(sa)==DMG_OK&&dmg_result_get_overview(direct.get(),&sb)==DMG_OK);CHECK(std::string_view(sa.snapshot_id)==sb.snapshot_id);
   for(uint32_t i=0;i<ia.candidates_count;++i){dmg_value_row_v2 x{},y{};CHECK(isolated.value(i,x)==DMG_OK&&dmg_result_get_value_v2(direct.get(),i,&y,sizeof(y))==DMG_OK);compare_value(x,y);
     dmg_source_info ox{},oy{};CHECK(isolated.origin(i,ox)==DMG_OK&&dmg_result_get_origin(direct.get(),i,&oy)==DMG_OK);CHECK(ox.source_index==oy.source_index&&std::string_view(ox.dex.occurrence_id)==oy.dex.occurrence_id);
     uint32_t ca=0,cb=0;CHECK(isolated.binding_count(i,ca)==DMG_OK&&dmg_result_get_binding_count(direct.get(),i,&cb)==DMG_OK&&ca==cb);
     for(uint32_t j=0;j<ca;++j){dmg_binding_row_v2 ba{},bb{};dmg_binding_path pa{},pb{};
       CHECK(isolated.binding(i,j,ba)==DMG_OK&&dmg_result_get_binding_v2(direct.get(),i,j,&bb,sizeof(bb))==DMG_OK);CHECK(same_text(ba.label,bb.label));compare_value(ba.value,bb.value);
       CHECK(isolated.binding_path(i,j,pa)==DMG_OK&&dmg_result_get_binding_path(direct.get(),i,j,&pb,sizeof(pb))==DMG_OK);compare_path(pa,pb);}
     uint32_t wa=0,wb=0;CHECK(isolated.witness_count(i,wa)==DMG_OK&&dmg_result_get_witness_count(direct.get(),i,&wb)==DMG_OK&&wa==wb);
     for(uint32_t j=0;j<wa;++j){dmg_relation_witness_v2 xa{},xb{};CHECK(isolated.witness(i,j,xa)==DMG_OK&&dmg_result_get_relation_witness_v2(direct.get(),i,j,&xb,sizeof(xb))==DMG_OK);compare_witness(xa,xb);}
     uint32_t la=0,lb=0;CHECK(isolated.link_count(i,la)==DMG_OK&&dmg_result_get_link_count(direct.get(),i,&lb)==DMG_OK&&la==lb);
     for(uint32_t j=0;j<la;++j){dmg_relation_link_v2 xa{},xb{};CHECK(isolated.link(i,j,xa)==DMG_OK&&dmg_result_get_link_v2(direct.get(),i,j,&xb,sizeof(xb))==DMG_OK);CHECK(xa.node_id==xb.node_id&&xa.key==xb.key);compare_identity(xa.left,xb.left);compare_identity(xa.right,xb.right);}
     uint32_t pa=0,pb=0;CHECK(isolated.proof_binding_count(i,pa)==DMG_OK&&dmg_result_get_proof_binding_count(direct.get(),i,&pb)==DMG_OK&&pa==pb);
     if(entry.first=="semi")CHECK(pa>0);
     for(uint32_t j=0;j<pa;++j){dmg_proof_binding_row_v2 xa{},xb{};dmg_binding_path pxa{},pxb{};CHECK(isolated.proof_binding(i,j,xa)==DMG_OK&&dmg_result_get_proof_binding_v2(direct.get(),i,j,&xb,sizeof(xb))==DMG_OK);CHECK(xa.operator_node==xb.operator_node&&same_text(xa.binding.label,xb.binding.label));compare_value(xa.binding.value,xb.binding.value);CHECK(isolated.proof_binding_path(i,j,pxa)==DMG_OK&&dmg_result_get_proof_binding_path(direct.get(),i,j,&pxb,sizeof(pxb))==DMG_OK);compare_path(pxa,pxb);}
   }
   auto c=session->stats();dmg_engine_stats d{};CHECK(dmg_engine_get_stats(engine.get(),&d)==DMG_OK);
   CHECK(c.result_bytes-a.result_bytes==d.result_bytes-b.result_bytes&&c.result_bytes>a.result_bytes);
   CHECK(c.scratch_bytes==a.scratch_bytes&&d.scratch_bytes==b.scratch_bytes);
 }
 const auto idle=session->stats();try{(void)session->execute_one("missing");CHECK(false);}catch(const std::invalid_argument&){} CHECK(session->stats().owned_bytes==idle.owned_bytes);
 try{(void)session->execute_one("low");CHECK(false);}catch(const planner::SessionError& e2){CHECK(e2.status==DMG_BUDGET_EXCEEDED);} CHECK(session->stats().owned_bytes==idle.owned_bytes);
 dmg_result* failed=nullptr;CHECK(dmg_query_execute(snapshot.get(),qlow.get(),&failed,&error)==DMG_BUDGET_EXCEEDED&&failed==nullptr);
 {auto limited=session->execute_one("limit");dmg_result_info result{};CHECK(limited.info(result)==DMG_OK&&result.execution_status==DMG_BUDGET_EXCEEDED&&result.reason==DMG_RESULT_LIMIT&&result.candidates_count==1);}
 CHECK(session->stats().owned_bytes==idle.owned_bytes);
 // A partial source declaration can never prove a missing method globally.
 {auto incomplete=so;incomplete.scope_complete=0;auto s=planner::IsolatedMultiSession::open(&opts,sources.data(),sources.size(),&incomplete);
  s->add("absent",R"({"schema_version":1,"relation":"method_defs","where":{"name":"absent"},"intent":"exists"})");
  auto r=s->execute_one("absent");dmg_result_info info{};CHECK(r.info(info)==DMG_OK&&info.coverage==DMG_COVERAGE_PARTIAL&&info.decision==DMG_UNDETERMINED&&info.candidates_count==0);}
 // Deterministic Engine-budget boundaries: each failed or released result must
 // restore the exact per-session owned-byte baseline; no retry is performed.
 uint64_t tight_base=0;{auto s=planner::IsolatedMultiSession::open(&opts,sources.data(),sources.size(),&so);s->add("one",one);tight_base=s->stats().peak_owned_bytes;}
 unsigned budget_failures=0,budget_successes=0;
 for(uint64_t extra:std::array<uint64_t,6>{0,64,256,1024,8192,65536}){
  auto tight_opts=opts;tight_opts.owned_bytes_limit=tight_base+extra;
  auto s=planner::IsolatedMultiSession::open(&tight_opts,sources.data(),sources.size(),&so);s->add("one",one);const auto before=s->stats();
  std::vector<planner::MaterializedRule> retained;bool failed=false;
  for(unsigned attempt=0;attempt<512;++attempt){
   try{auto r=s->execute_one("one");dmg_result_info info{};CHECK(r.info(info)==DMG_OK&&info.candidates_count>0);retained.push_back(std::move(r));++budget_successes;}
   catch(const planner::SessionError& error2){CHECK(error2.status==DMG_BUDGET_EXCEEDED);++budget_failures;failed=true;break;}
  }
  CHECK(failed);retained.clear();
  CHECK(s->stats().owned_bytes==before.owned_bytes&&s->stats().scratch_bytes==before.scratch_bytes&&s->stats().result_bytes==before.result_bytes);
 }
 CHECK(budget_failures>0&&budget_successes>0);
 const std::array<std::string_view,2> ids{"one","two"};
 {auto cached=session->execute(ids,1u<<20,1000000);CHECK(cached.profile().cache_hits>0);
  CHECK(cached.query_id(0)!=cached.query_id(1));
  for(uint32_t i=0;i<2;++i){auto standalone=session->execute_one(ids[i]);const auto summary=cached.summary(i);
   dmg_relation_info a{};CHECK(standalone.relation_info(a)==DMG_OK&&a.candidates_count==summary.rows);
   CHECK(summary.code==planner::OutcomeCode::result_available&&summary.scope_complete&&summary.scope_source_count==2);
   dmg_query_info qi{};CHECK(standalone.query_info(qi)==DMG_OK&&cached.query_id(i)==qi.query_id);
   dmg_query_profile profile{};CHECK(standalone.profile(profile)==DMG_OK);
   CHECK(profile.work_units==summary.profile.work_units&&profile.fact_requests==summary.profile.fact_requests&&profile.methods_decoded==summary.profile.methods_decoded&&profile.code_units==summary.profile.code_units&&profile.string_pool_lookups==summary.profile.string_pool_lookups&&profile.matches_seen==summary.profile.matches_seen);
   for(uint32_t j=0;j<a.candidates_count;++j){dmg_value_row_v2 row{};CHECK(standalone.value(j,row)==DMG_OK);const auto key=cached.row_key(i,j);CHECK(row.kind==DMG_VALUE_ENTITY&&row.entity.source_index==key.source_index&&row.entity.local_index==key.ordinal);
    const auto entity=cached.entity(key);CHECK(row.entity.reference_index==entity.reference_index&&row.entity.record_offset==entity.record_offset&&(row.entity.definition_known!=0)==entity.definition_known&&row.entity.definition_offset==entity.definition_offset);
    CHECK(text(row.entity.owner,row.entity.owner_length)==entity.owner&&text(row.entity.name,row.entity.name_length)==entity.name&&text(row.entity.prototype,row.entity.prototype_length)==entity.prototype&&text(row.entity.type_descriptor,row.entity.type_descriptor_length)==entity.type_descriptor);
    dmg_source_info origin{};CHECK(standalone.origin(j,origin)==DMG_OK);const auto source=cached.source(key.source_index);CHECK(source.occurrence==origin.dex.occurrence_id&&source.content==origin.dex.content_id);
    uint32_t count=0;CHECK(standalone.witness_count(j,count)==DMG_OK&&count==cached.witness_count(i,j));
    for(uint32_t k=0;k<count;++k){dmg_relation_witness_v2 w{};CHECK(standalone.witness(j,k,w)==DMG_OK);const auto v=cached.witness(i,j,k);const auto& x=w.witness;
     CHECK(x.kind==static_cast<uint32_t>(v.kind)&&x.node_id==v.node&&x.matched==v.matched&&x.dex_pc==v.dex_pc&&x.opcode==v.opcode&&x.reference_index==v.reference_index&&x.reference_kind==v.reference_kind&&x.extra_proto==v.extra_proto&&x.code_units==v.code_units);
     CHECK(w.operator_node==v.relation_node&&w.entity.source_index==v.source_index&&w.entity.local_index==v.entity_ordinal&&w.entity.dex_pc==v.entity_pc);
    }
   }
  }
 }
 CHECK(session->stats().owned_bytes==idle.owned_bytes);
 // Actual cache hits are converted into independent C Result handles by the
 // same materializer as execute_one, not by executing every rule again.
 {
  auto batch=session->execute_materialized(ids,1u<<20,1000000);
  CHECK(batch.size()==2&&batch.profile().cache_hits>0&&!batch.retried());
  dmg_graph_info unsupported_graph{};CHECK(batch.at(0).graph_info(unsupported_graph)==DMG_UNSUPPORTED);
  dmg_relation_info_v2 unsupported_use{};CHECK(batch.at(0).relation_info_v2(unsupported_use)==DMG_UNSUPPORTED);
  for(uint32_t i=0;i<2;++i){auto scalar=session->execute_one(ids[i]);const auto& shared=batch.at(i);
   dmg_relation_info a{},b{};CHECK(scalar.relation_info(a)==DMG_OK&&shared.relation_info(b)==DMG_OK);
   CHECK(a.relation==b.relation&&a.execution_status==b.execution_status&&a.coverage==b.coverage&&a.decision==b.decision&&a.reason==b.reason&&a.candidates_count==b.candidates_count&&a.unknown_rows==b.unknown_rows);
   dmg_query_info qa{},qb{};CHECK(scalar.query_info(qa)==DMG_OK&&shared.query_info(qb)==DMG_OK&&std::string_view(qa.query_id)==qb.query_id);
   dmg_query_profile pa{},pb{};CHECK(scalar.profile(pa)==DMG_OK&&shared.profile(pb)==DMG_OK);
   CHECK(pa.work_units==pb.work_units&&pa.fact_requests==pb.fact_requests&&pa.methods_decoded==pb.methods_decoded&&pa.code_units==pb.code_units&&pa.string_pool_lookups==pb.string_pool_lookups&&pa.matches_seen==pb.matches_seen&&pa.scope_complete==pb.scope_complete&&pa.scope_source_count==pb.scope_source_count);
   for(uint32_t j=0;j<a.candidates_count;++j){dmg_value_row_v2 x{},y{};CHECK(scalar.value(j,x)==DMG_OK&&shared.value(j,y)==DMG_OK);compare_value(x,y);
    dmg_source_info sx{},sy{};CHECK(scalar.origin(j,sx)==DMG_OK&&shared.origin(j,sy)==DMG_OK&&std::string_view(sx.dex.occurrence_id)==sy.dex.occurrence_id);
    uint32_t count=0,other=0;CHECK(scalar.witness_count(j,count)==DMG_OK&&shared.witness_count(j,other)==DMG_OK&&count==other);
    for(uint32_t k=0;k<count;++k){dmg_relation_witness_v2 wx{},wy{};CHECK(scalar.witness(j,k,wx)==DMG_OK&&shared.witness(j,k,wy)==DMG_OK);compare_witness(wx,wy);}
   }
  }
  auto taken=batch.take(0);dmg_relation_info held{};CHECK(taken.relation_info(held)==DMG_OK&&held.candidates_count>0);
  dmg_relation_info invalid{};CHECK(batch.at(0).relation_info(invalid)==DMG_INVALID_ARGUMENT);
  bool repeated=false;try{(void)batch.take(0);}catch(const std::logic_error&){repeated=true;}CHECK(repeated);
 }
 CHECK(session->stats().owned_bytes==idle.owned_bytes);
 {auto empty=session->execute_materialized({},1u<<20,1000000);CHECK(empty.size()==0&&empty.profile().cache_hits==0&&!empty.retried());}
 CHECK(session->stats().owned_bytes==idle.owned_bytes);
 {const std::array<std::string_view,2> limited_ids{"limit","one"};auto batch=session->execute_materialized(limited_ids,1u<<20,1000000);dmg_result_info info{};
  CHECK(batch.size()==2&&batch.at(0).info(info)==DMG_OK&&info.execution_status==DMG_BUDGET_EXCEEDED&&info.reason==DMG_RESULT_LIMIT&&info.candidates_count==1);
  dmg_relation_info second{};CHECK(batch.at(1).relation_info(second)==DMG_OK&&second.candidates_count>0);
 }
 CHECK(session->stats().owned_bytes==idle.owned_bytes);
 // Relation graphs currently fall back to independent scalar evaluation, but
 // still use the same all-or-nothing formal Result materializer.
 {
  const std::array<std::string_view,2> graphs{"join","semi"};auto batch=session->execute_materialized(graphs,1u<<20,1000000);
  CHECK(batch.size()==2&&batch.profile().cache_hits==0);
  for(uint32_t i=0;i<2;++i){auto scalar=session->execute_one(graphs[i]);const auto& result=batch.at(i);dmg_relation_info a{},b{};
   CHECK(scalar.relation_info(a)==DMG_OK&&result.relation_info(b)==DMG_OK&&a.candidates_count==b.candidates_count&&a.coverage==b.coverage&&a.unknown_rows==b.unknown_rows);
   dmg_graph_info ga{},gb{};CHECK(scalar.graph_info(ga)==DMG_OK&&result.graph_info(gb)==DMG_OK&&ga.root_node==gb.root_node&&ga.operator_count==gb.operator_count);
   for(uint32_t j=0;j<a.candidates_count;++j){dmg_value_row_v2 x{},y{};CHECK(scalar.value(j,x)==DMG_OK&&result.value(j,y)==DMG_OK);compare_value(x,y);
    uint32_t na=0,nb=0;CHECK(scalar.binding_count(j,na)==DMG_OK&&result.binding_count(j,nb)==DMG_OK&&na==nb);
    for(uint32_t k=0;k<na;++k){dmg_binding_row_v2 x1{},y1{};dmg_binding_path xp{},yp{};CHECK(scalar.binding(j,k,x1)==DMG_OK&&result.binding(j,k,y1)==DMG_OK);CHECK(same_text(x1.label,y1.label));compare_value(x1.value,y1.value);CHECK(scalar.binding_path(j,k,xp)==DMG_OK&&result.binding_path(j,k,yp)==DMG_OK);compare_path(xp,yp);}
    CHECK(scalar.link_count(j,na)==DMG_OK&&result.link_count(j,nb)==DMG_OK&&na==nb);
    for(uint32_t k=0;k<na;++k){dmg_relation_link_v2 x1{},y1{};CHECK(scalar.link(j,k,x1)==DMG_OK&&result.link(j,k,y1)==DMG_OK&&x1.node_id==y1.node_id&&x1.key==y1.key);compare_identity(x1.left,y1.left);compare_identity(x1.right,y1.right);}
    CHECK(scalar.proof_binding_count(j,na)==DMG_OK&&result.proof_binding_count(j,nb)==DMG_OK&&na==nb);if(i==1)CHECK(na>0);
    for(uint32_t k=0;k<na;++k){dmg_proof_binding_row_v2 x1{},y1{};dmg_binding_path xp{},yp{};CHECK(scalar.proof_binding(j,k,x1)==DMG_OK&&result.proof_binding(j,k,y1)==DMG_OK&&x1.operator_node==y1.operator_node&&same_text(x1.binding.label,y1.binding.label));compare_value(x1.binding.value,y1.binding.value);CHECK(scalar.proof_binding_path(j,k,xp)==DMG_OK&&result.proof_binding_path(j,k,yp)==DMG_OK);compare_path(xp,yp);}
   }
  }
 }
 CHECK(session->stats().owned_bytes==idle.owned_bytes);
 {
  const std::array<std::string_view,3> failing{"one","low","two"};bool seen=false;
  try{(void)session->execute_materialized(failing,1u<<20,1000000);}catch(const planner::BatchError& e2){seen=true;CHECK(e2.rule_index==1&&e2.code==planner::OutcomeCode::budget);}
  CHECK(seen&&session->stats().owned_bytes==idle.owned_bytes&&session->stats().result_bytes==idle.result_bytes);
 }
 // Find a deterministic Engine limit where evaluation succeeds but one of the
 // subsequent C materializations fails; no previous Result may escape or leak.
 uint64_t compile_peak=0;{auto s=planner::IsolatedMultiSession::open(&opts,sources.data(),sources.size(),&so);s->add("one",one);s->add("two",two);compile_peak=s->stats().peak_owned_bytes;}
 bool materialize_failed=false;
 for(uint64_t extra=0;extra<=65536&&!materialize_failed;extra+=128){
  auto tight=opts;tight.owned_bytes_limit=compile_peak+extra;
  try{auto s=planner::IsolatedMultiSession::open(&tight,sources.data(),sources.size(),&so);s->add("one",one);s->add("two",two);const auto before=s->stats();
   try{auto b=s->execute_materialized(ids,0,0);(void)b;}
   catch(const planner::BatchMaterializationError& e2){CHECK(e2.status==DMG_BUDGET_EXCEEDED);if(e2.rule_index==1)materialize_failed=true;}
   catch(const BudgetExceeded&){}catch(const planner::BatchError& e2){CHECK(e2.code==planner::OutcomeCode::budget);}
   const auto after=s->stats();CHECK(after.owned_bytes==before.owned_bytes&&after.scratch_bytes==before.scratch_bytes&&after.result_bytes==before.result_bytes);
  }catch(const planner::SessionError& e2){CHECK(e2.status==DMG_BUDGET_EXCEEDED);}catch(const BudgetExceeded&){}
 }
 CHECK(materialize_failed);
 // v18 is deliberately not cached; its formal materialized results still keep
 // inherited path witness details and incomplete scope on the scalar fallback.
 {
  auto read_fixture=[&](std::string_view name){std::ifstream f(std::filesystem::path(argv[1])/name,std::ios::binary);CHECK(f.good());return std::vector<uint8_t>{std::istreambuf_iterator<char>(f),{}};};
  auto method=read_fixture("generated/inherited-use/local-target.dex"),parent=read_fixture("generated/inherited/root.dex");
  std::array<dmg_source_spec,2> v18src{{{sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,method.data(),method.size(),"a","raw",nullptr},{sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,parent.data(),parent.size(),"b","raw",nullptr}}};
  constexpr auto v18=R"({"schema_version":1,"required_capabilities":["inherited_fields","use_target_symbol","inherited_target_symbol"],"relation":{"op":"join","on":"target_symbol","left":{"op":"scan","relation":"invoke_sites"},"right":{"op":"scan","relation":"method_defs","where":{"all":[{"name":"uses"},{"declares_fields":{"scope":"inherited","where":{"name":"unseen"},"min":0,"max":0}}]}}},"max_results":100})";
  for(uint32_t complete:{0u,1u}){auto options=so;options.scope_complete=complete;auto s=planner::IsolatedMultiSession::open(&opts,v18src.data(),v18src.size(),&options);s->add("a",v18);s->add("b",v18);
   const std::array<std::string_view,2> ids18{"a","b"};auto batch=s->execute_materialized(ids18,1u<<20,1000000);auto scalar=s->execute_one("a");CHECK(batch.profile().cache_hits==0&&batch.size()==2);
   dmg_relation_info_v2 a{},b{};CHECK(scalar.relation_info_v2(a)==DMG_OK&&batch.at(0).relation_info_v2(b)==DMG_OK&&a.candidates_count==b.candidates_count&&a.coverage==b.coverage&&a.unknown_rows==b.unknown_rows);
   dmg_query_profile pa{},pb{};CHECK(scalar.profile(pa)==DMG_OK&&batch.at(0).profile(pb)==DMG_OK&&pa.scope_complete==pb.scope_complete&&pb.scope_complete==complete);
   uint32_t inherited=0;for(uint32_t i=0;i<a.candidates_count;++i){dmg_value_row_v2 x{},y{};CHECK(scalar.value(i,x)==DMG_OK&&batch.at(0).value(i,y)==DMG_OK);compare_value(x,y);
    uint32_t n=0,m=0;CHECK(scalar.witness_count(i,n)==DMG_OK&&batch.at(0).witness_count(i,m)==DMG_OK&&n==m);
    for(uint32_t k=0;k<n;++k){dmg_relation_witness_v2 wx{},wy{};CHECK(scalar.witness(i,k,wx)==DMG_OK&&batch.at(0).witness(i,k,wy)==DMG_OK);compare_witness(wx,wy);if(wx.witness.kind==DMG_WITNESS_INHERITED){dmg_inherited_witness ix{},iy{};CHECK(scalar.inherited_witness(i,k,ix)==DMG_OK&&batch.at(0).inherited_witness(i,k,iy)==DMG_OK);CHECK(ix.node_id==iy.node_id&&ix.matched==iy.matched&&ix.item_kind==iy.item_kind&&ix.path_index==iy.path_index&&ix.aux==iy.aux&&ix.branch_index==iy.branch_index&&ix.detail==iy.detail&&ix.source_index==iy.source_index&&ix.relation==iy.relation&&ix.local_index==iy.local_index);++inherited;}}
   }
   if(complete)CHECK(a.candidates_count>0&&inherited>0);
  }
 }
 auto retained=session->execute_one("one");auto retained_shared=[&]{auto b=session->execute_materialized(ids,1u<<20,1000000);CHECK(b.profile().cache_hits>0);return b.take(0);}();
 session->close();try{(void)session->execute_one("one");CHECK(false);}catch(const std::logic_error&){}session.reset();
 dmg_relation_info after{};dmg_value_row_v2 row{};CHECK(retained.relation_info(after)==DMG_OK&&after.candidates_count>0&&retained.value(0,row)==DMG_OK);CHECK(text(row.entity.name,row.entity.name_length)==u"uses");
 dmg_relation_info after_shared{};dmg_value_row_v2 row_shared{};dmg_query_info query_shared{};CHECK(retained_shared.relation_info(after_shared)==DMG_OK&&after_shared.candidates_count==after.candidates_count&&retained_shared.value(0,row_shared)==DMG_OK&&retained_shared.query_info(query_shared)==DMG_OK);CHECK(text(row_shared.entity.name,row_shared.entity.name_length)==u"uses"&&query_shared.query_id);
 std::cout<<"PASS materialized single-rule parity, release, budget and lifetime\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}





