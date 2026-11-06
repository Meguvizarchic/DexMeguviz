#include "dexmeguviz/dexmeguviz.h"
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#define CHECK(x) do{if(!(x))throw std::runtime_error("line "+std::to_string(__LINE__)+": " #x);}while(false)
static std::vector<uint8_t> read(const std::filesystem::path& p){std::ifstream f(p,std::ios::binary);CHECK(f.good());return {std::istreambuf_iterator<char>(f),{}};}
static bool same_identity(const dmg_value_identity_v2& a,const dmg_value_identity_v2& b){return a.relation==b.relation&&a.source_index==b.source_index&&a.local_index==b.local_index&&a.dex_pc==b.dex_pc;}
static bool same_text(const uint16_t* a,uint64_t an,const uint16_t* b,uint64_t bn){if(an!=bn)return false;if(!an)return true;return a&&b&&std::equal(a,a+an,b);}
static bool same_entity(const dmg_entity_row& a,const dmg_entity_row& b){return a.relation==b.relation&&a.source_index==b.source_index&&a.local_index==b.local_index&&a.reference_index==b.reference_index&&a.record_offset==b.record_offset&&a.definition_known==b.definition_known&&a.definition_offset==b.definition_offset&&a.flags_known==b.flags_known&&a.access_flags==b.access_flags&&a.code_known==b.code_known&&a.code_offset==b.code_offset&&same_text(a.owner,a.owner_length,b.owner,b.owner_length)&&same_text(a.name,a.name_length,b.name,b.name_length)&&same_text(a.prototype,a.prototype_length,b.prototype,b.prototype_length)&&same_text(a.type_descriptor,a.type_descriptor_length,b.type_descriptor,b.type_descriptor_length)&&same_text(a.string_value,a.string_value_length,b.string_value,b.string_value_length);}
static bool same_use(const dmg_use_row& a,const dmg_use_row& b){return a.relation==b.relation&&a.source_index==b.source_index&&a.caller_ordinal==b.caller_ordinal&&a.caller_method_ref==b.caller_method_ref&&a.dex_pc==b.dex_pc&&a.opcode==b.opcode&&a.code_offset==b.code_offset&&a.target_domain==b.target_domain&&a.target_index==b.target_index&&a.extra_proto==b.extra_proto&&same_text(a.owner,a.owner_length,b.owner,b.owner_length)&&same_text(a.name,a.name_length,b.name,b.name_length)&&same_text(a.prototype,a.prototype_length,b.prototype,b.prototype_length);}
static void equivalent(const dmg_result* a,const dmg_result* b){
 dmg_relation_info_v2 x{},y{};CHECK(dmg_result_get_relation_info_v2(a,&x,sizeof(x))==DMG_OK&&dmg_result_get_relation_info_v2(b,&y,sizeof(y))==DMG_OK);
 CHECK(x.relation==y.relation&&x.execution_status==y.execution_status&&x.coverage==y.coverage&&x.decision==y.decision&&x.reason==y.reason&&x.candidates_count==y.candidates_count&&x.entity_visited==y.entity_visited&&x.entity_total==y.entity_total&&x.method_visited==y.method_visited&&x.method_total==y.method_total&&x.events_collected==y.events_collected&&x.unknown_rows==y.unknown_rows);
 dmg_query_profile p{},q{};CHECK(dmg_result_get_profile(a,&p)==DMG_OK&&dmg_result_get_profile(b,&q)==DMG_OK);
 CHECK(p.work_units==q.work_units&&p.fact_requests==q.fact_requests&&p.methods_decoded==q.methods_decoded&&p.code_units==q.code_units&&p.string_pool_lookups==q.string_pool_lookups&&p.invoke_sites==q.invoke_sites&&p.field_uses==q.field_uses&&p.declared_fields==q.declared_fields&&p.matches_seen==q.matches_seen&&p.sort_comparisons==q.sort_comparisons&&p.scope_source_count==q.scope_source_count&&p.scope_complete==q.scope_complete&&p.order_verified==q.order_verified);
 dmg_graph_info ga{},gb{};CHECK(dmg_result_get_graph_info(a,&ga,sizeof(ga))==DMG_OK&&dmg_result_get_graph_info(b,&gb,sizeof(gb))==DMG_OK&&ga.root_node==gb.root_node&&ga.unique_identity==gb.unique_identity&&ga.identity_count==gb.identity_count&&ga.operator_count==gb.operator_count);
 for(uint32_t i=0;i<ga.operator_count;++i){dmg_operator_profile_v2 u{},v{};CHECK(dmg_result_get_operator_profile_v2(a,i,&u,sizeof(u))==DMG_OK&&dmg_result_get_operator_profile_v2(b,i,&v,sizeof(v))==DMG_OK);CHECK(u.node_id==v.node_id&&u.op==v.op&&u.scan_domain==v.scan_domain&&u.complete==v.complete&&u.input_rows==v.input_rows&&u.output_rows==v.output_rows&&u.unknown_rows==v.unknown_rows&&u.visited==v.visited&&u.total==v.total&&u.attempted_methods==v.attempted_methods&&u.no_body_methods==v.no_body_methods&&u.decoded_methods==v.decoded_methods&&u.events_collected==v.events_collected&&u.code_units==v.code_units);}
 for(uint32_t i=0;i<p.scope_source_count;++i){uint32_t u=UINT32_MAX,v=UINT32_MAX;CHECK(dmg_result_get_scope_source(a,i,&u)==DMG_OK&&dmg_result_get_scope_source(b,i,&v)==DMG_OK&&u==v);}
 dmg_query_info qi{},qj{};CHECK(dmg_result_get_query_info(a,&qi)==DMG_OK&&dmg_result_get_query_info(b,&qj)==DMG_OK&&std::strcmp(qi.query_id,qj.query_id)==0);
 for(uint32_t i=0;i<x.candidates_count;++i){dmg_value_row_v2 l{},r{};CHECK(dmg_result_get_value_v2(a,i,&l,sizeof(l))==DMG_OK&&dmg_result_get_value_v2(b,i,&r,sizeof(r))==DMG_OK&&l.kind==DMG_VALUE_USE&&r.kind==DMG_VALUE_USE&&same_use(l.use,r.use));
  uint32_t ca=0,cb=0;CHECK(dmg_result_get_link_count(a,i,&ca)==DMG_OK&&dmg_result_get_link_count(b,i,&cb)==DMG_OK&&ca==cb);
  for(uint32_t j=0;j<ca;++j){dmg_relation_link_v2 la{},lb{};CHECK(dmg_result_get_link_v2(a,i,j,&la,sizeof(la))==DMG_OK&&dmg_result_get_link_v2(b,i,j,&lb,sizeof(lb))==DMG_OK);CHECK(la.node_id==lb.node_id&&la.key==lb.key&&same_identity(la.left,lb.left)&&same_identity(la.right,lb.right));}
  CHECK(dmg_result_get_binding_count(a,i,&ca)==DMG_OK&&dmg_result_get_binding_count(b,i,&cb)==DMG_OK&&ca==cb);
  for(uint32_t j=0;j<ca;++j){dmg_binding_row_v2 ba{},bb{};CHECK(dmg_result_get_binding_v2(a,i,j,&ba,sizeof(ba))==DMG_OK&&dmg_result_get_binding_v2(b,i,j,&bb,sizeof(bb))==DMG_OK&&ba.value.kind==bb.value.kind);
   CHECK((!ba.label&&!bb.label)||(ba.label&&bb.label&&std::strcmp(ba.label,bb.label)==0));if(ba.value.kind==DMG_VALUE_USE)CHECK(same_use(ba.value.use,bb.value.use));else CHECK(same_entity(ba.value.entity,bb.value.entity));dmg_binding_path pa{},pb{};CHECK(dmg_result_get_binding_path(a,i,j,&pa,sizeof(pa))==DMG_OK&&dmg_result_get_binding_path(b,i,j,&pb,sizeof(pb))==DMG_OK&&pa.length==pb.length);for(uint32_t k=0;k<pa.length;++k)CHECK(pa.sides[k]==pb.sides[k]);}
  CHECK(dmg_result_get_witness_count(a,i,&ca)==DMG_OK&&dmg_result_get_witness_count(b,i,&cb)==DMG_OK&&ca==cb);
  for(uint32_t j=0;j<ca;++j){dmg_relation_witness_v2 wa{},wb{};CHECK(dmg_result_get_relation_witness_v2(a,i,j,&wa,sizeof(wa))==DMG_OK&&dmg_result_get_relation_witness_v2(b,i,j,&wb,sizeof(wb))==DMG_OK);CHECK(wa.operator_node==wb.operator_node&&same_identity(wa.entity,wb.entity)&&std::memcmp(&wa.witness,&wb.witness,sizeof(wa.witness))==0);}
 }
}
static dmg_query* compile(dmg_engine* engine,const std::string& sql){dmg_query* q=nullptr;dmg_error e{};auto rc=dmg_query_compile_json(engine,reinterpret_cast<const uint8_t*>(sql.data()),sql.size(),&q,&e);if(rc!=DMG_OK)std::cerr<<"compile "<<rc<<" "<<e.message<<'\n';CHECK(rc==DMG_OK&&q);return q;}
static std::string plan(const std::string& right_where="",const std::string& left_where="",uint64_t max_work=1000000){
 return "{\"schema_version\":1,\"relation\":{\"op\":\"join\",\"on\":\"target_ref\",\"left\":{\"op\":\"scan\",\"relation\":\"invoke_sites\""+left_where+"},\"right\":{\"op\":\"scan\",\"relation\":\"method_refs\""+right_where+"}},\"max_results\":1000,\"max_work\":"+std::to_string(max_work)+"}";
}
static std::string with_intent(const std::string& extra){auto value=plan();const auto at=value.find(",\"max_results\":1000");CHECK(at!=std::string::npos);value.insert(at,extra);return value;}
static std::string with_result_limit(){auto value=plan();const auto at=value.find("\"max_results\":1000");CHECK(at!=std::string::npos);value.replace(at,std::strlen("\"max_results\":1000"),"\"max_results\":1");return value;}
int main(int argc,char** argv){try{
 CHECK(argc==7);auto two=read(argv[1]),special=read(argv[2]),multi=read(argv[3]),poly=read(argv[4]);dmg_engine* engine=nullptr;dmg_error e{};CHECK(dmg_engine_create(nullptr,&engine,&e)==DMG_OK);
 struct E{dmg_engine* p;~E(){if(p)dmg_engine_release(p);}} eg{engine};
 std::vector<std::vector<uint8_t>*> files{&two,&two,&special,&multi,&poly};std::vector<std::string> slots{"a","b","c","d","e"};std::vector<dmg_source_spec> src;
 for(size_t i=0;i<files.size();++i)src.push_back({sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,files[i]->data(),files[i]->size(),slots[i].c_str(),"join",nullptr});
 dmg_reverse_join_options_v1 opt{sizeof(opt),DMG_ABI_VERSION,1000000,1u<<20,1000000,100000,10000,0,0};
 for(uint32_t complete: {0u,1u}){dmg_source_set_options so{sizeof(so),DMG_ABI_VERSION,"reverse-join",complete,16,8u<<20};dmg_snapshot* snap=nullptr;CHECK(dmg_snapshot_open_sources(engine,src.data(),static_cast<uint32_t>(src.size()),&so,&snap,&e)==DMG_OK);
  struct S{dmg_snapshot* p;~S(){if(p)dmg_snapshot_release(p);}} sg{snap};
  for(const auto& request: {plan(),plan(",\"where\":{\"name\":\"sink\"}"),plan("",",\"where\":{\"pc\":3}"),plan(",\"where\":{\"flags_contains\":1}"),plan(",\"scope\":{\"slots\":[\"b\"]}",",\"scope\":{\"slots\":[\"a\"]}"),with_intent(",\"intent\":\"unique\""),with_intent(",\"intent\":\"top_n\",\"order_by\":[{\"field\":\"pc\",\"direction\":\"desc\"}]"),with_result_limit()}){
   auto* q=compile(engine,request);dmg_result *old=nullptr,*fast=nullptr;CHECK(dmg_query_execute(snap,q,&old,&e)==DMG_OK);
   dmg_reverse_profile_v1 before{},after{};CHECK(dmg_snapshot_reverse_profile_v1(snap,&before,sizeof(before))==DMG_OK);
   auto rc=dmg_query_execute_reverse_intersection_v2(snap,q,&opt,&fast,&e);if(rc!=DMG_OK)std::cerr<<"opt "<<rc<<" "<<e.message<<'\n';CHECK(rc==DMG_OK&&fast);equivalent(old,fast);
   CHECK(dmg_snapshot_reverse_profile_v1(snap,&after,sizeof(after))==DMG_OK);CHECK(after.builds>=before.builds);
   dmg_query* qs[]{q,q};
   for(uint64_t cache_bytes: {uint64_t(0),uint64_t(65536)}){
    dmg_multi_options_v1 mo{sizeof(mo),DMG_ABI_VERSION,cache_bytes,cache_bytes?1000000u:0u,0,0};dmg_multi_batch_v1* batch=nullptr;uint32_t fail=UINT32_MAX;CHECK(dmg_multi_execute_v1(snap,qs,2,&mo,&batch,&fail,&e)==DMG_OK&&batch);
    for(uint32_t i=0;i<2;++i){dmg_result* item=nullptr;CHECK(dmg_multi_batch_get_result_v1(batch,i,&item)==DMG_OK&&item);equivalent(old,item);dmg_result_release(item);}dmg_multi_batch_release_v1(batch);
   }
   dmg_reverse_profile_v1 after_batch{};CHECK(dmg_snapshot_reverse_profile_v1(snap,&after_batch,sizeof(after_batch))==DMG_OK&&after_batch.builds==after.builds&&after_batch.reuses==after.reuses);
   dmg_relation_info_v2 info{};CHECK(dmg_result_get_relation_info_v2(fast,&info,sizeof(info))==DMG_OK);
   if(request==with_result_limit())CHECK(info.candidates_count==1&&info.execution_status==DMG_BUDGET_EXCEEDED&&info.reason==DMG_RESULT_LIMIT);
   std::cout<<"RESULT "<<complete<<' '<<info.candidates_count<<' '<<info.unknown_rows<<' '<<info.coverage<<' '<<info.decision<<'\n';
   if(request==plan()){for(uint32_t i=0;i<info.candidates_count;++i){dmg_value_row_v2 row{};CHECK(dmg_result_get_value_v2(fast,i,&row,sizeof(row))==DMG_OK&&row.kind==DMG_VALUE_USE);auto& u=row.use;std::cout<<"EVENT "<<complete<<' '<<u.source_index<<' '<<u.caller_ordinal<<' '<<u.caller_method_ref<<' '<<u.dex_pc<<' '<<u.opcode<<' '<<u.code_offset<<' '<<u.target_domain<<' '<<u.target_index<<' '<<u.extra_proto<<'\n';}}
   dmg_result_release(old);dmg_result_release(fast);dmg_query_release(q);
  }
 }
 std::cout<<"PASS prototype method intersection\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
