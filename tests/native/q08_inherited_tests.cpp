#include "dexmeguviz/dexmeguviz.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#define CHECK(x) do { if(!(x)) throw std::runtime_error(std::string("line ")+std::to_string(__LINE__)+": " #x); } while(0)
using Engine=std::unique_ptr<dmg_engine,decltype(&dmg_engine_release)>;
using Snapshot=std::unique_ptr<dmg_snapshot,decltype(&dmg_snapshot_release)>;
using Query=std::unique_ptr<dmg_query,decltype(&dmg_query_release)>;
using Result=std::unique_ptr<dmg_result,decltype(&dmg_result_release)>;
static std::vector<uint8_t> load(const std::filesystem::path& p){std::ifstream f(p,std::ios::binary);CHECK(f.good());return {std::istreambuf_iterator<char>(f),{}};}
static Snapshot open(dmg_engine* engine,const std::vector<std::vector<uint8_t>>& bytes,bool complete=true){
    std::vector<std::string> slots;for(size_t i=0;i<bytes.size();++i)slots.push_back("slot"+std::to_string(i));
    std::vector<dmg_source_spec> inputs(bytes.size());
    for(size_t i=0;i<bytes.size();++i){auto& s=inputs[i];s.struct_size=sizeof(s);s.abi_version=DMG_ABI_VERSION;s.format=DMG_INPUT_RAW_DEX;
        s.data=bytes[i].data();s.size=bytes[i].size();s.slot_key=slots[i].c_str();s.role=i?"code-split":"base";}
    dmg_source_set_options o{sizeof(o),DMG_ABI_VERSION,"q08-inherited",complete?1u:0u,16,1u<<20};dmg_snapshot* raw=nullptr;dmg_error error{};
    const auto status=dmg_snapshot_open_sources(engine,inputs.data(),static_cast<uint32_t>(inputs.size()),&o,&raw,&error);
    if(status!=DMG_OK)std::cerr<<"open error: "<<error.message<<" offset="<<error.offset<<" inputs="<<inputs.size()<<'\n';
    CHECK(status==DMG_OK&&raw);return Snapshot(raw,&dmg_snapshot_release);
}
static Query compile(dmg_engine* engine,const std::string& text){dmg_query* q=nullptr;dmg_error error{};auto s=dmg_query_compile_json(engine,reinterpret_cast<const uint8_t*>(text.data()),text.size(),&q,&error);
    if(s!=DMG_OK)std::cerr<<"compile: "<<error.message<<'\n';CHECK(s==DMG_OK&&q);return Query(q,&dmg_query_release);}
static std::string query(const std::string& name,const std::string& range="\"min\":1,\"max\":1",bool negate=false,const std::string& owner="Lfixture/Child;"){
    const auto condition="{\"declares_fields\":{\"scope\":\"inherited\",\"where\":{\"name\":\""+name+"\"},"+range+"}}";
    return "{\"schema_version\":1,\"relation\":\"class_defs\",\"where\":{\"all\":[{\"descriptor\":\""+owner+"\"},"+(negate?"{\"not\":"+condition+"}":condition)+"]},\"intent\":\"unique\"}";
}
static Result run(dmg_engine* e,dmg_snapshot* s,const std::string& json){auto q=compile(e,json);dmg_result* r=nullptr;dmg_error error{};const auto code=dmg_query_execute(s,q.get(),&r,&error);
    if(code!=DMG_OK)std::cerr<<"execute: "<<error.message<<'\n';CHECK(code==DMG_OK&&r);return Result(r,&dmg_result_release);}
static dmg_relation_info info(dmg_result* result){dmg_relation_info r{};CHECK(dmg_result_get_relation_info(result,&r,sizeof(r))==DMG_OK);return r;}
int main(int argc,char** argv){try{
    CHECK(argc==2);std::filesystem::path dir(argv[1]);auto child=load(dir/"child.dex"),base=load(dir/"base-a.dex"),other=load(dir/"base-b.dex"),alt=load(dir/"alt.dex"),top=load(dir/"root.dex");
    dmg_engine* raw=nullptr;dmg_error error{};CHECK(dmg_engine_create(nullptr,&raw,&error)==DMG_OK);Engine engine(raw,&dmg_engine_release);
    auto snap=open(engine.get(),{child,base,top});
    auto explicit_cap=compile(engine.get(),"{\"schema_version\":1,\"relation\":\"method_defs\",\"required_capabilities\":[\"inherited_fields\"]}");
    dmg_query_info explicit_info{};CHECK(dmg_query_get_info(explicit_cap.get(),&explicit_info)==DMG_OK&&std::string(explicit_info.query_id).rfind("query:v6:",0)==0&&(explicit_info.required_capabilities&16384));
    auto q=compile(engine.get(),query("parentOnly"));dmg_query_info qi{};CHECK(dmg_query_get_info(q.get(),&qi)==DMG_OK);
    CHECK(std::string(qi.query_id).rfind("query:v6:",0)==0&&(qi.required_capabilities&16384));
    auto matched=run(engine.get(),snap.get(),query("parentOnly"));auto result_info=info(matched.get());
    CHECK(result_info.candidates_count==1&&result_info.decision==DMG_PROVEN_TRUE&&result_info.coverage==DMG_COVERAGE_COMPLETE);
    uint32_t count=0;CHECK(dmg_result_get_witness_count(matched.get(),0,&count)==DMG_OK);unsigned paths=0,ends=0,branches=0,fields=0;
    for(uint32_t i=0;i<count;++i){dmg_witness w{};CHECK(dmg_result_get_witness(matched.get(),0,i,&w)==DMG_OK);if(w.kind!=DMG_WITNESS_INHERITED)continue;
        dmg_inherited_witness h{};CHECK(dmg_result_get_inherited_witness(matched.get(),0,i,&h,sizeof(h))==DMG_OK&&h.node_id==w.node_id&&h.matched==DMG_MATCH_TRUE);
        if(h.item_kind==DMG_INHERITED_PATH)++paths;else if(h.item_kind==DMG_INHERITED_END)++ends;else if(h.item_kind==DMG_INHERITED_BRANCH)++branches;
        else if(h.item_kind==DMG_INHERITED_FIELD){++fields;CHECK(h.source_index==1&&h.relation==DMG_FIELD_DEFS&&h.local_index==1&&h.path_index==1&&h.branch_index==0);}
        dmg_inherited_witness unchanged{};unchanged.item_kind=999;CHECK(dmg_result_get_inherited_witness(matched.get(),0,i,&unchanged,sizeof(unchanged)-1)==DMG_INVALID_ARGUMENT&&unchanged.item_kind==999);
    }
    CHECK(paths==3&&ends==1&&branches==1&&fields==1);
    auto hidden=run(engine.get(),snap.get(),query("shared","\"min\":1,\"max\":1",true));CHECK(info(hidden.get()).candidates_count==1);
    auto own=run(engine.get(),snap.get(),query("childOnly","\"min\":1,\"max\":1",true));CHECK(info(own.get()).candidates_count==1);
    auto priv=run(engine.get(),snap.get(),query("privateOnly","\"min\":1,\"max\":1",true));CHECK(info(priv.get()).candidates_count==1);
    auto package=run(engine.get(),snap.get(),query("packageOnly"));CHECK(info(package.get()).candidates_count==0&&info(package.get()).unknown_rows==1&&info(package.get()).coverage==DMG_COVERAGE_PARTIAL);
    auto missing=open(engine.get(),{child,base});auto bounded=run(engine.get(),missing.get(),query("parentOnly"));CHECK(info(bounded.get()).unknown_rows==1&&info(bounded.get()).decision==DMG_UNDETERMINED);
    auto lower=run(engine.get(),missing.get(),query("parentOnly","\"min\":1"));CHECK(info(lower.get()).candidates_count==1);
    auto ambiguous=open(engine.get(),{child,base,other,alt,top});auto amb=run(engine.get(),ambiguous.get(),query("parentOnly"));CHECK(info(amb.get()).unknown_rows==1&&info(amb.get()).candidates_count==0);
    const auto edges=dir.parent_path()/"inherited-edges-v2";
    auto private_child=load(edges/"child-private.dex"),clear_child=load(edges/"child-clear.dex"),iface_child=load(edges/"child-interface.dex"),collision=load(edges/"base-collision.dex");
    const std::string edge_owner="Lfixture/EdgeChild;";
    auto private_snap=open(engine.get(),{private_child,collision,top});auto private_hidden=run(engine.get(),private_snap.get(),query("shared","\"min\":1",true,edge_owner));
    CHECK(info(private_hidden.get()).candidates_count==1&&info(private_hidden.get()).decision==DMG_PROVEN_TRUE);
    auto clear_snap=open(engine.get(),{clear_child,collision,top});auto both_types=run(engine.get(),clear_snap.get(),query("shared","\"min\":2,\"max\":2",false,edge_owner));
    CHECK(info(both_types.get()).candidates_count==1&&info(both_types.get()).decision==DMG_PROVEN_TRUE);
    auto iface_snap=open(engine.get(),{iface_child,collision,top});auto interface_result=run(engine.get(),iface_snap.get(),query("shared","\"min\":1",false,edge_owner));
    CHECK(info(interface_result.get()).unknown_rows==1&&info(interface_result.get()).decision==DMG_UNDETERMINED);
    auto repeated=open(engine.get(),{child,base,base,top});auto repeated_result=run(engine.get(),repeated.get(),query("parentOnly"));
    CHECK(info(repeated_result.get()).candidates_count==1&&info(repeated_result.get()).decision==DMG_PROVEN_TRUE);
    const auto cycle=load(dir/"base-cycle.dex");auto cyclic=open(engine.get(),{child,cycle,top});auto cycle_result=run(engine.get(),cyclic.get(),query("parentOnly"));
    CHECK(info(cycle_result.get()).unknown_rows==1&&info(cycle_result.get()).candidates_count==0);
    auto partial_scope=open(engine.get(),{child,base,top},false);auto partial=run(engine.get(),partial_scope.get(),query("parentOnly"));
    CHECK(info(partial.get()).unknown_rows==1&&info(partial.get()).decision==DMG_UNDETERMINED);
    auto selected_text=query("parentOnly");selected_text.insert(selected_text.size()-1,",\"scope\":{\"slots\":[\"slot0\",\"slot1\"]}");
    auto selected=run(engine.get(),snap.get(),selected_text);CHECK(info(selected.get()).unknown_rows==1&&info(selected.get()).decision==DMG_UNDETERMINED);
    auto limited_text=query("parentOnly");limited_text.insert(limited_text.size()-1,",\"max_work\":1");auto limited=compile(engine.get(),limited_text);
    dmg_result* no_result=nullptr;CHECK(dmg_query_execute(snap.get(),limited.get(),&no_result,&error)==DMG_BUDGET_EXCEEDED&&!no_result);
    auto declared1=compile(engine.get(),"{\"schema_version\":1,\"relation\":\"class_defs\",\"where\":{\"declares_fields\":{\"where\":{\"name\":\"childOnly\"},\"min\":1}}}");
    auto declared2=compile(engine.get(),"{\"schema_version\":1,\"relation\":\"class_defs\",\"where\":{\"declares_fields\":{\"scope\":\"declared\",\"where\":{\"name\":\"childOnly\"},\"min\":1}}}");
    dmg_query_info a{},b{};CHECK(dmg_query_get_info(declared1.get(),&a)==DMG_OK&&dmg_query_get_info(declared2.get(),&b)==DMG_OK&&std::string(a.query_id)==b.query_id&&std::string(a.query_id).rfind("query:v2:",0)==0);
    dmg_job* job=nullptr;dmg_job_options jo{sizeof(jo),DMG_ABI_VERSION,16,1,0};CHECK(dmg_job_start(snap.get(),q.get(),&jo,&job,&error)==DMG_OK&&job);
    dmg_batch* batch=nullptr;CHECK(dmg_job_next(job,10000,&batch,&error)==DMG_OK&&batch);dmg_relation_job_status js{};
    CHECK(dmg_job_wait_relation(job,10000,&js,sizeof(js))==DMG_OK&&js.terminal&&js.outcome.decision==DMG_PROVEN_TRUE);dmg_job_release(job);
    CHECK(dmg_result_get_witness_count(batch,0,&count)==DMG_OK&&count>0);unsigned retained=0;
    for(uint32_t i=0;i<count;++i){dmg_witness w{};CHECK(dmg_result_get_witness(batch,0,i,&w)==DMG_OK);if(w.kind==DMG_WITNESS_INHERITED){dmg_inherited_witness h{};CHECK(dmg_result_get_inherited_witness(batch,0,i,&h,sizeof(h))==DMG_OK);++retained;}}
    CHECK(retained>0);dmg_batch_release(batch);
    const std::string graph="{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"class_defs\",\"where\":{\"declares_fields\":{\"scope\":\"inherited\",\"where\":{}}}}}";
    dmg_query* unsupported=nullptr;CHECK(dmg_query_compile_json(engine.get(),reinterpret_cast<const uint8_t*>(graph.data()),graph.size(),&unsupported,&error)==DMG_OK&&unsupported);
    dmg_query_release(unsupported);unsupported=nullptr;
    const std::string mixed_numeric="{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"all\":[{\"declares_fields\":{\"scope\":\"inherited\",\"where\":{}}},{\"numeric_bits\":{\"width\":32,\"bits\":\"ffffffff\",\"kind\":\"constant\"}}]}}";
    CHECK(dmg_query_compile_json(engine.get(),reinterpret_cast<const uint8_t*>(mixed_numeric.data()),mixed_numeric.size(),&unsupported,&error)==DMG_OK&&unsupported);
    dmg_query_info mixed_info{};CHECK(dmg_query_get_info(unsupported,&mixed_info)==DMG_OK&&(mixed_info.required_capabilities&262144u)&&std::string(mixed_info.query_id).starts_with("query:v10:"));
    dmg_query_release(unsupported);unsupported=nullptr;
    const std::string cap_graph="{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"class_defs\"},\"required_capabilities\":[\"inherited_fields\"]}";
    CHECK(dmg_query_compile_json(engine.get(),reinterpret_cast<const uint8_t*>(cap_graph.data()),cap_graph.size(),&unsupported,&error)==DMG_OK&&unsupported);
    dmg_query_release(unsupported);unsupported=nullptr;
    for(const auto cap:{"bounded_expand","interface_fields"}){auto unsupported_text=query("parentOnly");unsupported_text.insert(unsupported_text.size()-1,",\"required_capabilities\":[\""+std::string(cap)+"\"]");
        CHECK(dmg_query_compile_json(engine.get(),reinterpret_cast<const uint8_t*>(unsupported_text.data()),unsupported_text.size(),&unsupported,&error)==DMG_UNSUPPORTED&&!unsupported);}

    std::cout<<"PASS direct inherited: scoped multidex, path proof, hiding, access, missing and ambiguous definitions\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
