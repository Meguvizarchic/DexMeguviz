#include "dexmeguviz/dexmeguviz.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#define CHECK(x) do{if(!(x))throw std::runtime_error("q08 relation line "+std::to_string(__LINE__)+": " #x);}while(0)
using Engine=std::unique_ptr<dmg_engine,decltype(&dmg_engine_release)>;
using Snapshot=std::unique_ptr<dmg_snapshot,decltype(&dmg_snapshot_release)>;
using Query=std::unique_ptr<dmg_query,decltype(&dmg_query_release)>;
using Result=std::unique_ptr<dmg_result,decltype(&dmg_result_release)>;
using Batch=std::unique_ptr<dmg_batch,decltype(&dmg_batch_release)>;
static std::vector<uint8_t> load(const std::filesystem::path& p){std::ifstream f(p,std::ios::binary);CHECK(f.good());return {std::istreambuf_iterator<char>(f),{}};}
static Snapshot snapshot(dmg_engine* e,const std::vector<std::vector<uint8_t>>& bytes,bool complete){
    const char* slots[]={"slot0","slot1","slot2"};std::vector<dmg_source_spec> inputs(bytes.size());
    for(size_t i=0;i<bytes.size();++i){auto& s=inputs[i];s.struct_size=sizeof(s);s.abi_version=DMG_ABI_VERSION;s.format=DMG_INPUT_RAW_DEX;s.slot_key=slots[i];s.role=i?"code-split":"base";s.data=bytes[i].data();s.size=bytes[i].size();}
    dmg_source_set_options o{sizeof(o),DMG_ABI_VERSION,"q08-graph-scope",complete?1u:0u,8,1u<<20};dmg_snapshot* raw=nullptr;dmg_error error{};
    CHECK(dmg_snapshot_open_sources(e,inputs.data(),static_cast<uint32_t>(inputs.size()),&o,&raw,&error)==DMG_OK&&raw);return Snapshot(raw,&dmg_snapshot_release);
}
static Query compile(dmg_engine* e,const std::string& text){dmg_query* raw=nullptr;dmg_error error{};auto status=dmg_query_compile_json(e,reinterpret_cast<const uint8_t*>(text.data()),text.size(),&raw,&error);if(status!=DMG_OK)std::cerr<<error.message<<'\n';CHECK(status==DMG_OK&&raw);return Query(raw,&dmg_query_release);}
static Result run(dmg_engine* e,dmg_snapshot* s,const std::string& text){auto q=compile(e,text);dmg_query_info qi{};CHECK(dmg_query_get_info(q.get(),&qi)==DMG_OK&&std::string(qi.query_id).starts_with("query:v6:"));dmg_result* r=nullptr;dmg_error error{};auto status=dmg_query_execute(s,q.get(),&r,&error);if(status!=DMG_OK)std::cerr<<error.message<<'\n';CHECK(status==DMG_OK&&r);return Result(r,&dmg_result_release);}
static dmg_relation_info info(dmg_result* r){dmg_relation_info value{};CHECK(dmg_result_get_relation_info(r,&value,sizeof(value))==DMG_OK);return value;}
static void witness(dmg_result* result){
    uint32_t n=0;CHECK(dmg_result_get_witness_count(result,0,&n)==DMG_OK);unsigned fields=0,paths=0;
    for(uint32_t i=0;i<n;++i){dmg_witness w{};CHECK(dmg_result_get_witness(result,0,i,&w)==DMG_OK);if(w.kind!=DMG_WITNESS_INHERITED)continue;
        dmg_relation_witness rw{};dmg_inherited_witness hw{};CHECK(dmg_result_get_relation_witness(result,0,i,&rw,sizeof(rw))==DMG_OK);
        CHECK(dmg_result_get_inherited_witness(result,0,i,&hw,sizeof(hw))==DMG_OK&&hw.node_id==w.node_id&&hw.matched==DMG_MATCH_TRUE);
        CHECK(rw.witness.kind==DMG_WITNESS_INHERITED&&rw.operator_node!=UINT32_MAX);
        if(hw.item_kind==DMG_INHERITED_PATH)++paths;
        if(hw.item_kind==DMG_INHERITED_FIELD){++fields;CHECK(hw.source_index==1&&hw.relation==DMG_FIELD_DEFS&&hw.local_index==1);}
    }
    CHECK(paths==3&&fields==1);
}
int main(int argc,char** argv){try{
    CHECK(argc==2);std::filesystem::path root(argv[1]);auto child=load(root/"child.dex"),base=load(root/"base-a.dex"),top=load(root/"root.dex");
    dmg_engine* raw=nullptr;dmg_error error{};CHECK(dmg_engine_create(nullptr,&raw,&error)==DMG_OK);Engine engine(raw,&dmg_engine_release);
    auto full=snapshot(engine.get(),{child,base,top},true);auto partial=snapshot(engine.get(),{child,base,top},false);
    const std::string predicate=R"({"all":[{"descriptor":"Lfixture/Child;"},{"declares_fields":{"scope":"inherited","where":{"name":"parentOnly"},"min":1,"max":1}}]})";
    const auto query=[&](const std::string& relation,const std::string& suffix=""){return std::string(R"({"schema_version":1,"relation":)")+relation+R"(,"intent":"unique")"+suffix+"}";};
    const auto scan=query(std::string(R"({"op":"scan","relation":"class_defs","where":)")+predicate+"}");
    const auto filter=query(std::string(R"({"op":"filter","input":{"op":"scan","relation":"class_defs"},"where":)")+predicate+"}");
    for(const auto& text:{scan,filter}){auto r=run(engine.get(),full.get(),text);auto x=info(r.get());CHECK(x.candidates_count==1&&x.decision==DMG_PROVEN_TRUE&&x.coverage==DMG_COVERAGE_COMPLETE);witness(r.get());}
    auto unknown=run(engine.get(),partial.get(),scan);CHECK(info(unknown.get()).unknown_rows==1&&info(unknown.get()).decision==DMG_UNDETERMINED);
    const auto restricted=std::string(R"({"op":"scan","relation":"class_defs","scope":{"slots":["slot0"]},"where":)")+predicate+"}";
    const auto no_rows=R"({"op":"scan","relation":"class_defs","scope":{"slots":["slot1","slot2"]},"where":false})";
    const auto independent=query(std::string(R"({"op":"union","semantics":"bag","inputs":[)")+restricted+","+no_rows+"]}");
    auto isolated=run(engine.get(),full.get(),independent);CHECK(info(isolated.get()).unknown_rows==1&&info(isolated.get()).candidates_count==0);
    const auto child_rows=R"({"op":"scan","relation":"class_defs","scope":{"slots":["slot0"]},"where":{"descriptor":"Lfixture/Child;"}})";
    const auto union_input=std::string(R"({"op":"union","semantics":"bag","inputs":[)")+child_rows+","+no_rows+"]}";
    const auto union_filter=query(std::string(R"({"op":"filter","input":)")+union_input+R"(,"where":)"+predicate+"}");
    auto combined=run(engine.get(),full.get(),union_filter);CHECK(info(combined.get()).candidates_count==1&&info(combined.get()).decision==DMG_PROVEN_TRUE);witness(combined.get());
    const auto selected=query(std::string(R"({"op":"scan","relation":"class_defs","scope":{"slots":["slot0","slot1","slot2"]},"where":)")+predicate+"}");
    auto closed=run(engine.get(),partial.get(),selected);CHECK(info(closed.get()).candidates_count==1&&info(closed.get()).coverage==DMG_COVERAGE_COMPLETE);
    auto q=compile(engine.get(),scan);dmg_job_options options{sizeof(options),DMG_ABI_VERSION,1,2,0};dmg_job* job=nullptr;
    CHECK(dmg_job_start(full.get(),q.get(),&options,&job,&error)==DMG_OK&&job);dmg_batch* raw_batch=nullptr;CHECK(dmg_job_next(job,10000,&raw_batch,&error)==DMG_OK&&raw_batch);Batch batch(raw_batch,&dmg_batch_release);
    dmg_relation_job_status status{};CHECK(dmg_job_wait_relation(job,10000,&status,sizeof(status))==DMG_OK&&status.terminal&&status.outcome.decision==DMG_PROVEN_TRUE);
    dmg_job_release(job);witness(batch.get());
    auto limited=compile(engine.get(),query(std::string(R"({"op":"scan","relation":"class_defs","where":)")+predicate+"}",R"(,"max_work":1)"));
    dmg_result* none=nullptr;CHECK(dmg_query_execute(full.get(),limited.get(),&none,&error)==DMG_BUDGET_EXCEEDED&&!none);
    std::cout<<"PASS inherited relation scan/filter, independent scopes, incomplete scope, evidence, Job and budget\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
