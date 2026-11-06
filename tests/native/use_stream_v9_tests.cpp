#include "c_api/runtime.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace dexmeguviz;
namespace dexmeguviz::runtime {extern std::atomic<void(*)(uint32_t)> test_job_scan_barrier;}
#define CHECK(x) do{if(!(x))throw std::runtime_error("use v9 line "+std::to_string(__LINE__)+": " #x);}while(0)
using Engine=std::unique_ptr<dmg_engine,decltype(&dmg_engine_release)>;
using Snapshot=std::unique_ptr<dmg_snapshot,decltype(&dmg_snapshot_release)>;
using Query=std::unique_ptr<dmg_query,decltype(&dmg_query_release)>;
using Job=std::unique_ptr<dmg_job,decltype(&dmg_job_release)>;
using Batch=std::unique_ptr<dmg_batch,decltype(&dmg_batch_release)>;
using Result=std::unique_ptr<dmg_result,decltype(&dmg_result_release)>;
static std::mutex gate_mutex;static std::condition_variable gate_cv;static bool entered=false,opened=false;static uint32_t target=0;
static void gate(uint32_t count){if(count!=target)return;std::unique_lock lock(gate_mutex);entered=true;gate_cv.notify_all();gate_cv.wait(lock,[]{return opened;});}
static void arm(uint32_t count){std::lock_guard lock(gate_mutex);entered=false;opened=false;target=count;runtime::test_job_scan_barrier.store(&gate,std::memory_order_release);}
static void await_gate(){std::unique_lock lock(gate_mutex);CHECK(gate_cv.wait_for(lock,std::chrono::seconds(15),[]{return entered;}));}
static void unblock(){{std::lock_guard lock(gate_mutex);opened=true;runtime::test_job_scan_barrier.store(nullptr,std::memory_order_release);}gate_cv.notify_all();}
struct Unblock{~Unblock(){unblock();}};
static std::vector<uint8_t> load(const std::filesystem::path& path){std::ifstream in(path,std::ios::binary);CHECK(in.good());return {std::istreambuf_iterator<char>(in),{}};}
static Engine engine(){dmg_engine* e=nullptr;dmg_error error{};CHECK(dmg_engine_create(nullptr,&e,&error)==DMG_OK&&e);return Engine(e,&dmg_engine_release);}
static Snapshot snapshot(dmg_engine* e,const std::vector<uint8_t>& first,const std::vector<uint8_t>* second=nullptr,bool complete=true){
    std::vector<dmg_source_spec> specs;const auto add=[&](const auto& bytes,const char* slot){dmg_source_spec s{};s.struct_size=sizeof(s);s.abi_version=DMG_ABI_VERSION;s.format=DMG_INPUT_RAW_DEX;s.data=bytes.data();s.size=bytes.size();s.slot_key=slot;s.role="code-split";specs.push_back(s);};
    add(first,"first");if(second)add(*second,"second");dmg_source_set_options options{sizeof(options),DMG_ABI_VERSION,"use-v9",complete?1u:0u,8,1u<<20};dmg_snapshot* raw=nullptr;dmg_error error{};
    CHECK(dmg_snapshot_open_sources(e,specs.data(),static_cast<uint32_t>(specs.size()),&options,&raw,&error)==DMG_OK&&raw);return Snapshot(raw,&dmg_snapshot_release);
}
static std::string query_text(bool stream,uint64_t max_work=0,uint32_t max_results=100){
    std::string s=std::string(R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"intent":"unique","max_results":)")+std::to_string(max_results);
    if(stream)s+=R"(,"required_capabilities":["use_streaming"])";
    if(max_work)s+=",\"max_work\":"+std::to_string(max_work);return s+'}';
}
static Query compile(dmg_engine* e,bool stream,uint64_t work=0,uint32_t max_results=100){const auto text=query_text(stream,work,max_results);dmg_query* raw=nullptr;dmg_error error{};
    CHECK(dmg_query_compile_json(e,reinterpret_cast<const uint8_t*>(text.data()),text.size(),&raw,&error)==DMG_OK&&raw);dmg_query_info info{};CHECK(dmg_query_get_info(raw,&info)==DMG_OK);
    CHECK(std::string(info.query_id).starts_with(stream?"query:v9:":"query:v4:"));CHECK(((info.required_capabilities&131072u)!=0)==stream);return Query(raw,&dmg_query_release);}
static Job start(dmg_snapshot* s,dmg_query* q){dmg_job_options o{sizeof(o),DMG_ABI_VERSION,1,4,0};dmg_job* raw=nullptr;dmg_error error{};CHECK(dmg_job_start(s,q,&o,&raw,&error)==DMG_OK&&raw);return Job(raw,&dmg_job_release);}
static dmg_relation_job_status_v2 wait(dmg_job* j){dmg_relation_job_status_v2 s{};CHECK(dmg_job_wait_relation_v2(j,15000,&s,sizeof(s))==DMG_OK&&s.terminal);return s;}
static std::vector<uint32_t> drain(dmg_job* j){std::vector<uint32_t> pcs;for(;;){dmg_batch* raw=nullptr;dmg_error error{};const auto code=dmg_job_next(j,1000,&raw,&error);if(code==DMG_END_OF_STREAM)return pcs;CHECK(code==DMG_OK&&raw);Batch b(raw,&dmg_batch_release);dmg_relation_info_v2 info{};dmg_value_row_v2 row{};CHECK(dmg_result_get_relation_info_v2(b.get(),&info,sizeof(info))==DMG_OK&&info.coverage==DMG_COVERAGE_PARTIAL&&info.candidates_count==1);CHECK(dmg_result_get_value_v2(b.get(),0,&row,sizeof(row))==DMG_OK&&row.kind==DMG_VALUE_USE&&row.use.source_index==0);
    CHECK(row.use.relation==DMG_INVOKE_SITES&&row.use.caller_ordinal==2&&row.use.caller_method_ref==3&&row.use.opcode==0x71&&row.use.code_offset==416&&row.use.target_index==4&&row.use.target_domain==DMG_TARGET_METHOD_REF);
    uint32_t count=0;CHECK(dmg_result_get_witness_count(b.get(),0,&count)==DMG_OK);bool found=false;
    for(uint32_t i=0;i<count;++i){dmg_relation_witness_v2 w{};CHECK(dmg_result_get_relation_witness_v2(b.get(),0,i,&w,sizeof(w))==DMG_OK);if(w.witness.kind==DMG_WITNESS_INVOKE){CHECK(w.entity.source_index==0&&w.entity.local_index==2&&w.entity.dex_pc==row.use.dex_pc&&w.witness.dex_pc==row.use.dex_pc&&w.witness.reference_index==4);found=true;}}
    CHECK(found);pcs.push_back(row.use.dex_pc);}}
static void interrupt(const std::vector<uint8_t>& bytes,uint32_t count){auto e=engine();auto s=snapshot(e.get(),bytes);auto q=compile(e.get(),true);arm(count);auto j=start(s.get(),q.get());Unblock guard;await_gate();
    dmg_relation_job_status_v2 live{};CHECK(dmg_job_get_relation_status_v2(j.get(),&live,sizeof(live))==DMG_OK&&!live.terminal);
    CHECK(live.outcome.candidates_count==count&&live.outcome.events_collected==2&&live.outcome.method_visited>=3);
    dmg_job_cancel(j.get());unblock();const auto done=wait(j.get());CHECK(done.outcome.execution_status==DMG_CANCELLED&&done.outcome.coverage==DMG_COVERAGE_PARTIAL&&done.outcome.candidates_count==count&&done.outcome.events_collected==2);
    CHECK(done.outcome.decision==static_cast<uint32_t>(count==1?DMG_UNDETERMINED:DMG_PROVEN_FALSE));if(count==2)CHECK(done.outcome.reason==DMG_AMBIGUOUS);
    const auto pcs=drain(j.get());CHECK(pcs.size()==count&&pcs[0]==0);if(count==2)CHECK(pcs[1]==3);
}
static dmg_status sync_status(dmg_snapshot* s,dmg_query* q,Result& output){dmg_result* raw=nullptr;dmg_error error{};const auto status=dmg_query_execute(s,q,&raw,&error);output.reset(raw);return status;}
static void budget_equivalence(const std::vector<uint8_t>& bytes){auto e=engine();auto s=snapshot(e.get(),bytes);auto q=compile(e.get(),true);Result r(nullptr,&dmg_result_release);CHECK(sync_status(s.get(),q.get(),r)==DMG_OK&&r);
    dmg_relation_info_v2 info{};CHECK(dmg_result_get_relation_info_v2(r.get(),&info,sizeof(info))==DMG_OK&&info.execution_status==DMG_OK&&info.candidates_count==2);dmg_query_profile profile{};CHECK(dmg_result_get_profile(r.get(),&profile)==DMG_OK&&profile.work_units>1);
    std::vector<uint64_t> limits{1,2,3,profile.work_units/2,profile.work_units-2,profile.work_units-1,profile.work_units,profile.work_units+1};std::sort(limits.begin(),limits.end());limits.erase(std::unique(limits.begin(),limits.end()),limits.end());
    for(const auto work:limits){auto limited=compile(e.get(),true,work);Result direct(nullptr,&dmg_result_release);const auto rc=sync_status(s.get(),limited.get(),direct);auto j=start(s.get(),limited.get());const auto outcome=wait(j.get());
        const auto direct_execution=rc==DMG_OK?([&]{dmg_relation_info_v2 x{};CHECK(dmg_result_get_relation_info_v2(direct.get(),&x,sizeof(x))==DMG_OK);return static_cast<dmg_status>(x.execution_status);}()):rc;
        CHECK(outcome.outcome.execution_status==direct_execution);CHECK(direct_execution==static_cast<dmg_status>(work>=profile.work_units?DMG_OK:DMG_BUDGET_EXCEEDED));auto pcs=drain(j.get());if(direct_execution==DMG_OK){CHECK(pcs==std::vector<uint32_t>({0,3}));dmg_query_profile observed{};CHECK(dmg_job_get_profile(j.get(),&observed)==DMG_OK&&observed.work_units==profile.work_units&&outcome.outcome.events_collected==info.events_collected&&outcome.outcome.method_visited==info.method_visited);}
    }
}
static void limited_unique_equivalence(const std::vector<uint8_t>& bytes){auto e=engine();auto s=snapshot(e.get(),bytes);
    for(const uint64_t work:{36,37,38,39,40,41,42,64}){auto q=compile(e.get(),true,work,1);Result direct(nullptr,&dmg_result_release);const auto rc=sync_status(s.get(),q.get(),direct);uint32_t direct_status=rc,direct_reason=UINT32_MAX;
        if(direct){dmg_relation_info_v2 info{};CHECK(dmg_result_get_relation_info_v2(direct.get(),&info,sizeof(info))==DMG_OK);direct_status=info.execution_status;direct_reason=info.reason;}
        auto j=start(s.get(),q.get());const auto done=wait(j.get());CHECK(done.outcome.execution_status==direct_status);
        if(direct)CHECK(done.outcome.reason==direct_reason);else{CHECK(done.outcome.reason!=DMG_RESULT_LIMIT&&done.outcome.candidates_count==0);}
        const auto rows=drain(j.get());CHECK(rows.size()==done.outcome.candidates_count);
    }
}
static void rejected_combinations(dmg_engine* e){
    const std::vector<std::string> values{
      R"({"schema_version":1,"relation":"method_defs","required_capabilities":["use_streaming"]})",
      R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"required_capabilities":["use_streaming","inherited_fields","interface_fields"]})"};
    for(const auto& text:values){dmg_query* q=nullptr;dmg_error error{};CHECK(dmg_query_compile_json(e,reinterpret_cast<const uint8_t*>(text.data()),text.size(),&q,&error)==DMG_UNSUPPORTED&&q==nullptr);}
    for(const auto* capability:{"numeric_literals","inherited_fields","interface_fields"}){
        const auto text=std::string(R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"},"required_capabilities":["use_streaming",")")+capability+R"("]})";
        dmg_query* raw=nullptr;dmg_error error{};CHECK(dmg_query_compile_json(e,reinterpret_cast<const uint8_t*>(text.data()),text.size(),&raw,&error)==DMG_OK&&raw);
        Query q(raw,&dmg_query_release);dmg_query_info info{};CHECK(dmg_query_get_info(q.get(),&info)==DMG_OK&&(info.required_capabilities&262144u)&&std::string(info.query_id).starts_with("query:v10:"));
    }
}
static void rejected_unpaired_hook(const std::vector<uint8_t>& bytes){auto e=engine();auto s=snapshot(e.get(),bytes);const auto& source=*s->dataset->sources[0];facts::UseScanProgress progress{};facts::UseScanHooks hooks{};
    hooks.remaining=[](void*)noexcept->uint64_t{return 1000;};bool rejected=false;
    try{(void)facts::collect_uses(source.view(),source.facts,0,facts::UseKind::invoke_site,progress,std::pmr::get_default_resource(),{},{},hooks);}
    catch(const facts::UseScanError& error){rejected=error.code==facts::UseScanError::Code::invalid;}
    CHECK(rejected&&progress.attempted_methods==0);
}
static void corruption(const std::vector<uint8_t>& good,const std::vector<uint8_t>& bad){auto e=engine();auto q=compile(e.get(),true);
    {auto s=snapshot(e.get(),bad);auto j=start(s.get(),q.get());const auto done=wait(j.get());CHECK(done.outcome.execution_status==DMG_CORRUPT_INPUT&&done.outcome.candidates_count==0);CHECK(drain(j.get()).empty());}
    {auto s=snapshot(e.get(),good,&bad);auto j=start(s.get(),q.get());const auto done=wait(j.get());CHECK(done.outcome.execution_status==DMG_CORRUPT_INPUT&&done.outcome.candidates_count==2&&done.outcome.decision==DMG_PROVEN_FALSE&&done.outcome.reason==DMG_AMBIGUOUS);CHECK(drain(j.get())==std::vector<uint32_t>({0,3}));}
}
static std::vector<std::pair<uint32_t,uint32_t>> drain_methods(dmg_job* j){std::vector<std::pair<uint32_t,uint32_t>> out;
    for(;;){dmg_batch* raw=nullptr;dmg_error error{};const auto code=dmg_job_next(j,1000,&raw,&error);if(code==DMG_END_OF_STREAM)return out;CHECK(code==DMG_OK&&raw);Batch b(raw,&dmg_batch_release);dmg_value_row_v2 row{};
        CHECK(dmg_result_get_value_v2(b.get(),0,&row,sizeof(row))==DMG_OK&&row.kind==DMG_VALUE_USE&&row.use.source_index==0&&row.use.opcode==0x71&&row.use.target_index==4);
        out.push_back({row.use.caller_ordinal,row.use.dex_pc});}}
static void separate_methods(const std::vector<uint8_t>& good,const std::vector<uint8_t>& bad){auto e=engine();auto q=compile(e.get(),true);auto s=snapshot(e.get(),good);
    {arm(1);auto j=start(s.get(),q.get());Unblock guard;await_gate();dmg_relation_job_status_v2 live{};CHECK(dmg_job_get_relation_status_v2(j.get(),&live,sizeof(live))==DMG_OK&&!live.terminal);
     CHECK(live.outcome.candidates_count==1&&live.outcome.method_visited==2&&live.outcome.events_collected==1);dmg_job_cancel(j.get());unblock();const auto done=wait(j.get());CHECK(done.outcome.execution_status==DMG_CANCELLED&&done.outcome.candidates_count==1&&done.outcome.decision==DMG_UNDETERMINED);
     const auto found=drain_methods(j.get());CHECK(found.size()==1&&found[0]==std::make_pair(1u,0u));}
    {auto j=start(s.get(),q.get());const auto done=wait(j.get());CHECK(done.outcome.execution_status==DMG_OK&&done.outcome.candidates_count==2);
     const auto found=drain_methods(j.get());CHECK(found.size()==2&&found[0]==std::make_pair(1u,0u)&&found[1]==std::make_pair(2u,2u));}
    {auto broken=snapshot(e.get(),bad);auto j=start(broken.get(),q.get());const auto done=wait(j.get());CHECK(done.outcome.execution_status==DMG_CORRUPT_INPUT&&done.outcome.candidates_count==1&&done.outcome.decision==DMG_UNDETERMINED);
     const auto found=drain_methods(j.get());CHECK(found.size()==1&&found[0]==std::make_pair(1u,0u));}
    {auto broken=snapshot(e.get(),bad);auto legacy=compile(e.get(),false);auto j=start(broken.get(),legacy.get());const auto done=wait(j.get());CHECK(done.outcome.execution_status==DMG_CORRUPT_INPUT&&done.outcome.candidates_count==0);CHECK(drain_methods(j.get()).empty());}
    {auto broken=snapshot(e.get(),bad);for(const uint64_t work:{1,2,4,8,16,24,32,48,64,96,128}){auto limited=compile(e.get(),true,work);Result direct(nullptr,&dmg_result_release);const auto expected=sync_status(broken.get(),limited.get(),direct);auto j=start(broken.get(),limited.get());const auto done=wait(j.get());
        CHECK(done.outcome.execution_status==expected&&(expected==DMG_BUDGET_EXCEEDED||expected==DMG_CORRUPT_INPUT));CHECK(done.outcome.candidates_count<=1&&done.outcome.decision==DMG_UNDETERMINED);const auto rows=drain_methods(j.get());CHECK(rows.size()==done.outcome.candidates_count);}}
    Result r(nullptr,&dmg_result_release);CHECK(sync_status(s.get(),q.get(),r)==DMG_OK&&r);dmg_query_profile p{};CHECK(dmg_result_get_profile(r.get(),&p)==DMG_OK&&p.work_units>2);
    for(const auto work:{uint64_t{1},p.work_units/2,p.work_units-1,p.work_units}){auto limited=compile(e.get(),true,work);Result direct(nullptr,&dmg_result_release);const auto rc=sync_status(s.get(),limited.get(),direct);auto j=start(s.get(),limited.get());const auto done=wait(j.get());
        const auto sync=rc==DMG_OK?([&]{dmg_relation_info_v2 x{};CHECK(dmg_result_get_relation_info_v2(direct.get(),&x,sizeof(x))==DMG_OK);return static_cast<dmg_status>(x.execution_status);}()):rc;
        CHECK(done.outcome.execution_status==sync);CHECK(sync==static_cast<dmg_status>(work==p.work_units?DMG_OK:DMG_BUDGET_EXCEEDED));(void)drain_methods(j.get());}
}
static std::atomic<unsigned> offers{0};
static void count_offer(uint32_t){offers.fetch_add(1,std::memory_order_relaxed);}
static Query compile_expr(dmg_engine* e,const std::string& relation,const char* intent,uint64_t work=0,const char* options=""){
    std::string text="{\"schema_version\":1,\"relation\":"+relation+",\"intent\":\""+intent+"\",\"max_results\":100,\"required_capabilities\":[\"use_streaming\"]"+options;
    if(work)text+=",\"max_work\":"+std::to_string(work);text+='}';dmg_query* raw=nullptr;dmg_error error{};
    CHECK(dmg_query_compile_json(e,reinterpret_cast<const uint8_t*>(text.data()),text.size(),&raw,&error)==DMG_OK&&raw);return Query(raw,&dmg_query_release);
}
static void append_value(std::ostringstream& out,const dmg_value_row_v2& v){out<<v.kind<<':';if(v.kind==DMG_VALUE_USE)out<<v.use.relation<<','<<v.use.source_index<<','<<v.use.caller_ordinal<<','<<v.use.caller_method_ref<<','<<v.use.dex_pc<<','<<v.use.opcode<<','<<v.use.code_offset<<','<<v.use.target_domain<<','<<v.use.target_index<<','<<v.use.extra_proto;
    else{CHECK(v.kind==DMG_VALUE_ENTITY);out<<v.entity.relation<<','<<v.entity.source_index<<','<<v.entity.local_index<<','<<v.entity.reference_index<<','<<v.entity.definition_known<<','<<v.entity.definition_offset;}}
static void append_key(std::ostringstream& out,const dmg_value_identity_v2& k){out<<k.relation<<','<<k.source_index<<','<<k.local_index<<','<<k.dex_pc;}
static std::string row_evidence(dmg_result* r,uint32_t row){std::ostringstream out;dmg_value_row_v2 value{};CHECK(dmg_result_get_value_v2(r,row,&value,sizeof(value))==DMG_OK);append_value(out,value);
    dmg_source_info origin{};CHECK(dmg_result_get_origin(r,row,&origin)==DMG_OK&&origin.dex.occurrence_id&&origin.dex.snapshot_id);out<<'|'<<origin.dex.occurrence_id<<'|'<<origin.dex.snapshot_id;
    uint32_t n=0;CHECK(dmg_result_get_binding_count(r,row,&n)==DMG_OK);out<<"|bindings:"<<n;
    for(uint32_t i=0;i<n;++i){dmg_binding_row_v2 b{};dmg_binding_path path{};CHECK(dmg_result_get_binding_v2(r,row,i,&b,sizeof(b))==DMG_OK&&dmg_result_get_binding_path(r,row,i,&path,sizeof(path))==DMG_OK);out<<'|'<<(b.label?b.label:"")<<':';append_value(out,b.value);for(uint32_t j=0;j<path.length;++j)out<<unsigned(path.sides[j]);}
    CHECK(dmg_result_get_proof_binding_count(r,row,&n)==DMG_OK);out<<"|proofs:"<<n;
    for(uint32_t i=0;i<n;++i){dmg_proof_binding_row_v2 b{};dmg_binding_path path{};CHECK(dmg_result_get_proof_binding_v2(r,row,i,&b,sizeof(b))==DMG_OK&&dmg_result_get_proof_binding_path(r,row,i,&path,sizeof(path))==DMG_OK);out<<'|'<<b.operator_node<<':'<<(b.binding.label?b.binding.label:"")<<':';append_value(out,b.binding.value);for(uint32_t j=0;j<path.length;++j)out<<unsigned(path.sides[j]);}
    CHECK(dmg_result_get_link_count(r,row,&n)==DMG_OK);out<<"|links:"<<n;for(uint32_t i=0;i<n;++i){dmg_relation_link_v2 x{};CHECK(dmg_result_get_link_v2(r,row,i,&x,sizeof(x))==DMG_OK);out<<'|'<<x.node_id<<':'<<x.key<<':';append_key(out,x.left);out<<':';append_key(out,x.right);}
    CHECK(dmg_result_get_witness_count(r,row,&n)==DMG_OK);out<<"|witnesses:"<<n;for(uint32_t i=0;i<n;++i){
        dmg_numeric_witness_v1 numeric{};if(dmg_result_get_numeric_witness_v1(r,row,i,&numeric,sizeof(numeric))==DMG_OK){out<<"|numeric:"<<numeric.node_id<<','<<numeric.matched<<','<<numeric.dex_pc<<','<<numeric.opcode<<','<<numeric.code_units<<','<<numeric.operator_node<<','<<numeric.source_index<<','<<numeric.relation<<','<<numeric.local_index<<','<<numeric.entity_pc<<','<<numeric.width_bits<<','<<numeric.literal_kind<<','<<numeric.bits;continue;}
        dmg_interface_witness_v1 proof{};if(dmg_result_get_interface_witness_v1(r,row,i,&proof,sizeof(proof))==DMG_OK){out<<"|interface:"<<proof.node_id<<','<<proof.matched<<','<<proof.operator_node<<','<<proof.item_kind<<','<<proof.branch_index<<','<<proof.node_index<<','<<proof.aux<<','<<proof.detail<<','<<proof.source_index<<','<<proof.relation<<','<<proof.local_index;continue;}
        dmg_relation_witness_v2 x{};CHECK(dmg_result_get_relation_witness_v2(r,row,i,&x,sizeof(x))==DMG_OK);out<<'|'<<x.witness.kind<<','<<x.witness.node_id<<','<<x.witness.matched<<','<<x.witness.dex_pc<<','<<x.witness.opcode<<','<<x.witness.reference_index<<','<<x.witness.reference_kind<<','<<x.witness.extra_proto<<','<<x.witness.code_units<<','<<x.operator_node<<':';append_key(out,x.entity);
        if(x.witness.kind==DMG_WITNESS_INHERITED){dmg_inherited_witness w{};CHECK(dmg_result_get_inherited_witness(r,row,i,&w,sizeof(w))==DMG_OK);out<<":inherited:"<<w.node_id<<','<<w.matched<<','<<w.item_kind<<','<<w.path_index<<','<<w.aux<<','<<w.branch_index<<','<<w.detail<<','<<w.source_index<<','<<w.relation<<','<<w.local_index;}}
    return out.str();
}
static std::vector<std::string> drain_graph(dmg_job* j){std::vector<std::string> rows;for(;;){dmg_batch* raw=nullptr;dmg_error error{};const auto status=dmg_job_next(j,1000,&raw,&error);if(status==DMG_END_OF_STREAM)return rows;CHECK(status==DMG_OK&&raw);Batch b(raw,&dmg_batch_release);dmg_relation_info_v2 info{};CHECK(dmg_result_get_relation_info_v2(b.get(),&info,sizeof(info))==DMG_OK&&info.coverage==DMG_COVERAGE_PARTIAL);for(uint32_t i=0;i<info.candidates_count;++i)rows.push_back(row_evidence(b.get(),i));}}
static void graph_case(dmg_engine* e,dmg_snapshot* snap,const char* name,const std::string& relation,const char* intent,const char* options,bool streams){
    auto q=compile_expr(e,relation,intent,0,options);Result expected(nullptr,&dmg_result_release);CHECK(sync_status(snap,q.get(),expected)==DMG_OK&&expected);dmg_relation_info_v2 info{};dmg_query_profile profile{};CHECK(dmg_result_get_relation_info_v2(expected.get(),&info,sizeof(info))==DMG_OK&&info.execution_status==DMG_OK&&info.candidates_count>0);CHECK(dmg_result_get_profile(expected.get(),&profile)==DMG_OK&&profile.work_units>1);
    std::vector<std::string> rows;for(uint32_t i=0;i<info.candidates_count;++i)rows.push_back(row_evidence(expected.get(),i));
    for(const uint64_t limit:{profile.work_units/2,profile.work_units-1,profile.work_units}){
        auto limited=compile_expr(e,relation,intent,limit,options);Result direct(nullptr,&dmg_result_release);const auto rc=sync_status(snap,limited.get(),direct);offers.store(0);runtime::test_job_scan_barrier.store(&count_offer);auto job=start(snap,limited.get());const auto done=wait(job.get());runtime::test_job_scan_barrier.store(nullptr);
        const auto expected_status=rc==DMG_OK?([&]{dmg_relation_info_v2 x{};CHECK(dmg_result_get_relation_info_v2(direct.get(),&x,sizeof(x))==DMG_OK);return x.execution_status;}()):rc;
        CHECK(done.outcome.execution_status==expected_status);const auto emitted=drain_graph(job.get());
        if(limit==profile.work_units){CHECK(rc==DMG_OK&&done.outcome.coverage==info.coverage&&done.outcome.decision==info.decision&&done.outcome.reason==info.reason&&emitted==rows);dmg_query_profile actual{};CHECK(dmg_job_get_profile(job.get(),&actual)==DMG_OK&&actual.work_units==profile.work_units);CHECK((offers.load()!=0)==streams);}
        else CHECK(expected_status==DMG_BUDGET_EXCEEDED);
    }
    std::cout<<"graph "<<name<<" sync/Job proof and work boundary passed\n";
}
static void graph_matrix(const std::vector<uint8_t>& good,const std::vector<uint8_t>& bad,const std::filesystem::path& fixtures){auto e=engine();auto s=snapshot(e.get(),good);
    {const auto composite=load(fixtures/"generated/composite-v10/composite.dex"),root=load(fixtures/"generated/inherited/root.dex");auto snap=snapshot(e.get(),composite,&root);
     const std::string invoke=R"({"op":"scan","relation":"invoke_sites"})";
     for(const auto* scope:{"inherited","inherited_interfaces"}){
        const auto method=std::string(R"({"op":"scan","relation":"method_defs","where":{"all":[{"name":"access"},{"declares_fields":{"scope":")")+scope+R"(","where":{"name":"parentOnly"},"min":1}},{"numeric_bits":{"width":32,"bits":"ffffffff","kind":"constant"}}]}})";
        const auto relation=R"({"op":"join","on":"caller","left":)"+method+R"(,"right":)"+invoke+"}";
        graph_case(e.get(),snap.get(),scope,relation,"exists","",false);}}
    const std::string scan=R"({"op":"scan","relation":"invoke_sites"})",methods=R"({"op":"scan","relation":"method_defs"})",refs=R"({"op":"scan","relation":"method_refs"})";
    const auto filter="{\"op\":\"filter\",\"input\":"+scan+",\"where\":{\"opcode\":113}}";
    const auto label="{\"op\":\"label\",\"label\":\"evt\",\"input\":"+filter+"}";
    const auto caller="{\"op\":\"join\",\"on\":\"caller\",\"left\":"+methods+",\"right\":"+scan+"}";
    const auto target_join="{\"op\":\"join\",\"on\":\"target_ref\",\"left\":"+scan+",\"right\":"+refs+"}";
    const auto semi="{\"op\":\"semi_join\",\"on\":\"caller\",\"left\":"+methods+",\"right\":"+scan+"}";
    const auto bag="{\"op\":\"union\",\"semantics\":\"bag\",\"inputs\":["+scan+","+scan+"]}";
    const auto set="{\"op\":\"union\",\"semantics\":\"set\",\"inputs\":["+scan+","+scan+"]}";
    const auto distinct="{\"op\":\"distinct\",\"identity\":\"entity\",\"input\":"+bag+"}";
    const auto group="{\"op\":\"group_by_owner\",\"inputs\":["+caller+"],\"min\":1}";
    graph_case(e.get(),s.get(),"scan-exists",scan,"exists","",true);
    graph_case(e.get(),s.get(),"filter",filter,"unique","",true);graph_case(e.get(),s.get(),"filter-exists",filter,"exists","",true);
    graph_case(e.get(),s.get(),"label",label,"unique",",\"unique_by\":\"tuple\"",true);graph_case(e.get(),s.get(),"label-exists",label,"exists","",true);
    graph_case(e.get(),s.get(),"caller-exists",caller,"exists","",true);graph_case(e.get(),s.get(),"caller-unique",caller,"unique",",\"unique_by\":\"tuple\"",false);
    graph_case(e.get(),s.get(),"target-exists",target_join,"exists","",true);graph_case(e.get(),s.get(),"target-unique",target_join,"unique","",false);
    graph_case(e.get(),s.get(),"semi-exists",semi,"exists","",true);graph_case(e.get(),s.get(),"semi-unique",semi,"unique","",false);
    graph_case(e.get(),s.get(),"bag-exists",bag,"exists","",true);graph_case(e.get(),s.get(),"bag-unique",bag,"unique","",false);
    graph_case(e.get(),s.get(),"set-exists",set,"exists","",true);graph_case(e.get(),s.get(),"set-unique",set,"unique","",false);
    graph_case(e.get(),s.get(),"distinct-exists",distinct,"exists","",true);graph_case(e.get(),s.get(),"distinct-unique",distinct,"unique","",false);
    graph_case(e.get(),s.get(),"group-exists",group,"exists","",true);graph_case(e.get(),s.get(),"group-unique",group,"unique","",false);
    graph_case(e.get(),s.get(),"sorted",scan,"unique",",\"order_by\":[{\"field\":\"pc\",\"direction\":\"desc\"}]",false);
    const auto untested_label="{\"op\":\"label\",\"label\":\"direct\",\"input\":"+scan+"}";
    const auto reverse_caller="{\"op\":\"join\",\"on\":\"caller\",\"left\":"+scan+",\"right\":"+methods+"}";
    const auto target_semi="{\"op\":\"semi_join\",\"on\":\"target_ref\",\"left\":"+scan+",\"right\":"+refs+"}";
    const auto union_three="{\"op\":\"union\",\"semantics\":\"bag\",\"inputs\":["+scan+","+scan+","+scan+"]}";
    graph_case(e.get(),s.get(),"fallback-label",untested_label,"exists","",false);graph_case(e.get(),s.get(),"fallback-reverse-caller",reverse_caller,"exists","",false);
    graph_case(e.get(),s.get(),"fallback-target-semi",target_semi,"exists","",false);graph_case(e.get(),s.get(),"fallback-union-three",union_three,"exists","",false);
    const auto filtered_scan=R"({"op":"scan","relation":"invoke_sites","where":{"caller_name":"uses"}})";
    graph_case(e.get(),s.get(),"scan-predicate-exists",filtered_scan,"exists","",true);graph_case(e.get(),s.get(),"scan-predicate-unique",filtered_scan,"unique","",true);
    for(const auto& pair:std::vector<std::pair<std::string,std::string>>{{"field_uses","generated/use_relations/field-read-write.dex"},{"string_uses","generated/use_relations/string-normal-jumbo.dex"},{"invoke_sites","generated/method_facts/invoke-domains-038.dex"}}){
        const auto bytes=load(fixtures/pair.second);auto snap=snapshot(e.get(),bytes);const auto expression="{\"op\":\"scan\",\"relation\":\""+pair.first+"\"}";
        graph_case(e.get(),snap.get(),pair.first.c_str(),expression,"unique","",true);}
    {const auto bytes=load(fixtures/"generated/method_facts/invoke-domains-038.dex");auto snap=snapshot(e.get(),bytes);graph_case(e.get(),snap.get(),"target-038",target_join,"exists","",true);}
    auto pair=snapshot(e.get(),good,&bad);const auto first=R"({"op":"scan","relation":"invoke_sites","scope":{"slots":["first"]}})",second=R"({"op":"scan","relation":"invoke_sites","scope":{"slots":["second"]}})";
    for(const auto semantics:{"bag","set"}){const auto relation="{\"op\":\"union\",\"semantics\":\""+std::string(semantics)+"\",\"inputs\":["+first+","+second+"]}";auto q=compile_expr(e.get(),relation,"exists");Result direct(nullptr,&dmg_result_release);CHECK(sync_status(pair.get(),q.get(),direct)==DMG_CORRUPT_INPUT&&!direct);
        auto job=start(pair.get(),q.get());const auto done=wait(job.get());const auto rows=drain_graph(job.get());CHECK(done.outcome.execution_status==DMG_CORRUPT_INPUT);
        if(std::string(semantics)=="bag")CHECK(done.outcome.candidates_count==1&&done.outcome.decision==DMG_PROVEN_TRUE&&rows.size()==1);
        else CHECK(done.outcome.candidates_count==0&&done.outcome.decision==DMG_UNDETERMINED&&rows.empty());}
    {const auto relation="{\"op\":\"distinct\",\"identity\":\"entity\",\"input\":{\"op\":\"union\",\"semantics\":\"bag\",\"inputs\":["+std::string(first)+","+second+"]}}";
        auto q=compile_expr(e.get(),relation,"exists");Result direct(nullptr,&dmg_result_release);CHECK(sync_status(pair.get(),q.get(),direct)==DMG_CORRUPT_INPUT&&!direct);auto job=start(pair.get(),q.get());const auto done=wait(job.get());CHECK(done.outcome.execution_status==DMG_CORRUPT_INPUT&&done.outcome.candidates_count==0&&drain_graph(job.get()).empty());}
    {auto incomplete=snapshot(e.get(),good,nullptr,false);const auto no_matches=R"({"op":"scan","relation":"invoke_sites","where":{"pc":999}})";
        const auto unknown_semi="{\"op\":\"semi_join\",\"on\":\"caller\",\"left\":"+methods+",\"right\":"+no_matches+"}";
        for(const auto& relation:{group,unknown_semi}){auto q=compile_expr(e.get(),relation,"exists");Result direct(nullptr,&dmg_result_release);CHECK(sync_status(incomplete.get(),q.get(),direct)==DMG_OK&&direct);dmg_relation_info_v2 info{};CHECK(dmg_result_get_relation_info_v2(direct.get(),&info,sizeof(info))==DMG_OK&&info.coverage==DMG_COVERAGE_PARTIAL&&info.decision==DMG_UNDETERMINED&&info.unknown_rows>0);
            offers.store(0);runtime::test_job_scan_barrier.store(&count_offer);auto job=start(incomplete.get(),q.get());const auto done=wait(job.get());runtime::test_job_scan_barrier.store(nullptr);CHECK(done.outcome.execution_status==DMG_OK&&done.outcome.coverage==DMG_COVERAGE_PARTIAL&&done.outcome.decision==DMG_UNDETERMINED&&done.outcome.unknown_rows==info.unknown_rows&&done.outcome.candidates_count==0&&offers.load()==0&&drain_graph(job.get()).empty());}}
}
int main(int argc,char** argv){try{CHECK(argc==5||argc==7);const auto good=load(argv[1]),bad=load(argv[2]),multi=load(argv[3]),later=load(argv[4]);if(argc==7){CHECK(std::string(argv[6])=="graph");graph_matrix(multi,later,argv[5]);return 0;}auto e=engine();rejected_combinations(e.get());rejected_unpaired_hook(good);interrupt(good,1);interrupt(good,2);budget_equivalence(good);limited_unique_equivalence(good);corruption(good,bad);separate_methods(multi,later);std::cout<<"PASS use v9: checked methods before events, interrupt, budget equivalence, corruption and source isolation\n";return 0;}catch(const std::exception& e){unblock();runtime::test_job_scan_barrier.store(nullptr);std::cerr<<e.what()<<'\n';return 1;}}
