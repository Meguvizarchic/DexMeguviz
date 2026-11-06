#include "c_api/runtime.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <vector>
using namespace dexmeguviz;
#define CHECK(x) do{if(!(x))throw std::runtime_error("expand job check "+std::to_string(__LINE__)+": " #x);}while(0)
static std::vector<uint8_t> load(const std::filesystem::path& p){std::ifstream f(p,std::ios::binary);CHECK(f.good());return {(std::istreambuf_iterator<char>(f)),{}};}
static dmg_query* compile(dmg_engine* e,const std::string& text){dmg_query* q=nullptr;dmg_error err{};CHECK(dmg_query_compile_json(e,reinterpret_cast<const uint8_t*>(text.data()),text.size(),&q,&err)==DMG_OK);return q;}
static std::string query_text(const std::string& options="",const std::string& top=""){
    return "{\"schema_version\":1,\"relation\":{\"op\":\"bounded_expand\",\"input\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"name\":\"a\"}},\"min_depth\":2,\"max_depth\":2"+options+"}"+top+"}";
}
static dmg_snapshot* snapshot(dmg_engine* e,const std::filesystem::path& root,unsigned mode,bool complete){
    const char* names[]={"amb-a.dex","amb-b1.dex","amb-b2.dex","amb-c1.dex","amb-c2.dex"};const char* slots[]={"a","b1","b2","c1","c2"};
    std::vector<std::vector<uint8_t>> data;std::vector<dmg_source_spec> specs;const unsigned count=mode==1?5:mode==2?3:1;data.reserve(count);specs.reserve(count);
    for(unsigned n=0;n<count;++n){const unsigned i=mode==2&&n==2?3:n;data.push_back(load(root/names[i]));dmg_source_spec s{};s.struct_size=sizeof(s);s.abi_version=DMG_ABI_VERSION;s.format=DMG_INPUT_RAW_DEX;s.data=data.back().data();s.size=data.back().size();s.slot_key=slots[i];s.role="code";specs.push_back(s);}
    dmg_source_set_options options{sizeof(options),DMG_ABI_VERSION,"expand-test",complete?1u:0u,16,1u<<20};dmg_snapshot* result=nullptr;dmg_error err{};
    CHECK(dmg_snapshot_open_sources(e,specs.data(),count,&options,&result,&err)==DMG_OK);return result;
}
static dmg_expand_info info(dmg_result* r){dmg_expand_info x{};CHECK(dmg_result_get_expand_info(r,&x,sizeof(x))==DMG_OK);return x;}
static dmg_expand_job_status wait(dmg_job* j){dmg_expand_job_status s{};CHECK(dmg_job_wait_expand(j,10000,&s,sizeof(s))==DMG_OK&&s.terminal);return s;}
static void validate_first(dmg_result* r){dmg_expand_info x=info(r);CHECK(x.outcome.candidates_count==1&&x.total_candidates==4);dmg_expand_path_info p{};dmg_expand_hop h{};
    CHECK(dmg_result_get_expand_path(r,0,0,&p,sizeof(p))==DMG_OK&&p.hop_count==2&&p.seed.source_index==0&&p.seed_witness_count>0);
    dmg_relation_witness_v2 witness{};CHECK(dmg_result_get_expand_path_witness(r,0,0,DMG_EXPAND_SEED_WITNESS,0,&witness,sizeof(witness))==DMG_OK);
    CHECK(dmg_result_get_expand_path_hop(r,0,0,0,&h,sizeof(h))==DMG_OK&&h.caller.source_index==0&&h.dex_pc==0&&h.resolved.source_index==1&&h.target_symbol.prototype_length==3);
    CHECK(h.target_symbol.prototype&&h.target_symbol.prototype[0]=='('&&h.target_symbol.prototype[1]==')'&&h.target_symbol.prototype[2]=='V');
    CHECK(dmg_result_get_expand_path_hop(r,0,0,1,&h,sizeof(h))==DMG_OK&&h.caller.source_index==1&&h.resolved.source_index==3);
}
int main(int argc,char** argv){try{
    CHECK(argc==2);const std::filesystem::path root(argv[1]);constexpr uint64_t LIMIT=8u<<20;
    dmg_engine_options eo{sizeof(eo),DMG_ABI_VERSION,LIMIT,LIMIT,1u<<20,4,0};dmg_engine* e=nullptr;dmg_error err{};CHECK(dmg_engine_create(&eo,&e,&err)==DMG_OK);
    auto* s=snapshot(e,root,true,true);auto* q=compile(e,query_text());dmg_result* sync=nullptr;CHECK(dmg_query_execute(s,q,&sync,&err)==DMG_OK);
    auto initial=info(sync);CHECK(initial.outcome.candidates_count==4&&initial.outcome.coverage==DMG_COVERAGE_COMPLETE);
    dmg_relation_info legacy;std::memset(&legacy,0xa5,sizeof(legacy));CHECK(dmg_result_get_relation_info(sync,&legacy,sizeof(legacy))==DMG_UNSUPPORTED);
    for(auto c:std::span(reinterpret_cast<const uint8_t*>(&legacy),sizeof(legacy)))CHECK(c==0xa5);
    dmg_expand_path_info size_sentinel;std::memset(&size_sentinel,0xa5,sizeof(size_sentinel));CHECK(dmg_result_get_expand_path(sync,0,0,&size_sentinel,sizeof(size_sentinel)-1)==DMG_INVALID_ARGUMENT);
    for(auto c:std::span(reinterpret_cast<const uint8_t*>(&size_sentinel),sizeof(size_sentinel)))CHECK(c==0xa5);
    dmg_result_release(sync);
    dmg_job_options jo{sizeof(jo),DMG_ABI_VERSION,1,1,0};dmg_job* j=nullptr;CHECK(dmg_job_start(s,q,&jo,&j,&err)==DMG_OK);
    auto done=wait(j);CHECK(done.lifecycle==DMG_JOB_COMPLETED&&done.info.outcome.candidates_count==4);
    dmg_job_cancel(j);auto after_cancel=wait(j);CHECK(after_cancel.lifecycle==DMG_JOB_COMPLETED&&after_cancel.info.outcome.execution_status==DMG_OK);
    // The worker is terminal: hold all remaining account bytes, then release
    // them to prove a failed view allocation does not advance the batch cursor.
    const auto remaining=LIMIT-e->owner->account.total();CHECK(remaining>1024);auto& resource=e->owner->control_resource;
    void* held=resource.allocate(static_cast<size_t>(remaining),alignof(std::max_align_t));dmg_batch* b=nullptr;
    CHECK(dmg_job_next(j,0,&b,&err)==DMG_BUDGET_EXCEEDED&&b==nullptr);resource.deallocate(held,static_cast<size_t>(remaining),alignof(std::max_align_t));
    CHECK(dmg_job_next(j,0,&b,&err)==DMG_OK&&b);validate_first(b);
    unsigned count=1;for(;;){dmg_batch* next=nullptr;const auto st=dmg_job_next(j,0,&next,&err);if(st==DMG_END_OF_STREAM)break;CHECK(st==DMG_OK&&next);++count;dmg_batch_release(next);}CHECK(count==4);
    dmg_job_release(j);dmg_query_release(q);dmg_snapshot_release(s);dmg_engine_release(e);validate_first(b);dmg_batch_release(b);

    CHECK(dmg_engine_create(&eo,&e,&err)==DMG_OK);s=snapshot(e,root,true,true);
    q=compile(e,query_text("",",\"intent\":\"unique\",\"max_results\":1"));sync=nullptr;CHECK(dmg_query_execute(s,q,&sync,&err)==DMG_OK);
    auto cap=info(sync);CHECK(cap.outcome.candidates_count==1&&cap.outcome.execution_status==DMG_BUDGET_EXCEEDED&&cap.outcome.reason==DMG_RESULT_LIMIT&&cap.outcome.coverage==DMG_COVERAGE_PARTIAL&&cap.outcome.decision==DMG_UNDETERMINED);
    CHECK(dmg_job_start(s,q,&jo,&j,&err)==DMG_OK);done=wait(j);CHECK(done.lifecycle==DMG_JOB_COMPLETED&&done.info.outcome.execution_status==cap.outcome.execution_status&&done.info.outcome.coverage==cap.outcome.coverage&&done.info.outcome.decision==cap.outcome.decision&&done.info.outcome.reason==cap.outcome.reason&&done.info.outcome.candidates_count==cap.outcome.candidates_count);
    b=nullptr;CHECK(dmg_job_next(j,0,&b,&err)==DMG_OK&&b);dmg_batch_release(b);b=nullptr;CHECK(dmg_job_next(j,0,&b,&err)==DMG_END_OF_STREAM);dmg_job_release(j);dmg_result_release(sync);dmg_query_release(q);dmg_snapshot_release(s);
    s=snapshot(e,root,2,false);q=compile(e,query_text(",\"output\":\"endpoints\"",",\"intent\":\"unique\""));sync=nullptr;CHECK(dmg_query_execute(s,q,&sync,&err)==DMG_OK);
    auto unknown=info(sync);CHECK(unknown.outcome.candidates_count==1&&unknown.outcome.coverage==DMG_COVERAGE_PARTIAL&&unknown.outcome.decision==DMG_UNDETERMINED&&unknown.outcome.unknown_rows>0);
    CHECK(dmg_job_start(s,q,&jo,&j,&err)==DMG_OK);done=wait(j);CHECK(done.lifecycle==DMG_JOB_COMPLETED&&done.info.outcome.coverage==unknown.outcome.coverage&&done.info.outcome.decision==unknown.outcome.decision&&done.info.outcome.unknown_rows==unknown.outcome.unknown_rows);
    dmg_job_release(j);dmg_result_release(sync);dmg_query_release(q);dmg_snapshot_release(s);s=snapshot(e,root,1,true);
    q=compile(e,query_text(",\"max_edges\":1"));sync=nullptr;CHECK(dmg_query_execute(s,q,&sync,&err)==DMG_BUDGET_EXCEEDED&&sync==nullptr);
    CHECK(dmg_job_start(s,q,&jo,&j,&err)==DMG_OK);done=wait(j);CHECK(done.lifecycle==DMG_JOB_FAILED&&done.info.outcome.execution_status==DMG_BUDGET_EXCEEDED);
    b=nullptr;CHECK(dmg_job_next(j,0,&b,&err)==DMG_END_OF_STREAM&&b==nullptr);dmg_job_release(j);dmg_query_release(q);
    // Locking the job state makes the cancellation observation precede the
    // worker's final commit lock. Retry if a tiny job completed before the lock.
    q=compile(e,query_text());bool observed=false;
    for(unsigned n=0;n<32&&!observed;++n){CHECK(dmg_job_start(s,q,&jo,&j,&err)==DMG_OK);
        {std::lock_guard lock(j->state->mutex);if(!j->state->status.terminal){j->state->cancelled.store(true,std::memory_order_release);observed=true;}}j->state->changed.notify_all();
        done=wait(j);if(observed){CHECK(done.lifecycle==DMG_JOB_CANCELLED&&done.info.outcome.execution_status==DMG_CANCELLED);b=nullptr;CHECK(dmg_job_next(j,0,&b,&err)==DMG_END_OF_STREAM&&b==nullptr);}dmg_job_release(j);
    }CHECK(observed);dmg_query_release(q);dmg_snapshot_release(s);
    // A complete scope can yield unresolved frontiers with zero result rows;
    // the terminal Job must retain those frontiers without requiring a Batch.
    s=snapshot(e,root,false,true);q=compile(e,query_text());CHECK(dmg_job_start(s,q,&jo,&j,&err)==DMG_OK);done=wait(j);
    CHECK(done.lifecycle==DMG_JOB_COMPLETED&&done.info.outcome.candidates_count==0&&done.info.frontier_count==2);
    dmg_expand_frontier f{};CHECK(dmg_job_get_expand_frontier(j,0,&f,sizeof(f))==DMG_OK&&f.reason==DMG_EXPAND_UNRESOLVED&&f.has_target_symbol);
    b=nullptr;CHECK(dmg_job_next(j,0,&b,&err)==DMG_END_OF_STREAM&&b==nullptr);dmg_job_release(j);dmg_query_release(q);dmg_snapshot_release(s);dmg_engine_release(e);
    std::cout<<"PASS v5 job: aggregate commit, retryable allocation, cancellation ordering, cap parity, zero-row frontiers and retained batch\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
