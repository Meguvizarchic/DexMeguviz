#include "isolated_multi.hpp"
#include <algorithm>

namespace dexmeguviz::planner {
namespace {
[[noreturn]] void status_error(dmg_status status,const dmg_error& error){throw SessionError(status,error);}
void require_open(bool closed){if(closed)throw std::logic_error("multi session is closed");}
}
IsolatedMultiSession::IsolatedMultiSession(std::unique_ptr<dmg_engine,EngineDelete> e,std::unique_ptr<dmg_snapshot,SnapshotDelete> s):
    engine(std::move(e)),snapshot(std::move(s)),rules(&engine->owner->control_resource){}
std::unique_ptr<IsolatedMultiSession> IsolatedMultiSession::open(const dmg_engine_options* engine_options,
    const dmg_source_spec* sources,uint32_t count,const dmg_source_set_options* source_options){
    dmg_error error{};dmg_engine* raw_engine=nullptr;
    auto status=dmg_engine_create(engine_options,&raw_engine,&error);
    std::unique_ptr<dmg_engine,EngineDelete> engine(raw_engine);
    if(status!=DMG_OK)status_error(status,error);
    if(!engine)throw std::logic_error("engine creation returned no handle");
    dmg_snapshot* raw_snapshot=nullptr;error={};
    status=dmg_snapshot_open_sources(engine.get(),sources,count,source_options,&raw_snapshot,&error);
    std::unique_ptr<dmg_snapshot,SnapshotDelete> snapshot(raw_snapshot);
    if(status!=DMG_OK)status_error(status,error);
    if(!snapshot)throw std::logic_error("snapshot creation returned no handle");
    return std::unique_ptr<IsolatedMultiSession>(new IsolatedMultiSession(std::move(engine),std::move(snapshot)));
}
void IsolatedMultiSession::add(std::string_view id,std::string_view json){
    std::lock_guard lock(gate);require_open(closed);
    if(id.empty()||id.size()>256||rules.size()>=256)throw std::invalid_argument("invalid rule id or count");
    if(std::any_of(rules.begin(),rules.end(),[&](const RuleEntry& x){return x.id==id;}))throw std::invalid_argument("duplicate rule id");
    dmg_error error{};dmg_query* raw=nullptr;
    auto status=dmg_query_compile_json(engine.get(),reinterpret_cast<const uint8_t*>(json.data()),json.size(),&raw,&error);
    struct QueryDelete{void operator()(dmg_query* p)const noexcept{if(p)dmg_query_release(p);}};
    std::unique_ptr<dmg_query,QueryDelete> query(raw);
    if(status!=DMG_OK)status_error(status,error);
    if(!query||!query->query||!query->query->plan)throw std::logic_error("compiled query absent");
    RuleEntry item(&engine->owner->control_resource);item.id.assign(id);item.query=query->query;rules.push_back(std::move(item));
}
IsolatedBatch IsolatedMultiSession::execute(std::span<const std::string_view> ids,size_t cache_bytes,uint64_t max_cache_work){
    std::lock_guard lock(gate);require_open(closed);
    if(ids.size()>256)throw std::invalid_argument("too many rule ids");
    std::pmr::vector<EngineRule> selected(&engine->owner->control_resource);selected.reserve(ids.size());
    for(const auto id:ids){
        const auto found=std::find_if(rules.begin(),rules.end(),[&](const RuleEntry& entry){return entry.id==id;});
        if(found==rules.end())throw std::invalid_argument("unknown rule id");
        selected.push_back({found->id,found->query,{}});
    }
    return IsolatedBatch(execute_engine_multi(engine->owner,snapshot->dataset,selected,cache_bytes,max_cache_work));
}
MaterializedRule IsolatedMultiSession::execute_one(std::string_view id){
    std::lock_guard lock(gate);require_open(closed);
    const auto found=std::find_if(rules.begin(),rules.end(),[&](const RuleEntry& entry){return entry.id==id;});
    if(found==rules.end())throw std::invalid_argument("unknown rule id");
    // The stack facade owns the existing immutable QueryState for the duration
    // of the public execution call; it is not retained or released as a handle.
    dmg_query facade(engine->owner,found->query);
    dmg_error error{};dmg_result* raw=nullptr;
    const auto status=dmg_query_execute(snapshot.get(),&facade,&raw,&error);
    runtime::ResultOwner result(raw);
    if(status!=DMG_OK)status_error(status,error);
    if(!result)throw std::logic_error("successful query returned no result");
    return MaterializedRule(std::move(result));
}
MaterializedBatch IsolatedMultiSession::execute_materialized(std::span<const std::string_view> ids,size_t cache_bytes,uint64_t max_cache_work){
    std::lock_guard lock(gate);require_open(closed);
    if(ids.size()>256)throw std::invalid_argument("too many rule ids");
    runtime::admit(engine->owner);
    std::pmr::vector<EngineRule> selected(&engine->owner->control_resource);selected.reserve(ids.size());
    for(const auto id:ids){
        const auto found=std::find_if(rules.begin(),rules.end(),[&](const RuleEntry& entry){return entry.id==id;});
        if(found==rules.end())throw std::invalid_argument("unknown rule id");
        selected.push_back({found->id,found->query,{}});
    }
    auto evaluated=execute_engine_multi(engine->owner,snapshot->dataset,selected,cache_bytes,max_cache_work);
    for(size_t i=0;i<evaluated.result->rules.size();++i){
        const auto& item=evaluated.result->rules[i];
        if(item.code!=OutcomeCode::result_available||!item.result)throw BatchError(i,item);
    }
    MaterializedBatch batch(engine->owner,evaluated.result->shared,evaluated.budget_retry);
    batch.reserve(ids.size());const runtime::Control control;
    for(size_t i=0;i<evaluated.result->rules.size();++i){
        const auto& item=evaluated.result->rules[i];
        runtime::ResultOwner result;dmg_error error{};
        const auto status=runtime::guard([&]()->dmg_status{
            result=runtime::materialize_evaluated(evaluated.owner,evaluated.dataset,evaluated.plans[i],*item.result,item.progress,control);
            return DMG_OK;
        },&error);
        if(status!=DMG_OK)throw BatchMaterializationError(i,status,error);
        batch.append(std::move(result));
    }
    return batch;
}
dmg_engine_stats IsolatedMultiSession::stats()const {
    std::lock_guard lock(gate);dmg_engine_stats result{};
    const auto status=dmg_engine_get_stats(engine.get(),&result);
    if(status!=DMG_OK){dmg_error error{};status_error(status,error);}return result;
}
void IsolatedMultiSession::close(){std::lock_guard lock(gate);closed=true;}
uint64_t IsolatedMultiSession::owned_bytes()const{std::lock_guard lock(gate);return engine->owner->account.total();}
}


