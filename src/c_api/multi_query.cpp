#include "runtime.hpp"
#include "planner/engine_multi_rule.hpp"
#include <array>
#include <charconv>
#include <limits>

using namespace dexmeguviz;
using namespace dexmeguviz::runtime;
namespace {
struct SharedResultDelete {void operator()(dmg_result* p)const noexcept{dmg_result_release(p);}};
using SharedResult=std::unique_ptr<dmg_result,SharedResultDelete>;
dmg_status outcome_status(planner::OutcomeCode code)noexcept{
    switch(code){
    case planner::OutcomeCode::invalid:return DMG_INVALID_ARGUMENT;
    case planner::OutcomeCode::unsupported:return DMG_UNSUPPORTED;
    case planner::OutcomeCode::budget:return DMG_BUDGET_EXCEEDED;
    case planner::OutcomeCode::cancelled:return DMG_CANCELLED;
    case planner::OutcomeCode::source_mismatch:return DMG_SOURCE_MISMATCH;
    case planner::OutcomeCode::corrupt:return DMG_CORRUPT_INPUT;
    case planner::OutcomeCode::out_of_memory:return DMG_OUT_OF_MEMORY;
    default:return DMG_INTERNAL_ERROR;
    }
}
}
struct dmg_multi_batch_v1 {
    std::atomic<uint32_t> references{1};
    std::shared_ptr<EngineState> owner;
    std::pmr::vector<SharedResult> results;
    dmg_multi_profile_v1 profile{};
    explicit dmg_multi_batch_v1(std::shared_ptr<EngineState> e):owner(std::move(e)),results(&owner->control_resource){}
};
namespace {
struct MultiDelete {void operator()(dmg_multi_batch_v1* p)const noexcept{if(p)destroy(p);}};
using MultiOwner=std::unique_ptr<dmg_multi_batch_v1,MultiDelete>;
}
extern "C" {
dmg_status dmg_multi_execute_v1(dmg_snapshot* snapshot,dmg_query* const* queries,uint32_t count,const dmg_multi_options_v1* options,
    dmg_multi_batch_v1** out,uint32_t* failure_index,dmg_error* error){
    if(out)*out=nullptr;if(failure_index)*failure_index=UINT32_MAX;
    return guard([&]()->dmg_status{
        if(!snapshot||!options||!out||!failure_index||(!queries&&count)||count>256||
           options->struct_size!=sizeof(*options)||options->abi_version!=DMG_ABI_VERSION||(options->flags&~DMG_MULTI_FUSE_METHOD_ENUM_V1)||options->reserved||
           options->cache_bytes>std::numeric_limits<size_t>::max())return DMG_INVALID_ARGUMENT;
        if(snapshot->closed.load(std::memory_order_acquire))return DMG_CLOSED;
        admit(snapshot->owner);
        std::array<std::array<char,4>,256> names{};
        std::pmr::vector<planner::EngineRule> selected(&snapshot->owner->control_resource);selected.reserve(count);
        for(uint32_t i=0;i<count;++i){
            if(!queries[i]||queries[i]->owner!=snapshot->owner||!queries[i]->query||
               queries[i]->query->engine!=snapshot->owner||!queries[i]->query->plan){*failure_index=i;return DMG_INVALID_ARGUMENT;}
            const auto converted=std::to_chars(names[i].data(),names[i].data()+names[i].size(),i);
            if(converted.ec!=std::errc{})return DMG_INTERNAL_ERROR;
            selected.push_back({std::string_view(names[i].data(),static_cast<size_t>(converted.ptr-names[i].data())),queries[i]->query,{}});
        }
        // The public API does not silently retry a rule under changing shared
        // Engine budgets. Independent concurrent callers have separate caches.
        auto evaluated=planner::execute_engine_multi(snapshot->owner,snapshot->dataset,selected,
            static_cast<size_t>(options->cache_bytes),options->max_cache_work,false,(options->flags&DMG_MULTI_FUSE_METHOD_ENUM_V1)!=0);
        if(!evaluated.result||evaluated.result->rules.size()!=count||evaluated.plans.size()!=count)return DMG_INTERNAL_ERROR;
        for(uint32_t i=0;i<count;++i){const auto& item=evaluated.result->rules[i];
            if(item.code!=planner::OutcomeCode::result_available||!item.result){
                *failure_index=i;message(error,item.error_offset,"multi-rule evaluation failed");return outcome_status(item.code);
            }
        }
        MultiOwner batch(handle<dmg_multi_batch_v1>(snapshot->owner));batch->results.reserve(count);
        const auto& p=evaluated.result->shared;
        batch->profile={p.physical_collects,p.cache_hits,p.cache_builds,p.trace_overflows,p.cache_rejections,p.replay_failures,p.cache_work_charged,evaluated.arena_budget_unavailable?1u:0u,0};
        const Control control;
        for(uint32_t i=0;i<count;++i){
            const auto& item=evaluated.result->rules[i];ResultOwner result;dmg_error local{};
            const auto status=guard([&]()->dmg_status{
                result=materialize_evaluated(evaluated.owner,evaluated.dataset,evaluated.plans[i],*item.result,item.progress,control);return DMG_OK;
            },&local);
            if(status!=DMG_OK){*failure_index=i;if(error)*error=local;return status;}
            SharedResult owned(result.release());batch->results.push_back(std::move(owned));
        }
        *out=batch.release();return DMG_OK;
    },error);
}
void dmg_multi_batch_retain_v1(dmg_multi_batch_v1* b){if(b)b->references.fetch_add(1,std::memory_order_relaxed);}
void dmg_multi_batch_release_v1(dmg_multi_batch_v1* b){if(b&&b->references.fetch_sub(1,std::memory_order_acq_rel)==1)destroy(b);}
dmg_status dmg_multi_batch_count_v1(const dmg_multi_batch_v1* b,uint32_t* out){if(!b||!out)return DMG_INVALID_ARGUMENT;*out=static_cast<uint32_t>(b->results.size());return DMG_OK;}
dmg_status dmg_multi_batch_profile_v1(const dmg_multi_batch_v1* b,dmg_multi_profile_v1* out,uint32_t size){if(!b||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;*out=b->profile;return DMG_OK;}
dmg_status dmg_multi_batch_get_result_v1(const dmg_multi_batch_v1* b,uint32_t index,dmg_result** out){
    if(out)*out=nullptr;if(!b||!out||index>=b->results.size())return DMG_INVALID_ARGUMENT;
    auto* result=b->results[index].get();dmg_result_retain(result);*out=result;return DMG_OK;
}
}
