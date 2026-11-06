#pragma once
#include "c_api/runtime.hpp"
#include "multi_rule.hpp"

namespace dexmeguviz::planner {
// Experimental internal entry point. Not an implementation of the public C
// query API: results are reference results, retained together in scratch.
// The caller must serialize all activity on this Engine for the whole call.
// No external cache backing or allocator replay attestation is accepted.
struct EngineRule {
    std::string_view id;
    std::shared_ptr<const runtime::QueryState> query;
    reference::Cancel cancel{};
};
struct EngineMultiResult {
    // Declaration order keeps every allocator and referenced input alive until
    // after the retained results and query plans have been destroyed.
    std::shared_ptr<runtime::EngineState> owner;
    std::shared_ptr<const runtime::Dataset> dataset;
    std::pmr::vector<std::shared_ptr<const runtime::QueryState>> plans;
    std::optional<MultiResult> result;
    reference::SharedFactsProfile attempted_cache{};
    bool budget_retry=false;
    bool arena_budget_unavailable=false;
    EngineMultiResult(std::shared_ptr<runtime::EngineState> e,std::shared_ptr<const runtime::Dataset> d):
        owner(std::move(e)),dataset(std::move(d)),plans(&owner->control_resource){}
    EngineMultiResult(EngineMultiResult&&)=default;
    EngineMultiResult& operator=(EngineMultiResult&&)=delete;
    EngineMultiResult(const EngineMultiResult&)=delete;
};
// Cache memory is charged to Engine control and freed before returning. A
// cache-related Engine budget failure causes one complete scalar retry after
// all unobservable attempt results and the cache allocation are released.
// This does not establish C ABI or concurrent independent-call equivalence.
EngineMultiResult execute_engine_multi(std::shared_ptr<runtime::EngineState> owner,
    std::shared_ptr<const runtime::Dataset> dataset,std::span<const EngineRule> rules,
    size_t cache_bytes,uint64_t max_cache_work,bool allow_budget_retry=true,bool fused_methods=false);
}
