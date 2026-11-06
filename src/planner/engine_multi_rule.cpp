#include "engine_multi_rule.hpp"
#include <stdexcept>

namespace dexmeguviz::planner {
EngineMultiResult execute_engine_multi(std::shared_ptr<runtime::EngineState> owner,
    std::shared_ptr<const runtime::Dataset> dataset,std::span<const EngineRule> rules,
    size_t cache_bytes,uint64_t max_cache_work,bool allow_budget_retry,bool fused_methods){
    if(!owner||!dataset||dataset->engine!=owner||rules.size()>256)
        throw std::invalid_argument("invalid engine multi-rule dataset");
    EngineMultiResult out(std::move(owner),std::move(dataset));
    auto* control=&out.owner->control_resource;
    std::pmr::vector<reference::SourceView> sources(control);
    std::pmr::vector<std::string_view> slots(control);
    std::pmr::vector<Rule> internal_rules(control);
    out.plans.reserve(rules.size());internal_rules.reserve(rules.size());
    bool cancel_requested=false;
    for(const auto& rule:rules){
        if(!rule.query||rule.query->engine!=out.owner||!rule.query->plan)
            throw std::invalid_argument("query belongs to another engine or is not compiled");
        out.plans.push_back(rule.query);
        cancel_requested|=rule.cancel.requested!=nullptr;
        internal_rules.push_back({rule.id,&*rule.query->plan,&out.owner->scratch_resource,rule.cancel,true});
    }
    if(rules.empty()){
        out.result.emplace(control);
        return out;
    }
    if(out.dataset->sources.size()>UINT32_MAX)throw std::invalid_argument("too many sources");
    for(uint32_t i=0;i<out.dataset->sources.size();++i){
        if(!out.dataset->sources[i])throw std::invalid_argument("missing source");
        const auto& source=*out.dataset->sources[i];
        if(source.engine!=out.owner)throw std::invalid_argument("source belongs to another engine");
        sources.push_back({i,source.input_index,&source.facts,source.view()});
    }
    for(const auto& input:out.dataset->inputs)slots.push_back(input.slot);
    const reference::DatasetView view{sources,slots,out.dataset->scope_complete};
    const auto run=[&](std::span<std::byte> arena,uint64_t work){
        return execute(view,internal_rules,control,arena,work,fused_methods);
    };
    // Fresh Engine allocations cannot overlap any still-live valid allocation,
    // including nested Plan storage, source storage, results or resource state.
    // Borrowed source leases must satisfy the existing lifetime contract.
    bool retry=false;
    if(cache_bytes&&max_cache_work&&!cancel_requested){
        {
            std::pmr::vector<std::byte> arena(control);
            try{arena.resize(cache_bytes);}catch(const BudgetExceeded&){out.arena_budget_unavailable=true;}
            if(!arena.empty()){
                try{
                    out.result.emplace(run(arena,max_cache_work));
                    out.attempted_cache=out.result->shared;
                    bool nondeterministic_failure=false;
                    for(const auto& result:out.result->rules){
                        if(result.code==OutcomeCode::budget)retry=true;
                        if(result.code==OutcomeCode::out_of_memory||result.code==OutcomeCode::internal||result.code==OutcomeCode::cancelled)
                            nondeterministic_failure=true;
                    }
                    // Do not turn a system allocation failure or unexpected
                    // error into a successful result by replaying it.
                    if(nondeterministic_failure||!allow_budget_retry)retry=false;
                    if(retry)out.result.reset();
                }catch(const BudgetExceeded&){if(!allow_budget_retry)throw;retry=true;}
            }
        }
    }
    if(!out.result){
        out.budget_retry=retry;
        out.result.emplace(run({},0));
    }
    return out;
}
}
