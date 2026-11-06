#pragma once
#include "engine_multi_rule.hpp"
#include <mutex>
#include <stdexcept>
#include <string_view>

namespace dexmeguviz::planner {
struct SessionError final:std::runtime_error {
    dmg_status status; uint64_t offset;
    SessionError(dmg_status value,const dmg_error& error):std::runtime_error(error.message),status(value),offset(error.offset){}
};
// Retains the private engine, source set and plans. Read-only views are valid
// only while this object is alive. This is internal, not a public C Result.
struct RuleSummary {
    std::string_view id; OutcomeCode code; uint64_t error_offset; uint32_t error_pc;
    uint32_t visited,total,scope_source_count; bool scope_complete,order_verified,scope_derived_unknown;
    reference::Profile profile; bool result_available,result_limit,graph_available;
    uint32_t rows,graph_nodes;
};
struct SourceIdentity {
    uint32_t source_index,input_index; std::string_view slot,role,content,occurrence,logical;
};
struct EntitySnapshot {
    reference::EntityKey key;uint32_t reference_index,record_offset,definition_offset,access_flags,code_offset;
    bool definition_known,flags_known,code_known;
    std::u16string_view owner,name,prototype,type_descriptor,value;
};
class IsolatedBatch {
    EngineMultiResult value;
    const Outcome& outcome(size_t rule)const{return value.result->rules.at(rule);}
    const reference::Result& result(size_t rule)const{
        const auto& o=outcome(rule);if(!o.result)throw std::logic_error("rule has no result");return *o.result;
    }
    const reference::Candidate& candidate(size_t rule,size_t row)const{return result(rule).rows.at(row);}
public:
    explicit IsolatedBatch(EngineMultiResult&& result):value(std::move(result)){}
    IsolatedBatch(IsolatedBatch&&)=default;
    IsolatedBatch& operator=(IsolatedBatch&&)=delete;
    IsolatedBatch(const IsolatedBatch&)=delete;
    size_t size()const noexcept{return value.result?value.result->rules.size():0;}
    RuleSummary summary(size_t index)const {
        const auto& o=outcome(index);const auto& p=o.progress;
        return {o.rule_id,o.code,o.error_offset,o.error_pc,p.visited,p.total,p.scope_source_count,p.scope_complete,
            p.order_verified,p.scope_derived_unknown,p.profile,bool(o.result),o.result&&o.result->result_limit,
            bool(p.graph),o.result?static_cast<uint32_t>(o.result->rows.size()):0u,
            p.graph?static_cast<uint32_t>(p.graph->nodes.size()):0u};
    }
    reference::SharedFactsProfile profile()const{return value.result->shared;}
    std::string_view query_id(size_t index)const{return value.plans.at(index)->plan->id;}
    bool retried()const noexcept{return value.budget_retry;}
    bool arena_unavailable()const noexcept{return value.arena_budget_unavailable;}
    reference::EntityKey row_key(size_t rule,size_t row)const{return candidate(rule,row).key();}
    bool row_uncertain(size_t rule,size_t row)const{return candidate(rule,row).uncertain;}
    size_t witness_count(size_t rule,size_t row)const{return candidate(rule,row).witnesses.size();}
    reference::Witness witness(size_t rule,size_t row,size_t index)const{return candidate(rule,row).witnesses.at(index);}
    size_t binding_count(size_t rule,size_t row)const{return candidate(rule,row).bindings.size();}
    reference::Binding binding(size_t rule,size_t row,size_t index)const{return candidate(rule,row).bindings.at(index);}
    size_t proof_binding_count(size_t rule,size_t row)const{return candidate(rule,row).proof_bindings.size();}
    reference::ProofBinding proof_binding(size_t rule,size_t row,size_t index)const{return candidate(rule,row).proof_bindings.at(index);}
    size_t link_count(size_t rule,size_t row)const{return candidate(rule,row).links.size();}
    reference::JoinLink link(size_t rule,size_t row,size_t index)const{return candidate(rule,row).links.at(index);}
    uint32_t scope_source(size_t rule,size_t index)const{return result(rule).scope_sources.at(index);}
    size_t result_scope_count(size_t rule)const{return result(rule).scope_sources.size();}
    reference::OperatorProfile graph_node(size_t rule,size_t index)const {
        const auto& graph=outcome(rule).progress.graph;if(!graph)throw std::logic_error("rule has no graph profile");return graph->nodes.at(index);
    }
    facts::UseRecord use(size_t rule,size_t row)const{return reference::use_record(result(rule),candidate(rule,row).key());}
    std::string_view label(size_t rule,size_t index)const{return value.plans.at(rule)->plan->labels.at(index);}
    size_t source_method_count(size_t index)const{return value.dataset->sources.at(index)->facts.methods.size();}
    SourceIdentity source(size_t index)const {
        const auto& item=*value.dataset->sources.at(index);
        return {static_cast<uint32_t>(index),item.input_index,item.slot_key,item.role,item.content,item.occurrence,item.logical};
    }
    // Only metadata entity keys; use-event callers/targets are explicit keys.
    EntitySnapshot entity(reference::EntityKey key)const {
        if(query::is_use_relation(key.relation)||key.dex_pc!=UINT32_MAX)throw std::invalid_argument("use event is not a metadata entity");
        const auto& item=*value.dataset->sources.at(key.source_index);
        reference::validate_entity_relation(key.relation);
        if(key.ordinal>=reference::relation_size(item.facts,key.relation))throw std::out_of_range("entity ordinal exceeds source");
        reference::SourceView view{key.source_index,item.input_index,&item.facts,item.view()};
        const auto e=reference::entity(view,key.relation,key.ordinal);
        return {key,e.reference_index,e.record_offset,e.definition_offset,e.access_flags,e.code_offset,
            e.definition_known,e.flags_known,e.code_known,e.owner,e.name,e.prototype,e.type_descriptor,e.value};
    }
};
// One independently materialized C ABI result. Views inside returned C structs
// remain valid only until this object is destroyed or moved from. No native
// result handle is exposed; status codes and coverage must still be inspected.
class MaterializedRule {
    runtime::ResultOwner result;
public:
    explicit MaterializedRule(runtime::ResultOwner&& value):result(std::move(value)){}
    MaterializedRule(MaterializedRule&&)=default;
    MaterializedRule& operator=(MaterializedRule&&)=default;
    MaterializedRule(const MaterializedRule&)=delete;
    explicit operator bool()const noexcept{return bool(result);}
    dmg_status info(dmg_result_info& out)const noexcept{return dmg_result_get_info(result.get(),&out);}
    dmg_status relation_info(dmg_relation_info& out)const noexcept{return dmg_result_get_relation_info(result.get(),&out,sizeof(out));}
    dmg_status relation_info_v2(dmg_relation_info_v2& out)const noexcept{return dmg_result_get_relation_info_v2(result.get(),&out,sizeof(out));}
    dmg_status value(uint32_t row,dmg_value_row_v2& out)const noexcept{return dmg_result_get_value_v2(result.get(),row,&out,sizeof(out));}
    dmg_status query_info(dmg_query_info& out)const noexcept{return dmg_result_get_query_info(result.get(),&out);}
    dmg_status profile(dmg_query_profile& out)const noexcept{return dmg_result_get_profile(result.get(),&out);}
    dmg_status overview(dmg_snapshot_overview& out)const noexcept{return dmg_result_get_overview(result.get(),&out);}
    dmg_status origin(uint32_t row,dmg_source_info& out)const noexcept{return dmg_result_get_origin(result.get(),row,&out);}
    dmg_status binding_count(uint32_t row,uint32_t& out)const noexcept{return dmg_result_get_binding_count(result.get(),row,&out);}
    dmg_status binding(uint32_t row,uint32_t index,dmg_binding_row_v2& out)const noexcept{return dmg_result_get_binding_v2(result.get(),row,index,&out,sizeof(out));}
    dmg_status binding_path(uint32_t row,uint32_t index,dmg_binding_path& out)const noexcept{return dmg_result_get_binding_path(result.get(),row,index,&out,sizeof(out));}
    dmg_status proof_binding_count(uint32_t row,uint32_t& out)const noexcept{return dmg_result_get_proof_binding_count(result.get(),row,&out);}
    dmg_status proof_binding(uint32_t row,uint32_t index,dmg_proof_binding_row_v2& out)const noexcept{return dmg_result_get_proof_binding_v2(result.get(),row,index,&out,sizeof(out));}
    dmg_status proof_binding_path(uint32_t row,uint32_t index,dmg_binding_path& out)const noexcept{return dmg_result_get_proof_binding_path(result.get(),row,index,&out,sizeof(out));}
    dmg_status link_count(uint32_t row,uint32_t& out)const noexcept{return dmg_result_get_link_count(result.get(),row,&out);}
    dmg_status link(uint32_t row,uint32_t index,dmg_relation_link_v2& out)const noexcept{return dmg_result_get_link_v2(result.get(),row,index,&out,sizeof(out));}
    dmg_status graph_info(dmg_graph_info& out)const noexcept{return dmg_result_get_graph_info(result.get(),&out,sizeof(out));}
    dmg_status witness_count(uint32_t row,uint32_t& out)const noexcept{return dmg_result_get_witness_count(result.get(),row,&out);}
    dmg_status witness(uint32_t row,uint32_t index,dmg_relation_witness_v2& out)const noexcept{return dmg_result_get_relation_witness_v2(result.get(),row,index,&out,sizeof(out));}
    dmg_status inherited_witness(uint32_t row,uint32_t index,dmg_inherited_witness& out)const noexcept{return dmg_result_get_inherited_witness(result.get(),row,index,&out,sizeof(out));}
};
// Atomic, internal batch of independently owned public C Result objects.
// The container retains its Engine resource until all result owners are gone.
class MaterializedBatch {
    std::shared_ptr<runtime::EngineState> owner;
    std::pmr::vector<MaterializedRule> values;
    reference::SharedFactsProfile shared_{};
    bool retried_=false;
public:
    explicit MaterializedBatch(std::shared_ptr<runtime::EngineState> engine,reference::SharedFactsProfile shared,bool retried):
        owner(std::move(engine)),values(&owner->control_resource),shared_(shared),retried_(retried){}
    MaterializedBatch(MaterializedBatch&&)=default;
    MaterializedBatch& operator=(MaterializedBatch&&)=delete;
    MaterializedBatch(const MaterializedBatch&)=delete;
    size_t size()const noexcept{return values.size();}
    const MaterializedRule& at(size_t index)const{return values.at(index);}
    MaterializedRule take(size_t index){auto& value=values.at(index);if(!value)throw std::logic_error("result already taken");return std::move(value);}
    reference::SharedFactsProfile profile()const noexcept{return shared_;}
    bool retried()const noexcept{return retried_;}
    void reserve(size_t n){values.reserve(n);}
    void append(runtime::ResultOwner&& result){values.emplace_back(std::move(result));}
};
struct BatchError final:std::runtime_error {
    size_t rule_index;OutcomeCode code;uint64_t offset;uint32_t pc;
    BatchError(size_t index,const Outcome& failure):std::runtime_error("multi-rule evaluation failed"),
        rule_index(index),code(failure.code),offset(failure.error_offset),pc(failure.error_pc){}
};
struct BatchMaterializationError final:std::runtime_error {
    size_t rule_index;dmg_status status;dmg_error detail;
    BatchMaterializationError(size_t index,dmg_status value,const dmg_error& error):
        std::runtime_error("multi-rule materialization failed"),rule_index(index),status(value),detail(error){}
};
// Owns an otherwise unshared Engine and snapshot; never returns those handles.
// Methods serialize on gate; cancellation callbacks and external mutation are
// not accepted. Destroying the session concurrently with a method is invalid.
class IsolatedMultiSession final {
    struct EngineDelete {void operator()(dmg_engine* p)const noexcept{if(p)dmg_engine_release(p);}};
    struct SnapshotDelete {void operator()(dmg_snapshot* p)const noexcept{if(p)dmg_snapshot_release(p);}};
    struct RuleEntry {
        std::pmr::string id;std::shared_ptr<const runtime::QueryState> query;
        explicit RuleEntry(std::pmr::memory_resource* r):id(r){}
    };
    mutable std::mutex gate;
    std::unique_ptr<dmg_engine,EngineDelete> engine;
    std::unique_ptr<dmg_snapshot,SnapshotDelete> snapshot;
    std::pmr::vector<RuleEntry> rules;
    bool closed=false;
    IsolatedMultiSession(std::unique_ptr<dmg_engine,EngineDelete> e,std::unique_ptr<dmg_snapshot,SnapshotDelete> s);
public:
    static std::unique_ptr<IsolatedMultiSession> open(const dmg_engine_options* engine_options,
        const dmg_source_spec* sources,uint32_t count,const dmg_source_set_options* source_options);
    IsolatedMultiSession(const IsolatedMultiSession&)=delete;
    IsolatedMultiSession& operator=(const IsolatedMultiSession&)=delete;
    void add(std::string_view id,std::string_view json);
    IsolatedBatch execute(std::span<const std::string_view> ids,size_t cache_bytes,uint64_t max_cache_work);
    // Single rule follows dmg_query_execute; no shared fact cache or retries.
    MaterializedRule execute_one(std::string_view id);
    // All-or-nothing batch. An evaluation or materialization failure publishes
    // no Result. Successful Results may be taken and released independently.
    MaterializedBatch execute_materialized(std::span<const std::string_view> ids,size_t cache_bytes,uint64_t max_cache_work);
    dmg_engine_stats stats()const;
    void close();
    uint64_t owned_bytes()const;
};
}



