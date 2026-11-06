#include "runtime.hpp"
using namespace dexmeguviz;
using namespace dexmeguviz::runtime;
#ifdef DMG_TEST_REVERSE_JOIN_BARRIER
namespace dexmeguviz::runtime {std::atomic<void(*)()> test_reverse_join_materialize_barrier{nullptr};}
#endif
namespace dexmeguviz::runtime {
void fill_query_info(const QueryState& q,dmg_query_info* out)noexcept{
    const auto& p=*q.plan;*out={p.id.c_str(),static_cast<uint32_t>(p.stable_order.size()),p.required_capabilities,p.demand_mask,p.projection,
        static_cast<uint32_t>(p.intent),p.max_results,p.explicit_scope?1u:0u,p.max_work};
}
void fill_query_profile(const reference::Progress& progress,uint32_t count,dmg_query_profile* out)noexcept{
    const auto& p=progress.profile;*out={p.work_units,p.fact_requests,p.methods_decoded,p.code_units,p.string_pool_lookups,p.invoke_sites,p.field_uses,p.declared_fields,
        p.matches_seen,p.sort_comparisons,count,progress.scope_complete?1u:0u,progress.order_verified?1u:0u};
}
reference::Result evaluate_query(const Dataset& dataset,const QueryState& query,reference::Progress& progress,const Control& control,std::pmr::memory_resource* memory,reference::CandidateSink sink,reference::ReverseTargetJoin* reverse_join){
    control.check();std::pmr::vector<reference::SourceView> sources(memory);std::pmr::vector<std::string_view> slots(memory);
    for(uint32_t i=0;i<dataset.sources.size();++i){control.check();const auto& s=*dataset.sources[i];sources.push_back({i,s.input_index,&s.facts,s.view()});}
    for(const auto& input:dataset.inputs)slots.push_back(input.slot);
    auto cancelled=[](void* raw)noexcept{
        const auto& c=*static_cast<const Control*>(raw);return (c.cancelled&&c.cancelled->load(std::memory_order_acquire))||std::chrono::steady_clock::now()>=c.deadline;
    };
    try{return reference::execute({sources,slots,dataset.scope_complete,reverse_join},*query.plan,progress,memory,{cancelled,const_cast<Control*>(&control)},sink);}
    catch(const dexmeguviz::query::Error& error){if(error.code==dexmeguviz::query::ErrorCode::cancelled)control.check();throw;}
    catch(const instructions::DecodeError& error){if(error.code==instructions::DecodeCode::cancelled)control.check();throw;}
    catch(const facts::UseScanError& error){if(error.code==facts::UseScanError::Code::cancelled)control.check();throw;}
}
ResultOwner materialize_evaluated(const std::shared_ptr<EngineState>& owner,
    const std::shared_ptr<const Dataset>& dataset,const std::shared_ptr<const QueryState>& query,
    const reference::Result& evaluated,const reference::Progress& progress,const Control& control){
    if(!owner||!dataset||!query||!query->plan||dataset->engine!=owner||query->engine!=owner)
        throw query::Error(query::ErrorCode::invalid,"materialization owners differ");
    control.check();ResultOwner result(handle<dmg_result>(owner,dataset,query));
    initial(result->info,*dataset,*query);result->info.total_methods=progress.total;result->info.visited_methods=progress.visited;
    result->scope_sources.assign(evaluated.scope_sources.begin(),evaluated.scope_sources.end());
    for(const auto& row:evaluated.rows){
        auto value=materialize_value(*dataset,evaluated,row.key(),&owner->result_resource,control,query->plan->projection);
        result->rows.emplace_back(std::move(value),&owner->result_resource,row_evidence(*query->plan,row));
        materialize_bindings(result->rows.back(),*dataset,evaluated,row,&owner->result_resource,control);
        if(query->plan->contains_expand)materialize_expand_paths(result->rows.back(),*dataset,evaluated,row,&owner->result_resource,control);
    }
    if(query->plan->contains_expand)materialize_expand_frontiers(result->expand_frontiers,*dataset,evaluated,&owner->result_resource,control);
    result->info.candidates_count=static_cast<uint32_t>(result->rows.size());
    if(evaluated.result_limit||evaluated.unique_one_limit_pending){result->info.execution_status=DMG_BUDGET_EXCEEDED;result->info.reason=DMG_RESULT_LIMIT;}
    copy_graph(progress,result->graph);result->unknown_rows=progress.profile.unknown_rows;finalize(result->info,*query,progress.scope_complete,result->unknown_rows,progress.scope_derived_unknown);fill_query_profile(progress,static_cast<uint32_t>(result->scope_sources.size()),&result->profile);
    return result;
}
dmg_status execute_query(dmg_snapshot* snapshot,const std::shared_ptr<const QueryState>& query,dmg_result** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{
        if(!snapshot||!query||!out||snapshot->owner!=query->engine)return DMG_INVALID_ARGUMENT;
        if(snapshot->closed.load(std::memory_order_acquire))return DMG_CLOSED;admit(snapshot->owner);
        Control control;reference::Progress progress;
        auto evaluated=evaluate_query(*snapshot->dataset,*query,progress,control,&snapshot->owner->scratch_resource);
        auto result=materialize_evaluated(snapshot->owner,snapshot->dataset,query,evaluated,progress,control);
        *out=result.release();return DMG_OK;
    },error);
}
}
extern "C" {
dmg_status dmg_result_get_value_v2(const dmg_result* result,uint32_t row,dmg_value_row_v2* out,uint32_t size){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size())return DMG_INVALID_ARGUMENT;if(result->query->plan->required_capabilities&1073741824u)return DMG_UNSUPPORTED;
    fill_value(result->rows[row],out);return DMG_OK;
}
dmg_status dmg_result_get_binding_v2(const dmg_result* result,uint32_t row,uint32_t index,dmg_binding_row_v2* out,uint32_t size){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].bindings.size())return DMG_INVALID_ARGUMENT;if(result->query->plan->required_capabilities&1073741824u)return DMG_UNSUPPORTED;
    const auto& binding=result->rows[row].bindings[index];dmg_binding_row_v2 value{};
    value.label=binding.label==query::none?nullptr:result->query->plan->labels[binding.label].c_str();fill_value(binding.entity,&value.value);*out=value;return DMG_OK;
}
dmg_status dmg_result_get_proof_binding_v2(const dmg_result* result,uint32_t row,uint32_t index,dmg_proof_binding_row_v2* out,uint32_t size){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].proof_bindings.size())return DMG_INVALID_ARGUMENT;if(result->query->plan->required_capabilities&1073741824u)return DMG_UNSUPPORTED;
    const auto& proof=result->rows[row].proof_bindings[index];dmg_proof_binding_row_v2 value{};value.operator_node=proof.node;
    value.binding.label=proof.binding.label==query::none?nullptr:result->query->plan->labels[proof.binding.label].c_str();
    fill_value(proof.binding.entity,&value.binding.value);*out=value;return DMG_OK;
}
dmg_status dmg_result_get_link_v2(const dmg_result* result,uint32_t row,uint32_t index,dmg_relation_link_v2* out,uint32_t size){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].links.size())return DMG_INVALID_ARGUMENT;if(result->query->plan->required_capabilities&1073741824u)return DMG_UNSUPPORTED;
    const auto& link=result->rows[row].links[index];*out={link.node,static_cast<uint32_t>(link.key),identity_v2(link.left),identity_v2(link.right)};return DMG_OK;
}
dmg_status dmg_result_get_relation_witness_v2(const dmg_result* result,uint32_t row,uint32_t index,dmg_relation_witness_v2* out,uint32_t size){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].witnesses.size())return DMG_INVALID_ARGUMENT;if(result->query->plan->required_capabilities&1073741824u)return DMG_UNSUPPORTED;
    const auto& w=result->rows[row].witnesses[index];
    if(w.kind==reference::WitnessKind::numeric_literal||w.kind==reference::WitnessKind::interface_inherited||w.kind==reference::WitnessKind::interface_resolved||w.kind==reference::WitnessKind::field_declaration||w.kind==reference::WitnessKind::caller_field_relation||w.kind==reference::WitnessKind::class_annotation_flags)return DMG_UNSUPPORTED;
    *out={{static_cast<uint32_t>(w.kind),w.node,w.matched,w.dex_pc,w.opcode,w.reference_index,w.reference_kind,w.extra_proto,w.code_units},
        w.relation_node,identity_v2({w.source_index,w.entity_ordinal,w.entity_relation,w.entity_pc})};return DMG_OK;
}
dmg_status dmg_result_get_relation_info_v2(const dmg_result* result,dmg_relation_info_v2* out,uint32_t size){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(result->query->plan->required_capabilities&1073741824u)return DMG_UNSUPPORTED;if(!result->query->plan->contains_uses)return DMG_UNSUPPORTED;
    *out=relation_info_v2(result->info,*result->query,result->unknown_rows,result->graph);return DMG_OK;
}
dmg_status dmg_result_get_operator_profile_v2(const dmg_result* result,uint32_t index,dmg_operator_profile_v2* out,uint32_t size){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(result->query->plan->required_capabilities&1073741824u)return DMG_UNSUPPORTED;if(!result->query->plan->contains_uses)return DMG_UNSUPPORTED;
    if(index>=result->graph.nodes.size())return DMG_INVALID_ARGUMENT;fill_operator_v2(result->graph.nodes[index],out);return DMG_OK;
}
dmg_status dmg_job_get_relation_status_v2(const dmg_job* job,dmg_relation_job_status_v2* out,uint32_t size){if(job&&job->state->query->plan->contains_expand)return DMG_UNSUPPORTED;return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(job->state->query->plan->required_capabilities&1073741824u)return DMG_UNSUPPORTED;if(!job->state->query->plan->contains_uses)return DMG_UNSUPPORTED;
    const auto& s=*job->state;std::lock_guard lock(job->state->mutex);
    *out={s.status.lifecycle,s.status.terminal,relation_info_v2(s.status.outcome,*s.query,s.unknown_rows,s.graph),s.status.error};return DMG_OK;
});}
dmg_status dmg_job_wait_relation_v2(dmg_job* job,uint32_t timeout,dmg_relation_job_status_v2* out,uint32_t size){if(job&&job->state->query->plan->contains_expand)return DMG_UNSUPPORTED;return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(job->state->query->plan->required_capabilities&1073741824u)return DMG_UNSUPPORTED;if(!job->state->query->plan->contains_uses)return DMG_UNSUPPORTED;
    auto& s=*job->state;std::unique_lock lock(s.mutex);const bool ready=s.changed.wait_for(lock,std::chrono::milliseconds(timeout),[&]{return s.status.terminal!=0;});
    *out={s.status.lifecycle,s.status.terminal,relation_info_v2(s.status.outcome,*s.query,s.unknown_rows,s.graph),s.status.error};return ready?DMG_OK:DMG_NOT_READY;
});}
dmg_status dmg_job_get_operator_profile_v2(const dmg_job* job,uint32_t index,dmg_operator_profile_v2* out,uint32_t size){if(job&&job->state->query->plan->contains_expand)return DMG_UNSUPPORTED;return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(job->state->query->plan->required_capabilities&1073741824u)return DMG_UNSUPPORTED;if(!job->state->query->plan->contains_uses)return DMG_UNSUPPORTED;
    std::lock_guard lock(job->state->mutex);if(index>=job->state->graph.nodes.size())return DMG_INVALID_ARGUMENT;fill_operator_v2(job->state->graph.nodes[index],out);return DMG_OK;
});}
// v21 uses separate getters so old consumers never receive new enum values.
dmg_status dmg_result_get_value_v3(const dmg_result* result,uint32_t row,dmg_value_row_v3* out,uint32_t size){
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size())return DMG_INVALID_ARGUMENT;if(!(result->query->plan->required_capabilities&1073741824u)||result->query->plan->method_type_query)return DMG_UNSUPPORTED;
    fill_value_v3(result->rows[row],out);return DMG_OK;
}
dmg_status dmg_result_get_binding_v3(const dmg_result* result,uint32_t row,uint32_t index,dmg_binding_row_v3* out,uint32_t size){
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].bindings.size())return DMG_INVALID_ARGUMENT;if(!(result->query->plan->required_capabilities&1073741824u)||result->query->plan->method_type_query)return DMG_UNSUPPORTED;
    const auto& b=result->rows[row].bindings[index];dmg_binding_row_v3 v{};v.label=b.label==query::none?nullptr:result->query->plan->labels[b.label].c_str();fill_value_v3(b.entity,&v.value);*out=v;return DMG_OK;
}
dmg_status dmg_result_get_proof_binding_v3(const dmg_result* result,uint32_t row,uint32_t index,dmg_proof_binding_row_v3* out,uint32_t size){
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].proof_bindings.size())return DMG_INVALID_ARGUMENT;if(!(result->query->plan->required_capabilities&1073741824u)||result->query->plan->method_type_query)return DMG_UNSUPPORTED;
    const auto& b=result->rows[row].proof_bindings[index];dmg_proof_binding_row_v3 v{};v.operator_node=b.node;v.binding.label=b.binding.label==query::none?nullptr:result->query->plan->labels[b.binding.label].c_str();fill_value_v3(b.binding.entity,&v.binding.value);*out=v;return DMG_OK;
}
dmg_status dmg_result_get_link_v3(const dmg_result* result,uint32_t row,uint32_t index,dmg_relation_link_v3* out,uint32_t size){
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].links.size())return DMG_INVALID_ARGUMENT;if(!(result->query->plan->required_capabilities&1073741824u)||result->query->plan->method_type_query)return DMG_UNSUPPORTED;
    const auto& l=result->rows[row].links[index];*out={l.node,static_cast<uint32_t>(l.key),identity_v2(l.left),identity_v2(l.right)};return DMG_OK;
}
dmg_status dmg_result_get_relation_witness_v3(const dmg_result* result,uint32_t row,uint32_t index,dmg_relation_witness_v3* out,uint32_t size){
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].witnesses.size())return DMG_INVALID_ARGUMENT;if(!(result->query->plan->required_capabilities&1073741824u)||result->query->plan->method_type_query)return DMG_UNSUPPORTED;
    const auto& w=result->rows[row].witnesses[index];if(w.kind!=reference::WitnessKind::type_use&&w.kind!=reference::WitnessKind::metadata)return DMG_UNSUPPORTED;
    *out={{static_cast<uint32_t>(w.kind),w.node,w.matched,w.dex_pc,w.opcode,w.reference_index,w.reference_kind,w.extra_proto,w.code_units},w.relation_node,identity_v2({w.source_index,w.entity_ordinal,w.entity_relation,w.entity_pc})};return DMG_OK;
}
dmg_status dmg_result_get_relation_info_v3(const dmg_result* result,dmg_relation_info_v3* out,uint32_t size){
    if(!result||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(!(result->query->plan->required_capabilities&1073741824u)||result->query->plan->method_type_query)return DMG_UNSUPPORTED;
    *out=relation_info_v2(result->info,*result->query,result->unknown_rows,result->graph);return DMG_OK;
}
dmg_status dmg_result_get_operator_profile_v3(const dmg_result* result,uint32_t index,dmg_operator_profile_v3* out,uint32_t size){
    if(!result||!out||size!=sizeof(*out)||index>=result->graph.nodes.size())return DMG_INVALID_ARGUMENT;if(!(result->query->plan->required_capabilities&1073741824u)||result->query->plan->method_type_query)return DMG_UNSUPPORTED;fill_operator_v2(result->graph.nodes[index],out);return DMG_OK;
}
dmg_status dmg_job_get_relation_status_v3(const dmg_job* job,dmg_relation_job_status_v3* out,uint32_t size){return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(!(job->state->query->plan->required_capabilities&1073741824u)||job->state->query->plan->method_type_query)return DMG_UNSUPPORTED;
    const auto& state=*job->state;std::lock_guard lock(job->state->mutex);*out={state.status.lifecycle,state.status.terminal,relation_info_v2(state.status.outcome,*state.query,state.unknown_rows,state.graph),state.status.error};return DMG_OK;
});}
dmg_status dmg_job_wait_relation_v3(dmg_job* job,uint32_t timeout,dmg_relation_job_status_v3* out,uint32_t size){return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(!(job->state->query->plan->required_capabilities&1073741824u)||job->state->query->plan->method_type_query)return DMG_UNSUPPORTED;
    auto& state=*job->state;std::unique_lock lock(state.mutex);const bool ready=state.changed.wait_for(lock,std::chrono::milliseconds(timeout),[&]{return state.status.terminal!=0;});*out={state.status.lifecycle,state.status.terminal,relation_info_v2(state.status.outcome,*state.query,state.unknown_rows,state.graph),state.status.error};return ready?DMG_OK:DMG_NOT_READY;
});}
dmg_status dmg_job_get_operator_profile_v3(const dmg_job* job,uint32_t index,dmg_operator_profile_v3* out,uint32_t size){return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(!(job->state->query->plan->required_capabilities&1073741824u)||job->state->query->plan->method_type_query)return DMG_UNSUPPORTED;
    std::lock_guard lock(job->state->mutex);if(index>=job->state->graph.nodes.size())return DMG_INVALID_ARGUMENT;fill_operator_v2(job->state->graph.nodes[index],out);return DMG_OK;
});}
dmg_status dmg_result_get_binding_count(const dmg_result* result,uint32_t row,uint32_t* out){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||row>=result->rows.size())return DMG_INVALID_ARGUMENT;*out=static_cast<uint32_t>(result->rows[row].bindings.size());return DMG_OK;
}
dmg_status dmg_result_get_binding(const dmg_result* result,uint32_t row,uint32_t index,dmg_binding_row* out,uint32_t size){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].bindings.size())return DMG_INVALID_ARGUMENT;if(result->query->plan->required_capabilities&1073741824u)return DMG_UNSUPPORTED;
    const auto& binding=result->rows[row].bindings[index];dmg_binding_row value{};
    if(binding.entity.use)return DMG_UNSUPPORTED;
    value.label=binding.label==query::none?nullptr:result->query->plan->labels[binding.label].c_str();fill_entity(binding.entity,&value.entity);*out=value;return DMG_OK;
}
dmg_status dmg_result_get_binding_path(const dmg_result* result,uint32_t row,uint32_t index,dmg_binding_path* out,uint32_t size){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].bindings.size())return DMG_INVALID_ARGUMENT;
    const auto& binding=result->rows[row].bindings[index];*out={binding.path.data(),binding.path_length};return DMG_OK;
}
dmg_status dmg_result_get_proof_binding_count(const dmg_result* result,uint32_t row,uint32_t* out){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||row>=result->rows.size())return DMG_INVALID_ARGUMENT;*out=static_cast<uint32_t>(result->rows[row].proof_bindings.size());return DMG_OK;
}
dmg_status dmg_result_get_proof_binding(const dmg_result* result,uint32_t row,uint32_t index,dmg_proof_binding_row* out,uint32_t size){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].proof_bindings.size())return DMG_INVALID_ARGUMENT;if(result->query->plan->required_capabilities&1073741824u)return DMG_UNSUPPORTED;
    const auto& proof=result->rows[row].proof_bindings[index];dmg_proof_binding_row value{};value.operator_node=proof.node;
    if(proof.binding.entity.use)return DMG_UNSUPPORTED;
    value.binding.label=proof.binding.label==query::none?nullptr:result->query->plan->labels[proof.binding.label].c_str();
    fill_entity(proof.binding.entity,&value.binding.entity);*out=value;return DMG_OK;
}
dmg_status dmg_result_get_proof_binding_path(const dmg_result* result,uint32_t row,uint32_t index,dmg_binding_path* out,uint32_t size){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].proof_bindings.size())return DMG_INVALID_ARGUMENT;
    const auto& binding=result->rows[row].proof_bindings[index].binding;*out={binding.path.data(),binding.path_length};return DMG_OK;
}
dmg_status dmg_result_get_link_count(const dmg_result* result,uint32_t row,uint32_t* out){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||row>=result->rows.size())return DMG_INVALID_ARGUMENT;*out=static_cast<uint32_t>(result->rows[row].links.size());return DMG_OK;
}
dmg_status dmg_result_get_link(const dmg_result* result,uint32_t row,uint32_t index,dmg_relation_link* out,uint32_t size){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].links.size())return DMG_INVALID_ARGUMENT;if(result->query->plan->required_capabilities&1073741824u)return DMG_UNSUPPORTED;
    const auto& link=result->rows[row].links[index];
    if(query::is_use_relation(link.left.relation)||query::is_use_relation(link.right.relation))return DMG_UNSUPPORTED;
    *out={link.node,static_cast<uint32_t>(link.key),link.left.source_index,static_cast<uint32_t>(link.left.relation),link.left.ordinal,
        link.right.source_index,static_cast<uint32_t>(link.right.relation),link.right.ordinal};return DMG_OK;
}
dmg_status dmg_result_get_relation_witness(const dmg_result* result,uint32_t row,uint32_t index,dmg_relation_witness* out,uint32_t size){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].witnesses.size())return DMG_INVALID_ARGUMENT;if(result->query->plan->required_capabilities&1073741824u)return DMG_UNSUPPORTED;
    const auto& w=result->rows[row].witnesses[index];
    if(query::is_use_relation(w.entity_relation)||w.kind==reference::WitnessKind::numeric_literal||w.kind==reference::WitnessKind::interface_inherited||w.kind==reference::WitnessKind::interface_resolved||w.kind==reference::WitnessKind::field_declaration||w.kind==reference::WitnessKind::caller_field_relation||w.kind==reference::WitnessKind::class_annotation_flags)return DMG_UNSUPPORTED;
    *out={{static_cast<uint32_t>(w.kind),w.node,w.matched,w.dex_pc,w.opcode,w.reference_index,w.reference_kind,w.extra_proto,w.code_units},w.relation_node,w.source_index,static_cast<uint32_t>(w.entity_relation),w.entity_ordinal};return DMG_OK;
}
dmg_status dmg_result_get_graph_info(const dmg_result* result,dmg_graph_info* out,uint32_t size){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(result->query->plan->relation_root==query::none)return DMG_UNSUPPORTED;*out=result->graph.info;return DMG_OK;
}
dmg_status dmg_result_get_operator_profile(const dmg_result* result,uint32_t index,dmg_operator_profile* out,uint32_t size){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(result->query->plan->relation_root==query::none||result->query->plan->contains_uses)return DMG_UNSUPPORTED;
    if(index>=result->graph.nodes.size())return DMG_INVALID_ARGUMENT;fill_operator(result->graph.nodes[index],out);return DMG_OK;
}
dmg_status dmg_job_get_graph_info(const dmg_job* job,dmg_graph_info* out,uint32_t size){if(job&&job->state->query->plan->contains_expand)return DMG_UNSUPPORTED;return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(job->state->query->plan->relation_root==query::none)return DMG_UNSUPPORTED;
    std::lock_guard lock(job->state->mutex);*out=job->state->graph.info;return DMG_OK;
});}
dmg_status dmg_job_get_operator_profile(const dmg_job* job,uint32_t index,dmg_operator_profile* out,uint32_t size){if(job&&job->state->query->plan->contains_expand)return DMG_UNSUPPORTED;return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(job->state->query->plan->relation_root==query::none||job->state->query->plan->contains_uses)return DMG_UNSUPPORTED;
    std::lock_guard lock(job->state->mutex);if(index>=job->state->graph.nodes.size())return DMG_INVALID_ARGUMENT;fill_operator(job->state->graph.nodes[index],out);return DMG_OK;
});}
dmg_status dmg_result_get_entity(const dmg_result* result,uint32_t index,dmg_entity_row* out,uint32_t size){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out)||index>=result->rows.size())return DMG_INVALID_ARGUMENT;if((result->query->plan->required_capabilities&1073741824u)&&!result->query->plan->method_type_query)return DMG_UNSUPPORTED;
    if(result->rows[index].use)return DMG_UNSUPPORTED;
    fill_entity(result->rows[index],out);return DMG_OK;
}
dmg_status dmg_result_get_relation_info(const dmg_result* result,dmg_relation_info* out,uint32_t size){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;
    if(result->query->plan->contains_uses)return DMG_UNSUPPORTED;
    *out=relation_info(result->info,*result->query,result->unknown_rows);return DMG_OK;
}
dmg_status dmg_job_get_relation_status(const dmg_job* job,dmg_relation_job_status* out,uint32_t size){if(job&&job->state->query->plan->contains_expand)return DMG_UNSUPPORTED;return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(job->state->query->plan->contains_uses)return DMG_UNSUPPORTED;
    const auto& s=*job->state;std::lock_guard lock(job->state->mutex);
    *out={s.status.lifecycle,s.status.terminal,relation_info(s.status.outcome,*s.query,s.unknown_rows),s.status.error};return DMG_OK;
});}
dmg_status dmg_job_wait_relation(dmg_job* job,uint32_t timeout,dmg_relation_job_status* out,uint32_t size){if(job&&job->state->query->plan->contains_expand)return DMG_UNSUPPORTED;return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(job->state->query->plan->contains_uses)return DMG_UNSUPPORTED;
    auto& s=*job->state;std::unique_lock lock(s.mutex);
    const bool ready=s.changed.wait_for(lock,std::chrono::milliseconds(timeout),[&]{return s.status.terminal!=0;});
    *out={s.status.lifecycle,s.status.terminal,relation_info(s.status.outcome,*s.query,s.unknown_rows),s.status.error};return ready?DMG_OK:DMG_NOT_READY;
});}
dmg_status dmg_query_compile_json(dmg_engine* engine,const uint8_t* json,uint64_t length,dmg_query** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{
        if(!engine||!out||(!json&&length))return DMG_INVALID_ARGUMENT;if(length>65536)throw dexmeguviz::query::Error(dexmeguviz::query::ErrorCode::budget,"QueryIR JSON exceeds 64 KiB");admit(engine->owner);
        auto q=state<QueryState>(engine->owner);
        q->plan.emplace(query::compile({reinterpret_cast<const char*>(json),static_cast<size_t>(length)},&engine->owner->query_resource,&engine->owner->scratch_resource));
        q->options.struct_size=sizeof(q->options);q->options.abi_version=DMG_ABI_VERSION;q->options.intent=static_cast<uint32_t>(q->plan->intent);q->options.max_results=q->plan->max_results;
        *out=handle<dmg_query>(engine->owner,std::move(q));return DMG_OK;
    },error);
}
dmg_status dmg_query_get_info(const dmg_query* query,dmg_query_info* out){if(!query||!out)return DMG_INVALID_ARGUMENT;if(query->query->plan->class_annotation_requested)return DMG_UNSUPPORTED;fill_query_info(*query->query,out);return DMG_OK;}
dmg_status dmg_query_get_info_v2(const dmg_query* query,dmg_query_info_v2* out,uint32_t size){if(!query||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;dmg_query_info_v2 v{};fill_query_info(*query->query,&v.legacy);v.extended_capabilities=query->query->plan->class_annotation_string_requested?"class_annotation_static;class_annotation_string_static":query->query->plan->class_annotation_requested?"class_annotation_static":"";*out=v;return DMG_OK;}
dmg_status dmg_query_execute(dmg_snapshot* snapshot,dmg_query* query,dmg_result** out,dmg_error* error){if(out)*out=nullptr;return guard([&]()->dmg_status{if(!query)return DMG_INVALID_ARGUMENT;return execute_query(snapshot,query->query,out,error);},error);}
dmg_status dmg_query_execute_reverse_target_v1(dmg_snapshot* snapshot,dmg_query* query,const dmg_reverse_join_options_v1* options,dmg_result** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{
        if(!snapshot||!query||!options||!out||snapshot->owner!=query->query->engine||options->struct_size!=sizeof(*options)||
           options->abi_version!=DMG_ABI_VERSION||options->reserved0||options->reserved1||!options->max_index_work||
           options->max_index_work>100000000||!options->max_index_bytes||!options->max_adapter_work||
           options->max_adapter_work>100000000||!options->max_records||options->max_records>100000||
           !options->max_page_calls||options->max_page_calls>65536)return DMG_INVALID_ARGUMENT;
        const auto captured=*options;
        if(snapshot->closed.load(std::memory_order_acquire))return DMG_CLOSED;admit(snapshot->owner);
        Control control;reference::Progress progress;
        reference::ReverseTargetJoin index{&snapshot->dataset->reverse,{captured.max_index_work,captured.max_index_bytes,captured.max_records},captured.max_adapter_work,0,captured.max_page_calls,0};
        auto evaluated=evaluate_query(*snapshot->dataset,*query->query,progress,control,&snapshot->owner->scratch_resource,{},&index);
#ifdef DMG_TEST_REVERSE_JOIN_BARRIER
        if(const auto hook=test_reverse_join_materialize_barrier.load(std::memory_order_acquire))hook();
#endif
        auto result=materialize_evaluated(snapshot->owner,snapshot->dataset,query->query,evaluated,progress,control);
        *out=result.release();return DMG_OK;
    },error);
}
dmg_status dmg_query_execute_reverse_field_target_v1(dmg_snapshot* snapshot,dmg_query* query,const dmg_reverse_join_options_v1* options,dmg_result** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{
        if(!snapshot||!query||!options||!out||snapshot->owner!=query->query->engine||options->struct_size!=sizeof(*options)||
           options->abi_version!=DMG_ABI_VERSION||options->reserved0||options->reserved1||!options->max_index_work||
           options->max_index_work>100000000||!options->max_index_bytes||!options->max_adapter_work||
           options->max_adapter_work>100000000||!options->max_records||options->max_records>100000||
           !options->max_page_calls||options->max_page_calls>65536)return DMG_INVALID_ARGUMENT;
        const auto captured=*options;
        if(snapshot->closed.load(std::memory_order_acquire))return DMG_CLOSED;admit(snapshot->owner);
        Control control;reference::Progress progress;
        reference::ReverseTargetJoin index{&snapshot->dataset->reverse,{captured.max_index_work,captured.max_index_bytes,captured.max_records},captured.max_adapter_work,0,captured.max_page_calls,0};
        index.use_relation=dexmeguviz::query::Relation::field_uses;
        auto evaluated=evaluate_query(*snapshot->dataset,*query->query,progress,control,&snapshot->owner->scratch_resource,{},&index);
#ifdef DMG_TEST_REVERSE_JOIN_BARRIER
        if(const auto hook=test_reverse_join_materialize_barrier.load(std::memory_order_acquire))hook();
#endif
        auto result=materialize_evaluated(snapshot->owner,snapshot->dataset,query->query,evaluated,progress,control);
        *out=result.release();return DMG_OK;
    },error);
}
dmg_status dmg_query_execute_reverse_string_target_v1(dmg_snapshot* snapshot,dmg_query* query,const dmg_reverse_join_options_v1* options,dmg_result** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{
        if(!snapshot||!query||!options||!out||snapshot->owner!=query->query->engine||options->struct_size!=sizeof(*options)||
           options->abi_version!=DMG_ABI_VERSION||options->reserved0||options->reserved1||!options->max_index_work||
           options->max_index_work>100000000||!options->max_index_bytes||!options->max_adapter_work||
           options->max_adapter_work>100000000||!options->max_records||options->max_records>100000||
           !options->max_page_calls||options->max_page_calls>65536)return DMG_INVALID_ARGUMENT;
        const auto captured=*options;
        if(snapshot->closed.load(std::memory_order_acquire))return DMG_CLOSED;admit(snapshot->owner);
        Control control;reference::Progress progress;
        reference::ReverseTargetJoin index{&snapshot->dataset->reverse,{captured.max_index_work,captured.max_index_bytes,captured.max_records},captured.max_adapter_work,0,captured.max_page_calls,0};
        index.use_relation=dexmeguviz::query::Relation::string_uses;
        auto evaluated=evaluate_query(*snapshot->dataset,*query->query,progress,control,&snapshot->owner->scratch_resource,{},&index);
#ifdef DMG_TEST_REVERSE_JOIN_BARRIER
        if(const auto hook=test_reverse_join_materialize_barrier.load(std::memory_order_acquire))hook();
#endif
        auto result=materialize_evaluated(snapshot->owner,snapshot->dataset,query->query,evaluated,progress,control);
        *out=result.release();return DMG_OK;
    },error);
}
dmg_status dmg_query_execute_reverse_intersection_v2(dmg_snapshot* snapshot,dmg_query* query,const dmg_reverse_join_options_v1* options,dmg_result** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{
        if(!snapshot||!query||!options||!out||snapshot->owner!=query->query->engine||options->struct_size!=sizeof(*options)||
           options->abi_version!=DMG_ABI_VERSION||options->reserved0||options->reserved1||!options->max_index_work||
           options->max_index_work>100000000||!options->max_index_bytes||!options->max_adapter_work||
           options->max_adapter_work>100000000||!options->max_records||options->max_records>100000||
           !options->max_page_calls||options->max_page_calls>65536)return DMG_INVALID_ARGUMENT;
        const auto captured=*options;
        if(snapshot->closed.load(std::memory_order_acquire))return DMG_CLOSED;admit(snapshot->owner);
        Control control;reference::Progress progress;
        reference::ReverseTargetJoin index{&snapshot->dataset->reverse,{captured.max_index_work,captured.max_index_bytes,captured.max_records},captured.max_adapter_work,0,captured.max_page_calls,0};
        const auto& plan=*query->query->plan;
        if(plan.relation_root<plan.relations.size()){
            const auto& root=plan.relations[plan.relation_root];
            if(root.children.size()==2&&root.children[0]<plan.relations.size())index.use_relation=plan.relations[root.children[0]].relation;
        }
        index.intersection_only=true;
        auto evaluated=evaluate_query(*snapshot->dataset,*query->query,progress,control,&snapshot->owner->scratch_resource,{},&index);
#ifdef DMG_TEST_REVERSE_JOIN_BARRIER
        if(const auto hook=test_reverse_join_materialize_barrier.load(std::memory_order_acquire))hook();
#endif
        auto result=materialize_evaluated(snapshot->owner,snapshot->dataset,query->query,evaluated,progress,control);
        *out=result.release();return DMG_OK;
    },error);
}
dmg_status dmg_result_get_query_info(const dmg_result* result,dmg_query_info* out){if(!result||!out)return DMG_INVALID_ARGUMENT;if(result->query->plan->class_annotation_requested)return DMG_UNSUPPORTED;fill_query_info(*result->query,out);return DMG_OK;}
dmg_status dmg_result_get_query_info_v2(const dmg_result* result,dmg_query_info_v2* out,uint32_t size){if(!result||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;dmg_query_info_v2 v{};fill_query_info(*result->query,&v.legacy);v.extended_capabilities=result->query->plan->class_annotation_string_requested?"class_annotation_static;class_annotation_string_static":result->query->plan->class_annotation_requested?"class_annotation_static":"";*out=v;return DMG_OK;}
dmg_status dmg_job_get_query_info_v2(const dmg_job* job,dmg_query_info_v2* out,uint32_t size){if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;dmg_query_info_v2 v{};fill_query_info(*job->state->query,&v.legacy);v.extended_capabilities=job->state->query->plan->class_annotation_string_requested?"class_annotation_static;class_annotation_string_static":job->state->query->plan->class_annotation_requested?"class_annotation_static":"";*out=v;return DMG_OK;}
dmg_status dmg_result_get_profile(const dmg_result* result,dmg_query_profile* out){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;if(!result||!out)return DMG_INVALID_ARGUMENT;*out=result->profile;return DMG_OK;}
dmg_status dmg_result_get_scope_source(const dmg_result* result,uint32_t index,uint32_t* out){if(!result||!out)return DMG_INVALID_ARGUMENT;const auto& source=expand_root(*result);if(index>=source.scope_sources.size())return DMG_INVALID_ARGUMENT;*out=source.scope_sources[index];return DMG_OK;}
dmg_status dmg_result_get_witness_count(const dmg_result* result,uint32_t row,uint32_t* out){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;if(!result||!out||row>=result->rows.size())return DMG_INVALID_ARGUMENT;*out=static_cast<uint32_t>(result->rows[row].witnesses.size());return DMG_OK;}
dmg_status dmg_result_get_witness(const dmg_result* result,uint32_t row,uint32_t witness,dmg_witness* out){if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||row>=result->rows.size()||witness>=result->rows[row].witnesses.size())return DMG_INVALID_ARGUMENT;if(result->query->plan->required_capabilities&1073741824u)return DMG_UNSUPPORTED;
    const auto& w=result->rows[row].witnesses[witness];if(query::is_use_relation(w.entity_relation)||w.kind==reference::WitnessKind::numeric_literal||w.kind==reference::WitnessKind::interface_inherited||w.kind==reference::WitnessKind::interface_resolved||w.kind==reference::WitnessKind::field_declaration||w.kind==reference::WitnessKind::caller_field_relation||w.kind==reference::WitnessKind::class_annotation_flags)return DMG_UNSUPPORTED;
    *out={static_cast<uint32_t>(w.kind),w.node,w.matched,w.dex_pc,w.opcode,w.reference_index,w.reference_kind,w.extra_proto,w.code_units};return DMG_OK;
}
dmg_status dmg_result_get_method_type_identity_v1(const dmg_result* result,uint32_t row,dmg_method_type_identity_v1* out,uint32_t size){
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size())return DMG_INVALID_ARGUMENT;if(!result->query->plan->method_type_query)return DMG_UNSUPPORTED;
    const auto& r=result->rows[row];*out={r.source_index,r.ordinal,r.method_index};return DMG_OK;
}
dmg_status dmg_result_get_method_witness_v1(const dmg_result* result,uint32_t row,uint32_t index,dmg_witness* out,uint32_t size){
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].witnesses.size())return DMG_INVALID_ARGUMENT;if(!result->query->plan->method_type_query)return DMG_UNSUPPORTED;
    const auto& w=result->rows[row].witnesses[index];if(w.kind!=reference::WitnessKind::metadata&&w.kind!=reference::WitnessKind::string_use&&w.kind!=reference::WitnessKind::invoke&&w.kind!=reference::WitnessKind::field_use&&w.kind!=reference::WitnessKind::instruction_scope&&w.kind!=reference::WitnessKind::no_body&&w.kind!=reference::WitnessKind::string_pool_absence&&w.kind!=reference::WitnessKind::type_use)return DMG_UNSUPPORTED;
    *out={static_cast<uint32_t>(w.kind),w.node,w.matched,w.dex_pc,w.opcode,w.reference_index,w.reference_kind,w.extra_proto,w.code_units};return DMG_OK;
}
dmg_status dmg_result_get_method_type_witness_v1(const dmg_result* result,uint32_t row,uint32_t index,dmg_method_type_witness_v1* out,uint32_t size){
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].witnesses.size())return DMG_INVALID_ARGUMENT;if(!result->query->plan->method_type_query)return DMG_UNSUPPORTED;
    const auto& w=result->rows[row].witnesses[index];if(w.kind!=reference::WitnessKind::type_use)return DMG_UNSUPPORTED;
    if(w.source_index>=result->dataset->sources.size())return DMG_INTERNAL_ERROR;const auto& facts=result->dataset->sources[w.source_index]->facts;
    if(w.reference_index>=facts.types.size()||facts.types[w.reference_index]>=facts.strings.size())return DMG_INTERNAL_ERROR;
    const auto& text=facts.strings[facts.types[w.reference_index]];*out={{static_cast<uint32_t>(w.kind),w.node,w.matched,w.dex_pc,w.opcode,w.reference_index,w.reference_kind,w.extra_proto,w.code_units},w.source_index,w.entity_ordinal,text.size()};return DMG_OK;
}
dmg_status dmg_result_copy_method_type_descriptor_v1(const dmg_result* result,uint32_t row,uint32_t index,uint16_t* out,uint64_t capacity){
    if(!result||row>=result->rows.size()||index>=result->rows[row].witnesses.size())return DMG_INVALID_ARGUMENT;if(!result->query->plan->method_type_query)return DMG_UNSUPPORTED;
    const auto& w=result->rows[row].witnesses[index];if(w.kind!=reference::WitnessKind::type_use)return DMG_UNSUPPORTED;
    if(w.source_index>=result->dataset->sources.size())return DMG_INTERNAL_ERROR;const auto& facts=result->dataset->sources[w.source_index]->facts;
    if(w.reference_index>=facts.types.size()||facts.types[w.reference_index]>=facts.strings.size())return DMG_INTERNAL_ERROR;
    const auto& text=facts.strings[facts.types[w.reference_index]];if(capacity!=text.size()||(!out&&capacity))return DMG_INVALID_ARGUMENT;
    for(size_t i=0;i<text.size();++i)out[i]=static_cast<uint16_t>(text[i]);return DMG_OK;
}
dmg_status dmg_result_get_numeric_witness_v1(const dmg_result* result,uint32_t row,uint32_t index,dmg_numeric_witness_v1* out,uint32_t size){
    if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].witnesses.size())return DMG_INVALID_ARGUMENT;
    const auto& w=result->rows[row].witnesses[index];if(w.kind!=reference::WitnessKind::numeric_literal)return DMG_UNSUPPORTED;
    *out={w.node,w.matched,w.dex_pc,w.opcode,w.code_units,w.relation_node,w.source_index,static_cast<uint32_t>(w.entity_relation),w.entity_ordinal,w.entity_pc,w.numeric_width,w.numeric_kind,w.numeric_bits};return DMG_OK;
}
dmg_status dmg_result_get_inherited_witness(const dmg_result* result,uint32_t row,uint32_t index,dmg_inherited_witness* out,uint32_t size){
    if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].witnesses.size())return DMG_INVALID_ARGUMENT;
    const auto& w=result->rows[row].witnesses[index];if(w.kind!=reference::WitnessKind::inherited)return DMG_UNSUPPORTED;
    *out={w.node,w.matched,w.inherited_item,w.inherited_path,w.inherited_aux,w.inherited_branch,w.inherited_detail,
        w.source_index,static_cast<uint32_t>(w.entity_relation),w.entity_ordinal};return DMG_OK;
}
dmg_status dmg_result_get_interface_witness_v1(const dmg_result* result,uint32_t row,uint32_t index,dmg_interface_witness_v1* out,uint32_t size){
    if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].witnesses.size())return DMG_INVALID_ARGUMENT;
    const auto& w=result->rows[row].witnesses[index];if(w.kind!=reference::WitnessKind::interface_inherited)return DMG_UNSUPPORTED;
    *out={w.node,w.matched,w.relation_node,w.inherited_item,w.inherited_branch,w.inherited_path,w.inherited_aux,w.inherited_detail,
        w.source_index,static_cast<uint32_t>(w.entity_relation),w.entity_ordinal};return DMG_OK;
}
dmg_status dmg_result_get_caller_field_relation_witness_v1(const dmg_result* result,uint32_t row,uint32_t index,dmg_caller_field_relation_witness_v1* out,uint32_t size){
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].witnesses.size())return DMG_INVALID_ARGUMENT;
    const auto& entry=result->rows[row];const auto& w=entry.witnesses[index];if(w.kind!=reference::WitnessKind::caller_field_relation)return DMG_UNSUPPORTED;
    dmg_caller_field_relation_witness_v1 value{};value.node_id=w.node;value.operator_node=w.relation_node;value.item_kind=w.inherited_item;
    value.status=value.reason=value.path_index=value.parent_index=value.edge_kind=value.interface_index=value.target_source=value.target_class=value.target_field=value.event_source=value.event_caller=value.event_pc=UINT32_MAX;
    value.source_index=w.source_index;value.class_ordinal=w.entity_ordinal;
    if(w.inherited_item==0){
        if(entry.links.size()!=1||entry.links[0].key!=query::JoinKey::caller)return DMG_INTERNAL_ERROR;
        const auto& event=entry.links[0].right;value.status=w.inherited_path;value.reason=w.inherited_aux;value.target_source=w.inherited_branch;value.target_class=w.inherited_detail;value.target_field=w.reference_index;value.event_source=event.source_index;value.event_caller=event.ordinal;value.event_pc=event.dex_pc;
     }else if(w.inherited_item==1||w.inherited_item==2||w.inherited_item==3){value.path_index=w.inherited_path;value.parent_index=w.inherited_aux;value.edge_kind=w.inherited_branch;value.interface_index=w.inherited_detail;}
    else return DMG_INTERNAL_ERROR;
    *out=value;return DMG_OK;
}
dmg_status dmg_result_get_field_declaration_witness_v1(const dmg_result* result,uint32_t row,uint32_t index,dmg_field_declaration_witness_v1* out,uint32_t size){
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].witnesses.size())return DMG_INVALID_ARGUMENT;
    const auto& w=result->rows[row].witnesses[index];if(w.kind!=reference::WitnessKind::field_declaration)return DMG_UNSUPPORTED;
    *out={w.node,w.matched,w.relation_node,w.inherited_item,w.inherited_path,w.inherited_aux,w.inherited_branch,w.inherited_detail,w.source_index,static_cast<uint32_t>(w.entity_relation),w.entity_ordinal};return DMG_OK;
}
dmg_status dmg_result_get_class_annotation_flags_witness_v1(const dmg_result* result,uint32_t row,uint32_t index,dmg_class_annotation_flags_witness_v1* out,uint32_t size){
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].witnesses.size())return DMG_INVALID_ARGUMENT;
    const auto& w=result->rows[row].witnesses[index];if(w.kind!=reference::WitnessKind::class_annotation_flags)return DMG_UNSUPPORTED;
    if(w.entity_relation!=query::Relation::class_defs||w.numeric_bits>UINT32_MAX)return DMG_INTERNAL_ERROR;
    *out={w.node,w.matched,w.relation_node,w.source_index,w.entity_ordinal,w.inherited_item,w.inherited_path,w.inherited_aux,w.inherited_branch,w.inherited_detail,w.numeric_kind,static_cast<uint32_t>(w.numeric_bits),w.numeric_width};return DMG_OK;
}
dmg_status dmg_result_get_interface_resolved_witness_v1(const dmg_result* result,uint32_t row,uint32_t index,dmg_interface_witness_v1* out,uint32_t size){
    if(result&&result->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!result||!out||size!=sizeof(*out)||row>=result->rows.size()||index>=result->rows[row].witnesses.size())return DMG_INVALID_ARGUMENT;
    const auto& w=result->rows[row].witnesses[index];if(w.kind!=reference::WitnessKind::interface_resolved)return DMG_UNSUPPORTED;
    *out={w.node,w.matched,w.relation_node,w.inherited_item,w.inherited_branch,w.inherited_path,w.inherited_aux,w.inherited_detail,w.source_index,static_cast<uint32_t>(w.entity_relation),w.entity_ordinal};return DMG_OK;
}
dmg_status dmg_job_get_terminal_scope_v1(const dmg_job* job,dmg_job_terminal_scope_v1* out,uint32_t size){return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;
    const auto& s=*job->state;const auto& plan=*s.query->plan;
    if(!plan.class_annotation_requested||!plan.explicit_scope||plan.relation_root!=query::none||plan.relation!=query::Relation::class_defs)return DMG_UNSUPPORTED;
    std::lock_guard lock(job->state->mutex);if(!s.status.terminal)return DMG_NOT_READY;
    if(s.status.outcome.execution_status!=DMG_OK)return static_cast<dmg_status>(s.status.outcome.execution_status);
    if(!s.terminal_scope_sources||!s.profile.scope_complete||s.terminal_scope_sources->size()!=s.profile.scope_source_count)return DMG_INTERNAL_ERROR;
    const dmg_job_terminal_scope_v1 value{static_cast<uint32_t>(s.terminal_scope_sources->size()),s.profile.scope_complete};*out=value;return DMG_OK;
});}
dmg_status dmg_job_get_terminal_scope_source_v1(const dmg_job* job,uint32_t index,uint32_t* out){return guard([&]()->dmg_status{
    if(!job||!out)return DMG_INVALID_ARGUMENT;
    const auto& s=*job->state;const auto& plan=*s.query->plan;
    if(!plan.class_annotation_requested||!plan.explicit_scope||plan.relation_root!=query::none||plan.relation!=query::Relation::class_defs)return DMG_UNSUPPORTED;
    std::lock_guard lock(job->state->mutex);if(!s.status.terminal)return DMG_NOT_READY;
    if(s.status.outcome.execution_status!=DMG_OK)return static_cast<dmg_status>(s.status.outcome.execution_status);
    if(!s.terminal_scope_sources||!s.profile.scope_complete||s.terminal_scope_sources->size()!=s.profile.scope_source_count)return DMG_INTERNAL_ERROR;
    if(index>=s.terminal_scope_sources->size())return DMG_INVALID_ARGUMENT;
    *out=(*s.terminal_scope_sources)[index];return DMG_OK;
});}

dmg_status dmg_job_get_profile(const dmg_job* job,dmg_query_profile* out){if(job&&job->state->query->plan->contains_expand)return DMG_UNSUPPORTED;return guard([&]()->dmg_status{if(!job||!out)return DMG_INVALID_ARGUMENT;std::lock_guard lock(job->state->mutex);*out=job->state->profile;return DMG_OK;});}

#define EXPAND_RESULT(r,o,s) do{if(!(r)||!(o)||(s)!=sizeof(*(o)))return DMG_INVALID_ARGUMENT;if(!(r)->query->plan->contains_expand)return DMG_UNSUPPORTED;}while(0)
static dmg_expand_profile expand_profile_value(const reference::ExpandProfile& p){return {p.node,p.visited,p.edges,p.paths,p.decoded_methods,p.unresolved,p.unknown,p.reverse_builds,p.reverse_reuses};}
static dmg_expand_job_status expand_job_value(const JobState& s){
    dmg_expand_info info{};
    if(s.committed_expand)info=expand_info(*s.committed_expand);
    else{info.outcome=relation_info_v2(s.status.outcome,*s.query,s.unknown_rows,s.graph);info.profile=s.profile;info.graph=s.graph.info;info.total_candidates=s.status.outcome.candidates_count;}
    return {s.status.lifecycle,s.status.terminal,info,s.status.error};
}
dmg_status dmg_result_get_expand_info(const dmg_result* r,dmg_expand_info* out,uint32_t size){EXPAND_RESULT(r,out,size);*out=expand_info(*r);return DMG_OK;}
dmg_status dmg_job_get_expand_status(const dmg_job* job,dmg_expand_job_status* out,uint32_t size){return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(!job->state->query->plan->contains_expand)return DMG_UNSUPPORTED;
    std::lock_guard lock(job->state->mutex);*out=expand_job_value(*job->state);return DMG_OK;
});}
dmg_status dmg_job_wait_expand(dmg_job* job,uint32_t timeout,dmg_expand_job_status* out,uint32_t size){return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(!job->state->query->plan->contains_expand)return DMG_UNSUPPORTED;
    auto& s=*job->state;std::unique_lock lock(s.mutex);bool ready=s.changed.wait_for(lock,std::chrono::milliseconds(timeout),[&]{return s.status.terminal!=0;});
    if(!ready)return DMG_NOT_READY;*out=expand_job_value(s);return DMG_OK;
});}
dmg_status dmg_result_get_expand_profile(const dmg_result* r,uint32_t i,dmg_expand_profile* out,uint32_t size){
    EXPAND_RESULT(r,out,size);const auto& v=expand_root(*r).graph.expands;if(i>=v.size())return DMG_INVALID_ARGUMENT;*out=expand_profile_value(v[i]);return DMG_OK;
}
dmg_status dmg_job_get_expand_profile(const dmg_job* job,uint32_t i,dmg_expand_profile* out,uint32_t size){return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(!job->state->query->plan->contains_expand)return DMG_UNSUPPORTED;
    std::lock_guard lock(job->state->mutex);const auto& v=job->state->graph.expands;if(i>=v.size())return DMG_INVALID_ARGUMENT;*out=expand_profile_value(v[i]);return DMG_OK;
});}
dmg_status dmg_result_get_expand_operator(const dmg_result* r,uint32_t i,dmg_operator_profile_v2* out,uint32_t size){
    EXPAND_RESULT(r,out,size);const auto& v=expand_root(*r).graph.nodes;if(i>=v.size())return DMG_INVALID_ARGUMENT;fill_operator_v2(v[i],out);return DMG_OK;
}
dmg_status dmg_job_get_expand_operator(const dmg_job* job,uint32_t i,dmg_operator_profile_v2* out,uint32_t size){return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(!job->state->query->plan->contains_expand)return DMG_UNSUPPORTED;
    std::lock_guard lock(job->state->mutex);const auto& v=job->state->graph.nodes;if(i>=v.size())return DMG_INVALID_ARGUMENT;fill_operator_v2(v[i],out);return DMG_OK;
});}
dmg_status dmg_result_get_expand_endpoint(const dmg_result* r,uint32_t row,dmg_entity_row* out,uint32_t size){
    EXPAND_RESULT(r,out,size);if(row>=expand_rows(*r))return DMG_INVALID_ARGUMENT;const auto& value=expand_row(*r,row);if(value.use)return DMG_INTERNAL_ERROR;fill_entity(value,out);return DMG_OK;
}
dmg_status dmg_result_get_expand_row_evidence_info(const dmg_result* r,uint32_t row,dmg_expand_row_evidence_info* out,uint32_t size){
    EXPAND_RESULT(r,out,size);if(row>=expand_rows(*r))return DMG_INVALID_ARGUMENT;const auto& v=expand_row(*r,row);
    if(v.bindings.size()>UINT32_MAX||v.links.size()>UINT32_MAX||v.proof_bindings.size()>UINT32_MAX||v.witnesses.size()>UINT32_MAX)return DMG_INTERNAL_ERROR;
    *out={static_cast<uint32_t>(v.bindings.size()),static_cast<uint32_t>(v.links.size()),static_cast<uint32_t>(v.proof_bindings.size()),static_cast<uint32_t>(v.witnesses.size())};return DMG_OK;
}
dmg_status dmg_result_get_expand_row_binding(const dmg_result* r,uint32_t row,uint32_t i,dmg_expand_binding* out,uint32_t size){
    EXPAND_RESULT(r,out,size);if(row>=expand_rows(*r))return DMG_INVALID_ARGUMENT;const auto& v=expand_row(*r,row).bindings;
    if(i>=v.size())return DMG_INVALID_ARGUMENT;fill_expand_binding(v[i],*r->query,out);return DMG_OK;
}
dmg_status dmg_result_get_expand_row_link(const dmg_result* r,uint32_t row,uint32_t i,dmg_relation_link_v2* out,uint32_t size){
    EXPAND_RESULT(r,out,size);if(row>=expand_rows(*r))return DMG_INVALID_ARGUMENT;const auto& v=expand_row(*r,row).links;
    if(i>=v.size())return DMG_INVALID_ARGUMENT;fill_expand_link(v[i],out);return DMG_OK;
}
dmg_status dmg_result_get_expand_row_proof(const dmg_result* r,uint32_t row,uint32_t i,dmg_expand_proof* out,uint32_t size){
    EXPAND_RESULT(r,out,size);if(row>=expand_rows(*r))return DMG_INVALID_ARGUMENT;const auto& v=expand_row(*r,row).proof_bindings;
    if(i>=v.size())return DMG_INVALID_ARGUMENT;fill_expand_proof(v[i],*r->query,out);return DMG_OK;
}
dmg_status dmg_result_get_expand_row_witness(const dmg_result* r,uint32_t row,uint32_t i,dmg_relation_witness_v2* out,uint32_t size){
    EXPAND_RESULT(r,out,size);if(row>=expand_rows(*r))return DMG_INVALID_ARGUMENT;const auto& v=expand_row(*r,row).witnesses;
    if(i>=v.size())return DMG_INVALID_ARGUMENT;fill_expand_witness(v[i],out);return DMG_OK;
}
dmg_status dmg_result_get_expand_path_count(const dmg_result* r,uint32_t row,uint32_t* out){
    if(!r||!out)return DMG_INVALID_ARGUMENT;if(!r->query->plan->contains_expand)return DMG_UNSUPPORTED;if(row>=expand_rows(*r))return DMG_INVALID_ARGUMENT;
    *out=static_cast<uint32_t>(expand_row(*r,row).expand_paths.size());return DMG_OK;
}
dmg_status dmg_result_get_expand_path(const dmg_result* r,uint32_t row,uint32_t index,dmg_expand_path_info* out,uint32_t size){
    EXPAND_RESULT(r,out,size);if(row>=expand_rows(*r))return DMG_INVALID_ARGUMENT;const auto& paths=expand_row(*r,row).expand_paths;if(index>=paths.size())return DMG_INVALID_ARGUMENT;
    const auto& p=paths[index];*out={p.node,p.uncertain?1u:0u,static_cast<uint32_t>(p.bindings.size()),static_cast<uint32_t>(p.hops.size()),
        static_cast<uint32_t>(p.seed_links.size()),static_cast<uint32_t>(p.seed_proofs.size()),static_cast<uint32_t>(p.seed_witnesses.size()),
        static_cast<uint32_t>(p.walk_witnesses.size()),static_cast<uint32_t>(p.emit_witnesses.size()),identity_v2(p.seed),identity_v2(p.endpoint)};return DMG_OK;
}
dmg_status dmg_result_get_expand_path_binding(const dmg_result* r,uint32_t row,uint32_t path,uint32_t i,dmg_expand_binding* out,uint32_t size){
    EXPAND_RESULT(r,out,size);if(row>=expand_rows(*r))return DMG_INVALID_ARGUMENT;const auto& paths=expand_row(*r,row).expand_paths;
    if(path>=paths.size()||i>=paths[path].bindings.size())return DMG_INVALID_ARGUMENT;fill_expand_binding(paths[path].bindings[i],*r->query,out);return DMG_OK;
}
dmg_status dmg_result_get_expand_path_hop(const dmg_result* r,uint32_t row,uint32_t path,uint32_t i,dmg_expand_hop* out,uint32_t size){
    EXPAND_RESULT(r,out,size);if(row>=expand_rows(*r))return DMG_INVALID_ARGUMENT;const auto& paths=expand_row(*r,row).expand_paths;
    if(path>=paths.size()||i>=paths[path].hops.size())return DMG_INVALID_ARGUMENT;fill_expand_hop(paths[path].hops[i],out);return DMG_OK;
}
dmg_status dmg_result_get_expand_path_seed_link(const dmg_result* r,uint32_t row,uint32_t path,uint32_t i,dmg_relation_link_v2* out,uint32_t size){
    EXPAND_RESULT(r,out,size);if(row>=expand_rows(*r))return DMG_INVALID_ARGUMENT;const auto& v=expand_row(*r,row).expand_paths;
    if(path>=v.size()||i>=v[path].seed_links.size())return DMG_INVALID_ARGUMENT;fill_expand_link(v[path].seed_links[i],out);return DMG_OK;
}
dmg_status dmg_result_get_expand_path_seed_proof(const dmg_result* r,uint32_t row,uint32_t path,uint32_t i,dmg_expand_proof* out,uint32_t size){
    EXPAND_RESULT(r,out,size);if(row>=expand_rows(*r))return DMG_INVALID_ARGUMENT;const auto& v=expand_row(*r,row).expand_paths;
    if(path>=v.size()||i>=v[path].seed_proofs.size())return DMG_INVALID_ARGUMENT;fill_expand_proof(v[path].seed_proofs[i],*r->query,out);return DMG_OK;
}
dmg_status dmg_result_get_expand_path_witness(const dmg_result* r,uint32_t row,uint32_t path,uint32_t which,uint32_t i,dmg_relation_witness_v2* out,uint32_t size){
    EXPAND_RESULT(r,out,size);if(row>=expand_rows(*r))return DMG_INVALID_ARGUMENT;const auto& v=expand_row(*r,row).expand_paths;if(path>=v.size())return DMG_INVALID_ARGUMENT;
    const auto* list=expand_witnesses(v[path],which);if(!list||i>=list->size())return DMG_INVALID_ARGUMENT;fill_expand_witness((*list)[i],out);return DMG_OK;
}
dmg_status dmg_result_get_expand_frontier(const dmg_result* r,uint32_t i,dmg_expand_frontier* out,uint32_t size){
    EXPAND_RESULT(r,out,size);const auto& v=expand_root(*r).expand_frontiers;if(i>=v.size())return DMG_INVALID_ARGUMENT;fill_expand_frontier(v[i],out);return DMG_OK;
}
dmg_status dmg_result_get_expand_frontier_binding(const dmg_result* r,uint32_t i,uint32_t b,dmg_expand_binding* out,uint32_t size){
    EXPAND_RESULT(r,out,size);const auto& v=expand_root(*r).expand_frontiers;if(i>=v.size()||b>=v[i].bindings.size())return DMG_INVALID_ARGUMENT;fill_expand_binding(v[i].bindings[b],*r->query,out);return DMG_OK;
}
dmg_status dmg_result_get_expand_frontier_hop(const dmg_result* r,uint32_t i,uint32_t h,dmg_expand_hop* out,uint32_t size){
    EXPAND_RESULT(r,out,size);const auto& v=expand_root(*r).expand_frontiers;if(i>=v.size()||h>=v[i].prefix.size())return DMG_INVALID_ARGUMENT;fill_expand_hop(v[i].prefix[h],out);return DMG_OK;
}
dmg_status dmg_result_get_expand_frontier_seed_link(const dmg_result* r,uint32_t i,uint32_t k,dmg_relation_link_v2* out,uint32_t size){
    EXPAND_RESULT(r,out,size);const auto& v=expand_root(*r).expand_frontiers;if(i>=v.size()||k>=v[i].seed_links.size())return DMG_INVALID_ARGUMENT;fill_expand_link(v[i].seed_links[k],out);return DMG_OK;
}
dmg_status dmg_result_get_expand_frontier_seed_proof(const dmg_result* r,uint32_t i,uint32_t k,dmg_expand_proof* out,uint32_t size){
    EXPAND_RESULT(r,out,size);const auto& v=expand_root(*r).expand_frontiers;if(i>=v.size()||k>=v[i].seed_proofs.size())return DMG_INVALID_ARGUMENT;fill_expand_proof(v[i].seed_proofs[k],*r->query,out);return DMG_OK;
}
dmg_status dmg_result_get_expand_frontier_witness(const dmg_result* r,uint32_t i,uint32_t which,uint32_t k,dmg_relation_witness_v2* out,uint32_t size){
    EXPAND_RESULT(r,out,size);const auto& v=expand_root(*r).expand_frontiers;if(i>=v.size())return DMG_INVALID_ARGUMENT;const auto* list=expand_witnesses(v[i],which);
    if(!list||k>=list->size())return DMG_INVALID_ARGUMENT;fill_expand_witness((*list)[k],out);return DMG_OK;
}
dmg_status dmg_job_get_expand_frontier(const dmg_job* job,uint32_t i,dmg_expand_frontier* out,uint32_t size){return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(!job->state->query->plan->contains_expand)return DMG_UNSUPPORTED;
    std::lock_guard lock(job->state->mutex);if(!job->state->status.terminal)return DMG_NOT_READY;if(!job->state->committed_expand)return DMG_INVALID_ARGUMENT;
    const auto& v=job->state->committed_expand->expand_frontiers;if(i>=v.size())return DMG_INVALID_ARGUMENT;fill_expand_frontier(v[i],out);return DMG_OK;
});}
dmg_status dmg_job_get_expand_frontier_binding(const dmg_job* job,uint32_t i,uint32_t b,dmg_expand_binding* out,uint32_t size){return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(!job->state->query->plan->contains_expand)return DMG_UNSUPPORTED;
    std::lock_guard lock(job->state->mutex);if(!job->state->status.terminal)return DMG_NOT_READY;if(!job->state->committed_expand)return DMG_INVALID_ARGUMENT;
    const auto& v=job->state->committed_expand->expand_frontiers;if(i>=v.size()||b>=v[i].bindings.size())return DMG_INVALID_ARGUMENT;fill_expand_binding(v[i].bindings[b],*job->state->query,out);return DMG_OK;
});}
dmg_status dmg_job_get_expand_frontier_hop(const dmg_job* job,uint32_t i,uint32_t h,dmg_expand_hop* out,uint32_t size){return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(!job->state->query->plan->contains_expand)return DMG_UNSUPPORTED;
    std::lock_guard lock(job->state->mutex);if(!job->state->status.terminal)return DMG_NOT_READY;if(!job->state->committed_expand)return DMG_INVALID_ARGUMENT;
    const auto& v=job->state->committed_expand->expand_frontiers;if(i>=v.size()||h>=v[i].prefix.size())return DMG_INVALID_ARGUMENT;fill_expand_hop(v[i].prefix[h],out);return DMG_OK;
});}
dmg_status dmg_job_get_expand_frontier_seed_link(const dmg_job* job,uint32_t i,uint32_t k,dmg_relation_link_v2* out,uint32_t size){return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(!job->state->query->plan->contains_expand)return DMG_UNSUPPORTED;
    std::lock_guard lock(job->state->mutex);if(!job->state->status.terminal)return DMG_NOT_READY;if(!job->state->committed_expand)return DMG_INVALID_ARGUMENT;
    const auto& v=job->state->committed_expand->expand_frontiers;if(i>=v.size()||k>=v[i].seed_links.size())return DMG_INVALID_ARGUMENT;fill_expand_link(v[i].seed_links[k],out);return DMG_OK;
});}
dmg_status dmg_job_get_expand_frontier_seed_proof(const dmg_job* job,uint32_t i,uint32_t k,dmg_expand_proof* out,uint32_t size){return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(!job->state->query->plan->contains_expand)return DMG_UNSUPPORTED;
    std::lock_guard lock(job->state->mutex);if(!job->state->status.terminal)return DMG_NOT_READY;if(!job->state->committed_expand)return DMG_INVALID_ARGUMENT;
    const auto& v=job->state->committed_expand->expand_frontiers;if(i>=v.size()||k>=v[i].seed_proofs.size())return DMG_INVALID_ARGUMENT;fill_expand_proof(v[i].seed_proofs[k],*job->state->query,out);return DMG_OK;
});}
dmg_status dmg_job_get_expand_frontier_witness(const dmg_job* job,uint32_t i,uint32_t which,uint32_t k,dmg_relation_witness_v2* out,uint32_t size){return guard([&]()->dmg_status{
    if(!job||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(!job->state->query->plan->contains_expand)return DMG_UNSUPPORTED;
    std::lock_guard lock(job->state->mutex);if(!job->state->status.terminal)return DMG_NOT_READY;if(!job->state->committed_expand)return DMG_INVALID_ARGUMENT;
    const auto& v=job->state->committed_expand->expand_frontiers;if(i>=v.size())return DMG_INVALID_ARGUMENT;const auto* list=expand_witnesses(v[i],which);
    if(!list||k>=list->size())return DMG_INVALID_ARGUMENT;fill_expand_witness((*list)[k],out);return DMG_OK;
});}
#undef EXPAND_RESULT
#include "query_explain.inc"
}
