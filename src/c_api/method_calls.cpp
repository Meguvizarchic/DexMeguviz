#include "runtime.hpp"
#include "facts/method_facts.hpp"

using namespace dexmeguviz;
using namespace dexmeguviz::runtime;
namespace dexmeguviz::runtime {dmg_status fill_source(const Dataset&,uint32_t,dmg_source_info*)noexcept;}

struct dmg_method_calls_v1 {
    std::shared_ptr<EngineState> owner;
    std::shared_ptr<const Dataset> dataset;
    std::atomic<uint32_t> references{1};
    uint32_t source_index,ordinal;
    facts::MethodFacts facts;
    EntityData caller;
    std::pmr::vector<std::optional<EntityData>> targets;
    std::pmr::vector<std::pmr::vector<uint16_t>> extra_prototypes;
    dmg_method_calls_v1(std::shared_ptr<EngineState> engine,std::shared_ptr<const Dataset> data,uint32_t source,uint32_t method,const Control& control)
        :owner(std::move(engine)),dataset(std::move(data)),source_index(source),ordinal(method),facts(&owner->result_resource),
         caller(reference::entity({source,dataset->sources[source]->input_index,&dataset->sources[source]->facts,dataset->sources[source]->view()},query::Relation::method_defs,method),&owner->result_resource,control),
         targets(&owner->result_resource),extra_prototypes(&owner->result_resource){}
};
namespace {
struct CallsDelete {void operator()(dmg_method_calls_v1* p)const noexcept{if(p)destroy(p);}};
bool deadline(void* context)noexcept{return std::chrono::steady_clock::now()>=static_cast<const Control*>(context)->deadline;}
}
extern "C" {
dmg_status dmg_snapshot_collect_method_calls_v1(dmg_snapshot* snapshot,uint32_t source_index,uint32_t method_ref,
    const dmg_method_calls_options_v1* options,dmg_method_calls_v1** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{
        if(!snapshot||!options||!out||options->struct_size!=sizeof(*options)||options->abi_version!=DMG_ABI_VERSION||options->reserved||
           !options->max_records||options->max_records>100000||!options->max_work||options->max_work>100000000||options->deadline_after_ms>86400000)return DMG_INVALID_ARGUMENT;
        if(snapshot->closed.load(std::memory_order_acquire))return DMG_CLOSED;admit(snapshot->owner);
        const auto data=snapshot->dataset;if(source_index>=data->sources.size())return DMG_INVALID_ARGUMENT;const auto& source=*data->sources[source_index];const auto& meta=source.facts;
        if(method_ref>=meta.method_refs.size())return DMG_INVALID_ARGUMENT;const auto ordinal=meta.method_definition_by_ref[method_ref];
        if(ordinal==UINT32_MAX)return DMG_UNSUPPORTED;
        if(ordinal>=meta.methods.size()||meta.methods[ordinal].method_index!=method_ref)return DMG_INTERNAL_ERROR;
        Control control;if(options->deadline_after_ms)control.deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(options->deadline_after_ms);control.check();
        std::unique_ptr<dmg_method_calls_v1,CallsDelete> result(handle<dmg_method_calls_v1>(snapshot->owner,data,source_index,ordinal,control));
        try{result->facts=facts::collect_method(source.view(),meta,ordinal,instructions::invokes,&snapshot->owner->result_resource,deadline,&control,options->max_work);}
        catch(const instructions::DecodeError& e){if(e.code==instructions::DecodeCode::cancelled)control.check();throw;}
        control.check();if(result->facts.invoke_sites.size()>options->max_records)throw query::Error(query::ErrorCode::budget,"method call result exceeds max_records");
        result->targets.reserve(result->facts.invoke_sites.size());result->extra_prototypes.reserve(result->facts.invoke_sites.size());
        for(const auto& call:result->facts.invoke_sites){control.check();result->extra_prototypes.emplace_back();
            if(call.reference_kind==instructions::ReferenceKind::call_site)result->targets.emplace_back(std::nullopt);
            else result->targets.emplace_back(std::in_place,reference::entity({source_index,source.input_index,&meta,source.view()},query::Relation::method_refs,call.index),&snapshot->owner->result_resource,control);
            if(call.reference_kind==instructions::ReferenceKind::method_and_proto){const auto& text=meta.prototypes[call.extra_proto].descriptor;auto& copy=result->extra_prototypes.back();copy.reserve(text.size());for(size_t i=0;i<text.size();++i){if((i&1023)==0)control.check();copy.push_back(static_cast<uint16_t>(text[i]));}}
        }
        control.check();*out=result.release();return DMG_OK;
    },error);
}
void dmg_method_calls_retain_v1(dmg_method_calls_v1* result){if(result)result->references.fetch_add(1,std::memory_order_relaxed);}
void dmg_method_calls_release_v1(dmg_method_calls_v1* result){if(result&&result->references.fetch_sub(1,std::memory_order_acq_rel)==1)destroy(result);}
dmg_status dmg_method_calls_get_info_v1(const dmg_method_calls_v1* result,dmg_method_calls_info_v1* out,uint32_t size){
    if(!result||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;const auto& f=result->facts;
    *out={result->source_index,result->ordinal,f.method_index,f.code_offset,f.has_body?1u:0u,f.instruction_checked?1u:0u,f.decoded_code_units,static_cast<uint32_t>(f.invoke_sites.size()),f.validation_work,result->dataset->snapshot_id.c_str()};return DMG_OK;
}
dmg_status dmg_method_calls_get_caller_v1(const dmg_method_calls_v1* result,dmg_method_row* out,uint32_t size){
    if(!result||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;const auto& c=result->caller;
    *out={c.method_index,c.flags,c.declaration,c.code,c.owner.data(),c.owner.size(),c.name.data(),c.name.size(),c.prototype.data(),c.prototype.size()};return DMG_OK;
}
dmg_status dmg_method_calls_get_source_v1(const dmg_method_calls_v1* result,dmg_source_info* out,uint32_t size){
    if(!result||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;return fill_source(*result->dataset,result->source_index,out);
}
dmg_status dmg_method_calls_get_row_v1(const dmg_method_calls_v1* result,uint32_t index,dmg_method_call_row_v1* out,uint32_t size){
    if(!result||!out||size!=sizeof(*out)||index>=result->facts.invoke_sites.size())return DMG_INVALID_ARGUMENT;
    const auto& call=result->facts.invoke_sites[index];dmg_method_call_row_v1 row{};row.dex_pc=call.pc;row.opcode=call.opcode;row.target_index=call.index;row.extra_proto=call.extra_proto;
    row.target_domain=call.reference_kind==instructions::ReferenceKind::method?DMG_TARGET_METHOD_REF:call.reference_kind==instructions::ReferenceKind::method_and_proto?DMG_TARGET_METHOD_AND_PROTO:DMG_TARGET_CALL_SITE;
    if(const auto& target=result->targets[index]){row.owner=target->owner.data();row.owner_length=target->owner.size();row.name=target->name.data();row.name_length=target->name.size();row.prototype=target->prototype.data();row.prototype_length=target->prototype.size();}
    const auto& extra=result->extra_prototypes[index];row.extra_prototype=extra.data();row.extra_prototype_length=extra.size();*out=row;return DMG_OK;
}
}
