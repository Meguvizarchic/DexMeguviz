#include "runtime.hpp"
#include "format/instructions/decoder.hpp"
#include <optional>

using namespace dexmeguviz;
using namespace dexmeguviz::runtime;

struct dmg_method_facts_v1 {
    std::shared_ptr<EngineState> owner;
    std::shared_ptr<const Dataset> dataset;
    std::atomic<uint32_t> references{1};
    uint32_t source_index, ordinal, requested;
    bool has_body=false, checked=false;
    instructions::DecodeResult decoded;
    EntityData caller;
    std::pmr::vector<std::pmr::vector<uint16_t>> string_values, type_values, extra_prototypes;
    std::pmr::vector<EntityData> field_values;
    std::pmr::vector<std::optional<EntityData>> invoke_values;
    dmg_method_facts_v1(std::shared_ptr<EngineState> engine,std::shared_ptr<const Dataset> data,
                       uint32_t source,uint32_t method,uint32_t mask,const Control& control)
      :owner(std::move(engine)),dataset(std::move(data)),source_index(source),ordinal(method),requested(mask),
       decoded(&owner->result_resource),
       caller(reference::entity({source,dataset->sources[source]->input_index,&dataset->sources[source]->facts,
                                 dataset->sources[source]->view()},query::Relation::method_defs,method),
              &owner->result_resource,control),
       string_values(&owner->result_resource),type_values(&owner->result_resource),extra_prototypes(&owner->result_resource),
       field_values(&owner->result_resource),invoke_values(&owner->result_resource) {}
};
namespace {
struct FactsDelete {void operator()(dmg_method_facts_v1* p)const noexcept{if(p)destroy(p);}};
bool deadline_reached(void* context)noexcept{return std::chrono::steady_clock::now()>=static_cast<const Control*>(context)->deadline;}
void copy_text(std::pmr::vector<uint16_t>& out,std::u16string_view input,const Control& control){
    out.reserve(input.size());for(size_t i=0;i<input.size();++i){if((i&1023)==0)control.check();out.push_back(static_cast<uint16_t>(input[i]));}
}
}
extern "C" {
dmg_status dmg_snapshot_collect_method_facts_v1(dmg_snapshot* snapshot,uint32_t source_index,uint32_t method_ref,
    const dmg_method_facts_options_v1* options,dmg_method_facts_v1** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{
        constexpr uint32_t supported=DMG_METHOD_FACT_STRINGS|DMG_METHOD_FACT_FIELDS|DMG_METHOD_FACT_NUMBERS|
            DMG_METHOD_FACT_INVOKES|DMG_METHOD_FACT_TYPES|DMG_METHOD_FACT_INSTRUCTIONS;
        if(!snapshot||!options||!out||options->struct_size!=sizeof(*options)||options->abi_version!=DMG_ABI_VERSION||options->reserved||
           !options->requested_mask||(options->requested_mask&~supported)||!options->max_records||options->max_records>100000||
           !options->max_work||options->max_work>100000000||options->deadline_after_ms>86400000)return DMG_INVALID_ARGUMENT;
        if(snapshot->closed.load(std::memory_order_acquire))return DMG_CLOSED;admit(snapshot->owner);
        const auto data=snapshot->dataset;if(source_index>=data->sources.size())return DMG_INVALID_ARGUMENT;
        const auto& source=*data->sources[source_index];const auto& meta=source.facts;
        if(method_ref>=meta.method_refs.size())return DMG_INVALID_ARGUMENT;
        const auto ordinal=meta.method_definition_by_ref[method_ref];if(ordinal==UINT32_MAX)return DMG_UNSUPPORTED;
        if(ordinal>=meta.methods.size()||meta.methods[ordinal].method_index!=method_ref)return DMG_INTERNAL_ERROR;
        const auto& method=meta.methods[ordinal];Control control;
        if(options->deadline_after_ms)control.deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(options->deadline_after_ms);
        control.check();std::unique_ptr<dmg_method_facts_v1,FactsDelete> result(
            handle<dmg_method_facts_v1>(snapshot->owner,data,source_index,ordinal,options->requested_mask,control));
        result->has_body=method.code_offset!=0;
        if(result->has_body){
            if(meta.strings.size()>UINT32_MAX||meta.types.size()>UINT32_MAX||meta.field_refs.size()>UINT32_MAX||
               meta.method_refs.size()>UINT32_MAX||meta.prototypes.size()>UINT32_MAX)return DMG_CORRUPT_INPUT;
            instructions::DecodeInput input{source.view(),method.code_offset,meta.dex_version,{
                static_cast<uint32_t>(meta.strings.size()),static_cast<uint32_t>(meta.types.size()),
                static_cast<uint32_t>(meta.field_refs.size()),static_cast<uint32_t>(meta.method_refs.size()),
                static_cast<uint32_t>(meta.prototypes.size()),meta.call_site_count,meta.method_handle_count}};
            input.code_end=method.code_end;input.experimental_041=meta.dex_version==41;
            instructions::DecodeOptions decode;decode.max_validation_work=options->max_work;decode.cancelled=deadline_reached;decode.cancel_context=&control;
            if(options->requested_mask&DMG_METHOD_FACT_STRINGS)decode.demand_mask|=instructions::strings;
            if(options->requested_mask&DMG_METHOD_FACT_FIELDS)decode.demand_mask|=instructions::fields;
            if(options->requested_mask&DMG_METHOD_FACT_NUMBERS)decode.demand_mask|=instructions::numeric;
            if(options->requested_mask&DMG_METHOD_FACT_INVOKES)decode.demand_mask|=instructions::invokes;
            if(options->requested_mask&DMG_METHOD_FACT_TYPES)decode.demand_mask|=instructions::type_uses;
            try{result->decoded=instructions::decode(input,decode,&snapshot->owner->result_resource);}
            catch(const instructions::DecodeError& e){if(e.code==instructions::DecodeCode::cancelled)control.check();throw;}
            result->checked=true;control.check();
            // Decoder needs its instruction index for validation even when the
            // caller did not request opcodes. Release that temporary storage
            // before materializing the other categories.
            if(!(options->requested_mask&DMG_METHOD_FACT_INSTRUCTIONS)){
                std::pmr::vector<instructions::Instruction> unused(&snapshot->owner->result_resource);
                unused.swap(result->decoded.instructions);
            }
        }
        const auto& d=result->decoded;
        const uint64_t rows=uint64_t(d.string_uses.size())+d.field_uses.size()+d.numeric_literals.size()+d.invoke_sites.size()+d.type_uses.size()+
            ((options->requested_mask&DMG_METHOD_FACT_INSTRUCTIONS)?d.instructions.size():0);
        if(rows>options->max_records)throw query::Error(query::ErrorCode::budget,"method facts exceed max_records");
        result->string_values.reserve(d.string_uses.size());
        for(const auto& item:d.string_uses){control.check();result->string_values.emplace_back();copy_text(result->string_values.back(),meta.strings[item.string_index],control);}
        result->type_values.reserve(d.type_uses.size());
        for(const auto& item:d.type_uses){control.check();result->type_values.emplace_back();copy_text(result->type_values.back(),meta.strings[meta.types[item.type_index]],control);}
        const reference::SourceView view{source_index,source.input_index,&meta,source.view()};
        result->field_values.reserve(d.field_uses.size());
        for(const auto& item:d.field_uses){control.check();result->field_values.emplace_back(reference::entity(view,query::Relation::field_refs,item.field_index),&snapshot->owner->result_resource,control,query::project_owner|query::project_name|query::project_type);}
        result->invoke_values.reserve(d.invoke_sites.size());result->extra_prototypes.reserve(d.invoke_sites.size());
        for(const auto& item:d.invoke_sites){control.check();result->extra_prototypes.emplace_back();
            if(item.reference_kind==instructions::ReferenceKind::call_site)result->invoke_values.emplace_back(std::nullopt);
            else result->invoke_values.emplace_back(std::in_place,reference::entity(view,query::Relation::method_refs,item.index),&snapshot->owner->result_resource,control);
            if(item.reference_kind==instructions::ReferenceKind::method_and_proto)copy_text(result->extra_prototypes.back(),meta.prototypes[item.extra_proto].descriptor,control);
        }
        control.check();*out=result.release();return DMG_OK;
    },error);
}
void dmg_method_facts_retain_v1(dmg_method_facts_v1* r){if(r)r->references.fetch_add(1,std::memory_order_relaxed);}
void dmg_method_facts_release_v1(dmg_method_facts_v1* r){if(r&&r->references.fetch_sub(1,std::memory_order_acq_rel)==1)destroy(r);}
dmg_status dmg_method_facts_get_info_v1(const dmg_method_facts_v1* r,dmg_method_facts_info_v1* out,uint32_t size){
    if(!r||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;const auto& d=r->decoded;
    *out={r->source_index,r->ordinal,r->caller.method_index,r->caller.code,r->has_body?1u:0u,r->checked?1u:0u,d.code_units,r->requested,
          static_cast<uint32_t>(d.string_uses.size()),static_cast<uint32_t>(d.field_uses.size()),static_cast<uint32_t>(d.numeric_literals.size()),
          static_cast<uint32_t>(d.invoke_sites.size()),static_cast<uint32_t>(d.type_uses.size()),static_cast<uint32_t>((r->requested&DMG_METHOD_FACT_INSTRUCTIONS)?d.instructions.size():0),
          d.validation_work,r->dataset->snapshot_id.c_str()};return DMG_OK;
}
dmg_status dmg_method_facts_get_caller_v1(const dmg_method_facts_v1* r,dmg_method_row* out,uint32_t size){
    if(!r||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;const auto& c=r->caller;
    *out={c.method_index,c.flags,c.declaration,c.code,c.owner.data(),c.owner.size(),c.name.data(),c.name.size(),c.prototype.data(),c.prototype.size()};return DMG_OK;
}
dmg_status dmg_method_facts_get_source_v1(const dmg_method_facts_v1* r,dmg_source_info* out,uint32_t size){if(!r||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;return fill_source(*r->dataset,r->source_index,out);}
dmg_status dmg_method_facts_get_string_v1(const dmg_method_facts_v1* r,uint32_t i,dmg_method_string_use_v1* out,uint32_t size){
    if(!r||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(!(r->requested&DMG_METHOD_FACT_STRINGS))return DMG_UNSUPPORTED;
    if(i>=r->decoded.string_uses.size())return DMG_INVALID_ARGUMENT;const auto& x=r->decoded.string_uses[i];const auto& value=r->string_values[i];*out={x.pc,x.opcode,x.string_index,value.data(),value.size()};return DMG_OK;
}
dmg_status dmg_method_facts_get_field_v1(const dmg_method_facts_v1* r,uint32_t i,dmg_method_field_use_v1* out,uint32_t size){
    if(!r||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(!(r->requested&DMG_METHOD_FACT_FIELDS))return DMG_UNSUPPORTED;
    if(i>=r->decoded.field_uses.size())return DMG_INVALID_ARGUMENT;const auto& x=r->decoded.field_uses[i];const auto& v=r->field_values[i];
    *out={x.pc,x.opcode,x.field_index,v.owner.data(),v.owner.size(),v.name.data(),v.name.size(),v.type_descriptor.data(),v.type_descriptor.size()};return DMG_OK;
}
dmg_status dmg_method_facts_get_number_v1(const dmg_method_facts_v1* r,uint32_t i,dmg_method_number_v1* out,uint32_t size){
    if(!r||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(!(r->requested&DMG_METHOD_FACT_NUMBERS))return DMG_UNSUPPORTED;
    if(i>=r->decoded.numeric_literals.size())return DMG_INVALID_ARGUMENT;const auto& x=r->decoded.numeric_literals[i];*out={x.pc,x.opcode,x.width_bits,static_cast<uint32_t>(x.kind),x.bits};return DMG_OK;
}
dmg_status dmg_method_facts_get_invoke_v1(const dmg_method_facts_v1* r,uint32_t i,dmg_method_call_row_v1* out,uint32_t size){
    if(!r||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(!(r->requested&DMG_METHOD_FACT_INVOKES))return DMG_UNSUPPORTED;
    if(i>=r->decoded.invoke_sites.size())return DMG_INVALID_ARGUMENT;const auto& x=r->decoded.invoke_sites[i];dmg_method_call_row_v1 row{};
    row.dex_pc=x.pc;row.opcode=x.opcode;row.target_index=x.index;row.extra_proto=x.extra_proto;
    row.target_domain=x.reference_kind==instructions::ReferenceKind::method?DMG_TARGET_METHOD_REF:x.reference_kind==instructions::ReferenceKind::method_and_proto?DMG_TARGET_METHOD_AND_PROTO:DMG_TARGET_CALL_SITE;
    if(const auto& v=r->invoke_values[i]){row.owner=v->owner.data();row.owner_length=v->owner.size();row.name=v->name.data();row.name_length=v->name.size();row.prototype=v->prototype.data();row.prototype_length=v->prototype.size();}
    const auto& extra=r->extra_prototypes[i];row.extra_prototype=extra.data();row.extra_prototype_length=extra.size();*out=row;return DMG_OK;
}
dmg_status dmg_method_facts_get_type_v1(const dmg_method_facts_v1* r,uint32_t i,dmg_method_type_use_v1* out,uint32_t size){
    if(!r||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(!(r->requested&DMG_METHOD_FACT_TYPES))return DMG_UNSUPPORTED;
    if(i>=r->decoded.type_uses.size())return DMG_INVALID_ARGUMENT;const auto& x=r->decoded.type_uses[i];const auto& v=r->type_values[i];*out={x.pc,x.opcode,x.type_index,v.data(),v.size()};return DMG_OK;
}
dmg_status dmg_method_facts_get_instruction_v1(const dmg_method_facts_v1* r,uint32_t i,dmg_method_instruction_v1* out,uint32_t size){
    if(!r||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;if(!(r->requested&DMG_METHOD_FACT_INSTRUCTIONS))return DMG_UNSUPPORTED;
    if(i>=r->decoded.instructions.size())return DMG_INVALID_ARGUMENT;const auto& x=r->decoded.instructions[i];*out={x.pc,x.width,x.opcode,static_cast<uint32_t>(x.payload_kind)};return DMG_OK;
}
}
