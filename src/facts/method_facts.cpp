#include "method_facts.hpp"
#include <limits>
#include <utility>

namespace dexmeguviz::facts {
static MethodFacts collect_method_impl(std::span<const uint8_t> dex, const Facts& metadata,
    uint32_t method_ordinal, uint32_t demand_mask, std::pmr::memory_resource* resource,
    bool (*cancelled)(void*) noexcept, void* cancel_context, uint64_t max_validation_work,
    std::pmr::vector<instructions::Instruction>* opcode_output) {
    if((demand_mask & instructions::opcode_list) && !opcode_output)
        throw instructions::DecodeError(instructions::DecodeCode::unsupported,0,0,"opcode list requires explicit output");
    if(opcode_output && (!(demand_mask & instructions::opcode_list)||!opcode_output->empty()||opcode_output->get_allocator().resource()!=resource))
        throw std::invalid_argument("invalid opcode output resource or state");
    if (demand_mask & ~supported_demands)
        throw instructions::DecodeError(instructions::DecodeCode::unsupported, 0, 0, "unsupported method-fact demand");
    if (method_ordinal >= metadata.methods.size()) throw std::out_of_range("method ordinal exceeds definition directory");
    const auto& method = metadata.methods[method_ordinal];
    MethodFacts result(resource);
    result.method_index = method.method_index;
    result.code_offset = method.code_offset;
    result.requested_mask = demand_mask;
    result.has_body = method.code_offset != 0;
    if (!result.has_body || demand_mask == 0) return result;
    if (metadata.strings.size() > UINT32_MAX || metadata.types.size() > UINT32_MAX ||
        metadata.field_refs.size() > UINT32_MAX || metadata.method_refs.size() > UINT32_MAX || metadata.prototypes.size() > UINT32_MAX)
        throw instructions::DecodeError(instructions::DecodeCode::corrupt, method.code_offset, 0, "metadata directory exceeds local index width");
    instructions::DecodeInput input{dex, method.code_offset, metadata.dex_version, {
        static_cast<uint32_t>(metadata.strings.size()), static_cast<uint32_t>(metadata.types.size()),
        static_cast<uint32_t>(metadata.field_refs.size()), static_cast<uint32_t>(metadata.method_refs.size()),
        static_cast<uint32_t>(metadata.prototypes.size()), metadata.call_site_count, metadata.method_handle_count}};
    instructions::DecodeOptions options;
    input.code_end = method.code_end;
    input.experimental_041=metadata.dex_version==41;
    options.demand_mask = demand_mask;
    options.cancelled = cancelled;
    options.cancel_context = cancel_context;
    options.max_validation_work = max_validation_work;
    auto decoded = instructions::decode(input, options, resource);
    result.string_uses = std::move(decoded.string_uses);
    result.invoke_sites = std::move(decoded.invoke_sites);
    result.field_uses = std::move(decoded.field_uses);
    result.numeric_literals = std::move(decoded.numeric_literals);
    result.array_elements = std::move(decoded.array_elements);
    result.switch_cases = std::move(decoded.switch_cases);
    result.branches = std::move(decoded.branches);
    result.method_constants = std::move(decoded.method_constants);
    result.type_uses = std::move(decoded.type_uses);
    if(opcode_output)*opcode_output=std::move(decoded.instructions);
    result.decoded_code_units = decoded.code_units;
    result.validation_work = decoded.validation_work;
    result.instruction_checked = true;
    return result;
}
MethodFacts collect_method(std::span<const uint8_t> dex,const Facts& metadata,uint32_t method_ordinal,
    uint32_t demand_mask,std::pmr::memory_resource* resource,bool (*cancelled)(void*) noexcept,
    void* cancel_context,uint64_t max_validation_work){
    return collect_method_impl(dex,metadata,method_ordinal,demand_mask,resource,cancelled,cancel_context,max_validation_work,nullptr);
}
MethodFacts collect_method_with_instructions(std::span<const uint8_t> dex,const Facts& metadata,uint32_t method_ordinal,
    uint32_t demand_mask,std::pmr::vector<instructions::Instruction>& output,std::pmr::memory_resource* resource,
    bool (*cancelled)(void*) noexcept,void* cancel_context,uint64_t max_validation_work){
    return collect_method_impl(dex,metadata,method_ordinal,demand_mask,resource,cancelled,cancel_context,max_validation_work,&output);
}
}
