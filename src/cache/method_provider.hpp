#pragma once
#include "facts/method_facts.hpp"

namespace dexmeguviz::cache {
// Explicit internal injection point. Default evaluator construction has none.
// Implementations must return owned facts in memory, or run the real collector;
// failures/cancellation may never become a successful empty fact set.
class MethodProvider {
public:
    virtual ~MethodProvider()=default;
    virtual facts::MethodFacts collect(std::span<const uint8_t> bytes,const Facts& metadata,
        uint32_t method,uint32_t demand,std::pmr::memory_resource* memory,
        bool(*cancelled)(void*)noexcept,void* context,uint64_t remaining)=0;
};
// Explicit provider calls return the same method/demand and allocations owned
// by this request. A provider contract failure is an error, never empty facts.
inline facts::MethodFacts collect_method(MethodProvider* provider,std::span<const uint8_t> bytes,const Facts& metadata,
    uint32_t ordinal,uint32_t mask,std::pmr::memory_resource* memory,
    bool(*cancelled)(void*)noexcept,void* context,uint64_t remaining){
    if(mask&instructions::opcode_list)throw instructions::DecodeError(instructions::DecodeCode::unsupported,0,0,"opcode output is not provided by method cache");
    if(!provider)return facts::collect_method(bytes,metadata,ordinal,mask,memory,cancelled,context,remaining);
    if(!memory||ordinal>=metadata.methods.size()||(mask&~facts::supported_demands))
        throw instructions::DecodeError(instructions::DecodeCode::corrupt,0,0,"invalid method provider request");
    auto result=provider->collect(bytes,metadata,ordinal,mask,memory,cancelled,context,remaining);
    if(cancelled&&cancelled(context))throw instructions::DecodeError(instructions::DecodeCode::cancelled,0,0,"method provider cancelled");
    const auto& method=metadata.methods[ordinal];
    if(result.method_index!=method.method_index||result.code_offset!=method.code_offset||result.requested_mask!=mask||
       result.has_body!=(method.code_offset!=0)||result.instruction_checked!=(mask!=0&&method.code_offset!=0))
        throw instructions::DecodeError(instructions::DecodeCode::corrupt,method.code_offset,0,"method provider identity or coverage mismatch");
    for(const auto* resource:{result.string_uses.get_allocator().resource(),result.invoke_sites.get_allocator().resource(),result.field_uses.get_allocator().resource(),
        result.numeric_literals.get_allocator().resource(),result.array_elements.get_allocator().resource(),result.switch_cases.get_allocator().resource(),
        result.branches.get_allocator().resource(),result.method_constants.get_allocator().resource(),result.type_uses.get_allocator().resource()})
        if(resource!=memory)throw instructions::DecodeError(instructions::DecodeCode::corrupt,method.code_offset,0,"method provider returned foreign allocations");
    if(result.validation_work>remaining)throw instructions::DecodeError(instructions::DecodeCode::budget,method.code_offset,0,"method provider exceeds remaining work");
    return result;
}
}
