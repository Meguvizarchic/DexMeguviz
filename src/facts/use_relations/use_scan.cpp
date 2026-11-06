#include "use_scan.hpp"
#include "facts/method_facts.hpp"
#include "cache/method_provider.hpp"
#include <algorithm>
#include <limits>

namespace dexmeguviz::facts {
namespace {
using Error=UseScanError;
void check_cancel(UseScanCancel cancel){
    if(cancel.requested&&cancel.requested(cancel.context))throw Error(Error::Code::cancelled,"use scan cancelled");
}
uint32_t demand(UseKind kind){
    switch(kind){
    case UseKind::string_use:return instructions::Demand::strings;
    case UseKind::invoke_site:return instructions::Demand::invokes;
    case UseKind::field_use:return instructions::Demand::fields;
    case UseKind::type_use:return instructions::Demand::type_uses;
    }
    throw Error(Error::Code::unsupported,"unsupported use kind");
}
TargetDomain invoke_domain(instructions::ReferenceKind kind){
    switch(kind){
    case instructions::ReferenceKind::method:return TargetDomain::method_ref;
    case instructions::ReferenceKind::method_and_proto:return TargetDomain::method_and_proto;
    case instructions::ReferenceKind::call_site:return TargetDomain::call_site;
    }
    throw Error(Error::Code::unsupported,"unsupported invoke reference domain");
}
uint64_t sum(uint64_t value,uint64_t increment){
    if(increment>std::numeric_limits<uint64_t>::max()-value)throw Error(Error::Code::budget,"use scan counter overflow");
    return value+increment;
}
uint64_t available(const UseScanProgress& progress,UseScanLimits limits,UseScanHooks hooks){
    if(progress.work_units>limits.max_work)return 0;
    const auto local=limits.max_work-progress.work_units;
    return hooks.remaining?std::min(local,hooks.remaining(hooks.context)):local;
}
void charge(UseScanProgress& progress,UseScanLimits limits,UseScanHooks hooks,uint64_t amount){
    if(progress.work_units>limits.max_work||amount>limits.max_work-progress.work_units)
        throw Error(Error::Code::budget,"use scan work limit exceeded");
    if(hooks.remaining&&amount>hooks.remaining(hooks.context))throw Error(Error::Code::budget,"shared query work limit exceeded");
    progress.work_units+=amount;
}
}

UseScanResult collect_uses(std::span<const uint8_t> bytes,const Facts& metadata,
    uint32_t source_index,UseKind kind,UseScanProgress& progress,
    std::pmr::memory_resource* resource,UseScanLimits limits,UseScanCancel cancel,UseScanHooks hooks,cache::MethodProvider* provider){
    progress={};
    if(!resource||!limits.max_work||!limits.max_records)throw Error(Error::Code::invalid,"use scan resource and limits must be nonzero");
    if((hooks.remaining==nullptr)!=(hooks.method_complete==nullptr) || (hooks.discard_after_callback&&(!hooks.method_complete||kind!=UseKind::type_use)))throw Error(Error::Code::invalid,"use scan hooks must be paired and discard limited to type uses");
    const auto mask=demand(kind);
    if(metadata.methods.size()>std::numeric_limits<uint32_t>::max())throw Error(Error::Code::budget,"method directory exceeds progress counter range");
    const auto total=static_cast<uint32_t>(metadata.methods.size());
    progress.total_methods=total;
    check_cancel(cancel);
    UseScanResult result(resource);
    for(uint32_t ordinal=0;ordinal<total;++ordinal){
        check_cancel(cancel);
        charge(progress,limits,hooks,1);
        ++progress.attempted_methods;
        const auto& method=metadata.methods[ordinal];
        const auto collected=cache::collect_method(provider,bytes,metadata,ordinal,mask,resource,
            cancel.requested,cancel.context,available(progress,limits,hooks));
        if(collected.has_body&&!collected.instruction_checked)
            throw Error(Error::Code::invalid,"requested method facts were not checked");
        charge(progress,limits,hooks,collected.validation_work);
        size_t count=0;
        switch(kind){
        case UseKind::string_use:count=collected.string_uses.size();break;
        case UseKind::invoke_site:count=collected.invoke_sites.size();break;
        case UseKind::field_use:count=collected.field_uses.size();break;
        case UseKind::type_use:count=collected.type_uses.size();break;
        default:throw Error(Error::Code::unsupported,"unsupported use kind");
        }
        if(result.rows.size()>limits.max_records||count>size_t(limits.max_records)-result.rows.size())
            throw Error(Error::Code::budget,"use scan record limit exceeded");
        if(progress.work_units>limits.max_work||count>limits.max_work-progress.work_units)
            throw Error(Error::Code::budget,"use scan work limit exceeded");
        if(hooks.remaining&&count>hooks.remaining(hooks.context))throw Error(Error::Code::budget,"shared query work limit exceeded");
        const auto emitted=sum(progress.emitted_events,static_cast<uint64_t>(count));
        const auto units=sum(progress.code_units,collected.decoded_code_units);
        const auto validation=sum(progress.validation_work,collected.validation_work);
        const auto start=result.rows.size();
        auto append=[&](uint32_t pc,uint8_t opcode,uint32_t target,uint32_t extra,TargetDomain domain){
            check_cancel(cancel);
            result.rows.push_back({{source_index,ordinal,pc,kind},method.method_index,method.code_offset,target,extra,opcode,domain});
            charge(progress,limits,hooks,1);
        };
        switch(kind){
        case UseKind::string_use:
            for(const auto& use:collected.string_uses)append(use.pc,use.opcode,use.string_index,UINT32_MAX,TargetDomain::string_value);
            break;
        case UseKind::invoke_site:
            for(const auto& use:collected.invoke_sites)append(use.pc,use.opcode,use.index,use.extra_proto,invoke_domain(use.reference_kind));
            break;
        case UseKind::field_use:
            for(const auto& use:collected.field_uses)append(use.pc,use.opcode,use.field_index,UINT32_MAX,TargetDomain::field_ref);
            break;
        case UseKind::type_use:
            for(const auto& use:collected.type_uses)append(use.pc,use.opcode,use.type_index,UINT32_MAX,TargetDomain::type_ref);
            break;
        default:throw Error(Error::Code::unsupported,"unsupported use kind");
        }
        ++progress.visited_methods;
        if(!collected.has_body)++progress.no_body_methods;
        if(collected.instruction_checked)++progress.decoded_methods;
        progress.emitted_events=emitted;progress.code_units=units;progress.validation_work=validation;
        if(hooks.method_complete)hooks.method_complete(hooks.context,std::span<const UseRecord>(result.rows).subspan(start,count),progress);
        if(hooks.discard_after_callback)result.rows.clear();
    }
    check_cancel(cancel);
    return result;
}
}
