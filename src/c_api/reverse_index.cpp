#include "runtime.hpp"
#include <limits>
#include <cstddef>
#include <type_traits>
using namespace dexmeguviz;
using namespace dexmeguviz::runtime;
namespace {
thread_local bool inside_reverse_callback=false;
struct CancelContext {dmg_snapshot* snapshot;const dmg_reverse_options_v1* options;};
bool is_closed(const dmg_snapshot* s){
    if(s->closed.load(std::memory_order_acquire))return true;
    std::lock_guard lock(s->owner->admission);return s->owner->closed;
}
bool cancelled(void* opaque)noexcept{
    auto& c=*static_cast<CancelContext*>(opaque);
    try{
        if(!c.options->cancelled)return false;
        struct Guard {Guard(){inside_reverse_callback=true;}~Guard(){inside_reverse_callback=false;}} guard;
        return c.options->cancelled(c.options->cancel_context)!=0;
    }catch(...){return true;}
}
static_assert(std::is_standard_layout_v<facts::ReverseEvent> && std::is_standard_layout_v<dmg_reverse_event_v1>);
static_assert(sizeof(facts::ReverseEvent)==sizeof(dmg_reverse_event_v1));
#define SAME_OFFSET(name) static_assert(offsetof(facts::ReverseEvent,name)==offsetof(dmg_reverse_event_v1,name))
SAME_OFFSET(source_index);SAME_OFFSET(use_kind);SAME_OFFSET(caller_ordinal);SAME_OFFSET(caller_method_ref);SAME_OFFSET(dex_pc);
SAME_OFFSET(opcode);SAME_OFFSET(code_offset);SAME_OFFSET(target_domain);SAME_OFFSET(target_index);SAME_OFFSET(extra_proto);
#undef SAME_OFFSET
bool valid_key(const Facts& f,uint32_t kind,uint32_t domain,uint32_t target,uint32_t extra){
    switch(kind){
    case DMG_REVERSE_STRING_USE_V1:return domain==DMG_TARGET_STRING_VALUE&&target<f.string_count&&extra==UINT32_MAX;
    case DMG_REVERSE_FIELD_USE_V1:return domain==DMG_TARGET_FIELD_REF&&target<f.field_refs.size()&&extra==UINT32_MAX;
    case DMG_REVERSE_INVOKE_SITE_V1:
        if(domain==DMG_TARGET_METHOD_REF)return target<f.method_refs.size()&&extra==UINT32_MAX;
        if(domain==DMG_TARGET_METHOD_AND_PROTO)return target<f.method_refs.size()&&extra<f.prototypes.size();
        if(domain==DMG_TARGET_CALL_SITE)return target<f.call_site_count&&extra==UINT32_MAX;
        return false;
    default:return false;
    }
}
}
extern "C" {
dmg_status dmg_snapshot_reverse_profile_v1(const dmg_snapshot* snapshot,dmg_reverse_profile_v1* out,uint32_t out_size){
    return guard([&]()->dmg_status{
        if(!snapshot||!out||out_size!=sizeof(*out)||inside_reverse_callback)return DMG_INVALID_ARGUMENT;
        const auto p=snapshot->dataset->reverse.profile();
        *out={p.attempts,p.builds,p.failures,p.reuses,p.published,p.records};return DMG_OK;
    });
}
dmg_status dmg_snapshot_reverse_count_v1(dmg_snapshot* snapshot,uint32_t source_index,uint32_t use_kind,uint32_t target_domain,
    uint32_t target_index,uint32_t extra_proto,const dmg_reverse_options_v1* options,uint64_t* out_count,dmg_error* error){
    return guard([&]()->dmg_status{
        if(!snapshot||!options||!out_count||inside_reverse_callback||options->struct_size!=sizeof(*options)||
           options->abi_version!=DMG_ABI_VERSION||options->reserved||source_index>=snapshot->dataset->sources.size())return DMG_INVALID_ARGUMENT;
        const auto captured=*options;
        if(is_closed(snapshot))return DMG_CLOSED;
        const auto& source=*snapshot->dataset->sources[source_index];
        if(!valid_key(source.facts,use_kind,target_domain,target_index,extra_proto))return DMG_INVALID_ARGUMENT;
        CancelContext context{snapshot,&captured};facts::UseScanCancel cancel{cancelled,&context};
        try{
            const auto result=snapshot->dataset->reverse.lookup(source.view(),source.facts,source_index,static_cast<facts::UseKind>(use_kind),
                {static_cast<facts::TargetDomain>(target_domain),target_index,extra_proto},
                {captured.max_work,captured.max_index_bytes,captured.max_records},cancel);
            *out_count=result;return DMG_OK;
        }catch(...){throw;}
    },error);
}
dmg_status dmg_snapshot_reverse_page_v1(dmg_snapshot* snapshot,uint32_t source_index,uint32_t use_kind,uint32_t target_domain,
    uint32_t target_index,uint32_t extra_proto,const dmg_reverse_options_v1* options,uint64_t offset,
    dmg_reverse_event_v1* out_events,uint32_t capacity,uint32_t* out_count,uint64_t* out_total,dmg_error* error){
    return guard([&]()->dmg_status{
        if(!snapshot||!options||!out_count||!out_total||(capacity&&!out_events)||capacity>4096||inside_reverse_callback||
           options->struct_size!=sizeof(*options)||options->abi_version!=DMG_ABI_VERSION||options->reserved||
           source_index>=snapshot->dataset->sources.size())return DMG_INVALID_ARGUMENT;
        const auto captured=*options;
        if(is_closed(snapshot))return DMG_CLOSED;
        const auto& source=*snapshot->dataset->sources[source_index];
        if(!valid_key(source.facts,use_kind,target_domain,target_index,extra_proto))return DMG_INVALID_ARGUMENT;
        CancelContext context{snapshot,&captured};facts::UseScanCancel cancel{cancelled,&context};
        auto page=snapshot->dataset->reverse.page(source.view(),source.facts,source_index,static_cast<facts::UseKind>(use_kind),
            {static_cast<facts::TargetDomain>(target_domain),target_index,extra_proto},offset,capacity,
            {captured.max_work,captured.max_index_bytes,captured.max_records},cancel);
        if(!page.rows.empty())std::memcpy(out_events,page.rows.data(),page.rows.size()*sizeof(dmg_reverse_event_v1));
        *out_count=static_cast<uint32_t>(page.rows.size());*out_total=page.total;return DMG_OK;
    },error);
}
}
