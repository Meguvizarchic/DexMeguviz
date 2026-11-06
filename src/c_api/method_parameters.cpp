#include "dexmeguviz/method_parameters_v1.h"
#include "runtime.hpp"
#include "format/checked_leb128.hpp"
#include <limits>

using namespace dexmeguviz;
using namespace dexmeguviz::runtime;

struct ParameterValue {
    uint32_t type_index=0,name_state=DMG_PARAMETER_NAME_UNKNOWN,name_index=UINT32_MAX;
    std::pmr::vector<uint16_t> type,name;
    explicit ParameterValue(std::pmr::memory_resource* memory):type(memory),name(memory){}
};
struct dmg_method_parameters_v1 {
    std::shared_ptr<EngineState> owner;
    std::shared_ptr<const Dataset> dataset;
    std::atomic<uint32_t> references{1};
    uint32_t source_index,method_ref,ordinal=UINT32_MAX,debug_state=DMG_PARAMETER_DEBUG_NO_DEFINITION,debug_offset=0;
    uint64_t work=0;
    std::pmr::vector<uint16_t> return_type;
    std::pmr::vector<ParameterValue> parameters;
    dmg_method_parameters_v1(std::shared_ptr<EngineState> engine,std::shared_ptr<const Dataset> data,uint32_t source,uint32_t ref)
        :owner(std::move(engine)),dataset(std::move(data)),source_index(source),method_ref(ref),return_type(&owner->result_resource),parameters(&owner->result_resource){}
};
namespace {
struct ParametersDelete {void operator()(dmg_method_parameters_v1* p)const noexcept{if(p)destroy(p);}};
struct Work {
    const Control& control;uint64_t limit,used=0,text_limit,text_used=0;
    void charge(uint64_t n){control.check();if(n>limit-used)throw BudgetExceeded();used+=n;}
    void copy(std::pmr::vector<uint16_t>& out,std::u16string_view value){
        if(value.size()>text_limit-text_used)throw BudgetExceeded();text_used+=value.size();charge(value.size());
        out.reserve(value.size());for(size_t i=0;i<value.size();++i){if((i&1023)==0)control.check();out.push_back(static_cast<uint16_t>(value[i]));}
    }
};
uint32_t word32(std::span<const uint8_t> bytes,uint64_t pos,Work& work){
    work.charge(4);if(pos>bytes.size()||bytes.size()-pos<4)throw ReadError(ReadCode::corrupt,pos,"truncated code debug offset");
    return uint32_t(bytes[pos])|(uint32_t(bytes[pos+1])<<8)|(uint32_t(bytes[pos+2])<<16)|(uint32_t(bytes[pos+3])<<24);
}
uint32_t read_uleb(std::span<const uint8_t> bytes,uint64_t& at,Work& work){
    work.control.check();const auto before=at;const auto value=detail::read_uleb32(bytes,at,bytes.size());work.charge(at-before);return value;
}
std::u16string_view type_descriptor(const Facts& facts,uint32_t type){
    if(type>=facts.types.size()||facts.types[type]>=facts.strings.size())throw ReadError(ReadCode::corrupt,0,"parameter type index out of range");
    return facts.strings[facts.types[type]];
}
}
extern "C" {
dmg_status dmg_snapshot_get_method_parameters_v1(dmg_snapshot* snapshot,uint32_t source_index,uint32_t method_ref,
    const dmg_method_parameters_options_v1* options,dmg_method_parameters_v1** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{
        if(!snapshot||!options||!out||options->struct_size!=sizeof(*options)||options->abi_version!=DMG_ABI_VERSION||options->reserved||
           !options->max_parameters||options->max_parameters>65536||!options->max_text_units||options->max_text_units>1048576||
           !options->max_work||options->max_work>100000000||options->deadline_after_ms>86400000)return DMG_INVALID_ARGUMENT;
        if(snapshot->closed.load(std::memory_order_acquire))return DMG_CLOSED;admit(snapshot->owner);
        const auto dataset=snapshot->dataset;if(source_index>=dataset->sources.size())return DMG_INVALID_ARGUMENT;
        const auto& source=*dataset->sources[source_index];const auto& facts=source.facts;
        if(facts.dex_version!=35&&facts.dex_version!=37&&facts.dex_version!=38&&facts.dex_version!=39&&facts.dex_version!=40)return DMG_UNSUPPORTED;
        if(method_ref>=facts.method_refs.size()||method_ref>=facts.method_definition_by_ref.size())return DMG_INVALID_ARGUMENT;
        const auto proto_index=facts.method_refs[method_ref].type;
        if(proto_index>=facts.prototypes.size())return DMG_CORRUPT_INPUT;
        const auto& prototype=facts.prototypes[proto_index];if(prototype.parameters.size()>options->max_parameters)throw BudgetExceeded();
        Control control;if(options->deadline_after_ms)control.deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(options->deadline_after_ms);
        Work work{control,options->max_work,0,options->max_text_units,0};work.charge(1);
        std::unique_ptr<dmg_method_parameters_v1,ParametersDelete> result(handle<dmg_method_parameters_v1>(snapshot->owner,dataset,source_index,method_ref));
        work.copy(result->return_type,type_descriptor(facts,prototype.return_type));
        result->parameters.reserve(prototype.parameters.size());
        for(const auto index:prototype.parameters){work.charge(1);result->parameters.emplace_back(&snapshot->owner->result_resource);auto& parameter=result->parameters.back();parameter.type_index=index;work.copy(parameter.type,type_descriptor(facts,index));}
        const auto ordinal=facts.method_definition_by_ref[method_ref];result->ordinal=ordinal;
        if(ordinal!=UINT32_MAX){
            if(ordinal>=facts.methods.size()||facts.methods[ordinal].method_index!=method_ref)return DMG_CORRUPT_INPUT;
            const auto& method=facts.methods[ordinal];
            if(!method.code_offset)result->debug_state=DMG_PARAMETER_DEBUG_NO_BODY;
            else {
                const auto bytes=source.view();const uint64_t code=method.code_offset;
                if(code>bytes.size()||bytes.size()-code<16||method.code_end<code+16)throw ReadError(ReadCode::corrupt,code,"invalid checked code item extent");
                const auto debug=word32(bytes,code+8,work);result->debug_offset=debug;
                if(!debug)result->debug_state=DMG_PARAMETER_DEBUG_NOT_PRESENT;
                else {
                    uint64_t cursor=debug;const auto first=read_uleb(bytes,cursor,work);(void)first;const auto count=read_uleb(bytes,cursor,work);
                    if(count!=result->parameters.size())throw ReadError(ReadCode::corrupt,debug,"debug parameter count disagrees with prototype");
                    result->debug_state=DMG_PARAMETER_DEBUG_PRESENT;
                    for(auto& parameter:result->parameters){work.charge(1);const auto p1=read_uleb(bytes,cursor,work);
                        if(!p1){parameter.name_state=DMG_PARAMETER_NAME_NO_INDEX;continue;}
                        const auto index=p1-1;if(index>=facts.strings.size())throw ReadError(ReadCode::corrupt,cursor,"debug parameter name index outside strings");
                        parameter.name_state=DMG_PARAMETER_NAME_PRESENT;parameter.name_index=index;work.copy(parameter.name,facts.strings[index]);
                    }
                }
            }
        }
        control.check();result->work=work.used;*out=result.release();return DMG_OK;
    },error);
}
void dmg_method_parameters_retain_v1(dmg_method_parameters_v1* result){if(result)result->references.fetch_add(1,std::memory_order_relaxed);}
void dmg_method_parameters_release_v1(dmg_method_parameters_v1* result){if(result&&result->references.fetch_sub(1,std::memory_order_acq_rel)==1)destroy(result);}
dmg_status dmg_method_parameters_get_info_v1(const dmg_method_parameters_v1* r,dmg_method_parameters_info_v1* out,uint32_t size){
    if(!r||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;*out={r->source_index,r->method_ref,r->ordinal,r->debug_state,r->debug_offset,static_cast<uint32_t>(r->parameters.size()),r->work,r->dataset->snapshot_id.c_str()};return DMG_OK;
}
dmg_status dmg_method_parameters_get_source_v1(const dmg_method_parameters_v1* r,dmg_source_info* out,uint32_t size){if(!r||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;return fill_source(*r->dataset,r->source_index,out);}
dmg_status dmg_method_parameters_get_return_type_v1(const dmg_method_parameters_v1* r,dmg_parameter_text_v1* out,uint32_t size){if(!r||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;*out={r->return_type.data(),r->return_type.size()};return DMG_OK;}
dmg_status dmg_method_parameters_get_parameter_v1(const dmg_method_parameters_v1* r,uint32_t ordinal,dmg_method_parameter_v1* out,uint32_t size){
    if(!r||!out||size!=sizeof(*out)||ordinal>=r->parameters.size())return DMG_INVALID_ARGUMENT;const auto& p=r->parameters[ordinal];
    *out={ordinal,p.type_index,p.name_state,p.name_index,p.type.data(),p.type.size(),p.name_state==DMG_PARAMETER_NAME_PRESENT?p.name.data():nullptr,p.name.size()};return DMG_OK;
}
}
