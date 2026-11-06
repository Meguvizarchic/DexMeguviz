#include "dexmeguviz/fast_query_v1.h"
#include "fast/lazy_dex_prefilter.hpp"
#include "query/ir.hpp"
#include <algorithm>
#include <cstring>
#include <limits>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace fast=dexmeguviz::fast;
namespace query=dexmeguviz::query;
namespace {
struct Rejected { dmg_status code; const char* message; };
[[noreturn]] void unsupported(const char* why){throw Rejected{DMG_UNSUPPORTED,why};}
void error_message(dmg_error* error,const char* text) noexcept {
    if(!error)return;error->offset=0;size_t n=0;while(n+1<sizeof(error->message)&&text[n])++n;
    std::memcpy(error->message,text,n);error->message[n]=0;
}
dmg_status exception_status(std::exception_ptr p,dmg_error* error) noexcept {
    try {if(p)std::rethrow_exception(p);}
    catch(const Rejected& e){error_message(error,e.message);return e.code;}
    catch(const query::Error& e){error_message(error,e.what());switch(e.code){
        case query::ErrorCode::invalid:return DMG_INVALID_ARGUMENT;case query::ErrorCode::unsupported:return DMG_UNSUPPORTED;
        case query::ErrorCode::budget:return DMG_BUDGET_EXCEEDED;case query::ErrorCode::cancelled:return DMG_CANCELLED;
        case query::ErrorCode::source_mismatch:return DMG_SOURCE_MISMATCH;}}
    catch(const dexmeguviz::instructions::DecodeError& e){error_message(error,e.what());if(error)error->offset=e.dex_offset;
        switch(e.code){case dexmeguviz::instructions::DecodeCode::corrupt:return DMG_CORRUPT_INPUT;
        case dexmeguviz::instructions::DecodeCode::unsupported:return DMG_UNSUPPORTED;
        case dexmeguviz::instructions::DecodeCode::cancelled:return DMG_CANCELLED;
        case dexmeguviz::instructions::DecodeCode::budget:return DMG_BUDGET_EXCEEDED;}}
    catch(const fast::LimitError& e){error_message(error,e.what());return DMG_BUDGET_EXCEEDED;}
    catch(const fast::UnsupportedError& e){error_message(error,e.what());return DMG_UNSUPPORTED;}
    catch(const std::bad_alloc&){error_message(error,"allocation failed");return DMG_OUT_OF_MEMORY;}
    catch(const std::exception& e){error_message(error,e.what());return DMG_CORRUPT_INPUT;}
    catch(...){error_message(error,"unexpected fast query failure");return DMG_INTERNAL_ERROR;}
    error_message(error,"unexpected fast query failure");return DMG_INTERNAL_ERROR;
}
fast::TextFilter text_filter(const query::Plan& p,uint32_t index){
    if(index==query::none)return {};
    if(index>=p.texts.size())unsupported("invalid text reference");const auto& t=p.texts[index];
    if(t.ascii_fold)unsupported("case-insensitive fast text is unsupported");
    fast::TextOp op;
    switch(t.op){case query::TextOp::exact:op=fast::TextOp::exact;break;case query::TextOp::prefix:op=fast::TextOp::prefix;break;case query::TextOp::contains:op=fast::TextOp::contains;break;default:unsupported("unsupported text operator");}
    return {op,std::u16string(t.text)};
}
std::u16string exact_text(const query::Plan& p,uint32_t index){auto f=text_filter(p,index);if(f.op!=fast::TextOp::exact)unsupported("exact text required");return std::move(f.text);}
fast::InvokePattern invoke_filter(const query::Plan& p,uint32_t index){
    if(index>=p.symbols.size())unsupported("invalid invoke matcher");const auto& s=p.symbols[index];
    if(s.prototype!=query::none)unsupported("invoke prototype matcher unsupported");
    if(s.invoke_kind==query::InvokeKind::call_site && (s.owner!=query::none||s.name!=query::none||s.returned!=query::none||
       !s.parameters.empty()||s.minimum_parameters!=0||s.maximum_parameters!=UINT32_MAX))
        unsupported("call-site symbol predicates are unsupported");
    fast::InvokePattern out;out.owner=text_filter(p,s.owner);out.name=text_filter(p,s.name);out.returned=text_filter(p,s.returned);
    out.min_parameters=s.minimum_parameters;out.max_parameters=s.maximum_parameters;
    switch(s.invoke_kind){case query::InvokeKind::method_like:out.reference_kind=-1;break;case query::InvokeKind::normal:out.reference_kind=0;break;
        case query::InvokeKind::call_site:out.reference_kind=1;break;case query::InvokeKind::polymorphic:out.reference_kind=2;break;}
    if(!s.parameters.empty()){
        if(s.minimum_parameters!=s.maximum_parameters||s.minimum_parameters!=s.parameters.size())unsupported("partial invoke parameters unsupported");
        out.parameters_enabled=true;out.parameters.resize(s.parameters.size());std::vector<bool> seen(s.parameters.size());
        for(const auto& param:s.parameters){if(param.index>=seen.size()||seen[param.index])unsupported("invalid invoke parameter index");seen[param.index]=true;out.parameters[param.index]=exact_text(p,param.text);}
    }
    return out;
}
struct Translation {
    const query::Plan& plan;fast::QuerySpec spec;
    bool owner=false,name=false,prototype=false,returned=false,flags=false;
    std::vector<std::optional<std::u16string>> params;
    explicit Translation(const query::Plan& p):plan(p){}
    void node(uint32_t index){
        if(index>=plan.nodes.size())unsupported("invalid predicate node");const auto& n=plan.nodes[index];
        switch(n.kind){
        case query::Kind::yes:return;
        case query::Kind::all:for(auto child:n.children)node(child);return;
        case query::Kind::any:{
            if(n.children.empty())unsupported("empty any unsupported");std::vector<fast::InvokePattern> group;
            for(auto child:n.children){if(child>=plan.nodes.size()||plan.nodes[child].kind!=query::Kind::invoke)unsupported("only invoke alternatives are supported");group.push_back(invoke_filter(plan,plan.nodes[child].symbol));}
            spec.invoke_all_any.push_back(std::move(group));return;
        }
        case query::Kind::owner:if(owner)unsupported("multiple owner predicates unsupported");owner=true;spec.method.owner=text_filter(plan,n.text);return;
        case query::Kind::name:if(name)unsupported("multiple name predicates unsupported");name=true;spec.method.name=text_filter(plan,n.text);return;
        case query::Kind::prototype:if(prototype)unsupported("multiple prototype predicates unsupported");prototype=true;spec.method.prototype=text_filter(plan,n.text);return;
        case query::Kind::return_type:if(returned)unsupported("multiple return predicates unsupported");returned=true;spec.method.return_enabled=true;spec.method.returned=exact_text(plan,n.text);return;
        case query::Kind::parameter_count:spec.method.min_parameters=std::max(spec.method.min_parameters,n.minimum);spec.method.max_parameters=std::min(spec.method.max_parameters,n.maximum);return;
        case query::Kind::parameter_type:if(n.argument>=256)unsupported("parameter index too large");if(params.size()<=n.argument)params.resize(n.argument+1);if(params[n.argument])unsupported("duplicate parameter predicate");params[n.argument]=exact_text(plan,n.text);return;
        case query::Kind::flags_contains:if(n.argument&1u)unsupported("owner flags unsupported");if(flags&&spec.method.reflection_flags!=bool(n.argument&2u))unsupported("mixed flag domains unsupported");flags=true;spec.method.flags_enabled=true;spec.method.reflection_flags=bool(n.argument&2u);spec.method.flags_contains|=n.minimum;return;
        case query::Kind::using_string:spec.strings_all.push_back(exact_text(plan,n.text));return;
        case query::Kind::invoke:spec.invoke_all_any.push_back({invoke_filter(plan,n.symbol)});return;
        default:unsupported("predicate is not supported by fast candidate mode");
        }
    }
    fast::QuerySpec finish(bool capture){
        if(plan.relation!=query::Relation::method_defs||plan.relation_root!=query::none||plan.explicit_scope||!plan.order.empty()||plan.intent!=query::Intent::enumerate||plan.contains_expand||plan.has_inherited_predicate||plan.class_annotation_requested||plan.method_type_query)
            unsupported("fast mode supports unordered direct method enumeration only");
        if(!plan.max_results||plan.max_results>4096)unsupported("invalid fast result limit");
        spec.method.max_results=plan.max_results;spec.capture_invokes=capture;node(plan.root);
        if(spec.method.min_parameters>spec.method.max_parameters)unsupported("contradictory parameter count");
        if(!params.empty()){
            if(spec.method.min_parameters!=spec.method.max_parameters||params.size()!=spec.method.min_parameters)unsupported("partial method parameters unsupported");
            spec.method.parameters_enabled=true;for(auto& p:params){if(!p)unsupported("missing parameter predicate");spec.method.parameters.push_back(std::move(*p));}
        }
        return std::move(spec);
    }
};
struct Compiled {fast::QuerySpec spec;std::string query_id;bool class_rule=false;uint32_t class_limit=0;std::vector<std::vector<fast::TextFilter>> class_groups;};
void class_node(const query::Plan& plan,uint32_t index,std::vector<std::vector<fast::TextFilter>>& groups){
    if(index>=plan.nodes.size())unsupported("invalid class predicate");const auto& n=plan.nodes[index];
    if(n.kind==query::Kind::yes)return;
    if(n.kind==query::Kind::all){for(const auto child:n.children)class_node(plan,child,groups);return;}
    if(n.kind==query::Kind::descriptor){groups.push_back({text_filter(plan,n.text)});return;}
    if(n.kind==query::Kind::any){if(n.children.empty())unsupported("empty class any unsupported");std::vector<fast::TextFilter> group;
        for(const auto child:n.children){if(child>=plan.nodes.size()||plan.nodes[child].kind!=query::Kind::descriptor)unsupported("class any supports descriptor predicates only");group.push_back(text_filter(plan,plan.nodes[child].text));}
        groups.push_back(std::move(group));return;}
    unsupported("unsupported class predicate");
}
struct OwnedCall {uint32_t pc,index,extra,opcode,kind;std::u16string owner,name,prototype,extra_prototype;};
struct OwnedMethod {fast::Row row;std::u16string owner,name,prototype;std::vector<OwnedCall> calls;};
struct OwnedClass {uint32_t local_index,type_index,definition_offset,access_flags;std::u16string descriptor;};
struct OwnedRule {uint32_t relation=0,status=DMG_OK,unknown=0;bool limit=false;uint64_t selected_methods=0,decoded_bodies=0,class_defs=0;std::string query_id;std::vector<OwnedMethod> methods;std::vector<OwnedClass> classes;};
const uint16_t* units(const std::u16string& s) noexcept{return reinterpret_cast<const uint16_t*>(s.data());}
}
struct dmg_fast_plans_v1 {std::vector<Compiled> plans;};
struct dmg_fast_results_v1 {std::vector<OwnedRule> rules;};
extern "C" {
dmg_status dmg_fast_compile_v1(const dmg_fast_rule_v1* rules,uint32_t count,dmg_fast_plans_v1** out,uint32_t* failure,dmg_error* error){
    if(out)*out=nullptr;if(failure)*failure=UINT32_MAX;
    try{if(!out||!failure||!rules||!count||count>16)return DMG_INVALID_ARGUMENT;auto result=std::make_unique<dmg_fast_plans_v1>();result->plans.reserve(count);uint64_t total=0;
        for(uint32_t i=0;i<count;++i){*failure=i;const auto& r=rules[i];if(!r.bytes||!r.size||r.size>65536||r.capture_calls>1||r.size>1048576-total)return DMG_INVALID_ARGUMENT;total+=r.size;
            std::pmr::monotonic_buffer_resource plan_memory,temporary;auto plan=query::compile(std::string_view(reinterpret_cast<const char*>(r.bytes),static_cast<size_t>(r.size)),&plan_memory,&temporary);
            if(plan.relation==query::Relation::class_defs){
                if(r.capture_calls||plan.relation_root!=query::none||plan.explicit_scope||!plan.order.empty()||plan.intent!=query::Intent::enumerate||plan.class_annotation_requested||!plan.max_results||plan.max_results>4096)
                    unsupported("unsupported fast class query shape");
                Compiled compiled;compiled.query_id=std::string(plan.id);compiled.class_rule=true;compiled.class_limit=plan.max_results;class_node(plan,plan.root,compiled.class_groups);result->plans.push_back(std::move(compiled));
            }else{Translation translated(plan);auto spec=translated.finish(r.capture_calls!=0);result->plans.push_back({std::move(spec),std::string(plan.id)});}
        }*failure=UINT32_MAX;*out=result.release();return DMG_OK;
    }catch(...){return exception_status(std::current_exception(),error);}
}
void dmg_fast_plans_release_v1(dmg_fast_plans_v1* p){delete p;}
dmg_status dmg_fast_scan_v1(const dmg_fast_plans_v1* plans,const uint8_t* dex,uint64_t size,const dmg_fast_limits_v1* limits,dmg_fast_results_v1** out,uint32_t* failure,dmg_error* error){
    if(out)*out=nullptr;if(failure)*failure=UINT32_MAX;
    try{if(!plans||!out||!failure||!limits||limits->struct_size!=sizeof(*limits)||limits->abi_version!=DMG_ABI_VERSION||limits->caller_asserts_valid_sorted_dex!=1||limits->reserved||(!dex&&size)||!limits->max_dex_bytes||!limits->max_total_rows||limits->max_total_rows>65536||limits->max_total_calls>100000||!limits->max_output_utf16_units||limits->max_output_utf16_units>1048576||!limits->max_code_units||limits->max_code_units>1048576||!limits->max_instructions||limits->max_instructions>1048576)return DMG_INVALID_ARGUMENT;
        if(size>limits->max_dex_bytes||size>SIZE_MAX)return DMG_BUDGET_EXCEEDED;
        const fast::Reader reader(std::span<const uint8_t>(dex,static_cast<size_t>(size)));std::vector<fast::QuerySpec> specs;specs.reserve(plans->plans.size());for(const auto& p:plans->plans)if(!p.class_rule)specs.push_back(p.spec);
        fast::MultiResult raw;if(!specs.empty())raw=reader.scan_multi(specs,limits->max_total_rows,limits->max_total_calls,limits->max_code_units,limits->max_instructions);if(raw.rules.size()!=specs.size())return DMG_INTERNAL_ERROR;
        auto result=std::make_unique<dmg_fast_results_v1>();result->rules.reserve(plans->plans.size());uint64_t rows=0,calls=0,text=0;size_t method_rule=0;
        const auto account=[&](const std::u16string& s){if(s.size()>limits->max_output_utf16_units-text)throw Rejected{DMG_BUDGET_EXCEEDED,"fast result text limit"};text+=s.size();};
        for(size_t i=0;i<plans->plans.size();++i){*failure=static_cast<uint32_t>(i);const auto& compiled=plans->plans[i];OwnedRule out_rule;out_rule.query_id=compiled.query_id;
            if(compiled.class_rule){out_rule.relation=1;
                for(uint32_t ci=0;ci<reader.classes.size;++ci){++out_rule.class_defs;const auto at=uint64_t(reader.classes.offset)+uint64_t(ci)*32;const auto type=reader.u32(at);auto descriptor=reader.type_name(type);
                    bool match=true;for(const auto& group:compiled.class_groups)if(!std::any_of(group.begin(),group.end(),[&](const auto& term){return term.matches(descriptor);})){match=false;break;}
                    if(!match)continue;if(out_rule.classes.size()>=compiled.class_limit){out_rule.limit=true;break;}
                    if(++rows>limits->max_total_rows)throw Rejected{DMG_BUDGET_EXCEEDED,"fast row limit"};account(descriptor);
                    out_rule.classes.push_back({ci,type,static_cast<uint32_t>(at),reader.u32(at+4),std::move(descriptor)});
                }
                result->rules.push_back(std::move(out_rule));continue;
            }
            auto& from=raw.rules[method_rule++];
            if(from.error){out_rule.status=exception_status(from.error,nullptr);result->rules.push_back(std::move(out_rule));continue;}
            if(from.unknown_rows>UINT32_MAX)throw Rejected{DMG_BUDGET_EXCEEDED,"fast unknown row count"};out_rule.unknown=static_cast<uint32_t>(from.unknown_rows);out_rule.limit=from.result_limit;out_rule.selected_methods=from.visited_methods;out_rule.decoded_bodies=from.decoded_methods;
            for(const auto& match:from.matches){if(++rows>limits->max_total_rows)throw Rejected{DMG_BUDGET_EXCEEDED,"fast row limit"};auto desc=reader.describe_method(match.row.ref,static_cast<size_t>(limits->max_output_utf16_units-text));account(desc.owner);account(desc.name);account(desc.prototype);
                OwnedMethod m{match.row,std::move(desc.owner),std::move(desc.name),std::move(desc.prototype),{}};m.calls.reserve(match.all_invokes.size());
                for(const auto& call:match.all_invokes){if(++calls>limits->max_total_calls)throw Rejected{DMG_BUDGET_EXCEEDED,"fast call limit"};OwnedCall c{call.pc,call.index,call.extra_proto,call.opcode,static_cast<uint32_t>(call.kind),{},{},{},{}};
                    if(call.kind!=dexmeguviz::instructions::ReferenceKind::call_site){auto target=reader.describe_method(call.index,static_cast<size_t>(limits->max_output_utf16_units-text));account(target.owner);account(target.name);account(target.prototype);c.owner=std::move(target.owner);c.name=std::move(target.name);c.prototype=std::move(target.prototype);}
                    if(call.kind==dexmeguviz::instructions::ReferenceKind::method_and_proto){c.extra_prototype=reader.prototype_text(call.extra_proto,static_cast<size_t>(limits->max_output_utf16_units-text));account(c.extra_prototype);}m.calls.push_back(std::move(c));}
                out_rule.methods.push_back(std::move(m));}
            result->rules.push_back(std::move(out_rule));
        }*failure=UINT32_MAX;*out=result.release();return DMG_OK;
    }catch(...){return exception_status(std::current_exception(),error);}
}
void dmg_fast_results_release_v1(dmg_fast_results_v1* p){delete p;}
dmg_status dmg_fast_results_count_v1(const dmg_fast_results_v1* r,uint32_t* out){if(!r||!out)return DMG_INVALID_ARGUMENT;*out=static_cast<uint32_t>(r->rules.size());return DMG_OK;}
dmg_status dmg_fast_rule_info_get_v1(const dmg_fast_results_v1* r,uint32_t i,dmg_fast_rule_info_v1* out){if(!r||!out||i>=r->rules.size())return DMG_INVALID_ARGUMENT;const auto& x=r->rules[i];*out={x.relation,x.status,static_cast<uint32_t>(x.relation?x.classes.size():x.methods.size()),x.unknown,x.limit?1u:0u,DMG_COVERAGE_PARTIAL,(x.status==DMG_OK&&!x.limit&&!x.unknown)?1u:0u,x.selected_methods,x.decoded_bodies,x.class_defs,x.query_id.c_str()};return DMG_OK;}
dmg_status dmg_fast_method_get_v1(const dmg_fast_results_v1* r,uint32_t i,uint32_t j,dmg_fast_method_v1* out){if(!r||!out||i>=r->rules.size()||r->rules[i].relation||j>=r->rules[i].methods.size())return DMG_INVALID_ARGUMENT;const auto& x=r->rules[i].methods[j];*out={x.row.ref,x.row.flags,x.row.declaration,x.row.code,units(x.owner),static_cast<uint32_t>(x.owner.size()),units(x.name),static_cast<uint32_t>(x.name.size()),units(x.prototype),static_cast<uint32_t>(x.prototype.size()),static_cast<uint32_t>(x.calls.size())};return DMG_OK;}
dmg_status dmg_fast_class_get_v1(const dmg_fast_results_v1* r,uint32_t i,uint32_t j,dmg_fast_class_v1* out){if(!r||!out||i>=r->rules.size()||r->rules[i].relation!=1||j>=r->rules[i].classes.size())return DMG_INVALID_ARGUMENT;const auto& x=r->rules[i].classes[j];*out={x.local_index,x.type_index,x.definition_offset,x.access_flags,units(x.descriptor),static_cast<uint32_t>(x.descriptor.size())};return DMG_OK;}
dmg_status dmg_fast_call_get_v1(const dmg_fast_results_v1* r,uint32_t i,uint32_t j,uint32_t k,dmg_fast_call_v1* out){if(!r||!out||i>=r->rules.size()||j>=r->rules[i].methods.size()||k>=r->rules[i].methods[j].calls.size())return DMG_INVALID_ARGUMENT;const auto& x=r->rules[i].methods[j].calls[k];*out={x.pc,x.index,x.extra,x.opcode,x.kind,units(x.owner),static_cast<uint32_t>(x.owner.size()),units(x.name),static_cast<uint32_t>(x.name.size()),units(x.prototype),static_cast<uint32_t>(x.prototype.size()),units(x.extra_prototype),static_cast<uint32_t>(x.extra_prototype.size())};return DMG_OK;}
}
