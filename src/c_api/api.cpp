#include "runtime.hpp"
#include "source/sha1.hpp"
#include "miniz.h"
#include <algorithm>
using namespace dexmeguviz;
using namespace dexmeguviz::runtime;

namespace dexmeguviz::runtime {
std::shared_ptr<EngineState> make_engine(const dmg_engine_options* options){
    const dmg_engine_options defaults{sizeof(dmg_engine_options),DMG_ABI_VERSION,256ull<<20,256ull<<20,128ull<<20,4,0};
    const auto& o=options?*options:defaults;
    if(o.struct_size!=sizeof(o)||o.abi_version!=DMG_ABI_VERSION||!o.owned_bytes_limit||!o.max_source_bytes||!o.max_jobs||o.max_jobs>64||o.reserved)throw Stop{DMG_INVALID_ARGUMENT};
    return std::make_shared<EngineState>(o);
}
void admit(const std::shared_ptr<EngineState>& e){std::lock_guard lock(e->admission);if(e->closed)throw Stop{DMG_CLOSED};}
void fill_info(const Source& s,dmg_snapshot_info* out,const char* snapshot_id)noexcept{
    const auto& f=s.facts;*out={f.dex_version,f.string_count,f.type_count,f.class_count,f.method_ref_count,
        static_cast<uint32_t>(f.methods.size()),s.view().size(),s.digest.c_str(),s.content.c_str(),s.occurrence.c_str(),snapshot_id?snapshot_id:s.snapshot.c_str()};
}
void fill_overview(const Dataset& d,dmg_snapshot_overview* out)noexcept{
    *out={d.snapshot_id.c_str(),static_cast<uint32_t>(d.inputs.size()),static_cast<uint32_t>(d.sources.size()),d.scope_complete?1u:0u,0,
        d.input_bytes,d.dex_bytes,d.strings,d.types,d.classes,d.method_refs,d.methods};
}
dmg_status fill_input(const Dataset& d,uint32_t i,dmg_input_info* out)noexcept{
    if(!out||i>=d.inputs.size())return DMG_INVALID_ARGUMENT;const auto& input=d.inputs[i];
    *out={i,input.format,input.allow_no_dex?1u:0u,input.source_count,input.slot.c_str(),input.role.c_str(),input.digest.c_str(),input.content.c_str(),input.bytes,input.expected_verified?1u:0u,input.container_checked?1u:0u};return DMG_OK;
}
dmg_status fill_source(const Dataset& d,uint32_t i,dmg_source_info* out)noexcept{
    if(!out||i>=d.sources.size())return DMG_INVALID_ARGUMENT;const auto& s=*d.sources[i];
    fill_info(s,&out->dex,d.snapshot_id.c_str());out->source_index=i;out->input_index=s.input_index;
    out->slot_key=s.slot_key.c_str();out->role=s.role.c_str();out->logical_dex_id=s.logical.c_str();
    out->archive_sha256=s.archive_digest.c_str();out->archive_entry_name=s.entry_name.c_str();out->archive_entry_index=s.entry_index;
    out->crc_verified=s.crc_verified?1u:0u;out->header_consistency_verified=s.header_verified?1u:0u;out->expected_digest_verified=s.expected_verified?1u:0u;return DMG_OK;
}
dmg_status check_dex_checksums(const Dataset& dataset,uint32_t index,uint64_t limit,dmg_dex_checksums_v1* out,uint32_t size)noexcept{
    if(!out||size!=sizeof(*out)||index>=dataset.sources.size())return DMG_INVALID_ARGUMENT;
    // The v1 checksum contract uses a standard single-header byte extent.
    // Explicit 041 logical checksum semantics are not implemented here.
    if(dataset.sources[index]->facts.dex_version==41)return DMG_UNSUPPORTED;
    const auto bytes=dataset.sources[index]->view();
    if(bytes.size()>limit)return DMG_BUDGET_EXCEEDED;
    // Reader admitted only standard 035-040 DEX with exact file_size and 112-byte header.
    if(bytes.size()<112)return DMG_CORRUPT_INPUT;
    dmg_dex_checksums_v1 value{};
    value.input_bytes=bytes.size();
    value.adler32_expected=uint32_t(bytes[8])|(uint32_t(bytes[9])<<8)|(uint32_t(bytes[10])<<16)|(uint32_t(bytes[11])<<24);
    value.adler32_actual=static_cast<uint32_t>(mz_adler32(1,bytes.data()+12,bytes.size()-12));
    value.adler32_matches=value.adler32_expected==value.adler32_actual?1u:0u;
    std::copy_n(bytes.data()+12,20,value.sha1_expected);
    const auto digest=sha1(bytes.subspan(32));std::copy(digest.begin(),digest.end(),value.sha1_actual);
    value.sha1_matches=std::equal(digest.begin(),digest.end(),value.sha1_expected)?1u:0u;
    *out=value;return DMG_OK;
}
std::shared_ptr<QueryState> compile(const std::shared_ptr<EngineState>& e,const dmg_method_query& q){
    if(q.struct_size!=sizeof(q)||q.abi_version!=DMG_ABI_VERSION||q.intent>DMG_UNIQUE||q.name_enabled>1||q.owner_enabled>1||q.name_operator>DMG_CONTAINS||
       (q.name_length&&!q.name)||(q.owner_length&&!q.owner)||!q.max_results)throw Stop{DMG_INVALID_ARGUMENT};
    if(q.name_length>65536||q.owner_length>65536||q.max_results>100000)throw BudgetExceeded();
    auto result=state<QueryState>(e);result->options=q;result->options.name=nullptr;result->options.owner=nullptr;
    std::pmr::u16string name(&e->scratch_resource),owner(&e->scratch_resource);
    if(q.name_enabled)for(uint64_t i=0;i<q.name_length;++i)name.push_back(static_cast<char16_t>(q.name[i]));
    if(q.owner_enabled)for(uint64_t i=0;i<q.owner_length;++i)owner.push_back(static_cast<char16_t>(q.owner[i]));
    query::SimpleQuery simple;simple.name_enabled=q.name_enabled!=0;simple.owner_enabled=q.owner_enabled!=0;simple.name_op=q.name_operator==DMG_CONTAINS?query::TextOp::contains:query::TextOp::exact;
    simple.name=name;simple.owner=owner;simple.flags=q.flags_contains;simple.max_results=q.max_results;simple.intent=static_cast<query::Intent>(q.intent);
    result->plan.emplace(query::compile_simple(simple,&e->query_resource));
    return result;
}
}
extern "C" {
uint32_t dmg_abi_version(){return DMG_ABI_VERSION;}
const char* dmg_capabilities(){return "dex-query-method-v1;dex-query-entity-v2;dex-query-relational-v3;dex-query-use-v4;dex-query-expand-v5;dex-query-inherited-v6;dex-query-numeric-v7;dex-query-interface-v8;dex-query-use-stream-v9;dex-query-composite-v10;dex-query-interface-resolved-v11;dex-query-unique-one-v12;dex-query-reflection-flags-v13;dex-query-reflection-relational-v14;dex-query-reflection-method-uses-v15;dex-query-use-target-symbol-v16;dex-query-reflection-body-relational-v17;dex-query-inherited-target-symbol-v18;dex-query-field-declaration-v19;caller-field-relation-observation-v1;dex-query-reflection-class-annotations-v20;dex-query-type-uses-v21;dex-query-method-type-uses-v22;union,distinct,owner-groups,role-bindings,join,semi-join;class-defs,field-defs,method-refs,field-refs,string-values,type-refs;use-relations;three-valued-metadata;dex035,037,038,039,040;apk,zip64,stored,deflate;ordered-source-set;owned-copy,borrowed-lease,fd-range-copy;engine-budget;typed-json-query;job,batch,cancel,deadline;exact,contains,prefix,raw-flags;all,any,not;string-uses,invoke-sites,field-uses,type-uses;scope,projection,order,top-n;enumerate,exists,unique;sha256;dex-header-checksums-v1;method-parameters-static-v1;selected-method-facts-v1;annotation-encoded-v1;source-bytes-view-v1;source-symbol-text-v1;source-member-indices-v1;dex-query-opcode-sequence-v23;dex-query-class-annotation-static-v24;dex-query-class-annotation-string-static-v25";}
const char* dmg_status_name(dmg_status s){switch(s){case DMG_OK:return "Complete";case DMG_INVALID_ARGUMENT:return "InvalidArgument";case DMG_CORRUPT_INPUT:return "CorruptInput";case DMG_UNSUPPORTED:return "Unsupported";case DMG_BUDGET_EXCEEDED:return "BudgetExceeded";case DMG_OUT_OF_MEMORY:return "OutOfMemory";case DMG_INTERNAL_ERROR:return "InternalError";case DMG_CLOSED:return "Closed";case DMG_SOURCE_MISMATCH:return "SourceMismatch";case DMG_CANCELLED:return "Cancelled";case DMG_DEADLINE_EXCEEDED:return "DeadlineExceeded";case DMG_NOT_READY:return "NotReady";case DMG_END_OF_STREAM:return "EndOfStream";default:return "UnknownStatus";}}
dmg_status dmg_engine_create(const dmg_engine_options* o,dmg_engine** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{if(!out)return DMG_INVALID_ARGUMENT;auto e=make_engine(o);*out=handle<dmg_engine>(e);return DMG_OK;},error);
}
void dmg_engine_retain(dmg_engine* e){if(e)e->references.fetch_add(1,std::memory_order_relaxed);}
void dmg_engine_release(dmg_engine* e){if(e&&e->references.fetch_sub(1,std::memory_order_acq_rel)==1)destroy(e);}
dmg_status dmg_engine_shutdown(dmg_engine* e,uint32_t cancel){return guard([&]()->dmg_status{
    if(!e||cancel>1)return DMG_INVALID_ARGUMENT;std::lock_guard lock(e->owner->admission);e->owner->closed=true;
    if(cancel)for(auto& weak:e->owner->jobs)if(auto job=weak.lock()){job->cancelled.store(true,std::memory_order_release);job->changed.notify_all();}
    return DMG_OK;
});}
dmg_status dmg_engine_get_stats(const dmg_engine* e,dmg_engine_stats* out){return guard([&]()->dmg_status{
    if(!e||!out)return DMG_INVALID_ARGUMENT;const auto& a=e->owner->account;std::lock_guard lock(e->owner->admission);
    *out={a.total(),a.peak(),a.category(MemoryKind::source),a.category(MemoryKind::facts),a.category(MemoryKind::scratch),a.category(MemoryKind::query),a.category(MemoryKind::result),a.category(MemoryKind::control),a.borrowed(),e->owner->active_jobs,e->owner->closed?1u:0u};return DMG_OK;
});}
void dmg_snapshot_retain(dmg_snapshot* s){if(s)s->references.fetch_add(1,std::memory_order_relaxed);}
void dmg_snapshot_close(dmg_snapshot* s){if(s)s->closed.store(true,std::memory_order_release);}
void dmg_snapshot_release(dmg_snapshot* s){if(s&&s->references.fetch_sub(1,std::memory_order_acq_rel)==1)destroy(s);}
dmg_status dmg_snapshot_get_info(const dmg_snapshot* s,dmg_snapshot_info* out){if(!s||!out)return DMG_INVALID_ARGUMENT;if(s->dataset->sources.size()!=1)return DMG_UNSUPPORTED;fill_info(*s->dataset->sources[0],out,s->dataset->snapshot_id.c_str());return DMG_OK;}
dmg_status dmg_snapshot_get_overview(const dmg_snapshot* s,dmg_snapshot_overview* out){if(!s||!out)return DMG_INVALID_ARGUMENT;fill_overview(*s->dataset,out);return DMG_OK;}
dmg_status dmg_snapshot_get_input_info(const dmg_snapshot* s,uint32_t i,dmg_input_info* out){return s?fill_input(*s->dataset,i,out):DMG_INVALID_ARGUMENT;}
dmg_status dmg_snapshot_get_source_info(const dmg_snapshot* s,uint32_t i,dmg_source_info* out){return s?fill_source(*s->dataset,i,out):DMG_INVALID_ARGUMENT;}
dmg_status dmg_snapshot_copy_symbol_text_v1(const dmg_snapshot* s,uint32_t source_index,uint32_t kind,uint32_t index,uint64_t max_units,uint16_t* out,uint64_t capacity,uint64_t* length){
    if(length)*length=0;
    return guard([&]()->dmg_status{
        if(!s||!length||kind>DMG_SYMBOL_PROTO_V1||!max_units||max_units>1048576||(!out&&capacity))return DMG_INVALID_ARGUMENT;
        if(s->closed.load(std::memory_order_acquire))return DMG_CLOSED;admit(s->owner);
        if(source_index>=s->dataset->sources.size())return DMG_INVALID_ARGUMENT;
        const auto& f=s->dataset->sources[source_index]->facts;
        std::u16string_view text;
        if(kind==DMG_SYMBOL_PROTO_V1){if(index>=f.prototypes.size())return DMG_INVALID_ARGUMENT;text=f.prototypes[index].descriptor;}
        else {if(kind==DMG_SYMBOL_TYPE_V1){if(index>=f.types.size())return DMG_INVALID_ARGUMENT;index=f.types[index];}
            if(index>=f.strings.size())return DMG_INVALID_ARGUMENT;text=f.strings[index];}
        if(text.size()>max_units)return DMG_BUDGET_EXCEEDED;
        if(out&&capacity<text.size())return DMG_INVALID_ARGUMENT;
        if(out)for(size_t i=0;i<text.size();++i)out[i]=static_cast<uint16_t>(text[i]);
        *length=text.size();return DMG_OK;
    });
}
dmg_status dmg_snapshot_get_member_indices_v1(const dmg_snapshot* s,uint32_t source_index,uint32_t kind,uint32_t index,dmg_member_indices_v1* out,uint32_t out_size){
    return guard([&]()->dmg_status{
        if(!s||!out||out_size!=sizeof(dmg_member_indices_v1)||kind>DMG_MEMBER_METHOD_V1)return DMG_INVALID_ARGUMENT;
        if(s->closed.load(std::memory_order_acquire))return DMG_CLOSED;admit(s->owner);
        if(source_index>=s->dataset->sources.size())return DMG_INVALID_ARGUMENT;const auto& f=s->dataset->sources[source_index]->facts;
        if(kind==DMG_MEMBER_FIELD_V1){if(index>=f.field_refs.size())return DMG_INVALID_ARGUMENT;const auto& x=f.field_refs[index];*out={x.owner,x.name,x.type};}
        else {if(index>=f.method_refs.size())return DMG_INVALID_ARGUMENT;const auto& x=f.method_refs[index];*out={x.owner,x.name,x.type};}
        return DMG_OK;
    });
}
dmg_status dmg_snapshot_get_source_bytes_v1(const dmg_snapshot* s,uint32_t i,uint64_t max_bytes,const uint8_t** out,uint64_t* size){
    if(out)*out=nullptr;if(size)*size=0;
    return guard([&]()->dmg_status{if(!s||!out||!size||!max_bytes)return DMG_INVALID_ARGUMENT;if(s->closed.load(std::memory_order_acquire))return DMG_CLOSED;admit(s->owner);if(i>=s->dataset->sources.size())return DMG_INVALID_ARGUMENT;const auto bytes=s->dataset->sources[i]->view();if(bytes.size()>max_bytes)return DMG_BUDGET_EXCEEDED;*out=bytes.data();*size=bytes.size();return DMG_OK;});
}
dmg_status dmg_snapshot_check_dex_checksums_v1(const dmg_snapshot* s,uint32_t i,uint64_t max_bytes,dmg_dex_checksums_v1* out,uint32_t size){
    return s?check_dex_checksums(*s->dataset,i,max_bytes,out,size):DMG_INVALID_ARGUMENT;
}
dmg_status dmg_result_check_dex_checksums_v1(const dmg_result* r,uint32_t i,uint64_t max_bytes,dmg_dex_checksums_v1* out,uint32_t size){
    return r?check_dex_checksums(*r->dataset,i,max_bytes,out,size):DMG_INVALID_ARGUMENT;
}
dmg_status dmg_query_compile_methods(dmg_engine* e,const dmg_method_query* input,dmg_query** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{if(!e||!input||!out)return DMG_INVALID_ARGUMENT;admit(e->owner);*out=handle<dmg_query>(e->owner,compile(e->owner,*input));return DMG_OK;},error);
}
void dmg_query_retain(dmg_query* q){if(q)q->references.fetch_add(1,std::memory_order_relaxed);}
void dmg_query_release(dmg_query* q){if(q&&q->references.fetch_sub(1,std::memory_order_acq_rel)==1)destroy(q);}
dmg_status dmg_query_methods(dmg_snapshot* s,const dmg_method_query* input,dmg_result** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{
        if(!s||!input||!out)return DMG_INVALID_ARGUMENT;if(s->closed.load(std::memory_order_acquire))return DMG_CLOSED;admit(s->owner);
        return execute_query(s,compile(s->owner,*input),out,error);
    },error);
}
void dmg_result_retain(dmg_result* r){if(r)r->references.fetch_add(1,std::memory_order_relaxed);}
void dmg_result_release(dmg_result* r){if(r&&r->references.fetch_sub(1,std::memory_order_acq_rel)==1)destroy(r);}
dmg_status dmg_result_get_info(const dmg_result* r,dmg_result_info* out){if(!r||!out)return DMG_INVALID_ARGUMENT;if((r->query->plan->relation!=query::Relation::method_defs||r->query->plan->relation_root!=query::none))return DMG_UNSUPPORTED;*out=r->info;return DMG_OK;}
dmg_status dmg_result_get_source(const dmg_result* r,dmg_snapshot_info* out){if(!r||!out)return DMG_INVALID_ARGUMENT;if(r->dataset->sources.size()!=1)return DMG_UNSUPPORTED;fill_info(*r->dataset->sources[0],out,r->dataset->snapshot_id.c_str());return DMG_OK;}
dmg_status dmg_result_get_overview(const dmg_result* r,dmg_snapshot_overview* out){if(!r||!out)return DMG_INVALID_ARGUMENT;fill_overview(*r->dataset,out);return DMG_OK;}
dmg_status dmg_result_get_input_info(const dmg_result* r,uint32_t i,dmg_input_info* out){return r?fill_input(*r->dataset,i,out):DMG_INVALID_ARGUMENT;}
dmg_status dmg_result_get_source_info(const dmg_result* r,uint32_t i,dmg_source_info* out){return r?fill_source(*r->dataset,i,out):DMG_INVALID_ARGUMENT;}
dmg_status dmg_result_get_origin(const dmg_result* r,uint32_t i,dmg_source_info* out){if(r&&r->query->plan->contains_expand)return DMG_UNSUPPORTED;if(!r||i>=r->rows.size())return DMG_INVALID_ARGUMENT;return fill_source(*r->dataset,r->rows[i].source_index,out);}
dmg_status dmg_result_get_method(const dmg_result* r,uint32_t i,dmg_method_row* out){if(r&&r->query->plan->contains_expand)return DMG_UNSUPPORTED;
    if(!r||!out||i>=r->rows.size())return DMG_INVALID_ARGUMENT;if((r->query->plan->relation!=query::Relation::method_defs||r->query->plan->relation_root!=query::none))return DMG_UNSUPPORTED;const auto& m=r->rows[i];
    *out={m.method_index,m.flags,m.declaration,m.code,m.owner.data(),m.owner.size(),m.name.data(),m.name.size(),m.prototype.data(),m.prototype.size()};return DMG_OK;
}
void dmg_batch_retain(dmg_batch* b){dmg_result_retain(b);}void dmg_batch_release(dmg_batch* b){dmg_result_release(b);}
dmg_status dmg_batch_get_info(const dmg_batch* b,dmg_result_info* out){return dmg_result_get_info(b,out);}
dmg_status dmg_batch_get_source(const dmg_batch* b,dmg_snapshot_info* out){return dmg_result_get_source(b,out);}
dmg_status dmg_batch_get_method(const dmg_batch* b,uint32_t row,dmg_method_row* out){return dmg_result_get_method(b,row,out);}
}
