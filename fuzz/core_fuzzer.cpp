#include "dexmeguviz/dexmeguviz.h"
#include "execution/budget/account.hpp"
#include "format/instructions/decoder.hpp"
#include "source/archive/archive.hpp"
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#if defined(DMG_FUZZ_USE_SCAN)
#include "facts/use_relations/use_scan.hpp"
#include <span>
namespace {
using namespace dexmeguviz;
using namespace dexmeguviz::facts;
void use_require(bool condition){if(!condition)std::abort();}
uint16_t use_word(std::span<const uint8_t> bytes,uint64_t start,uint32_t count,uint32_t pc){
    use_require(pc<count);const uint64_t offset=start+uint64_t(pc)*2;
    use_require(offset<=bytes.size()&&bytes.size()-offset>=2);
    return uint16_t(bytes[static_cast<size_t>(offset)])|(uint16_t(bytes[static_cast<size_t>(offset+1)])<<8);
}
uint32_t use_dword(std::span<const uint8_t> bytes,uint64_t offset){
    use_require(offset<=bytes.size()&&bytes.size()-offset>=4);
    const auto p=bytes.data()+static_cast<size_t>(offset);
    return uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24);
}
void use_record(const UseRecord& record,UseKind kind,const Facts& metadata,std::span<const uint8_t> bytes){
    use_require(record.key.source_index==0&&record.key.kind==kind&&record.key.caller_ordinal<metadata.methods.size());
    const auto& method=metadata.methods[record.key.caller_ordinal];
    use_require(method.code_offset!=0&&record.code_offset==method.code_offset&&record.caller_method_ref==method.method_index);
    const uint64_t start=uint64_t(method.code_offset)+16;
    const uint32_t count=use_dword(bytes,uint64_t(method.code_offset)+12);
    const uint64_t end=start+uint64_t(count)*2;
    use_require(start<=bytes.size()&&end<=bytes.size()&&(!method.code_end||(end<=method.code_end&&method.code_end<=bytes.size())));
    const uint32_t pc=record.key.dex_pc;const uint16_t first=use_word(bytes,start,count,pc);
    use_require(uint8_t(first&255)==record.opcode);
    const auto operand=[&](uint32_t offset){use_require(uint64_t(pc)+offset<count);return use_word(bytes,start,count,pc+offset);};
    if(kind==UseKind::string_use){
        use_require((record.opcode==0x1a||record.opcode==0x1b)&&record.target_domain==TargetDomain::string_value&&record.extra_proto==UINT32_MAX);
        uint32_t target=operand(1);if(record.opcode==0x1b)target|=uint32_t(operand(2))<<16;
        use_require(target==record.target_index&&target<metadata.strings.size());
    }else if(kind==UseKind::field_use){
        use_require(record.opcode>=0x52&&record.opcode<=0x6d&&record.target_domain==TargetDomain::field_ref&&record.extra_proto==UINT32_MAX);
        const auto target=operand(1);use_require(target==record.target_index&&target<metadata.field_refs.size());
    }else{
        use_require(kind==UseKind::invoke_site);const auto opcode=record.opcode;
        const bool normal=(opcode>=0x6e&&opcode<=0x72)||(opcode>=0x74&&opcode<=0x78);
        const bool polymorphic=opcode==0xfa||opcode==0xfb,custom=opcode==0xfc||opcode==0xfd;
        use_require(normal||polymorphic||custom);const auto target=operand(1);use_require(target==record.target_index);
        if(custom)use_require(record.target_domain==TargetDomain::call_site&&target<metadata.call_site_count&&record.extra_proto==UINT32_MAX);
        else{
            use_require(target<metadata.method_refs.size());
            if(polymorphic){use_require(record.target_domain==TargetDomain::method_and_proto);const auto proto=operand(3);use_require(proto==record.extra_proto&&proto<metadata.prototypes.size());}
            else use_require(record.target_domain==TargetDomain::method_ref&&record.extra_proto==UINT32_MAX);
        }
    }
}
void use_progress(const UseScanProgress& p,const Facts& metadata,std::span<const uint8_t> bytes,UseScanLimits limits){
    use_require(p.total_methods==metadata.methods.size()&&p.visited_methods<=p.attempted_methods&&p.attempted_methods<=p.total_methods);
    use_require(p.attempted_methods-p.visited_methods<=1&&p.emitted_events<=limits.max_records&&p.work_units<=limits.max_work);
    uint32_t no_body=0;uint64_t code_units=0;
    for(uint32_t i=0;i<p.visited_methods;++i){const auto& method=metadata.methods[i];
        if(!method.code_offset)++no_body;else code_units+=use_dword(bytes,uint64_t(method.code_offset)+12);
    }
    use_require(p.no_body_methods==no_body&&p.decoded_methods==p.visited_methods-no_body&&p.code_units==code_units&&p.validation_work>=p.code_units);
    use_require(p.validation_work<=limits.max_work&&uint64_t(p.attempted_methods)<=limits.max_work-p.validation_work);
    const auto completed_and_attempted=p.validation_work+uint64_t(p.attempted_methods);
    use_require(p.emitted_events<=limits.max_work-completed_and_attempted&&completed_and_attempted+p.emitted_events<=p.work_units);
}
void use_failure(const UseScanError& error){
    switch(error.code){case UseScanError::Code::invalid:case UseScanError::Code::unsupported:case UseScanError::Code::budget:case UseScanError::Code::cancelled:return;}
    std::abort();
}
void decode_failure(const instructions::DecodeError& error){
    switch(error.code){case instructions::DecodeCode::corrupt:case instructions::DecodeCode::unsupported:case instructions::DecodeCode::budget:case instructions::DecodeCode::cancelled:return;}
    std::abort();
}
void read_failure(const ReadError& error){
    switch(error.code){case ReadCode::corrupt:case ReadCode::unsupported:case ReadCode::budget:return;}
    std::abort();
}
}
#endif
#if defined(DMG_FUZZ_RELATIONAL)
#include "fuzz_relation_fixtures.hpp"
namespace {
volatile uint32_t consumed=0;
void require(bool value){if(!value)std::abort();}
bool query_failure(dmg_status status){
    return status==DMG_INVALID_ARGUMENT||status==DMG_UNSUPPORTED||status==DMG_BUDGET_EXCEEDED||status==DMG_OUT_OF_MEMORY||status==DMG_SOURCE_MISMATCH;
}
void units(const uint16_t* text,uint64_t size){
    require(size<=65536&&(!size||text));uint32_t value=0;for(uint64_t i=0;i<size;++i)value=value*33u+text[i];consumed=value;
}
void string(const char* text,size_t maximum){
    require(text!=nullptr);uint32_t value=0;for(size_t i=0;i<=maximum;++i){if(!text[i]){consumed=value;return;}value=value*33u+static_cast<uint8_t>(text[i]);}std::abort();
}
void entity(const dmg_entity_row& row){
    require(row.relation<=DMG_TYPE_REFS&&row.source_index<2&&row.definition_known<=1&&row.flags_known<=1&&row.code_known<=1);
    units(row.owner,row.owner_length);units(row.name,row.name_length);units(row.prototype,row.prototype_length);
    units(row.type_descriptor,row.type_descriptor_length);units(row.string_value,row.string_value_length);
}
void path(const dmg_binding_path& value){
    require(value.length<=32&&(!value.length||value.sides));
    for(uint32_t i=0;i<value.length;++i)require(value.sides[i]==DMG_PATH_LEFT||value.sides[i]==DMG_PATH_RIGHT);
}
bool same_live(const dmg_engine_stats& a,const dmg_engine_stats& b){
    return a.owned_bytes==b.owned_bytes&&a.source_bytes==b.source_bytes&&a.fact_bytes==b.fact_bytes&&a.scratch_bytes==b.scratch_bytes&&
        a.query_bytes==b.query_bytes&&a.result_bytes==b.result_bytes&&a.control_bytes==b.control_bytes&&a.borrowed_bytes==b.borrowed_bytes&&a.active_jobs==b.active_jobs;
}
void legacy_result(dmg_result* output){
    dmg_relation_info info{};dmg_query_info query{};dmg_query_profile profile{};
    require(dmg_result_get_relation_info(output,&info,sizeof(info))==DMG_OK&&info.relation<=DMG_TYPE_REFS&&info.visited_rows<=info.total_rows);
    require(info.execution_status==DMG_OK||info.execution_status==DMG_BUDGET_EXCEEDED);
    require(dmg_result_get_query_info(output,&query)==DMG_OK&&info.candidates_count<=query.max_results);string(query.query_id,80);
    require(dmg_result_get_profile(output,&profile)==DMG_OK&&profile.scope_source_count<=2);
    for(uint32_t i=0;i<profile.scope_source_count;++i){uint32_t source=UINT32_MAX;require(dmg_result_get_scope_source(output,i,&source)==DMG_OK&&source<2);}
    dmg_graph_info graph{};const auto graph_status=dmg_result_get_graph_info(output,&graph,sizeof(graph));
    require(graph_status==DMG_OK||graph_status==DMG_UNSUPPORTED);
    if(graph_status==DMG_OK){
        require(graph.operator_count>0&&graph.operator_count<=128&&graph.unique_identity<=DMG_IDENTITY_TUPLE);
        for(uint32_t i=0;i<graph.operator_count;++i){dmg_operator_profile op{};
            require(dmg_result_get_operator_profile(output,i,&op,sizeof(op))==DMG_OK&&op.op<=DMG_REL_SEMI_JOIN&&op.unknown_rows<=op.output_rows&&op.visited_rows<=op.total_rows);
        }
    }
    for(uint32_t i=0;i<info.candidates_count;++i){
        dmg_entity_row row{};require(dmg_result_get_entity(output,i,&row,sizeof(row))==DMG_OK&&row.relation==info.relation);entity(row);
        dmg_source_info origin{};require(dmg_result_get_origin(output,i,&origin)==DMG_OK&&origin.source_index==row.source_index);string(origin.dex.source_sha256,64);string(origin.slot_key,5);
        uint32_t bindings=0,witnesses=0;require(dmg_result_get_binding_count(output,i,&bindings)==DMG_OK);
        for(uint32_t j=0;j<bindings;++j){dmg_binding_row binding{};dmg_binding_path binding_path{};
            require(dmg_result_get_binding(output,i,j,&binding,sizeof(binding))==DMG_OK);entity(binding.entity);if(binding.label)string(binding.label,64);
            require(dmg_result_get_binding_path(output,i,j,&binding_path,sizeof(binding_path))==DMG_OK);path(binding_path);
            if(j==0){dmg_binding_path invalid{nullptr,UINT32_MAX};require(dmg_result_get_binding_path(output,i,j,&invalid,sizeof(invalid)-1)==DMG_INVALID_ARGUMENT&&invalid.sides==nullptr&&invalid.length==UINT32_MAX);}
        }
        {dmg_binding_path invalid{nullptr,UINT32_MAX};require(dmg_result_get_binding_path(output,i,bindings,&invalid,sizeof(invalid))==DMG_INVALID_ARGUMENT&&invalid.sides==nullptr&&invalid.length==UINT32_MAX);}
        uint32_t links=0;require(dmg_result_get_link_count(output,i,&links)==DMG_OK);
        for(uint32_t j=0;j<links;++j){dmg_relation_link link{};require(dmg_result_get_link(output,i,j,&link,sizeof(link))==DMG_OK);
            require(graph_status==DMG_OK&&link.node_id<graph.operator_count&&link.key<=DMG_JOIN_SYMBOL&&link.left_source<2&&link.right_source<2&&link.left_relation<=DMG_TYPE_REFS&&link.right_relation<=DMG_TYPE_REFS);
            if(j==0){dmg_relation_link invalid{};invalid.node_id=UINT32_MAX;require(dmg_result_get_link(output,i,j,&invalid,sizeof(invalid)-1)==DMG_INVALID_ARGUMENT&&invalid.node_id==UINT32_MAX);}
        }
        {dmg_relation_link invalid{};invalid.node_id=UINT32_MAX;require(dmg_result_get_link(output,i,links,&invalid,sizeof(invalid))==DMG_INVALID_ARGUMENT&&invalid.node_id==UINT32_MAX);}
        uint32_t proofs=0;require(dmg_result_get_proof_binding_count(output,i,&proofs)==DMG_OK);
        for(uint32_t j=0;j<proofs;++j){dmg_proof_binding_row proof{};dmg_binding_path proof_path{};
            require(dmg_result_get_proof_binding(output,i,j,&proof,sizeof(proof))==DMG_OK&&graph_status==DMG_OK&&proof.operator_node<graph.operator_count);
            entity(proof.binding.entity);if(proof.binding.label)string(proof.binding.label,64);
            require(dmg_result_get_proof_binding_path(output,i,j,&proof_path,sizeof(proof_path))==DMG_OK);path(proof_path);
            if(j==0){dmg_proof_binding_row invalid{};invalid.operator_node=UINT32_MAX;require(dmg_result_get_proof_binding(output,i,j,&invalid,sizeof(invalid)-1)==DMG_INVALID_ARGUMENT&&invalid.operator_node==UINT32_MAX);
                dmg_binding_path invalid_path{nullptr,UINT32_MAX};require(dmg_result_get_proof_binding_path(output,i,j,&invalid_path,sizeof(invalid_path)-1)==DMG_INVALID_ARGUMENT&&invalid_path.sides==nullptr&&invalid_path.length==UINT32_MAX);}
        }
        {dmg_proof_binding_row invalid{};invalid.operator_node=UINT32_MAX;require(dmg_result_get_proof_binding(output,i,proofs,&invalid,sizeof(invalid))==DMG_INVALID_ARGUMENT&&invalid.operator_node==UINT32_MAX);
            dmg_binding_path invalid_path{nullptr,UINT32_MAX};require(dmg_result_get_proof_binding_path(output,i,proofs,&invalid_path,sizeof(invalid_path))==DMG_INVALID_ARGUMENT&&invalid_path.sides==nullptr&&invalid_path.length==UINT32_MAX);}
        require(dmg_result_get_witness_count(output,i,&witnesses)==DMG_OK);
        for(uint32_t j=0;j<witnesses;++j){dmg_relation_witness witness{};
            require(dmg_result_get_relation_witness(output,i,j,&witness,sizeof(witness))==DMG_OK&&witness.source_index<2&&witness.relation<=DMG_TYPE_REFS&&witness.witness.matched<=DMG_MATCH_UNKNOWN);
        }
    }
}
void value_v2(const dmg_value_row_v2& row){
    require(row.kind==DMG_VALUE_ENTITY||row.kind==DMG_VALUE_USE);
    if(row.kind==DMG_VALUE_ENTITY){entity(row.entity);return;}
    const auto& use=row.use;
    require(use.relation>=DMG_STRING_USES&&use.relation<=DMG_FIELD_USES&&use.source_index<2&&use.dex_pc!=UINT32_MAX);
    require(use.target_domain<=DMG_TARGET_CALL_SITE&&use.opcode<=255);
    // The right-hand fixed input is method-uses.dex. Check its event identity
    // against its known instructions, independently of relation operators.
    if(use.source_index==1){
        require(use.caller_ordinal==2&&use.caller_method_ref==3&&use.code_offset==416);
        if(use.relation==DMG_STRING_USES)require(use.dex_pc==0&&use.opcode==0x1a&&use.target_domain==DMG_TARGET_STRING_VALUE&&use.target_index==10);
        if(use.relation==DMG_INVOKE_SITES)require(use.dex_pc==2&&use.opcode==0x71&&use.target_domain==DMG_TARGET_METHOD_REF&&use.target_index==4);
        if(use.relation==DMG_FIELD_USES)require(use.dex_pc==5&&use.opcode==0x60&&use.target_domain==DMG_TARGET_FIELD_REF&&use.target_index==0);
    }
    units(use.owner,use.owner_length);units(use.name,use.name_length);units(use.prototype,use.prototype_length);
}
void identity_v2(const dmg_value_identity_v2& id){
    require(id.relation<=DMG_FIELD_USES&&id.source_index<2);
    require(id.relation<=DMG_TYPE_REFS?id.dex_pc==UINT32_MAX:id.dex_pc!=UINT32_MAX);
}
void result(dmg_result* output){
    dmg_relation_info legacy{};
    const auto old_status=dmg_result_get_relation_info(output,&legacy,sizeof(legacy));
    require(old_status==DMG_OK||old_status==DMG_UNSUPPORTED);
    if(old_status==DMG_OK){legacy_result(output);return;}
    dmg_relation_info_v2 info{};
    require(dmg_result_get_relation_info_v2(output,&info,sizeof(info))==DMG_OK);
    require(info.relation<=DMG_FIELD_USES&&info.entity_visited<=info.entity_total&&info.method_visited<=info.method_total);
    dmg_query_info query{};require(dmg_result_get_query_info(output,&query)==DMG_OK&&info.candidates_count<=query.max_results);
    dmg_graph_info graph{};const auto graph_status=dmg_result_get_graph_info(output,&graph,sizeof(graph));
    require(graph_status==DMG_OK||graph_status==DMG_UNSUPPORTED);
    if(graph_status==DMG_OK){
        require(graph.operator_count>0&&graph.operator_count<=128);
        for(uint32_t i=0;i<graph.operator_count;++i){dmg_operator_profile_v2 op{};
            require(dmg_result_get_operator_profile_v2(output,i,&op,sizeof(op))==DMG_OK);
            require(op.op<=DMG_REL_SEMI_JOIN&&op.scan_domain<=DMG_SCAN_DOMAIN_METHOD_DEFS&&op.unknown_rows<=op.output_rows&&op.visited<=op.total);
        }
    }
    for(uint32_t i=0;i<info.candidates_count;++i){
        dmg_value_row_v2 row{};require(dmg_result_get_value_v2(output,i,&row,sizeof(row))==DMG_OK);value_v2(row);
        dmg_source_info origin{};require(dmg_result_get_origin(output,i,&origin)==DMG_OK);
        require(origin.source_index==(row.kind==DMG_VALUE_USE?row.use.source_index:row.entity.source_index));
        string(origin.dex.source_sha256,64);string(origin.slot_key,5);
        uint32_t count=0;require(dmg_result_get_binding_count(output,i,&count)==DMG_OK);
        for(uint32_t j=0;j<count;++j){dmg_binding_row_v2 binding{};dmg_binding_path p{};
            require(dmg_result_get_binding_v2(output,i,j,&binding,sizeof(binding))==DMG_OK);value_v2(binding.value);if(binding.label)string(binding.label,64);
            require(dmg_result_get_binding_path(output,i,j,&p,sizeof(p))==DMG_OK);path(p);
        }
        require(dmg_result_get_proof_binding_count(output,i,&count)==DMG_OK);
        for(uint32_t j=0;j<count;++j){dmg_proof_binding_row_v2 proof{};dmg_binding_path p{};
            require(dmg_result_get_proof_binding_v2(output,i,j,&proof,sizeof(proof))==DMG_OK&&graph_status==DMG_OK&&proof.operator_node<graph.operator_count);
            value_v2(proof.binding.value);if(proof.binding.label)string(proof.binding.label,64);
            require(dmg_result_get_proof_binding_path(output,i,j,&p,sizeof(p))==DMG_OK);path(p);
        }
        require(dmg_result_get_link_count(output,i,&count)==DMG_OK);
        for(uint32_t j=0;j<count;++j){dmg_relation_link_v2 link{};
            require(dmg_result_get_link_v2(output,i,j,&link,sizeof(link))==DMG_OK&&graph_status==DMG_OK&&link.node_id<graph.operator_count&&link.key<=DMG_JOIN_TARGET_REF);
            identity_v2(link.left);identity_v2(link.right);
        }
        require(dmg_result_get_witness_count(output,i,&count)==DMG_OK);
        for(uint32_t j=0;j<count;++j){dmg_relation_witness_v2 witness{};
            require(dmg_result_get_relation_witness_v2(output,i,j,&witness,sizeof(witness))==DMG_OK&&witness.witness.matched<=DMG_MATCH_UNKNOWN);
            identity_v2(witness.entity);
        }
    }
}
}
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data,size_t size){
    if(size>65536)return 0;
#if defined(DMG_FUZZ_USE_SCAN)
    Account account(8u<<20,0);
    AccountResource metadata_memory(account,MemoryKind::facts),scratch_memory(account,MemoryKind::scratch);
    const std::span<const uint8_t> bytes(data,size);const UseScanLimits limits{100000,4096};
    try{
        auto metadata=read_metadata(bytes,&metadata_memory);
        for(const auto kind:{UseKind::string_use,UseKind::invoke_site,UseKind::field_use}){
            UseScanProgress progress{};
            try{
                const auto result=collect_uses(bytes,metadata,0,kind,progress,&scratch_memory,limits);
                use_progress(progress,metadata,bytes,limits);
                use_require(progress.attempted_methods==progress.total_methods&&progress.visited_methods==progress.total_methods);
                use_require(progress.emitted_events==result.rows.size()&&progress.work_units==uint64_t(progress.attempted_methods)+progress.validation_work+progress.emitted_events);
                const UseRecord* previous=nullptr;
                for(const auto& record:result.rows){
                    use_record(record,kind,metadata,bytes);
                    if(previous)use_require(previous->key.caller_ordinal<record.key.caller_ordinal||
                        (previous->key.caller_ordinal==record.key.caller_ordinal&&previous->key.dex_pc<record.key.dex_pc));
                    previous=&record;
                }
            }catch(const UseScanError& error){use_failure(error);}
            catch(const instructions::DecodeError& error){decode_failure(error);}
            catch(const std::bad_alloc&){}
            use_progress(progress,metadata,bytes,limits);
            use_require(account.category(MemoryKind::scratch)==0);
        }
    }catch(const ReadError& error){read_failure(error);}
    catch(const std::bad_alloc&){}
    use_require(account.total()==0&&account.borrowed()==0&&account.category(MemoryKind::facts)==0&&account.category(MemoryKind::scratch)==0);
#elif defined(DMG_FUZZ_RELATIONAL)
    dmg_engine_options options{sizeof(options),DMG_ABI_VERSION,8u<<20,0,65536,1,0};
    dmg_engine* engine=nullptr;dmg_error error{};require(dmg_engine_create(&options,&engine,&error)==DMG_OK);
    dmg_engine_stats baseline{};require(dmg_engine_get_stats(engine,&baseline)==DMG_OK);
    dmg_query* query=nullptr;dmg_snapshot* snapshot=nullptr;dmg_result* output=nullptr;
    const auto compiled=dmg_query_compile_json(engine,data,size,&query,&error);
    if(compiled==DMG_OK){
        require(query!=nullptr);
        const dmg_source_spec sources[]={
            {sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,dmg_fuzz_fixtures::definitions,sizeof(dmg_fuzz_fixtures::definitions),"left","base",dmg_fuzz_fixtures::definitions_sha256},
            {sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,dmg_fuzz_fixtures::method_uses,sizeof(dmg_fuzz_fixtures::method_uses),"right","code-split",dmg_fuzz_fixtures::method_uses_sha256}
        };
        const dmg_source_set_options source_options{sizeof(source_options),DMG_ABI_VERSION,"relational-fuzz",1,2,65536};
        const auto opened=dmg_snapshot_open_sources(engine,sources,2,&source_options,&snapshot,&error);
        if(opened==DMG_OK){
            require(snapshot!=nullptr);const auto executed=dmg_query_execute(snapshot,query,&output,&error);
            if(executed==DMG_OK){
                require(output!=nullptr);dmg_snapshot_release(snapshot);snapshot=nullptr;dmg_query_release(query);query=nullptr;
                result(output);dmg_result_release(output);output=nullptr;
            }else require(query_failure(executed)&&output==nullptr);
        }else require((opened==DMG_BUDGET_EXCEEDED||opened==DMG_OUT_OF_MEMORY)&&snapshot==nullptr);
    }else require(query_failure(compiled)&&query==nullptr);
    if(snapshot)dmg_snapshot_release(snapshot);if(query)dmg_query_release(query);
    dmg_engine_stats after{};require(dmg_engine_get_stats(engine,&after)==DMG_OK&&same_live(after,baseline));dmg_engine_release(engine);
#elif defined(DMG_FUZZ_QUERY)
    dmg_engine_options options{sizeof(options),DMG_ABI_VERSION,8u<<20,0,65536,1,0};
    dmg_engine* engine=nullptr;dmg_error error{};if(dmg_engine_create(&options,&engine,&error)!=DMG_OK)std::abort();
    dmg_engine_stats before{};dmg_engine_get_stats(engine,&before);dmg_query* query=nullptr;
    const auto status=dmg_query_compile_json(engine,data,size,&query,&error);
    if(status==DMG_INTERNAL_ERROR)std::abort();
    if(status==DMG_OK){dmg_query_info info{};if(dmg_query_get_info(query,&info)!=DMG_OK||!info.query_id||!info.node_count)std::abort();dmg_query_release(query);}
    else if(query)std::abort();
    dmg_engine_stats after{};dmg_engine_get_stats(engine,&after);if(after.owned_bytes!=before.owned_bytes)std::abort();dmg_engine_release(engine);
#elif defined(DMG_FUZZ_DEX)
    dmg_engine_options engine_options{sizeof(engine_options),DMG_ABI_VERSION,8u<<20,0,65536,1,0};
    dmg_engine* engine=nullptr;dmg_error error{};
    if(dmg_engine_create(&engine_options,&engine,&error)!=DMG_OK)std::abort();
    dmg_engine_stats baseline{};dmg_engine_get_stats(engine,&baseline);
    dmg_open_options options{sizeof(options),DMG_ABI_VERSION,65536,"fuzz","seed",nullptr};
    dmg_snapshot* snapshot=nullptr;
    const auto status=dmg_snapshot_open_copy_in(engine,data,size,&options,&snapshot,&error);
    if(status==DMG_INTERNAL_ERROR)std::abort();
    if(status==DMG_OK){
        dmg_method_query q{};q.struct_size=sizeof(q);q.abi_version=DMG_ABI_VERSION;q.max_results=16;
        dmg_result* result=nullptr;const auto query_status=dmg_query_methods(snapshot,&q,&result,&error);
        if(query_status==DMG_INTERNAL_ERROR)std::abort();
        dmg_snapshot_release(snapshot);
        if(result){dmg_result_info info{};if(dmg_result_get_info(result,&info)!=DMG_OK)std::abort();dmg_result_release(result);}
    }else if(snapshot)std::abort();
    dmg_engine_stats after{};dmg_engine_get_stats(engine,&after);
    if(after.owned_bytes!=baseline.owned_bytes||after.borrowed_bytes)std::abort();
    dmg_engine_release(engine);
#elif defined(DMG_FUZZ_CODE)
    dexmeguviz::Account account(2u<<20,0);
    dexmeguviz::AccountResource memory(account,dexmeguviz::MemoryKind::facts);
    try{
        dexmeguviz::instructions::DecodeInput input{{data,size},0,40,{2048,2048,2048,2048,2048,2048,2048},size};
        dexmeguviz::instructions::DecodeOptions options;
        options.demand_mask=7;options.max_code_units=4096;options.max_instructions=4096;
        options.max_payload_elements=4096;options.max_exception_items=4096;
        {auto result=dexmeguviz::instructions::decode(input,options,&memory);}
    }catch(const dexmeguviz::instructions::DecodeError&){}
    catch(const std::bad_alloc&){}
    if(account.total())std::abort();
#elif defined(DMG_FUZZ_ARCHIVE)
    dexmeguviz::Account account(4u<<20,0);
    dexmeguviz::AccountResource memory(account,dexmeguviz::MemoryKind::source);
    dexmeguviz::archive::Limits limits;
    limits.max_archive_bytes=65536;limits.max_entries=512;limits.max_central_directory_bytes=32768;
    limits.max_name_bytes=4096;limits.max_total_name_bytes=8192;
    limits.max_entry_output_bytes=262144;limits.max_total_output_bytes=262144;limits.chunk_bytes=4096;
    try{{auto entries=dexmeguviz::archive::read({data,size},limits,&memory);}}
    catch(const dexmeguviz::archive::Error& e){if(e.status==dexmeguviz::archive::Status::internal_error)std::abort();}
    catch(const std::bad_alloc&){}
    if(account.total())std::abort();
#endif
    return 0;
}
