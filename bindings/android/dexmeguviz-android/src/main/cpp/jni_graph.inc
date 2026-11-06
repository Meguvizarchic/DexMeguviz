// Private versioned wire representation for synchronous v3 metadata graphs.
// It is not an exported persistence format; both endpoints ship together.
namespace {
struct GraphError { dmg_status status; };
struct GraphWriter {
    static constexpr size_t limit=8u*1024u*1024u;
    static constexpr uint64_t text_limit=1048576;
    static constexpr uint32_t item_limit=100000;
    std::vector<uint8_t> data;
    uint64_t text_units=0;
    uint32_t items=0;
    void reserve(size_t n){if(n>limit-data.size())throw GraphError{DMG_BUDGET_EXCEEDED};}
    void item(uint32_t count){if(count>item_limit-items)throw GraphError{DMG_BUDGET_EXCEEDED};items+=count;}
    void u32(uint32_t v){reserve(4);for(unsigned i=0;i<4;++i)data.push_back(static_cast<uint8_t>(v>>(i*8)));}
    void u64(uint64_t v){if(v>uint64_t(std::numeric_limits<jlong>::max()))throw GraphError{DMG_BUDGET_EXCEEDED};reserve(8);for(unsigned i=0;i<8;++i)data.push_back(static_cast<uint8_t>(v>>(i*8)));}
    void ascii(const char* p){if(!p){u32(UINT32_MAX);return;}size_t n=0;while(n<=1024&&p[n]){if(static_cast<unsigned char>(p[n])>0x7f)throw GraphError{DMG_UNSUPPORTED};++n;}if(n>1024)throw GraphError{DMG_BUDGET_EXCEEDED};u32(static_cast<uint32_t>(n));reserve(n);for(size_t i=0;i<n;++i)data.push_back(static_cast<uint8_t>(p[i]));}
    void text(bool present,const uint16_t* p,uint64_t n){if(!present){u32(UINT32_MAX);return;}if((!p&&n)||n>text_limit-text_units)throw GraphError{static_cast<dmg_status>(!p&&n?DMG_INTERNAL_ERROR:DMG_BUDGET_EXCEEDED)};text_units+=n;u32(static_cast<uint32_t>(n));reserve(static_cast<size_t>(n)*2);for(uint64_t i=0;i<n;++i){data.push_back(static_cast<uint8_t>(p[i]));data.push_back(static_cast<uint8_t>(p[i]>>8));}}
    void path(const dmg_binding_path& p){if(p.length>32||(!p.sides&&p.length))throw GraphError{DMG_INTERNAL_ERROR};u32(p.length);reserve(p.length);for(uint32_t i=0;i<p.length;++i){if(p.sides[i]>1)throw GraphError{DMG_INTERNAL_ERROR};data.push_back(p.sides[i]);}}
    void entity(const dmg_entity_row& e,uint32_t mask,uint32_t source_count){
        if(e.relation>DMG_TYPE_REFS||e.source_index>=source_count||e.definition_known>1||e.flags_known>1||e.code_known>1)throw GraphError{DMG_INTERNAL_ERROR};
        const uint32_t applicable=(e.relation==DMG_METHOD_DEFS||e.relation==DMG_METHOD_REFS)?7u:(e.relation==DMG_FIELD_DEFS||e.relation==DMG_FIELD_REFS)?11u:e.relation==DMG_STRING_VALUES?16u:8u;
        u32(e.relation);u32(e.source_index);u32(e.local_index);u32(e.reference_index);u32(e.record_offset);
        u32(e.definition_known);u32(e.definition_offset);u32(e.flags_known);u32(e.access_flags);u32(e.code_known);u32(e.code_offset);
        text((mask&applicable&1)!=0,e.owner,e.owner_length);text((mask&applicable&2)!=0,e.name,e.name_length);
        text((mask&applicable&4)!=0,e.prototype,e.prototype_length);text((mask&applicable&8)!=0,e.type_descriptor,e.type_descriptor_length);
        text((mask&applicable&16)!=0,e.string_value,e.string_value_length);
    }
};
void graph_ok(dmg_status status){if(status!=DMG_OK)throw GraphError{status};}
void graph_binding(GraphWriter& out,const dmg_result* result,uint32_t row,uint32_t index,bool proof,uint32_t sources){
    dmg_binding_row binding{};dmg_binding_path path{};uint32_t node=UINT32_MAX;
    if(proof){dmg_proof_binding_row b{};graph_ok(dmg_result_get_proof_binding(result,row,index,&b,sizeof(b)));binding=b.binding;node=b.operator_node;graph_ok(dmg_result_get_proof_binding_path(result,row,index,&path,sizeof(path)));}
    else {graph_ok(dmg_result_get_binding(result,row,index,&binding,sizeof(binding)));graph_ok(dmg_result_get_binding_path(result,row,index,&path,sizeof(path)));}
    out.u32(node);out.ascii(binding.label);out.path(path);out.entity(binding.entity,31,sources);
}
jbyteArray graph_result(JNIEnv* env,const dmg_result* result,bool source_set,bool annotation_wire=false){
    dmg_query_info query{};dmg_relation_info info{};dmg_snapshot_overview overview{};dmg_query_profile profile{};dmg_graph_info graph{};
    graph_ok(dmg_result_get_query_info(result,&query));graph_ok(dmg_result_get_relation_info(result,&info,sizeof(info)));
    graph_ok(dmg_result_get_overview(result,&overview));graph_ok(dmg_result_get_profile(result,&profile));graph_ok(dmg_result_get_graph_info(result,&graph,sizeof(graph)));
    if(!query.query_id||!overview.snapshot_id||overview.scope_complete||!overview.input_count||overview.input_count>max_raw_sources||overview.source_count>max_expanded_sources||(!source_set&&(overview.input_count!=1||overview.source_count!=1))||info.relation>DMG_TYPE_REFS||(annotation_wire?info.coverage>DMG_COVERAGE_PARTIAL:info.coverage!=DMG_COVERAGE_PARTIAL)||info.candidates_count>max_query_results||graph.operator_count>128)throw GraphError{DMG_INTERNAL_ERROR};
    GraphWriter w;w.u32(annotation_wire?0x35474d44:0x34474d44);w.u32(info.relation);w.u32(info.execution_status);w.u32(info.coverage);w.u32(info.decision);w.u32(info.reason);w.u32(info.visited_rows);w.u32(info.total_rows);w.u64(info.unknown_rows);
    w.u32(query.node_count);w.u32(query.required_capabilities);w.u32(query.demand_mask);w.u32(query.projection_mask);w.u32(query.intent);w.u32(query.max_results);w.u32(query.explicit_scope);w.u64(query.max_work);w.ascii(query.query_id);w.ascii(overview.snapshot_id);
    for(auto value:{profile.work_units,profile.fact_requests,profile.methods_decoded,profile.code_units,profile.string_pool_lookups,profile.invoke_sites,profile.field_uses,profile.declared_fields,profile.matches_seen,profile.sort_comparisons})w.u64(value);
    w.u32(profile.scope_source_count);w.u32(profile.scope_complete);w.u32(profile.order_verified);
    w.u32(graph.root_node);w.u32(graph.unique_identity);w.u32(graph.identity_count);w.u32(graph.operator_count);
    for(uint32_t i=0;i<graph.operator_count;++i){dmg_operator_profile p{};graph_ok(dmg_result_get_operator_profile(result,i,&p,sizeof(p)));w.u32(p.node_id);w.u32(p.op);w.u64(p.input_rows);w.u64(p.output_rows);w.u64(p.unknown_rows);w.u64(p.visited_rows);w.u64(p.total_rows);w.u32(p.complete);}
    w.u32(overview.input_count);for(uint32_t i=0;i<overview.input_count;++i){dmg_input_info in{};graph_ok(dmg_result_get_input_info(result,i,&in));w.u32(in.input_index);w.u32(in.format);w.u32(in.allow_no_dex);w.u32(in.source_count);w.ascii(in.slot_key);w.ascii(in.role);w.ascii(in.source_sha256);w.ascii(in.content_id);w.u64(in.input_bytes);w.u32(in.expected_digest_verified);w.u32(in.container_metadata_checked);}
    w.u32(overview.source_count);for(uint32_t i=0;i<overview.source_count;++i){dmg_source_info s{};graph_ok(dmg_result_get_source_info(result,i,&s));w.u32(s.source_index);w.u32(s.input_index);w.ascii(s.slot_key);w.ascii(s.role);w.ascii(s.dex.source_sha256);w.ascii(s.dex.content_id);w.ascii(s.dex.occurrence_id);w.ascii(s.logical_dex_id);w.ascii(s.archive_entry_index==UINT32_MAX?nullptr:s.archive_sha256);w.ascii(s.archive_entry_index==UINT32_MAX?nullptr:s.archive_entry_name);w.u32(s.archive_entry_index);w.u32(s.crc_verified);w.u32(s.header_consistency_verified);w.u32(s.expected_digest_verified);w.u64(s.dex.source_bytes);for(auto value:{s.dex.dex_version,s.dex.string_count,s.dex.type_count,s.dex.class_count,s.dex.method_ref_count,s.dex.method_def_count})w.u32(value);}
    if(profile.scope_source_count>overview.source_count)throw GraphError{DMG_INTERNAL_ERROR};for(uint32_t i=0;i<profile.scope_source_count;++i){uint32_t s=0;graph_ok(dmg_result_get_scope_source(result,i,&s));if(s>=overview.source_count)throw GraphError{DMG_INTERNAL_ERROR};w.u32(s);}
    w.u32(info.candidates_count);w.item(info.candidates_count);
    for(uint32_t i=0;i<info.candidates_count;++i){dmg_entity_row entity{};graph_ok(dmg_result_get_entity(result,i,&entity,sizeof(entity)));w.entity(entity,query.projection_mask,overview.source_count);
        uint32_t n=0;graph_ok(dmg_result_get_binding_count(result,i,&n));w.item(n);w.u32(n);for(uint32_t j=0;j<n;++j)graph_binding(w,result,i,j,false,overview.source_count);
        graph_ok(dmg_result_get_proof_binding_count(result,i,&n));w.item(n);w.u32(n);for(uint32_t j=0;j<n;++j)graph_binding(w,result,i,j,true,overview.source_count);
        graph_ok(dmg_result_get_link_count(result,i,&n));w.item(n);w.u32(n);for(uint32_t j=0;j<n;++j){dmg_relation_link link{};graph_ok(dmg_result_get_link(result,i,j,&link,sizeof(link)));for(auto v:{link.node_id,link.key,link.left_source,link.left_relation,link.left_local,link.right_source,link.right_relation,link.right_local})w.u32(v);}
        graph_ok(dmg_result_get_witness_count(result,i,&n));w.item(n);w.u32(n);for(uint32_t j=0;j<n;++j){
            dmg_class_annotation_flags_witness_v1 detail{};const auto ds=annotation_wire?dmg_result_get_class_annotation_flags_witness_v1(result,i,j,&detail,sizeof(detail)):DMG_UNSUPPORTED;
            if(ds==DMG_OK){
                if(detail.source_index>=overview.source_count||detail.source_kind>DMG_CLASS_FLAGS_INNER_INT||detail.matched>DMG_MATCH_UNKNOWN)throw GraphError{DMG_INTERNAL_ERROR};
                for(auto v:{uint32_t(DMG_WITNESS_CLASS_ANNOTATION_FLAGS),detail.node_id,detail.matched,UINT32_MAX,0u,UINT32_MAX,0u,UINT32_MAX,0u,detail.operator_node,detail.source_index,uint32_t(DMG_CLASS_DEFS),detail.class_ordinal})w.u32(v);
                w.u32(1);for(auto v:{detail.source_kind,detail.directory_offset,detail.set_offset,detail.item_offset,detail.value_offset,detail.raw_flags,detail.encoded_flags,detail.projected_flags})w.u32(v);
            }else{
                if(ds!=DMG_UNSUPPORTED)throw GraphError{ds};dmg_relation_witness witness{};graph_ok(dmg_result_get_relation_witness(result,i,j,&witness,sizeof(witness)));const auto& x=witness.witness;
                for(auto v:{x.kind,x.node_id,x.matched,x.dex_pc,x.opcode,x.reference_index,x.reference_kind,x.extra_proto,x.code_units,witness.operator_node,witness.source_index,witness.relation,witness.local_index})w.u32(v);
                if(annotation_wire)w.u32(0);
            }
        }
    }
    if(w.data.size()>static_cast<size_t>(std::numeric_limits<jsize>::max()))throw GraphError{DMG_BUDGET_EXCEEDED};
    auto output=env->NewByteArray(static_cast<jsize>(w.data.size()));if(!output||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
    if(!w.data.empty())env->SetByteArrayRegion(output,0,static_cast<jsize>(w.data.size()),reinterpret_cast<const jbyte*>(w.data.data()));
    return env->ExceptionCheck()?nullptr:output;
}
}
extern "C" JNIEXPORT jbyteArray JNICALL Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryGraph(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set) noexcept {
    try{
        if(!input){java_exception(env,"java/lang/NullPointerException","queryJson is required");return nullptr;}
        const auto owner=lookup(token);if(!owner){native_failure(env,DMG_CLOSED);return nullptr;}
        if(owner->source_set!=(source_set==JNI_TRUE)){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        const auto size=env->GetArrayLength(input);if(env->ExceptionCheck())return nullptr;if(static_cast<uint64_t>(size)>max_query_bytes){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        std::vector<uint8_t> json(static_cast<size_t>(size));if(size)env->GetByteArrayRegion(input,0,size,reinterpret_cast<jbyte*>(json.data()));if(env->ExceptionCheck())return nullptr;
        dmg_error error{};dmg_query* raw_query=nullptr;auto status=dmg_query_compile_json(owner->engine,json.data(),json.size(),&raw_query,&error);
        if(status!=DMG_OK){if(raw_query)dmg_query_release(raw_query);native_failure(env,status,&error);return nullptr;}if(!raw_query){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        std::unique_ptr<dmg_query,QueryDeleter> query(raw_query);dmg_query_info qi{};graph_ok(dmg_query_get_info(query.get(),&qi));

        if(!graph_query_supported(qi)){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        if(qi.max_results>max_query_results||qi.max_work>max_query_work){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        dmg_result* raw=nullptr;error={};status=dmg_query_execute(owner->snapshot,query.get(),&raw,&error);if(status!=DMG_OK){if(raw)dmg_result_release(raw);native_failure(env,status,&error);return nullptr;}if(!raw){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        std::unique_ptr<dmg_result,ResultDeleter> result(raw);return graph_result(env,result.get(),source_set==JNI_TRUE);
    }catch(const GraphError& e){native_failure(env,e.status);}catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}

// Separate opt-in keeps old graph/Job profile acceptance and wire unchanged.
extern "C" JNIEXPORT jbyteArray JNICALL Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryClassAnnotationGraph(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set) noexcept {
    try{
        if(!input){java_exception(env,"java/lang/NullPointerException","queryJson is required");return nullptr;}
        const auto owner=lookup(token);if(!owner){native_failure(env,DMG_CLOSED);return nullptr;}
        if(owner->source_set!=(source_set==JNI_TRUE)){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        const auto size=env->GetArrayLength(input);if(env->ExceptionCheck())return nullptr;if(static_cast<uint64_t>(size)>max_query_bytes){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        std::vector<uint8_t> json(static_cast<size_t>(size));if(size)env->GetByteArrayRegion(input,0,size,reinterpret_cast<jbyte*>(json.data()));if(env->ExceptionCheck())return nullptr;
        dmg_error error{};dmg_query* raw_query=nullptr;auto status=dmg_query_compile_json(owner->engine,json.data(),json.size(),&raw_query,&error);
        if(status!=DMG_OK){if(raw_query)dmg_query_release(raw_query);native_failure(env,status,&error);return nullptr;}if(!raw_query){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        std::unique_ptr<dmg_query,QueryDeleter> query(raw_query);dmg_query_info qi{};graph_ok(dmg_query_get_info(query.get(),&qi));
        constexpr uint32_t required=536870912u|2097152u|4194304u|512u;
        constexpr uint32_t allowed=required|1u|2u|4u|8u|16u|32u|64u|128u|256u|1024u|2048u|33554432u;
        if(!qi.query_id||!std::string_view(qi.query_id).starts_with("query:v20:")||(qi.required_capabilities&required)!=required||(qi.required_capabilities&~allowed)||(qi.demand_mask&~7u)){
            native_failure(env,DMG_UNSUPPORTED);return nullptr;
        }
        if(qi.max_results>max_query_results||qi.max_work>max_query_work){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        dmg_result* raw=nullptr;error={};status=dmg_query_execute(owner->snapshot,query.get(),&raw,&error);if(status!=DMG_OK){if(raw)dmg_result_release(raw);native_failure(env,status,&error);return nullptr;}if(!raw){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        std::unique_ptr<dmg_result,ResultDeleter> result(raw);return graph_result(env,result.get(),source_set==JNI_TRUE,true);
    }catch(const GraphError& e){native_failure(env,e.status);}catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}




// Keep the consumer lock through native serialization, Java decode and poll
// construction. A consumed batch that fails in any stage poisons the stream.
extern "C" JNIEXPORT jobject JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeGraphJobNext(JNIEnv* env,jclass,jlong token,jint timeout_ms) noexcept {
    try {
        if(timeout_ms<0||timeout_ms>max_job_wait_ms){java_exception(env,"java/lang/IllegalArgumentException","invalid wait timeout");return nullptr;}
        const auto job=lookup_job(token);if(!job){native_failure(env,DMG_CLOSED);return nullptr;}
        if(!job->graph){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        if(job->delivery_failed.load(std::memory_order_acquire)){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        std::unique_lock lock(job->consumer,std::try_to_lock);
        if(!lock.owns_lock()){java_exception(env,"java/lang/IllegalStateException","only one batch consumer is allowed");return nullptr;}
        if(job->delivery_failed.load(std::memory_order_acquire)){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        dmg_batch* raw=nullptr;dmg_error error{};
        const auto status=dmg_job_next(job->job,static_cast<uint32_t>(timeout_ms),&raw,&error);
        std::unique_ptr<dmg_result,ResultDeleter> batch(raw);
        jint kind=0;jobject copied=nullptr;
        if(status==DMG_NOT_READY)kind=1;
        else if(status==DMG_END_OF_STREAM)kind=2;
        else if(status!=DMG_OK){native_failure(env,status,&error);return nullptr;}
        else if(!batch){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        else {
            try {
                const auto bytes=graph_result(env,batch.get(),job->owner->source_set);
                if(bytes&&!env->ExceptionCheck()) {
                    const auto cls=env->FindClass("io/github/jichuo1/dexmeguviz/GraphResult");
                    const auto decode=cls&&!env->ExceptionCheck()?env->GetStaticMethodID(cls,"decode","([B)Lio/github/jichuo1/dexmeguviz/GraphResult;"):nullptr;
                    if(decode&&!env->ExceptionCheck())copied=env->CallStaticObjectMethod(cls,decode,bytes);
                }
                if(!copied||env->ExceptionCheck()) {
                    job->delivery_failed.store(true,std::memory_order_release);dmg_job_cancel(job->job);
                    if(!env->ExceptionCheck())native_failure(env,DMG_INTERNAL_ERROR);return nullptr;
                }
            } catch(...) {
                job->delivery_failed.store(true,std::memory_order_release);dmg_job_cancel(job->job);throw;
            }
        }
        const auto cls=env->FindClass("io/github/jichuo1/dexmeguviz/NativeEngine$GraphJobPoll");
        const auto ctor=cls&&!env->ExceptionCheck()?env->GetMethodID(cls,"<init>","(ILio/github/jichuo1/dexmeguviz/GraphResult;)V"):nullptr;
        jobject value=nullptr;if(ctor&&!env->ExceptionCheck())value=env->NewObject(cls,ctor,kind,copied);
        if(!value||env->ExceptionCheck()) {
            if(batch){job->delivery_failed.store(true,std::memory_order_release);dmg_job_cancel(job->job);}
            if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;
        }
        return value;
    }catch(const GraphError& e){native_failure(env,e.status);}catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}

