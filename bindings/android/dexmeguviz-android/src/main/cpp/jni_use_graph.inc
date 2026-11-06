// Private tagged wire: v1 for v4/v9/v16, v2 for v18 inherited evidence.
namespace {
constexpr uint32_t use_caps = 1u|2u|4u|8u|16u|32u|64u|128u|256u|512u|1024u|2048u|4096u|16384u|131072u|16777216u|67108864u;
bool use_graph_supported(const dmg_query_info& q) {
    if (!q.query_id || (q.required_capabilities & ~use_caps) || (q.demand_mask & ~7u)) return false;
    const std::string_view id(q.query_id);
    const bool v18=id.substr(0,10)=="query:v18:" && (q.required_capabilities & (16384u|16777216u|67108864u))==(16384u|16777216u|67108864u) && !(q.required_capabilities&131072u);
    if ((q.explicit_scope || (q.required_capabilities & 8u)) && !v18) return false;
    const bool v4=id.substr(0,9)=="query:v4:" && !(q.required_capabilities&(131072u|16384u|67108864u));
    const bool v9=id.substr(0,9)=="query:v9:" && (q.required_capabilities&131072u) && !(q.required_capabilities&(16384u|67108864u));
    const bool v16=id.substr(0,10)=="query:v16:" && (q.required_capabilities&16777216u) && !(q.required_capabilities&(131072u|16384u|67108864u));
    return v4 || v9 || v16 || v18;
}
// Explicit v6 use-graph entry; old v4/v9/v16/v18 entry remains unchanged.
bool inherited_use_graph_supported(const dmg_query_info& q) {
    constexpr uint32_t caps=1u|2u|4u|8u|16u|32u|64u|128u|256u|512u|1024u|2048u|4096u|16384u;
    return q.query_id && std::string_view(q.query_id).starts_with("query:v6:") &&
        (q.required_capabilities&(16384u|4096u))==(16384u|4096u) &&
        !(q.required_capabilities&~caps) && q.demand_mask && !(q.demand_mask&~7u);
}
// Explicit v8/v11 interface inheritance with use events; old entries stay unchanged.
bool interface_use_graph_supported(const dmg_query_info& q) {
    constexpr uint32_t common=1u|2u|4u|8u|16u|32u|64u|128u|256u|512u|1024u|2048u|4096u;
    if(!q.query_id || !(q.required_capabilities&4096u) || !q.demand_mask || (q.demand_mask&~7u))return false;
    const std::string_view id(q.query_id);
    const uint32_t bit=id.starts_with("query:v8:")?65536u:id.starts_with("query:v11:")?524288u:0u;
    return bit && (q.required_capabilities&bit) && !(q.required_capabilities&~(common|bit));
}
// Separate opt-in: a top-level explicit static scope and v4 use graph only.
bool scoped_v4_use_graph_supported(const dmg_query_info& q) {
    if(!q.query_id || !q.explicit_scope || !(q.required_capabilities&8u) ||
       (q.required_capabilities&~use_caps) || (q.demand_mask&~7u)) return false;
    return std::string_view(q.query_id).substr(0,9)=="query:v4:" &&
           !(q.required_capabilities&(131072u|16384u|67108864u|16777216u));
}
bool field_declaration_use_graph_supported(const dmg_query_info& q) {
    constexpr uint32_t caps=1u|2u|4u|8u|128u|512u|2048u|4096u|134217728u;
    return q.query_id && std::string_view(q.query_id).substr(0,10)=="query:v19:" && q.explicit_scope &&
           (q.required_capabilities&134217728u) && !(q.required_capabilities&~caps) && !(q.demand_mask&~4u);
}
bool caller_field_relation_graph_supported(const dmg_query_info& q) {
    constexpr uint32_t caps=1u|2u|4u|8u|128u|512u|2048u|4096u|134217728u|268435456u;
    return q.query_id && std::string_view(q.query_id).substr(0,10)=="query:v19:" && q.explicit_scope &&
           (q.required_capabilities&134217728u) && (q.required_capabilities&268435456u) &&
           (q.required_capabilities&2048u) && !(q.required_capabilities&~caps) && !(q.demand_mask&~4u);
}
bool type_use_graph_supported(const dmg_query_info& q){
    constexpr uint32_t caps=1u|2u|4u|8u|16u|256u|512u|1024u|2048u|4096u|1073741824u;
    return q.query_id && std::string_view(q.query_id).starts_with("query:v21:") &&
        (q.required_capabilities&1073741824u) && !(q.required_capabilities&~caps) && q.demand_mask==256u;
}
void use_identity(GraphWriter& w,const dmg_value_identity_v2& id,uint32_t sources,bool v21=false) {
    if(id.relation>(v21?DMG_TYPE_USES:DMG_FIELD_USES) || id.source_index>=sources ||
       (id.relation<=DMG_TYPE_REFS ? id.dex_pc!=UINT32_MAX : id.dex_pc==UINT32_MAX)) throw GraphError{DMG_INTERNAL_ERROR};
    w.u32(id.relation);w.u32(id.source_index);w.u32(id.local_index);w.u32(id.dex_pc);
}
void use_value(GraphWriter& w,const dmg_value_row_v2& value,uint32_t mask,uint32_t sources,bool v21=false,const uint16_t* target=nullptr,uint64_t target_length=0) {
    w.u32(value.kind);
    if(value.kind==DMG_VALUE_ENTITY) { w.entity(value.entity,mask,sources);return; }
    if(value.kind!=DMG_VALUE_USE)throw GraphError{DMG_INTERNAL_ERROR};
    const auto& u=value.use;
    const bool domain_ok=(u.relation==DMG_STRING_USES&&u.target_domain==DMG_TARGET_STRING_VALUE)||
        (u.relation==DMG_FIELD_USES&&u.target_domain==DMG_TARGET_FIELD_REF)||
        (v21&&u.relation==DMG_TYPE_USES&&u.target_domain==DMG_TARGET_TYPE_REF)||
        (u.relation==DMG_INVOKE_SITES&&(u.target_domain==DMG_TARGET_METHOD_REF||u.target_domain==DMG_TARGET_METHOD_AND_PROTO||u.target_domain==DMG_TARGET_CALL_SITE));
    if(!domain_ok||u.source_index>=sources||u.dex_pc==UINT32_MAX||
       ((u.target_domain==DMG_TARGET_METHOD_AND_PROTO)!=(u.extra_proto!=UINT32_MAX)))throw GraphError{DMG_INTERNAL_ERROR};
    for(auto x:{u.relation,u.source_index,u.caller_ordinal,u.caller_method_ref,u.dex_pc,u.opcode,u.code_offset,u.target_domain,u.target_index,u.extra_proto})w.u32(x);
    w.text((mask&DMG_PROJECT_OWNER)!=0,u.owner,u.owner_length);
    w.text((mask&DMG_PROJECT_NAME)!=0,u.name,u.name_length);
    w.text((mask&DMG_PROJECT_PROTOTYPE)!=0,u.prototype,u.prototype_length);
    if(v21){if(u.relation!=DMG_TYPE_USES||!target||!target_length)throw GraphError{DMG_INTERNAL_ERROR};w.text(true,target,target_length);}
}
void use_binding(GraphWriter& w,const dmg_result* result,uint32_t row,uint32_t index,bool proof,uint32_t sources,bool v21){
    dmg_binding_row_v2 binding{};dmg_binding_path path{};uint32_t node=UINT32_MAX;const uint16_t* target=nullptr;uint64_t target_length=0;
    if(proof){if(v21){dmg_proof_binding_row_v3 b{};graph_ok(dmg_result_get_proof_binding_v3(result,row,index,&b,sizeof(b)));binding.label=b.binding.label;binding.value=b.binding.value.value;target=b.binding.value.target_descriptor;target_length=b.binding.value.target_descriptor_length;node=b.operator_node;}
        else {dmg_proof_binding_row_v2 b{};graph_ok(dmg_result_get_proof_binding_v2(result,row,index,&b,sizeof(b)));binding=b.binding;node=b.operator_node;}graph_ok(dmg_result_get_proof_binding_path(result,row,index,&path,sizeof(path)));}
    else {if(v21){dmg_binding_row_v3 b{};graph_ok(dmg_result_get_binding_v3(result,row,index,&b,sizeof(b)));binding.label=b.label;binding.value=b.value.value;target=b.value.target_descriptor;target_length=b.value.target_descriptor_length;}
        else graph_ok(dmg_result_get_binding_v2(result,row,index,&binding,sizeof(binding)));graph_ok(dmg_result_get_binding_path(result,row,index,&path,sizeof(path)));}
    w.u32(node);w.ascii(binding.label);w.path(path);use_value(w,binding.value,31,sources,v21,target,target_length);
}
jbyteArray use_graph_result(JNIEnv* env,const dmg_result* result,bool source_set,int mode){
    dmg_query_info q{};dmg_relation_info_v2 info{};dmg_snapshot_overview overview{};dmg_query_profile profile{};dmg_graph_info graph{};
    graph_ok(dmg_result_get_query_info(result,&q));const bool v21=q.query_id&&std::string_view(q.query_id).starts_with("query:v21:");
    graph_ok(v21?dmg_result_get_relation_info_v3(result,&info,sizeof(info)):dmg_result_get_relation_info_v2(result,&info,sizeof(info)));
    graph_ok(dmg_result_get_overview(result,&overview));graph_ok(dmg_result_get_profile(result,&profile));graph_ok(dmg_result_get_graph_info(result,&graph,sizeof(graph)));
    const bool v18=q.query_id && std::string_view(q.query_id).substr(0,10)=="query:v18:";
    const bool v19=q.query_id && std::string_view(q.query_id).substr(0,10)=="query:v19:";
    const bool v6=q.query_id && std::string_view(q.query_id).starts_with("query:v6:");
    const bool v8=q.query_id && std::string_view(q.query_id).starts_with("query:v8:");
    const bool v11=q.query_id && std::string_view(q.query_id).starts_with("query:v11:");
    if((mode==1 && !scoped_v4_use_graph_supported(q)) || (mode==2 && !field_declaration_use_graph_supported(q)) || (mode==3 && !caller_field_relation_graph_supported(q)) || (mode==4 && !type_use_graph_supported(q)) || (mode==5 && !inherited_use_graph_supported(q)) || (mode==6 && !interface_use_graph_supported(q)))throw GraphError{DMG_INTERNAL_ERROR};
    if(!q.query_id||!overview.snapshot_id||overview.scope_complete||!overview.input_count||overview.input_count>max_raw_sources||overview.source_count>max_expanded_sources||
       (!source_set&&(overview.input_count!=1||overview.source_count!=1))||info.relation>(v21?DMG_TYPE_USES:DMG_FIELD_USES)||
       ((v18||mode!=0) ? info.coverage>DMG_COVERAGE_PARTIAL : info.coverage!=DMG_COVERAGE_PARTIAL)||
       info.candidates_count>max_query_results||graph.operator_count>128)throw GraphError{DMG_INTERNAL_ERROR};
    GraphWriter w;w.u32((v8||v11)?0x59474d44:v21?0x58474d44:v19?0x57474d44:(v18||v6)?0x56474d44:0x55474d44);w.u32(info.relation);w.u32(info.execution_status);w.u32(info.coverage);w.u32(info.decision);w.u32(info.reason);w.u32(info.candidates_count);
    for(auto x:{info.entity_visited,info.entity_total,info.method_visited,info.method_total,info.events_collected,info.unknown_rows})w.u64(x);
    w.u32(q.node_count);w.u32(q.required_capabilities);w.u32(q.demand_mask);w.u32(q.projection_mask);w.u32(q.intent);w.u32(q.max_results);w.u32(q.explicit_scope);w.u64(q.max_work);w.ascii(q.query_id);w.ascii(overview.snapshot_id);
    for(auto x:{profile.work_units,profile.fact_requests,profile.methods_decoded,profile.code_units,profile.string_pool_lookups,profile.invoke_sites,profile.field_uses,profile.declared_fields,profile.matches_seen,profile.sort_comparisons})w.u64(x);
    w.u32(profile.scope_source_count);w.u32(profile.scope_complete);w.u32(profile.order_verified);
    w.u32(graph.root_node);w.u32(graph.unique_identity);w.u32(graph.identity_count);w.u32(graph.operator_count);
    for(uint32_t i=0;i<graph.operator_count;++i){dmg_operator_profile_v2 op{};graph_ok(v21?dmg_result_get_operator_profile_v3(result,i,&op,sizeof(op)):dmg_result_get_operator_profile_v2(result,i,&op,sizeof(op)));w.u32(op.node_id);w.u32(op.op);w.u32(op.scan_domain);w.u32(op.complete);for(auto x:{op.input_rows,op.output_rows,op.unknown_rows,op.visited,op.total,op.attempted_methods,op.no_body_methods,op.decoded_methods,op.events_collected,op.code_units})w.u64(x);}
    w.u32(overview.input_count);for(uint32_t i=0;i<overview.input_count;++i){dmg_input_info in{};graph_ok(dmg_result_get_input_info(result,i,&in));w.u32(in.input_index);w.u32(in.format);w.u32(in.allow_no_dex);w.u32(in.source_count);w.ascii(in.slot_key);w.ascii(in.role);w.ascii(in.source_sha256);w.ascii(in.content_id);w.u64(in.input_bytes);w.u32(in.expected_digest_verified);w.u32(in.container_metadata_checked);}
    w.u32(overview.source_count);for(uint32_t i=0;i<overview.source_count;++i){dmg_source_info s{};graph_ok(dmg_result_get_source_info(result,i,&s));w.u32(s.source_index);w.u32(s.input_index);w.ascii(s.slot_key);w.ascii(s.role);w.ascii(s.dex.source_sha256);w.ascii(s.dex.content_id);w.ascii(s.dex.occurrence_id);w.ascii(s.logical_dex_id);w.ascii(s.archive_entry_index==UINT32_MAX?nullptr:s.archive_sha256);w.ascii(s.archive_entry_index==UINT32_MAX?nullptr:s.archive_entry_name);w.u32(s.archive_entry_index);w.u32(s.crc_verified);w.u32(s.header_consistency_verified);w.u32(s.expected_digest_verified);w.u64(s.dex.source_bytes);for(auto x:{s.dex.dex_version,s.dex.string_count,s.dex.type_count,s.dex.class_count,s.dex.method_ref_count,s.dex.method_def_count})w.u32(x);}
    if(profile.scope_source_count>overview.source_count)throw GraphError{DMG_INTERNAL_ERROR};for(uint32_t i=0;i<profile.scope_source_count;++i){uint32_t source=0;graph_ok(dmg_result_get_scope_source(result,i,&source));if(source>=overview.source_count)throw GraphError{DMG_INTERNAL_ERROR};w.u32(source);}
    w.u32(info.candidates_count);w.item(info.candidates_count);
    for(uint32_t i=0;i<info.candidates_count;++i){dmg_value_row_v2 value{};dmg_value_row_v3 value3{};
        if(v21){graph_ok(dmg_result_get_value_v3(result,i,&value3,sizeof(value3)));value=value3.value;}else graph_ok(dmg_result_get_value_v2(result,i,&value,sizeof(value)));
        use_value(w,value,q.projection_mask,overview.source_count,v21,value3.target_descriptor,value3.target_descriptor_length);
        uint32_t n=0;graph_ok(dmg_result_get_binding_count(result,i,&n));w.item(n);w.u32(n);for(uint32_t j=0;j<n;++j)use_binding(w,result,i,j,false,overview.source_count,v21);
        graph_ok(dmg_result_get_proof_binding_count(result,i,&n));w.item(n);w.u32(n);for(uint32_t j=0;j<n;++j)use_binding(w,result,i,j,true,overview.source_count,v21);
        graph_ok(dmg_result_get_link_count(result,i,&n));w.item(n);w.u32(n);for(uint32_t j=0;j<n;++j){dmg_relation_link_v2 link{};graph_ok(v21?dmg_result_get_link_v3(result,i,j,&link,sizeof(link)):dmg_result_get_link_v2(result,i,j,&link,sizeof(link)));w.u32(link.node_id);w.u32(link.key);use_identity(w,link.left,overview.source_count,v21);use_identity(w,link.right,overview.source_count,v21);}
        graph_ok(dmg_result_get_witness_count(result,i,&n));uint32_t baseCount=n;
        if(mode==3)for(uint32_t j=0;j<n;++j){dmg_caller_field_relation_witness_v1 extra{};const auto status=dmg_result_get_caller_field_relation_witness_v1(result,i,j,&extra,sizeof(extra));if(status==DMG_OK)--baseCount;else if(status!=DMG_UNSUPPORTED)throw GraphError{status};}
        w.item(baseCount);w.u32(baseCount);for(uint32_t j=0;j<n;++j){
            if(mode==3){dmg_caller_field_relation_witness_v1 extra{};const auto status=dmg_result_get_caller_field_relation_witness_v1(result,i,j,&extra,sizeof(extra));if(status==DMG_OK)continue;if(status!=DMG_UNSUPPORTED)throw GraphError{status};}
            dmg_field_declaration_witness_v1 d{};const auto ds=v19?dmg_result_get_field_declaration_witness_v1(result,i,j,&d,sizeof(d)):DMG_UNSUPPORTED;
            if(ds==DMG_OK){
                if(d.item_kind>1 || d.source_index>=overview.source_count || (d.item_kind==0 ? d.relation!=DMG_CLASS_DEFS : d.relation!=DMG_FIELD_DEFS))throw GraphError{DMG_INTERNAL_ERROR};
                for(auto v:{uint32_t(DMG_WITNESS_FIELD_DECLARATION),d.node_id,d.matched,UINT32_MAX,0u,UINT32_MAX,0u,UINT32_MAX,0u,d.operator_node})w.u32(v);
                use_identity(w,{d.relation,d.source_index,d.local_index,UINT32_MAX},overview.source_count);
                w.u32(1u);for(auto v:{d.item_kind,d.path_index,d.edge_kind,d.interface_index,d.detail})w.u32(v);
                continue;
            }
            if(ds!=DMG_UNSUPPORTED)throw GraphError{ds};
            if(v8||v11){
                dmg_interface_witness_v1 detail{};
                const auto status=v11?dmg_result_get_interface_resolved_witness_v1(result,i,j,&detail,sizeof(detail)):dmg_result_get_interface_witness_v1(result,i,j,&detail,sizeof(detail));
                if(status==DMG_OK){
                    if(detail.item_kind>(v11?6u:5u)||detail.matched>DMG_MATCH_UNKNOWN||detail.source_index>=overview.source_count||detail.relation>DMG_TYPE_REFS)throw GraphError{DMG_INTERNAL_ERROR};
                    for(auto v:{v11?uint32_t(DMG_WITNESS_INTERFACE_RESOLVED):uint32_t(DMG_WITNESS_INTERFACE),detail.node_id,detail.matched,UINT32_MAX,0u,UINT32_MAX,0u,UINT32_MAX,0u,detail.operator_node})w.u32(v);
                    use_identity(w,{detail.relation,detail.source_index,detail.local_index,UINT32_MAX},overview.source_count);
                    w.u32(v11?2u:1u);for(auto v:{detail.item_kind,detail.branch_index,detail.node_index,detail.aux,detail.detail})w.u32(v);
                    continue;
                }
                if(status!=DMG_UNSUPPORTED)throw GraphError{status};
            }
            dmg_relation_witness_v2 witness{};graph_ok(v21?dmg_result_get_relation_witness_v3(result,i,j,&witness,sizeof(witness)):dmg_result_get_relation_witness_v2(result,i,j,&witness,sizeof(witness)));const auto& x=witness.witness;
            for(auto v:{x.kind,x.node_id,x.matched,x.dex_pc,x.opcode,x.reference_index,x.reference_kind,x.extra_proto,x.code_units,witness.operator_node})w.u32(v);use_identity(w,witness.entity,overview.source_count,v21);
            if(v19)w.u32(0u);
            if(v8||v11)w.u32(0u);
            if(v18||v6){const bool inherited=x.kind==DMG_WITNESS_INHERITED;w.u32(inherited?1u:0u);if(inherited){dmg_inherited_witness detail{};graph_ok(dmg_result_get_inherited_witness(result,i,j,&detail,sizeof(detail)));
                if(detail.node_id!=x.node_id||detail.matched!=x.matched||detail.source_index!=witness.entity.source_index||detail.relation!=witness.entity.relation||detail.local_index!=witness.entity.local_index||detail.item_kind>DMG_INHERITED_FIELD)throw GraphError{DMG_INTERNAL_ERROR};
                for(auto v:{detail.item_kind,detail.path_index,detail.aux,detail.branch_index,detail.detail})w.u32(v);}}
        }
    }
    auto output=env->NewByteArray(static_cast<jsize>(w.data.size()));if(!output||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
    if(!w.data.empty())env->SetByteArrayRegion(output,0,static_cast<jsize>(w.data.size()),reinterpret_cast<const jbyte*>(w.data.data()));
    return env->ExceptionCheck()?nullptr:output;
}
}
static jbyteArray query_use_graph_impl(JNIEnv* env,jlong token,jbyteArray input,jboolean source_set,int mode) noexcept {
    try{
        if(!input){java_exception(env,"java/lang/NullPointerException","queryJson is required");return nullptr;}
        const auto owner=lookup(token);if(!owner){native_failure(env,DMG_CLOSED);return nullptr;}
        if(owner->source_set!=(source_set==JNI_TRUE)){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        const auto size=env->GetArrayLength(input);if(env->ExceptionCheck())return nullptr;if(static_cast<uint64_t>(size)>max_query_bytes){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        std::vector<uint8_t> json(static_cast<size_t>(size));if(size)env->GetByteArrayRegion(input,0,size,reinterpret_cast<jbyte*>(json.data()));if(env->ExceptionCheck())return nullptr;
        dmg_error error{};dmg_query* raw_query=nullptr;auto status=dmg_query_compile_json(owner->engine,json.data(),json.size(),&raw_query,&error);
        if(status!=DMG_OK){if(raw_query)dmg_query_release(raw_query);native_failure(env,status,&error);return nullptr;}if(!raw_query){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        std::unique_ptr<dmg_query,QueryDeleter> query(raw_query);dmg_query_info q{};graph_ok(dmg_query_get_info(query.get(),&q));
        if(!(mode==6?interface_use_graph_supported(q):mode==5?inherited_use_graph_supported(q):mode==4?type_use_graph_supported(q):mode==2?field_declaration_use_graph_supported(q):mode==1?scoped_v4_use_graph_supported(q):use_graph_supported(q))){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        if(q.max_results>max_query_results||q.max_work>max_query_work){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        dmg_result* raw=nullptr;error={};status=dmg_query_execute(owner->snapshot,query.get(),&raw,&error);if(status!=DMG_OK){if(raw)dmg_result_release(raw);native_failure(env,status,&error);return nullptr;}if(!raw){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        std::unique_ptr<dmg_result,ResultDeleter> result(raw);return use_graph_result(env,result.get(),source_set==JNI_TRUE,mode);
    }catch(const GraphError& e){native_failure(env,e.status);}catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryInterfaceUseGraph(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set) noexcept {
    return query_use_graph_impl(env,token,input,source_set,6);
}
extern "C" JNIEXPORT jbyteArray JNICALL Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryInheritedUseGraph(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set) noexcept {
    return query_use_graph_impl(env,token,input,source_set,5);
}
extern "C" JNIEXPORT jbyteArray JNICALL Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryTypeUseGraph(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set) noexcept {
    return query_use_graph_impl(env,token,input,source_set,4);
}
extern "C" JNIEXPORT jbyteArray JNICALL Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryUseGraph(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set) noexcept {
    return query_use_graph_impl(env,token,input,source_set,false);
}
extern "C" JNIEXPORT jbyteArray JNICALL Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryUseGraphScopedV4(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set) noexcept {
    return query_use_graph_impl(env,token,input,source_set,true);
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryFieldDeclarationGraph(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set) noexcept {
    return query_use_graph_impl(env,token,input,source_set,2);
}

static jobjectArray query_caller_field_relation(JNIEnv* env,jlong token,jbyteArray input,jboolean source_set) noexcept {
    try{
        if(!input){java_exception(env,"java/lang/NullPointerException","queryJson is required");return nullptr;}
        const auto owner=lookup(token);if(!owner){native_failure(env,DMG_CLOSED);return nullptr;}
        if(owner->source_set!=(source_set==JNI_TRUE)){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        const auto size=env->GetArrayLength(input);if(env->ExceptionCheck())return nullptr;if(static_cast<uint64_t>(size)>max_query_bytes){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        std::vector<uint8_t> json(static_cast<size_t>(size));if(size)env->GetByteArrayRegion(input,0,size,reinterpret_cast<jbyte*>(json.data()));if(env->ExceptionCheck())return nullptr;
        dmg_error error{};dmg_query* raw_query=nullptr;auto status=dmg_query_compile_json(owner->engine,json.data(),json.size(),&raw_query,&error);
        if(status!=DMG_OK){if(raw_query)dmg_query_release(raw_query);native_failure(env,status,&error);return nullptr;}if(!raw_query){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        std::unique_ptr<dmg_query,QueryDeleter> query(raw_query);dmg_query_info q{};graph_ok(dmg_query_get_info(query.get(),&q));
        if(!caller_field_relation_graph_supported(q)){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        if(q.max_results>max_query_results||q.max_work>max_query_work){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        dmg_result* raw=nullptr;error={};status=dmg_query_execute(owner->snapshot,query.get(),&raw,&error);if(status!=DMG_OK){if(raw)dmg_result_release(raw);native_failure(env,status,&error);return nullptr;}if(!raw){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        std::unique_ptr<dmg_result,ResultDeleter> result(raw);auto base=use_graph_result(env,result.get(),source_set==JNI_TRUE,3);if(!base||env->ExceptionCheck())return nullptr;
        dmg_relation_info_v2 info{};graph_ok(dmg_result_get_relation_info_v2(result.get(),&info,sizeof(info)));GraphWriter w;w.u32(0x52464d44);w.u32(info.candidates_count);
        for(uint32_t row=0;row<info.candidates_count;++row){uint32_t n=0,count=0;graph_ok(dmg_result_get_witness_count(result.get(),row,&n));
            for(uint32_t i=0;i<n;++i){dmg_caller_field_relation_witness_v1 v{};const auto st=dmg_result_get_caller_field_relation_witness_v1(result.get(),row,i,&v,sizeof(v));if(st==DMG_OK)++count;else if(st!=DMG_UNSUPPORTED)throw GraphError{st};}
            if(!count)throw GraphError{DMG_INTERNAL_ERROR};w.item(count);w.u32(count);
            for(uint32_t i=0;i<n;++i){dmg_caller_field_relation_witness_v1 v{};const auto st=dmg_result_get_caller_field_relation_witness_v1(result.get(),row,i,&v,sizeof(v));if(st==DMG_UNSUPPORTED)continue;graph_ok(st);
                for(auto x:{v.node_id,v.operator_node,v.item_kind,v.status,v.reason,v.source_index,v.class_ordinal,v.path_index,v.parent_index,v.edge_kind,v.interface_index,v.target_source,v.target_class,v.target_field,v.event_source,v.event_caller,v.event_pc})w.u32(x);}
        }
        const auto baseSize=static_cast<size_t>(env->GetArrayLength(base));if(env->ExceptionCheck())return nullptr;if(baseSize>GraphWriter::limit||w.data.size()>GraphWriter::limit-baseSize)throw GraphError{DMG_BUDGET_EXCEEDED};
        auto extra=env->NewByteArray(static_cast<jsize>(w.data.size()));if(!extra||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        if(!w.data.empty())env->SetByteArrayRegion(extra,0,static_cast<jsize>(w.data.size()),reinterpret_cast<const jbyte*>(w.data.data()));if(env->ExceptionCheck())return nullptr;
        auto bytesClass=env->FindClass("[B");if(!bytesClass||env->ExceptionCheck())return nullptr;auto both=env->NewObjectArray(2,bytesClass,nullptr);if(!both||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        env->SetObjectArrayElement(both,0,base);env->SetObjectArrayElement(both,1,extra);return env->ExceptionCheck()?nullptr:both;
    }catch(const GraphError& e){native_failure(env,e.status);}catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}
extern "C" JNIEXPORT jobjectArray JNICALL Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryCallerFieldRelationGraph(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set) noexcept {
    return query_caller_field_relation(env,token,input,source_set);
}

extern "C" JNIEXPORT jlong JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartInterfaceUseGraphJob(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set,jint batch_size,jint queue_size,jlong deadline_ms) noexcept {
    return start_job(env,token,input,source_set,batch_size,queue_size,deadline_ms,false,false,false,false,false,false,false,false,false,true);
}
extern "C" JNIEXPORT jlong JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartInheritedUseGraphJob(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set,jint batch_size,jint queue_size,jlong deadline_ms) noexcept {
    return start_job(env,token,input,source_set,batch_size,queue_size,deadline_ms,false,false,false,false,false,false,false,false,true);
}
extern "C" JNIEXPORT jlong JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartTypeUseGraphJob(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set,jint batch_size,jint queue_size,jlong deadline_ms) noexcept {
    return start_job(env,token,input,source_set,batch_size,queue_size,deadline_ms,false,false,false,false,true);
}

extern "C" JNIEXPORT jlong JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartUseGraphJob(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set,jint batch_size,jint queue_size,jlong deadline_ms) noexcept {
    return start_job(env,token,input,source_set,batch_size,queue_size,deadline_ms,false,false,false,true);
}

extern "C" JNIEXPORT jobject JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeUseGraphJobNext(JNIEnv* env,jclass,jlong token,jint timeout_ms) noexcept {
    try {
        if(timeout_ms<0||timeout_ms>max_job_wait_ms){java_exception(env,"java/lang/IllegalArgumentException","invalid wait timeout");return nullptr;}
        const auto job=lookup_job(token);if(!job){native_failure(env,DMG_CLOSED);return nullptr;}
        if(!job->use_graph){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
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
                const bool type_use=job->query_id.starts_with("query:v21:");
                const bool inherited_use=job->query_id.starts_with("query:v6:");
                const bool interface_use=job->query_id.starts_with("query:v8:")||job->query_id.starts_with("query:v11:");
                const auto bytes=use_graph_result(env,batch.get(),job->owner->source_set,type_use?4:inherited_use?5:interface_use?6:0);
                if(bytes&&!env->ExceptionCheck()) {
                    const auto cls=env->FindClass("io/github/jichuo1/dexmeguviz/UseGraphResult");
                    const auto decode=cls&&!env->ExceptionCheck()?env->GetStaticMethodID(cls,"decode","([B)Lio/github/jichuo1/dexmeguviz/UseGraphResult;"):nullptr;
                    if(decode&&!env->ExceptionCheck())copied=env->CallStaticObjectMethod(cls,decode,bytes);
                }
                if(!copied||env->ExceptionCheck()) {
                    job->delivery_failed.store(true,std::memory_order_release);dmg_job_cancel(job->job);
                    if(!env->ExceptionCheck())native_failure(env,DMG_INTERNAL_ERROR);return nullptr;
                }
            }catch(...){job->delivery_failed.store(true,std::memory_order_release);dmg_job_cancel(job->job);throw;}
        }
        const auto cls=env->FindClass("io/github/jichuo1/dexmeguviz/NativeEngine$UseGraphJobPoll");
        const auto ctor=cls&&!env->ExceptionCheck()?env->GetMethodID(cls,"<init>","(ILio/github/jichuo1/dexmeguviz/UseGraphResult;)V"):nullptr;
        jobject value=nullptr;if(ctor&&!env->ExceptionCheck())value=env->NewObject(cls,ctor,kind,copied);
        if(!value||env->ExceptionCheck()){
            if(batch){job->delivery_failed.store(true,std::memory_order_release);dmg_job_cancel(job->job);}
            if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;
        }
        return value;
    }catch(const GraphError& e){native_failure(env,e.status);}catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}

extern "C" JNIEXPORT jobject JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeUseGraphJobStatus(JNIEnv* env,jclass,jlong token,jint timeout_ms) noexcept {
    try {
        if(timeout_ms< -1||timeout_ms>max_job_wait_ms){java_exception(env,"java/lang/IllegalArgumentException","invalid wait timeout");return nullptr;}
        const auto job=lookup_job(token);if(!job){native_failure(env,DMG_CLOSED);return nullptr;}
        if(!job->use_graph){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        if(job->delivery_failed.load(std::memory_order_acquire)){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        dmg_relation_job_status_v2 state{};
        const bool type_use=job->query_id.starts_with("query:v21:");
        const auto status=timeout_ms<0?(type_use?dmg_job_get_relation_status_v3(job->job,&state,sizeof(state)):dmg_job_get_relation_status_v2(job->job,&state,sizeof(state))):
            (type_use?dmg_job_wait_relation_v3(job->job,static_cast<uint32_t>(timeout_ms),&state,sizeof(state)):dmg_job_wait_relation_v2(job->job,static_cast<uint32_t>(timeout_ms),&state,sizeof(state)));
        if(status!=DMG_OK&&status!=DMG_NOT_READY){native_failure(env,status);return nullptr;}
        if(job->delivery_failed.load(std::memory_order_acquire)){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        const auto& o=state.outcome;constexpr auto max64=uint64_t(std::numeric_limits<jlong>::max());
        if(state.terminal>1||o.candidates_count>uint32_t(std::numeric_limits<jint>::max())||
           o.entity_visited>max64||o.entity_total>max64||o.method_visited>max64||o.method_total>max64||
           o.events_collected>max64||o.unknown_rows>max64||state.error.offset>max64){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        const jlong values[]={state.lifecycle,state.terminal,o.execution_status,o.coverage,o.decision,o.reason,o.candidates_count,
            static_cast<jlong>(o.entity_visited),static_cast<jlong>(o.entity_total),static_cast<jlong>(o.method_visited),static_cast<jlong>(o.method_total),
            static_cast<jlong>(o.events_collected),static_cast<jlong>(o.unknown_rows),static_cast<jlong>(state.error.offset)};
        const auto array=env->NewLongArray(14);if(!array||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        env->SetLongArrayRegion(array,0,14,values);if(env->ExceptionCheck())return nullptr;
        const auto cls=env->FindClass("io/github/jichuo1/dexmeguviz/NativeEngine$UseGraphJobStatus");
        const auto ctor=cls&&!env->ExceptionCheck()?env->GetMethodID(cls,"<init>","([JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V"):nullptr;
        if(!ctor||env->ExceptionCheck())return nullptr;
        std::array<char,256> message{};for(size_t i=0;i+1<message.size()&&state.error.message[i];++i){const auto ch=static_cast<unsigned char>(state.error.message[i]);message[i]=ch>=0x20&&ch<=0x7e?static_cast<char>(ch):'?';}
        const auto query=env->NewStringUTF(job->query_id.c_str());if(!query||env->ExceptionCheck())return nullptr;
        const auto snapshot=env->NewStringUTF(job->snapshot_id.c_str());if(!snapshot||env->ExceptionCheck())return nullptr;
        const auto detail=env->NewStringUTF(message.data());if(!detail||env->ExceptionCheck())return nullptr;
        auto value=env->NewObject(cls,ctor,array,query,snapshot,detail);
        if(!value&&!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return value;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}
