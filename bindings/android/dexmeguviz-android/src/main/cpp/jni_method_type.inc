// Explicit v22 method-body evidence wire. It is private to this JNI/Java build.
namespace {
jbyteArray method_type_result(JNIEnv* env,const dmg_result* result,bool source_set){
    dmg_query_info q{};dmg_result_info info{};dmg_relation_info relation{};dmg_query_profile profile{};dmg_snapshot_overview overview{};
    graph_ok(dmg_result_get_query_info(result,&q));if(!method_type_supported(q))throw GraphError{DMG_UNSUPPORTED};
    graph_ok(dmg_result_get_info(result,&info));graph_ok(dmg_result_get_relation_info(result,&relation,sizeof(relation)));graph_ok(dmg_result_get_profile(result,&profile));graph_ok(dmg_result_get_overview(result,&overview));
    if(!q.query_id||!overview.snapshot_id||overview.scope_complete||!overview.input_count||overview.input_count>max_raw_sources||overview.source_count>max_expanded_sources||(!source_set&&(overview.input_count!=1||overview.source_count!=1))||info.candidates_count>max_query_results)throw GraphError{DMG_INTERNAL_ERROR};
    GraphWriter w;w.u32(0x59474d44);for(auto x:{info.execution_status,info.coverage,info.decision,info.reason,info.candidates_count,info.visited_methods,info.total_methods})w.u32(x);w.u64(relation.unknown_rows);w.u32(profile.scope_complete);w.u32(overview.source_count);w.ascii(q.query_id);w.ascii(overview.snapshot_id);
    w.item(info.candidates_count);
    for(uint32_t i=0;i<info.candidates_count;++i){
        dmg_method_type_identity_v1 id{};dmg_method_row row{};dmg_source_info source{};graph_ok(dmg_result_get_method_type_identity_v1(result,i,&id,sizeof(id)));graph_ok(dmg_result_get_method(result,i,&row));graph_ok(dmg_result_get_origin(result,i,&source));
        if(id.source_index!=source.source_index||id.source_index>=overview.source_count||id.method_ordinal>=source.dex.method_def_count||id.method_ref!=row.method_index||id.method_ref>=source.dex.method_ref_count)throw GraphError{DMG_INTERNAL_ERROR};
        for(auto x:{id.source_index,source.input_index,id.method_ordinal,id.method_ref,row.access_flags,row.declaration_offset,row.code_offset,source.dex.string_count,source.dex.type_count,source.dex.method_ref_count,source.dex.method_def_count})w.u32(x);
        w.ascii(source.slot_key);w.ascii(source.dex.source_sha256);w.ascii(source.dex.occurrence_id);w.text((q.projection_mask&DMG_PROJECT_OWNER)!=0,row.owner,row.owner_length);w.text((q.projection_mask&DMG_PROJECT_NAME)!=0,row.name,row.name_length);w.text((q.projection_mask&DMG_PROJECT_PROTOTYPE)!=0,row.prototype,row.prototype_length);
        uint32_t count=0;graph_ok(dmg_result_get_witness_count(result,i,&count));w.item(count);w.u32(count);
        for(uint32_t j=0;j<count;++j){dmg_witness witness{};graph_ok(dmg_result_get_method_witness_v1(result,i,j,&witness,sizeof(witness)));for(auto x:{witness.kind,witness.node_id,witness.matched,witness.dex_pc,witness.opcode,witness.reference_index,witness.reference_kind,witness.extra_proto,witness.code_units})w.u32(x);
            if(witness.kind==DMG_WITNESS_TYPE_USE){dmg_method_type_witness_v1 detail{};graph_ok(dmg_result_get_method_type_witness_v1(result,i,j,&detail,sizeof(detail)));if(detail.source_index!=id.source_index||detail.method_ordinal!=id.method_ordinal||detail.descriptor_length>GraphWriter::text_limit)throw GraphError{DMG_BUDGET_EXCEEDED};std::vector<uint16_t> text(static_cast<size_t>(detail.descriptor_length));graph_ok(dmg_result_copy_method_type_descriptor_v1(result,i,j,text.data(),text.size()));w.text(true,text.data(),text.size());}
            else w.text(false,nullptr,0);
        }
    }
    auto out=env->NewByteArray(static_cast<jsize>(w.data.size()));if(!out||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}if(!w.data.empty())env->SetByteArrayRegion(out,0,static_cast<jsize>(w.data.size()),reinterpret_cast<const jbyte*>(w.data.data()));return env->ExceptionCheck()?nullptr:out;
}
}
extern "C" JNIEXPORT jbyteArray JNICALL Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryMethodType(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set) noexcept {
    try{
        if(!input){java_exception(env,"java/lang/NullPointerException","queryJson is required");return nullptr;}const auto owner=lookup(token);if(!owner){native_failure(env,DMG_CLOSED);return nullptr;}if(owner->source_set!=(source_set==JNI_TRUE)){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        const auto n=env->GetArrayLength(input);if(env->ExceptionCheck())return nullptr;if(static_cast<uint64_t>(n)>max_query_bytes){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}std::vector<uint8_t> json(static_cast<size_t>(n));if(n)env->GetByteArrayRegion(input,0,n,reinterpret_cast<jbyte*>(json.data()));if(env->ExceptionCheck())return nullptr;
        dmg_error error{};dmg_query* raw=nullptr;auto status=dmg_query_compile_json(owner->engine,json.data(),json.size(),&raw,&error);if(status!=DMG_OK){if(raw)dmg_query_release(raw);native_failure(env,status,&error);return nullptr;}if(!raw){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}std::unique_ptr<dmg_query,QueryDeleter> query(raw);dmg_query_info qi{};graph_ok(dmg_query_get_info(query.get(),&qi));if(!method_type_supported(qi)){native_failure(env,DMG_UNSUPPORTED);return nullptr;}if(qi.max_results>max_query_results||qi.max_work>max_query_work){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        dmg_result* rr=nullptr;status=dmg_query_execute(owner->snapshot,query.get(),&rr,&error);if(status!=DMG_OK){if(rr)dmg_result_release(rr);native_failure(env,status,&error);return nullptr;}if(!rr){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}std::unique_ptr<dmg_result,ResultDeleter> result(rr);return method_type_result(env,result.get(),source_set==JNI_TRUE);
    }catch(const GraphError& e){native_failure(env,e.status);}catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}
extern "C" JNIEXPORT jlong JNICALL Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartMethodTypeJob(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set,jint batch_size,jint queue_size,jlong deadline_ms) noexcept {
    return start_job(env,token,input,source_set,batch_size,queue_size,deadline_ms,false,false,false,false,false,true);
}
extern "C" JNIEXPORT jobject JNICALL Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeMethodTypeJobNext(JNIEnv* env,jclass,jlong token,jint timeout_ms) noexcept {
    try{
        if(timeout_ms<0||timeout_ms>max_job_wait_ms){java_exception(env,"java/lang/IllegalArgumentException","invalid wait timeout");return nullptr;}const auto job=lookup_job(token);if(!job){native_failure(env,DMG_CLOSED);return nullptr;}if(!job->method_type){native_failure(env,DMG_UNSUPPORTED);return nullptr;}if(job->delivery_failed.load(std::memory_order_acquire)){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        std::unique_lock lock(job->consumer,std::try_to_lock);if(!lock.owns_lock()){java_exception(env,"java/lang/IllegalStateException","only one batch consumer is allowed");return nullptr;}if(job->delivery_failed.load(std::memory_order_acquire)){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        dmg_batch* raw=nullptr;dmg_error error{};const auto status=dmg_job_next(job->job,static_cast<uint32_t>(timeout_ms),&raw,&error);std::unique_ptr<dmg_result,ResultDeleter> batch(raw);jint kind=0;jobject value=nullptr;
        if(status==DMG_NOT_READY)kind=1;else if(status==DMG_END_OF_STREAM)kind=2;else if(status!=DMG_OK){native_failure(env,status,&error);return nullptr;}else if(!batch){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}else{
            try{const auto bytes=method_type_result(env,batch.get(),job->owner->source_set);if(bytes&&!env->ExceptionCheck()){const auto cls=env->FindClass("io/github/jichuo1/dexmeguviz/MethodTypeResult");const auto decode=cls&&!env->ExceptionCheck()?env->GetStaticMethodID(cls,"decode","([B)Lio/github/jichuo1/dexmeguviz/MethodTypeResult;"):nullptr;if(decode&&!env->ExceptionCheck())value=env->CallStaticObjectMethod(cls,decode,bytes);}
                if(!value||env->ExceptionCheck()){job->delivery_failed.store(true,std::memory_order_release);dmg_job_cancel(job->job);if(!env->ExceptionCheck())native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}}
            catch(...){job->delivery_failed.store(true,std::memory_order_release);dmg_job_cancel(job->job);throw;}
        }
        const auto cls=env->FindClass("io/github/jichuo1/dexmeguviz/NativeEngine$MethodTypeJobPoll");const auto ctor=cls&&!env->ExceptionCheck()?env->GetMethodID(cls,"<init>","(ILio/github/jichuo1/dexmeguviz/MethodTypeResult;)V"):nullptr;jobject out=nullptr;if(ctor&&!env->ExceptionCheck())out=env->NewObject(cls,ctor,kind,value);if(!out||env->ExceptionCheck()){if(batch){job->delivery_failed.store(true,std::memory_order_release);dmg_job_cancel(job->job);}if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);}return out;
    }catch(const GraphError& e){native_failure(env,e.status);}catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}
