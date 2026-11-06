// Explicit scoped v24/v25 class annotation Jobs, with separately verified static scope.
static jobject start_scoped_class_annotation_job(JNIEnv* env,jobject snapshot,jboolean source_set,jbyteArray input,jint batch_size,jint queue_size,jlong deadline_ms,uint32_t version) noexcept {
    try {
        if(!input){java_exception(env,"java/lang/NullPointerException","queryJson is required");return nullptr;}
        if(batch_size<1||batch_size>4096||queue_size<1||queue_size>16||deadline_ms<0||deadline_ms>86400000){java_exception(env,"java/lang/IllegalArgumentException","invalid job limits");return nullptr;}
        if(version!=1&&version!=2){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        const auto owner=scoped_snapshot(env,snapshot,source_set);if(!owner)return nullptr;
        const auto length=env->GetArrayLength(input);if(env->ExceptionCheck())return nullptr;
        if(static_cast<uint64_t>(length)>max_query_bytes){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        std::vector<uint8_t> json(static_cast<size_t>(length));if(length)env->GetByteArrayRegion(input,0,length,reinterpret_cast<jbyte*>(json.data()));if(env->ExceptionCheck())return nullptr;
        dmg_error error{};dmg_query* raw=nullptr;auto status=dmg_query_compile_json(owner->engine,json.data(),json.size(),&raw,&error);
        if(status!=DMG_OK){if(raw)dmg_query_release(raw);native_failure(env,status,&error);return nullptr;}
        if(!raw){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}std::unique_ptr<dmg_query,QueryDeleter> query(raw);dmg_query_info_v2 info{};
        status=dmg_query_get_info_v2(query.get(),&info,sizeof(info));if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        const auto& q=info.legacy;constexpr uint32_t caps=2u|4u|8u|256u;
        if(!q.query_id||!std::string_view(q.query_id).starts_with(version==1?"query:v24:":"query:v25:")||!info.extended_capabilities||
           std::string_view(info.extended_capabilities)!=(version==1?"class_annotation_static":"class_annotation_static;class_annotation_string_static")||
           !q.explicit_scope||q.demand_mask||q.intent>DMG_UNIQUE||(q.required_capabilities&~caps)||(q.required_capabilities&(2u|8u|256u))!=(2u|8u|256u)||(q.projection_mask&~DMG_PROJECT_TYPE)){
            native_failure(env,DMG_UNSUPPORTED);return nullptr;
        }
        if(q.max_results>max_query_results||q.max_work>max_query_work){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        DeclaredMethodScope scope;status=declared_scope(owner->snapshot,query.get(),scope,true);if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        jobjectArray slots=nullptr;jintArray sources=nullptr;if(!scope_arrays(env,scope,slots,sources)){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        const auto base_cls=env->FindClass("io/github/jichuo1/dexmeguviz/NativeEngine$EntityJob");if(!base_cls||env->ExceptionCheck())return nullptr;
        const auto base_ctor=env->GetMethodID(base_cls,"<init>","(J)V");if(!base_ctor||env->ExceptionCheck())return nullptr;
        const auto cls=env->FindClass(version==1?"io/github/jichuo1/dexmeguviz/ScopedClassAnnotationQuery$Job":"io/github/jichuo1/dexmeguviz/ScopedClassAnnotationStringQuery$Job");if(!cls||env->ExceptionCheck())return nullptr;
        const auto ctor=env->GetMethodID(cls,"<init>","(Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityJob;[Ljava/lang/String;[I)V");if(!ctor||env->ExceptionCheck())return nullptr;
        dmg_snapshot_overview overview{};status=dmg_snapshot_get_overview(owner->snapshot,&overview);if(status!=DMG_OK||!overview.snapshot_id){native_failure(env,status==DMG_OK?DMG_INTERNAL_ERROR:status);return nullptr;}
        std::string query_id(q.query_id),snapshot_id(overview.snapshot_id);JobPermit permit;if(!permit.acquire()){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        const dmg_job_options options{sizeof(dmg_job_options),DMG_ABI_VERSION,static_cast<uint32_t>(batch_size),static_cast<uint32_t>(queue_size),static_cast<uint64_t>(deadline_ms)};
        dmg_job* raw_job=nullptr;error={};status=dmg_job_start(owner->snapshot,query.get(),&options,&raw_job,&error);
        if(status!=DMG_OK){if(raw_job)dmg_job_release(raw_job);native_failure(env,status,&error);return nullptr;}
        if(!raw_job){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}std::unique_ptr<dmg_job,JobDeleter> guard(raw_job);
        const auto job=std::make_shared<JobOwner>(guard.get(),owner,std::move(query_id),std::move(snapshot_id),true,false,false,false,false,false,version,true,std::move(scope.sources));guard.release();
        const auto token=permit.publish(job);if(!token){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        const auto delegate=env->NewObject(base_cls,base_ctor,token);
        if(!delegate||env->ExceptionCheck()){discard_scoped_job(token);if(!env->ExceptionCheck())native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        const auto out=env->NewObject(cls,ctor,delegate,slots,sources);
        if(!out||env->ExceptionCheck()){discard_scoped_job(token);if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}return out;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}
extern "C" JNIEXPORT jobject JNICALL Java_io_github_jichuo1_dexmeguviz_ScopedClassAnnotationQuery_nativeStart(JNIEnv* env,jclass,jobject snapshot,jboolean source_set,jbyteArray input,jint batch_size,jint queue_size,jlong deadline_ms) noexcept {
    return start_scoped_class_annotation_job(env,snapshot,source_set,input,batch_size,queue_size,deadline_ms,1);
}
extern "C" JNIEXPORT jobject JNICALL Java_io_github_jichuo1_dexmeguviz_ScopedClassAnnotationStringQuery_nativeStart(JNIEnv* env,jclass,jobject snapshot,jboolean source_set,jbyteArray input,jint batch_size,jint queue_size,jlong deadline_ms) noexcept {
    return start_scoped_class_annotation_job(env,snapshot,source_set,input,batch_size,queue_size,deadline_ms,2);
}
