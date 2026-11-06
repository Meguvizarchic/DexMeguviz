// Explicit caller-declared input slots; never authenticates installed/loader scope.
namespace {
struct DeclaredMethodScope {std::vector<std::string> slots;std::vector<jint> sources;};
std::shared_ptr<SnapshotOwner> scoped_snapshot(JNIEnv* env,jobject snapshot,jboolean source_set){
    if(!snapshot){java_exception(env,"java/lang/NullPointerException","snapshot is required");return {};}
    if(source_set!=JNI_FALSE&&source_set!=JNI_TRUE){native_failure(env,DMG_INVALID_ARGUMENT);return {};}
    const auto cls=env->FindClass(source_set?"io/github/jichuo1/dexmeguviz/NativeEngine$SourceSetSnapshot":"io/github/jichuo1/dexmeguviz/NativeEngine$Snapshot");
    if(!cls||env->ExceptionCheck())return {};
    if(!env->IsInstanceOf(snapshot,cls)){java_exception(env,"java/lang/IllegalArgumentException","snapshot type mismatch");return {};}
    const auto field=env->GetFieldID(cls,"token","J");if(!field||env->ExceptionCheck())return {};
    const auto token=env->GetLongField(snapshot,field);if(env->ExceptionCheck())return {};
    auto owner=lookup(token);if(!owner){native_failure(env,DMG_CLOSED);return {};}
    if(owner->source_set!=(source_set==JNI_TRUE)){native_failure(env,DMG_UNSUPPORTED);return {};}
    return owner;
}
std::unique_ptr<dmg_query,QueryDeleter> scoped_query(JNIEnv* env,const std::shared_ptr<SnapshotOwner>& owner,jbyteArray input){
    if(!input){java_exception(env,"java/lang/NullPointerException","queryJson is required");return {};}
    const auto length=env->GetArrayLength(input);if(env->ExceptionCheck())return {};
    if(static_cast<uint64_t>(length)>max_query_bytes){native_failure(env,DMG_BUDGET_EXCEEDED);return {};}
    std::vector<uint8_t> json(static_cast<size_t>(length));if(length)env->GetByteArrayRegion(input,0,length,reinterpret_cast<jbyte*>(json.data()));if(env->ExceptionCheck())return {};
    dmg_query* raw=nullptr;dmg_error error{};const auto status=dmg_query_compile_json(owner->engine,json.data(),json.size(),&raw,&error);
    if(status!=DMG_OK){if(raw)dmg_query_release(raw);native_failure(env,status,&error);return {};}
    if(!raw){native_failure(env,DMG_INTERNAL_ERROR);return {};}
    std::unique_ptr<dmg_query,QueryDeleter> query(raw);dmg_query_info info{};
    if(dmg_query_get_info(query.get(),&info)!=DMG_OK){native_failure(env,DMG_INTERNAL_ERROR);return {};}
    if(!info.query_id||std::string_view(info.query_id).substr(0,9)!="query:v1:"||!info.explicit_scope){native_failure(env,DMG_UNSUPPORTED);return {};}
    if(info.max_results>max_query_results||info.max_work>max_query_work){native_failure(env,DMG_BUDGET_EXCEEDED);return {};}
    return query;
}
dmg_status declared_scope(dmg_snapshot* snapshot,dmg_query* query,DeclaredMethodScope& out,bool extended=false){
    dmg_snapshot_overview overview{};auto status=dmg_snapshot_get_overview(snapshot,&overview);if(status!=DMG_OK)return status;
    if(!overview.snapshot_id||overview.scope_complete||!overview.input_count||overview.input_count>max_raw_sources||overview.source_count>max_expanded_sources)return DMG_INTERNAL_ERROR;
    uint32_t scope_count=0;
    if(extended){dmg_query_scope_v2 plan{};status=dmg_query_get_scope_v2(query,&plan,sizeof(plan));if(status!=DMG_OK)return status;if(!plan.explicit_scope)return DMG_UNSUPPORTED;scope_count=plan.slot_count;}
    else{dmg_query_explain_v1 plan{};status=dmg_query_get_explain_v1(query,&plan,sizeof(plan));if(status!=DMG_OK)return status;scope_count=plan.scope_count;}
    if(scope_count>overview.input_count)return DMG_SOURCE_MISMATCH;
    std::vector<std::string> input_slots;input_slots.reserve(overview.input_count);
    for(uint32_t i=0;i<overview.input_count;++i){dmg_input_info info{};status=dmg_snapshot_get_input_info(snapshot,i,&info);if(status!=DMG_OK)return status;if(info.input_index!=i||!info.slot_key)return DMG_INTERNAL_ERROR;input_slots.emplace_back(info.slot_key);}
    out.slots.reserve(scope_count);
    for(uint32_t i=0;i<scope_count;++i){const char* slot=nullptr;status=extended?dmg_query_get_scope_slot_v2(query,i,&slot):dmg_query_get_explain_scope_v1(query,UINT32_MAX,i,&slot);if(status!=DMG_OK||!slot)return DMG_INTERNAL_ERROR;
        std::string value(slot);if(value.empty()||value.size()>max_slot_chars||!std::all_of(value.begin(),value.end(),[](unsigned char c){return c>=0x21&&c<=0x7e;}))return DMG_SOURCE_MISMATCH;
        if(std::find(input_slots.begin(),input_slots.end(),value)==input_slots.end())return DMG_SOURCE_MISMATCH;out.slots.push_back(std::move(value));}
    out.sources.reserve(overview.source_count);
    for(uint32_t i=0;i<overview.source_count;++i){dmg_source_info source{};status=dmg_snapshot_get_source_info(snapshot,i,&source);if(status!=DMG_OK)return status;
        if(source.source_index!=i||source.input_index>=input_slots.size()||!source.slot_key||input_slots[source.input_index]!=source.slot_key)return DMG_INTERNAL_ERROR;
        if(std::find(out.slots.begin(),out.slots.end(),input_slots[source.input_index])!=out.slots.end())out.sources.push_back(static_cast<jint>(i));}
    return DMG_OK;
}
bool scope_arrays(JNIEnv* env,const DeclaredMethodScope& scope,jobjectArray& slots,jintArray& sources){
    const auto string_cls=env->FindClass("java/lang/String");if(!string_cls||env->ExceptionCheck())return false;
    slots=env->NewObjectArray(static_cast<jsize>(scope.slots.size()),string_cls,nullptr);if(!slots||env->ExceptionCheck())return false;
    for(jsize i=0;i<static_cast<jsize>(scope.slots.size());++i){const auto value=env->NewStringUTF(scope.slots[static_cast<size_t>(i)].c_str());if(!value||env->ExceptionCheck())return false;env->SetObjectArrayElement(slots,i,value);env->DeleteLocalRef(value);if(env->ExceptionCheck())return false;}
    sources=env->NewIntArray(static_cast<jsize>(scope.sources.size()));if(!sources||env->ExceptionCheck())return false;
    if(!scope.sources.empty())env->SetIntArrayRegion(sources,0,static_cast<jsize>(scope.sources.size()),scope.sources.data());
    return !env->ExceptionCheck();
}
void discard_scoped_job(jlong token)noexcept{
    try{std::shared_ptr<JobOwner> job;{std::lock_guard lock(registry_mutex);const auto it=jobs.find(token);if(it==jobs.end())return;job=std::move(it->second);jobs.erase(it);}dmg_job_cancel(job->job);}catch(...){}
}
}
extern "C" JNIEXPORT jobject JNICALL
Java_io_github_jichuo1_dexmeguviz_ScopedMethodQuery_nativeExecute(JNIEnv* env,jclass,jobject snapshot,jboolean source_set,jbyteArray input) noexcept {
    try{
        const auto owner=scoped_snapshot(env,snapshot,source_set);if(!owner)return nullptr;
        auto query=scoped_query(env,owner,input);if(!query)return nullptr;
        DeclaredMethodScope scope;auto status=declared_scope(owner->snapshot,query.get(),scope);if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        dmg_result* raw=nullptr;dmg_error error{};status=dmg_query_execute(owner->snapshot,query.get(),&raw,&error);
        if(status!=DMG_OK){if(raw)dmg_result_release(raw);native_failure(env,status,&error);return nullptr;}
        if(!raw){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}std::unique_ptr<dmg_result,ResultDeleter> result(raw);
        dmg_query_profile profile{};status=dmg_result_get_profile(result.get(),&profile);if(status!=DMG_OK||profile.scope_source_count!=scope.sources.size()){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        for(uint32_t i=0;i<profile.scope_source_count;++i){uint32_t index=0;status=dmg_result_get_scope_source(result.get(),i,&index);if(status!=DMG_OK||index!=static_cast<uint32_t>(scope.sources[i])){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}}
        const auto value=materialize_result(env,result.get(),source_set==JNI_TRUE,true);if(!value||env->ExceptionCheck())return nullptr;
        jobjectArray slots=nullptr;jintArray sources=nullptr;if(!scope_arrays(env,scope,slots,sources)){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        const auto cls=env->FindClass("io/github/jichuo1/dexmeguviz/ScopedMethodQuery$Result");if(!cls||env->ExceptionCheck())return nullptr;
        const auto ctor=env->GetMethodID(cls,"<init>","(Lio/github/jichuo1/dexmeguviz/NativeEngine$QueryResult;[Ljava/lang/String;[I)V");if(!ctor||env->ExceptionCheck())return nullptr;
        const auto out=env->NewObject(cls,ctor,value,slots,sources);if(!out&&!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return out;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}
extern "C" JNIEXPORT jobject JNICALL
Java_io_github_jichuo1_dexmeguviz_ScopedMethodQuery_nativeStart(JNIEnv* env,jclass,jobject snapshot,jboolean source_set,jbyteArray input,jint batch_size,jint queue_size,jlong deadline_ms) noexcept {
    try{
        if(batch_size<1||batch_size>4096||queue_size<1||queue_size>16||deadline_ms<0||deadline_ms>86400000){java_exception(env,"java/lang/IllegalArgumentException","invalid job limits");return nullptr;}
        const auto owner=scoped_snapshot(env,snapshot,source_set);if(!owner)return nullptr;
        auto query=scoped_query(env,owner,input);if(!query)return nullptr;
        DeclaredMethodScope scope;auto status=declared_scope(owner->snapshot,query.get(),scope);if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        jobjectArray slots=nullptr;jintArray sources=nullptr;if(!scope_arrays(env,scope,slots,sources)){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        const auto base_cls=env->FindClass("io/github/jichuo1/dexmeguviz/NativeEngine$Job");if(!base_cls||env->ExceptionCheck())return nullptr;
        const auto base_ctor=env->GetMethodID(base_cls,"<init>","(J)V");if(!base_ctor||env->ExceptionCheck())return nullptr;
        const auto cls=env->FindClass("io/github/jichuo1/dexmeguviz/ScopedMethodQuery$Job");if(!cls||env->ExceptionCheck())return nullptr;
        const auto ctor=env->GetMethodID(cls,"<init>","(Lio/github/jichuo1/dexmeguviz/NativeEngine$Job;[Ljava/lang/String;[I)V");if(!ctor||env->ExceptionCheck())return nullptr;
        dmg_query_info info{};status=dmg_query_get_info(query.get(),&info);if(status!=DMG_OK||!info.query_id){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        dmg_snapshot_overview overview{};status=dmg_snapshot_get_overview(owner->snapshot,&overview);if(status!=DMG_OK||!overview.snapshot_id){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        std::string query_id(info.query_id),snapshot_id(overview.snapshot_id);JobPermit permit;if(!permit.acquire()){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        const dmg_job_options options{sizeof(dmg_job_options),DMG_ABI_VERSION,static_cast<uint32_t>(batch_size),static_cast<uint32_t>(queue_size),static_cast<uint64_t>(deadline_ms)};
        dmg_job* raw=nullptr;dmg_error error{};status=dmg_job_start(owner->snapshot,query.get(),&options,&raw,&error);
        if(status!=DMG_OK){if(raw)dmg_job_release(raw);native_failure(env,status,&error);return nullptr;}
        if(!raw){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}std::unique_ptr<dmg_job,JobDeleter> guard(raw);
        const auto job=std::make_shared<JobOwner>(guard.get(),owner,std::move(query_id),std::move(snapshot_id));guard.release();
        const auto token=permit.publish(job);if(!token){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        const auto delegate=env->NewObject(base_cls,base_ctor,token);
        if(!delegate||env->ExceptionCheck()){discard_scoped_job(token);if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        const auto out=env->NewObject(cls,ctor,delegate,slots,sources);
        if(!out||env->ExceptionCheck()){discard_scoped_job(token);if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}return out;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}
