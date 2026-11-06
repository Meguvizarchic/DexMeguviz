// Explicit synchronous non-scoped method-v1 multi-query; caller owns the snapshot monitor.
namespace {
struct MultiBatchDeleter {void operator()(dmg_multi_batch_v1* p)const noexcept{if(p)dmg_multi_batch_release_v1(p);}};
constexpr jsize max_batch_rules=32;
constexpr uint64_t max_batch_json_bytes=1024u*1024u,max_batch_cache_bytes=16u*1024u*1024u;
void batch_failure(JNIEnv* env,dmg_status status,int index,const dmg_error* error=nullptr) noexcept {
    if(env->ExceptionCheck())return;
    const char* source=error&&error->message[0]?error->message:dmg_status_name(status);std::array<char,256> message{};
    for(size_t i=0;i+1<message.size()&&source[i];++i){const auto c=static_cast<unsigned char>(source[i]);message[i]=c>=0x20&&c<=0x7e?static_cast<char>(c):'?';}
    const auto cls=env->FindClass("io/github/jichuo1/dexmeguviz/MethodBatchQuery$Failure");if(!cls||env->ExceptionCheck())return;
    const auto ctor=env->GetMethodID(cls,"<init>","(IIJLjava/lang/String;)V");if(!ctor||env->ExceptionCheck())return;
    const auto text=env->NewStringUTF(message.data());if(!text||env->ExceptionCheck())return;
    const auto offset=error&&error->offset<=uint64_t(std::numeric_limits<jlong>::max())?static_cast<jlong>(error->offset):jlong{0};
    const auto value=env->NewObject(cls,ctor,static_cast<jint>(status),static_cast<jint>(index),offset,text);
    if(!value&&!env->ExceptionCheck()){java_exception(env,"java/lang/OutOfMemoryError","batch failure allocation failed");return;}
    if(value&&!env->ExceptionCheck())env->Throw(static_cast<jthrowable>(value));
}
}
static jobject execute_compiled_method_batch(JNIEnv* env,const std::shared_ptr<SnapshotOwner>& owner,
    const std::vector<dmg_query*>& queries,const std::vector<std::string>& identities,
    jlong cache_bytes,jlong cache_work,jboolean source_set,bool scoped,const DeclaredMethodScope& selected_scope,uint32_t flags) {
    const auto count=static_cast<jsize>(queries.size());
        const dmg_multi_options_v1 options{sizeof(dmg_multi_options_v1),DMG_ABI_VERSION,static_cast<uint64_t>(cache_bytes),static_cast<uint64_t>(cache_work),flags,0};
        dmg_multi_batch_v1* raw_batch=nullptr;uint32_t failed=UINT32_MAX;dmg_error error{};
        auto status=dmg_multi_execute_v1(owner->snapshot,queries.data(),static_cast<uint32_t>(queries.size()),&options,&raw_batch,&failed,&error);
        if(status!=DMG_OK){if(raw_batch)dmg_multi_batch_release_v1(raw_batch);batch_failure(env,status,failed==UINT32_MAX?-1:static_cast<int>(failed),&error);return nullptr;}
        if(!raw_batch){batch_failure(env,DMG_INTERNAL_ERROR,-1);return nullptr;}std::unique_ptr<dmg_multi_batch_v1,MultiBatchDeleter> batch(raw_batch);
        uint32_t actual=0;status=dmg_multi_batch_count_v1(batch.get(),&actual);if(status!=DMG_OK||actual!=static_cast<uint32_t>(count)){batch_failure(env,DMG_INTERNAL_ERROR,-1);return nullptr;}
        dmg_multi_profile_v1 profile{};status=dmg_multi_batch_profile_v1(batch.get(),&profile,sizeof(profile));if(status!=DMG_OK||profile.arena_budget_unavailable>1){batch_failure(env,DMG_INTERNAL_ERROR,-1);return nullptr;}
        const uint64_t counts[]={profile.physical_collects,profile.cache_hits,profile.cache_builds,profile.trace_overflows,profile.cache_rejections,profile.replay_failures,profile.cache_work_charged};
        for(auto v:counts)if(v>uint64_t(std::numeric_limits<jlong>::max())){batch_failure(env,DMG_INTERNAL_ERROR,-1);return nullptr;}
        std::vector<std::unique_ptr<dmg_result,ResultDeleter>> results;results.reserve(actual);uint64_t total_rows=0,total_text=0;
        if(scoped)for(const auto& slot:selected_scope.slots){if(slot.size()>max_output_text_units-total_text){batch_failure(env,DMG_BUDGET_EXCEEDED,-1);return nullptr;}total_text+=slot.size();}
        for(uint32_t i=0;i<actual;++i){
            dmg_result* raw=nullptr;status=dmg_multi_batch_get_result_v1(batch.get(),i,&raw);
            if(status!=DMG_OK||!raw){if(raw)dmg_result_release(raw);batch_failure(env,status==DMG_OK?DMG_INTERNAL_ERROR:status,static_cast<int>(i));return nullptr;}
            std::unique_ptr<dmg_result,ResultDeleter> result(raw);dmg_query_info info{};dmg_result_info summary{};
            status=dmg_result_get_query_info(result.get(),&info);if(status!=DMG_OK||!info.query_id||identities[i]!=info.query_id){batch_failure(env,DMG_INTERNAL_ERROR,static_cast<int>(i));return nullptr;}
            status=dmg_result_get_info(result.get(),&summary);if(status!=DMG_OK){batch_failure(env,status,static_cast<int>(i));return nullptr;}
            if(scoped){dmg_query_profile scope_profile{};status=dmg_result_get_profile(result.get(),&scope_profile);
                if(status!=DMG_OK||scope_profile.scope_complete!=1||scope_profile.scope_source_count!=selected_scope.sources.size()){batch_failure(env,DMG_INTERNAL_ERROR,static_cast<int>(i));return nullptr;}
                for(uint32_t j=0;j<scope_profile.scope_source_count;++j){uint32_t source=0;status=dmg_result_get_scope_source(result.get(),j,&source);
                    if(status!=DMG_OK||source!=static_cast<uint32_t>(selected_scope.sources[j])){batch_failure(env,DMG_INTERNAL_ERROR,static_cast<int>(i));return nullptr;}}}
            if(summary.candidates_count>max_query_results-total_rows){batch_failure(env,DMG_BUDGET_EXCEEDED,static_cast<int>(i));return nullptr;}total_rows+=summary.candidates_count;
            for(uint32_t row=0;row<summary.candidates_count;++row){dmg_method_row value{};status=dmg_result_get_method(result.get(),row,&value);if(status!=DMG_OK){batch_failure(env,status,static_cast<int>(i));return nullptr;}
                const uint64_t lengths[]={value.owner_length,value.name_length,value.prototype_length};for(auto n:lengths){if(n>max_output_text_units-total_text){batch_failure(env,DMG_BUDGET_EXCEEDED,static_cast<int>(i));return nullptr;}total_text+=n;}
                if(source_set==JNI_TRUE||scoped){dmg_source_info origin{};status=dmg_result_get_origin(result.get(),row,&origin);if(status!=DMG_OK||!origin.slot_key||!origin.dex.occurrence_id){batch_failure(env,status==DMG_OK?DMG_INTERNAL_ERROR:status,static_cast<int>(i));return nullptr;}
                    if(scoped&&std::find(selected_scope.sources.begin(),selected_scope.sources.end(),static_cast<jint>(origin.source_index))==selected_scope.sources.end()){batch_failure(env,DMG_INTERNAL_ERROR,static_cast<int>(i));return nullptr;}
                    for(auto text:{std::string_view(origin.slot_key),std::string_view(origin.dex.occurrence_id)}){if(text.size()>max_output_text_units-total_text){batch_failure(env,DMG_BUDGET_EXCEEDED,static_cast<int>(i));return nullptr;}total_text+=text.size();}}}
            results.push_back(std::move(result));
        }
        const auto row_cls=env->FindClass("io/github/jichuo1/dexmeguviz/NativeEngine$QueryResult");if(!row_cls||env->ExceptionCheck())return nullptr;
        const auto values=env->NewObjectArray(count,row_cls,nullptr);if(!values||env->ExceptionCheck()){if(!env->ExceptionCheck())batch_failure(env,DMG_OUT_OF_MEMORY,-1);return nullptr;}
        for(jsize i=0;i<count;++i){if(env->PushLocalFrame(8)<0){if(!env->ExceptionCheck())batch_failure(env,DMG_OUT_OF_MEMORY,i);return nullptr;}
            const auto value=materialize_result(env,results[static_cast<size_t>(i)].get(),source_set==JNI_TRUE,scoped);if(value&&!env->ExceptionCheck())env->SetObjectArrayElement(values,i,value);
            const bool fail=!value||env->ExceptionCheck();env->PopLocalFrame(nullptr);if(fail){if(!env->ExceptionCheck())batch_failure(env,DMG_INTERNAL_ERROR,i);return nullptr;}}
        const auto profile_cls=env->FindClass("io/github/jichuo1/dexmeguviz/MethodBatchQuery$Profile");if(!profile_cls||env->ExceptionCheck())return nullptr;
        const auto profile_ctor=env->GetMethodID(profile_cls,"<init>","(JJJJJJJZ)V");if(!profile_ctor||env->ExceptionCheck())return nullptr;
        const auto prof=env->NewObject(profile_cls,profile_ctor,static_cast<jlong>(counts[0]),static_cast<jlong>(counts[1]),static_cast<jlong>(counts[2]),static_cast<jlong>(counts[3]),static_cast<jlong>(counts[4]),static_cast<jlong>(counts[5]),static_cast<jlong>(counts[6]),static_cast<jboolean>(profile.arena_budget_unavailable));if(!prof||env->ExceptionCheck()){if(!env->ExceptionCheck())batch_failure(env,DMG_OUT_OF_MEMORY,-1);return nullptr;}
        const auto result_cls=env->FindClass(scoped?"io/github/jichuo1/dexmeguviz/ScopedMethodBatchQuery$Result":"io/github/jichuo1/dexmeguviz/MethodBatchQuery$Result");if(!result_cls||env->ExceptionCheck())return nullptr;
        const auto ctor=env->GetMethodID(result_cls,"<init>",scoped?"([Lio/github/jichuo1/dexmeguviz/NativeEngine$QueryResult;Lio/github/jichuo1/dexmeguviz/MethodBatchQuery$Profile;[Ljava/lang/String;[I)V":"([Lio/github/jichuo1/dexmeguviz/NativeEngine$QueryResult;Lio/github/jichuo1/dexmeguviz/MethodBatchQuery$Profile;)V");if(!ctor||env->ExceptionCheck())return nullptr;
        jobject out=nullptr;if(scoped){jobjectArray slots=nullptr;jintArray sources=nullptr;if(!scope_arrays(env,selected_scope,slots,sources)){if(!env->ExceptionCheck())batch_failure(env,DMG_OUT_OF_MEMORY,-1);return nullptr;}out=env->NewObject(result_cls,ctor,values,prof,slots,sources);}
        else out=env->NewObject(result_cls,ctor,values,prof);if(!out&&!env->ExceptionCheck())batch_failure(env,DMG_OUT_OF_MEMORY,-1);return out;
 }
static jobject execute_method_batch(JNIEnv* env,jobject snapshot,jboolean source_set,jobjectArray inputs,jlong cache_bytes,jlong cache_work,bool scoped) noexcept {
    try {
        if(!inputs){java_exception(env,"java/lang/NullPointerException","rules are required");return nullptr;}
        if(cache_bytes<0||static_cast<uint64_t>(cache_bytes)>max_batch_cache_bytes||cache_work<0||static_cast<uint64_t>(cache_work)>max_query_work){java_exception(env,"java/lang/IllegalArgumentException","invalid batch cache limits");return nullptr;}
        const auto owner=scoped_snapshot(env,snapshot,source_set);if(!owner)return nullptr;
        const auto count=env->GetArrayLength(inputs);if(env->ExceptionCheck())return nullptr;
        if(count<1||count>max_batch_rules){java_exception(env,"java/lang/IllegalArgumentException","batch must have 1..32 rules");return nullptr;}
        std::vector<std::unique_ptr<dmg_query,QueryDeleter>> owned;std::vector<dmg_query*> queries;std::vector<std::string> identities;
        owned.reserve(static_cast<size_t>(count));queries.reserve(static_cast<size_t>(count));identities.reserve(static_cast<size_t>(count));uint64_t total_json=0;DeclaredMethodScope selected_scope;
        for(jsize i=0;i<count;++i){
            const auto bytes=static_cast<jbyteArray>(env->GetObjectArrayElement(inputs,i));if(env->ExceptionCheck())return nullptr;
            if(!bytes){batch_failure(env,DMG_INVALID_ARGUMENT,i);return nullptr;}
            const auto length=env->GetArrayLength(bytes);if(env->ExceptionCheck()){env->DeleteLocalRef(bytes);return nullptr;}
            if(static_cast<uint64_t>(length)>max_query_bytes||static_cast<uint64_t>(length)>max_batch_json_bytes-total_json){env->DeleteLocalRef(bytes);batch_failure(env,DMG_BUDGET_EXCEEDED,i);return nullptr;}
            total_json+=static_cast<uint64_t>(length);std::vector<uint8_t> json(static_cast<size_t>(length));if(length)env->GetByteArrayRegion(bytes,0,length,reinterpret_cast<jbyte*>(json.data()));env->DeleteLocalRef(bytes);if(env->ExceptionCheck())return nullptr;
            dmg_query* raw=nullptr;dmg_error error{};auto status=dmg_query_compile_json(owner->engine,json.data(),json.size(),&raw,&error);
            if(status!=DMG_OK){if(raw)dmg_query_release(raw);batch_failure(env,status,i,&error);return nullptr;}if(!raw){batch_failure(env,DMG_INTERNAL_ERROR,i);return nullptr;}
            std::unique_ptr<dmg_query,QueryDeleter> q(raw);dmg_query_info info{};status=dmg_query_get_info(q.get(),&info);
            if(status!=DMG_OK){batch_failure(env,status,i);return nullptr;}
            const uint32_t caps=1u|2u|4u|16u|32u|64u|128u|(scoped?8u:0u);
            if(!info.query_id||!std::string_view(info.query_id).starts_with("query:v1:")||(info.explicit_scope!=0)!=scoped||info.intent>DMG_TOP_N||(info.required_capabilities&~caps)||(info.required_capabilities&(1u|2u))!=(1u|2u)||(info.demand_mask&~7u)||(info.projection_mask&~(DMG_PROJECT_OWNER|DMG_PROJECT_NAME|DMG_PROJECT_PROTOTYPE))){
                batch_failure(env,DMG_UNSUPPORTED,i);return nullptr;}
            if(info.max_results>max_query_results||info.max_work>max_query_work){batch_failure(env,DMG_BUDGET_EXCEEDED,i);return nullptr;}
            if(scoped){DeclaredMethodScope current;status=declared_scope(owner->snapshot,q.get(),current);if(status!=DMG_OK){batch_failure(env,status,i);return nullptr;}
                if(i==0)selected_scope=std::move(current);else if(current.slots!=selected_scope.slots||current.sources!=selected_scope.sources){batch_failure(env,DMG_SOURCE_MISMATCH,i);return nullptr;}}
            identities.emplace_back(info.query_id);queries.push_back(q.get());owned.push_back(std::move(q));
        }
        return execute_compiled_method_batch(env,owner,queries,identities,cache_bytes,cache_work,source_set,scoped,selected_scope,0);
    }catch(const std::bad_alloc&){batch_failure(env,DMG_OUT_OF_MEMORY,-1);}catch(...){batch_failure(env,DMG_INTERNAL_ERROR,-1);}return nullptr;
}

extern "C" JNIEXPORT jobject JNICALL Java_io_github_jichuo1_dexmeguviz_MethodBatchQuery_nativeExecute(JNIEnv* env,jclass,jobject snapshot,jboolean source_set,jobjectArray inputs,jlong cache_bytes,jlong cache_work) noexcept {
    return execute_method_batch(env,snapshot,source_set,inputs,cache_bytes,cache_work,false);
}
extern "C" JNIEXPORT jobject JNICALL Java_io_github_jichuo1_dexmeguviz_ScopedMethodBatchQuery_nativeExecute(JNIEnv* env,jclass,jobject snapshot,jboolean source_set,jobjectArray inputs,jlong cache_bytes,jlong cache_work) noexcept {
    return execute_method_batch(env,snapshot,source_set,inputs,cache_bytes,cache_work,true);
}

// Selects already-compiled plans owned by the session. Java holds both session
// and snapshot monitors; this call never keeps arrays or JNI references.
extern "C" JNIEXPORT jobject JNICALL Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeMethodStreamQueryBatch(
    JNIEnv* env,jclass,jlong stream_token,jlong snapshot_token,jintArray indices,jlong cache_bytes,jlong cache_work) noexcept {
    try {
        if(!indices){java_exception(env,"java/lang/NullPointerException","queryIndices are required");return nullptr;}
        if(cache_bytes<0||static_cast<uint64_t>(cache_bytes)>max_batch_cache_bytes||cache_work<0||static_cast<uint64_t>(cache_work)>max_query_work){java_exception(env,"java/lang/IllegalArgumentException","invalid batch cache limits");return nullptr;}
        const auto stream=lookup_method_stream(stream_token);const auto owner=lookup(snapshot_token);
        if(!stream||!owner){native_failure(env,DMG_CLOSED);return nullptr;}
        if(owner->source_set||owner->engine!=stream->engine.get()){native_failure(env,DMG_INVALID_ARGUMENT);return nullptr;}
        const auto count=env->GetArrayLength(indices);if(env->ExceptionCheck())return nullptr;
        if(count<1||count>max_batch_rules){java_exception(env,"java/lang/IllegalArgumentException","batch must have 1..32 indices");return nullptr;}
        std::array<jint,max_batch_rules> selected{};env->GetIntArrayRegion(indices,0,count,selected.data());if(env->ExceptionCheck())return nullptr;
        std::vector<dmg_query*> queries;std::vector<std::string> identities;queries.reserve(count);identities.reserve(count);
        for(jsize i=0;i<count;++i){
            const auto index=selected[static_cast<size_t>(i)];
            if(index<0||static_cast<size_t>(index)>=stream->queries.size()){batch_failure(env,DMG_INVALID_ARGUMENT,i);return nullptr;}
            auto* q=stream->queries[static_cast<size_t>(index)].get();dmg_query_info info{};auto status=dmg_query_get_info(q,&info);
            if(status!=DMG_OK){batch_failure(env,status,i);return nullptr;}
            constexpr uint32_t caps=1u|2u|4u|16u|32u|64u|128u;
            if(!info.query_id||!std::string_view(info.query_id).starts_with("query:v1:")||info.explicit_scope||info.intent>DMG_TOP_N||
               (info.required_capabilities&~caps)||(info.required_capabilities&(1u|2u))!=(1u|2u)||(info.demand_mask&~7u)||
               (info.projection_mask&~(DMG_PROJECT_OWNER|DMG_PROJECT_NAME|DMG_PROJECT_PROTOTYPE))){batch_failure(env,DMG_UNSUPPORTED,i);return nullptr;}
            if(info.max_results>max_query_results||info.max_work>max_query_work){batch_failure(env,DMG_BUDGET_EXCEEDED,i);return nullptr;}
            queries.push_back(q);identities.emplace_back(info.query_id);
        }
        const DeclaredMethodScope unused;
        return execute_compiled_method_batch(env,owner,queries,identities,cache_bytes,cache_work,JNI_FALSE,false,unused,DMG_MULTI_FUSE_METHOD_ENUM_V1);
    }catch(const std::bad_alloc&){batch_failure(env,DMG_OUT_OF_MEMORY,-1);}catch(...){batch_failure(env,DMG_INTERNAL_ERROR,-1);}return nullptr;
}
