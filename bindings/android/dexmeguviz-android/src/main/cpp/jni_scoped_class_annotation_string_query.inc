// Explicit static input-slot scope for a v25 class annotation string query.
extern "C" JNIEXPORT jobject JNICALL Java_io_github_jichuo1_dexmeguviz_ScopedClassAnnotationStringQuery_nativeExecute(JNIEnv* env,jclass,jobject snapshot,jboolean source_set,jbyteArray input) noexcept {
    try {
        if(!input){java_exception(env,"java/lang/NullPointerException","queryJson is required");return nullptr;}
        const auto owner=scoped_snapshot(env,snapshot,source_set);if(!owner)return nullptr;
        const auto length=env->GetArrayLength(input);if(env->ExceptionCheck())return nullptr;
        if(static_cast<uint64_t>(length)>max_query_bytes){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        std::vector<uint8_t> json(static_cast<size_t>(length));if(length)env->GetByteArrayRegion(input,0,length,reinterpret_cast<jbyte*>(json.data()));if(env->ExceptionCheck())return nullptr;
        dmg_error error{};dmg_query* raw=nullptr;auto status=dmg_query_compile_json(owner->engine,json.data(),json.size(),&raw,&error);
        if(status!=DMG_OK){if(raw)dmg_query_release(raw);native_failure(env,status,&error);return nullptr;}
        if(!raw){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}std::unique_ptr<dmg_query,QueryDeleter> query(raw);dmg_query_info_v2 info{};
        status=dmg_query_get_info_v2(query.get(),&info,sizeof(info));if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        const auto& q=info.legacy;constexpr uint32_t caps=2u|4u|8u|256u;
        if(!q.query_id||!std::string_view(q.query_id).starts_with("query:v25:")||!info.extended_capabilities||std::string_view(info.extended_capabilities)!="class_annotation_static;class_annotation_string_static"||!q.explicit_scope||q.demand_mask||q.intent>DMG_UNIQUE||(q.required_capabilities&~caps)||(q.required_capabilities&(2u|8u|256u))!=(2u|8u|256u)||(q.projection_mask&~DMG_PROJECT_TYPE)){
            native_failure(env,DMG_UNSUPPORTED);return nullptr;
        }
        if(q.max_results>max_query_results||q.max_work>max_query_work){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        DeclaredMethodScope scope;status=declared_scope(owner->snapshot,query.get(),scope,true);if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        dmg_result* raw_result=nullptr;error={};status=dmg_query_execute(owner->snapshot,query.get(),&raw_result,&error);
        if(status!=DMG_OK){if(raw_result)dmg_result_release(raw_result);native_failure(env,status,&error);return nullptr;}
        if(!raw_result){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}std::unique_ptr<dmg_result,ResultDeleter> result(raw_result);
        dmg_query_profile profile{};status=dmg_result_get_profile(result.get(),&profile);if(status!=DMG_OK||profile.scope_complete!=1||profile.scope_source_count!=scope.sources.size()){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        for(uint32_t i=0;i<profile.scope_source_count;++i){uint32_t index=0;status=dmg_result_get_scope_source(result.get(),i,&index);if(status!=DMG_OK||index!=static_cast<uint32_t>(scope.sources[i])){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}}
        dmg_relation_info relation{};status=dmg_result_get_relation_info(result.get(),&relation,sizeof(relation));if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        if(relation.relation!=DMG_CLASS_DEFS){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        if(relation.candidates_count>max_query_results){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        for(uint32_t i=0;i<relation.candidates_count;++i){dmg_entity_row row{};status=dmg_result_get_entity(result.get(),i,&row,sizeof(row));
            if(status!=DMG_OK||std::find(scope.sources.begin(),scope.sources.end(),static_cast<jint>(row.source_index))==scope.sources.end()){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}}
        const auto value=materialize_entity_result(env,result.get(),source_set==JNI_TRUE,2,true);if(!value||env->ExceptionCheck())return nullptr;
        jobjectArray slots=nullptr;jintArray sources=nullptr;if(!scope_arrays(env,scope,slots,sources)){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        const auto cls=env->FindClass("io/github/jichuo1/dexmeguviz/ScopedClassAnnotationStringQuery$Result");if(!cls||env->ExceptionCheck())return nullptr;
        const auto ctor=env->GetMethodID(cls,"<init>","(Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityResult;[Ljava/lang/String;[I)V");if(!ctor||env->ExceptionCheck())return nullptr;
        const auto out=env->NewObject(cls,ctor,value,slots,sources);if(!out&&!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return out;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}
