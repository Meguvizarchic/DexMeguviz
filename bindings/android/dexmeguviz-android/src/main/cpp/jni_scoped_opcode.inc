// Explicit input-slot subset for v23 opcode queries; never authenticates loader scope.
extern "C" JNIEXPORT jobject JNICALL
Java_io_github_jichuo1_dexmeguviz_ScopedOpcodeQuery_nativeExecute(JNIEnv* env,jclass,jobject snapshot,jboolean source_set,jbyteArray input) noexcept {
    try {
        if(!input){java_exception(env,"java/lang/NullPointerException","queryJson is required");return nullptr;}
        const auto owner=scoped_snapshot(env,snapshot,source_set);if(!owner)return nullptr;
        const auto length=env->GetArrayLength(input);if(env->ExceptionCheck())return nullptr;
        if(static_cast<uint64_t>(length)>max_query_bytes){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        std::vector<uint8_t> json(static_cast<size_t>(length));if(length)env->GetByteArrayRegion(input,0,length,reinterpret_cast<jbyte*>(json.data()));if(env->ExceptionCheck())return nullptr;
        dmg_error error{};dmg_query* raw_query=nullptr;auto status=dmg_query_compile_json(owner->engine,json.data(),json.size(),&raw_query,&error);
        if(status!=DMG_OK){if(raw_query)dmg_query_release(raw_query);native_failure(env,status,&error);return nullptr;}
        if(!raw_query){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}std::unique_ptr<dmg_query,QueryDeleter> query(raw_query);dmg_query_info info{};
        status=dmg_query_get_info(query.get(),&info);if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        constexpr uint32_t caps=1u|2u|4u|8u|32u|64u|128u|0x80000000u;
        if(!info.query_id||!std::string_view(info.query_id).starts_with("query:v23:")||!info.explicit_scope||
           !(info.required_capabilities&0x80000000u)||(info.required_capabilities&~caps)||!(info.demand_mask&512u)||(info.demand_mask&~(512u|1u|2u|4u))){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        if(info.max_results>max_query_results||info.max_work>max_query_work){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        DeclaredMethodScope scope;status=declared_scope(owner->snapshot,query.get(),scope);if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        dmg_result* raw_result=nullptr;error={};status=dmg_query_execute(owner->snapshot,query.get(),&raw_result,&error);
        if(status!=DMG_OK){if(raw_result)dmg_result_release(raw_result);native_failure(env,status,&error);return nullptr;}
        if(!raw_result){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}std::unique_ptr<dmg_result,ResultDeleter> result(raw_result);
        dmg_query_profile profile{};status=dmg_result_get_profile(result.get(),&profile);if(status!=DMG_OK||profile.scope_source_count!=scope.sources.size()){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        for(uint32_t i=0;i<profile.scope_source_count;++i){uint32_t index=0;status=dmg_result_get_scope_source(result.get(),i,&index);if(status!=DMG_OK||index!=static_cast<uint32_t>(scope.sources[i])){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}}
        const auto value=materialize_result(env,result.get(),source_set==JNI_TRUE,true);if(!value||env->ExceptionCheck())return nullptr;
        jobjectArray slots=nullptr;jintArray sources=nullptr;if(!scope_arrays(env,scope,slots,sources)){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        const auto cls=env->FindClass("io/github/jichuo1/dexmeguviz/ScopedOpcodeQuery$Result");if(!cls||env->ExceptionCheck())return nullptr;
        const auto ctor=env->GetMethodID(cls,"<init>","(Lio/github/jichuo1/dexmeguviz/NativeEngine$QueryResult;[Ljava/lang/String;[I)V");if(!ctor||env->ExceptionCheck())return nullptr;
        const auto out=env->NewObject(cls,ctor,value,slots,sources);if(!out&&!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return out;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}
