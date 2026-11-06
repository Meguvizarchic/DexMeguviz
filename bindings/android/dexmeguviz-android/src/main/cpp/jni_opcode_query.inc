// Explicit v23 direct opcode query; callers hold the snapshot monitor.
extern "C" JNIEXPORT jobject JNICALL Java_io_github_jichuo1_dexmeguviz_OpcodeQuery_nativeExecute(JNIEnv* env,jclass,jobject snapshot,jboolean source_set,jbyteArray input) noexcept {
    try {
        if(!input){java_exception(env,"java/lang/NullPointerException","queryJson is required");return nullptr;}
        const auto owner=scoped_snapshot(env,snapshot,source_set);if(!owner)return nullptr;
        const auto length=env->GetArrayLength(input);if(env->ExceptionCheck())return nullptr;
        if(static_cast<uint64_t>(length)>max_query_bytes){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        std::vector<uint8_t> json(static_cast<size_t>(length));if(length)env->GetByteArrayRegion(input,0,length,reinterpret_cast<jbyte*>(json.data()));if(env->ExceptionCheck())return nullptr;
        dmg_error error{};dmg_query* raw=nullptr;auto status=dmg_query_compile_json(owner->engine,json.data(),json.size(),&raw,&error);
        if(status!=DMG_OK){if(raw)dmg_query_release(raw);native_failure(env,status,&error);return nullptr;}
        if(!raw){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}std::unique_ptr<dmg_query,QueryDeleter> query(raw);dmg_query_info info{};
        status=dmg_query_get_info(query.get(),&info);if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        constexpr uint32_t caps=1u|2u|4u|32u|64u|128u|0x80000000u;
        if(!info.query_id||!std::string_view(info.query_id).starts_with("query:v23:")||info.explicit_scope||
           !(info.required_capabilities&0x80000000u)||(info.required_capabilities&~caps)||!(info.demand_mask&512u)||(info.demand_mask&~(512u|1u|2u|4u))){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        if(info.max_results>max_query_results||info.max_work>max_query_work){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        dmg_result* result_raw=nullptr;error={};status=dmg_query_execute(owner->snapshot,query.get(),&result_raw,&error);
        if(status!=DMG_OK){if(result_raw)dmg_result_release(result_raw);native_failure(env,status,&error);return nullptr;}
        if(!result_raw){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}std::unique_ptr<dmg_result,ResultDeleter> result(result_raw);
        return materialize_result(env,result.get(),source_set==JNI_TRUE);
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}
