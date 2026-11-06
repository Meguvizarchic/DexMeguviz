#include "dexmeguviz/method_parameters_v1.h"
// Selected method prototype/debug-header facts; not runtime reflection or a locator decision.
extern "C" JNIEXPORT jbyteArray JNICALL Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeInspectMethodParameters(
    JNIEnv* env,jclass,jlong token,jint source_index,jlong method_ref,jboolean source_set,
    jint max_parameters,jint max_text_units,jlong max_work,jlong deadline_ms) noexcept {
    try {
        if(source_index<0||method_ref<0||static_cast<uint64_t>(method_ref)>UINT32_MAX||
           max_parameters<1||max_parameters>65536||max_text_units<1||max_text_units>1048576||
           max_work<1||static_cast<uint64_t>(max_work)>max_query_work||deadline_ms<0||deadline_ms>86400000){
            java_exception(env,"java/lang/IllegalArgumentException","invalid method parameter bounds");return nullptr;
        }
        const auto owner=lookup(token);if(!owner){native_failure(env,DMG_CLOSED);return nullptr;}
        if(owner->source_set!=(source_set==JNI_TRUE)||(!owner->source_set&&source_index!=0)){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        dmg_method_parameters_options_v1 options{};options.struct_size=sizeof(options);options.abi_version=DMG_ABI_VERSION;
        options.max_parameters=static_cast<uint32_t>(max_parameters);options.max_text_units=static_cast<uint32_t>(max_text_units);
        options.max_work=static_cast<uint64_t>(max_work);options.deadline_after_ms=static_cast<uint64_t>(deadline_ms);
        dmg_method_parameters_v1* raw=nullptr;dmg_error error{};
        const auto status=dmg_snapshot_get_method_parameters_v1(owner->snapshot,static_cast<uint32_t>(source_index),static_cast<uint32_t>(method_ref),&options,&raw,&error);
        std::unique_ptr<dmg_method_parameters_v1,decltype(&dmg_method_parameters_release_v1)> result(raw,dmg_method_parameters_release_v1);
        if(status!=DMG_OK){native_failure(env,status,&error);return nullptr;}if(!result)throw GraphError{DMG_INTERNAL_ERROR};
        dmg_method_parameters_info_v1 info{};dmg_source_info source{};dmg_parameter_text_v1 returned{};
        graph_ok(dmg_method_parameters_get_info_v1(result.get(),&info,sizeof(info)));graph_ok(dmg_method_parameters_get_source_v1(result.get(),&source,sizeof(source)));
        graph_ok(dmg_method_parameters_get_return_type_v1(result.get(),&returned,sizeof(returned)));
        if(info.source_index!=static_cast<uint32_t>(source_index)||info.method_ref!=static_cast<uint32_t>(method_ref)||info.source_index!=source.source_index||
           info.parameter_count>static_cast<uint32_t>(max_parameters)||info.debug_state>DMG_PARAMETER_DEBUG_PRESENT||!info.snapshot_id||!source.slot_key||!source.role||
           !source.dex.source_sha256||!source.dex.content_id||!source.dex.occurrence_id||!source.logical_dex_id)throw GraphError{DMG_INTERNAL_ERROR};
        GraphWriter w;w.u32(0x50474d44);for(auto n:{info.source_index,source.input_index,info.method_ref,info.method_ordinal,info.debug_state,info.debug_offset,info.parameter_count})w.u32(n);w.u64(info.work_units);
        w.ascii(info.snapshot_id);w.ascii(source.slot_key);w.ascii(source.role);w.ascii(source.dex.source_sha256);w.ascii(source.dex.content_id);w.ascii(source.dex.occurrence_id);w.ascii(source.logical_dex_id);
        w.ascii(source.archive_entry_index==UINT32_MAX?nullptr:source.archive_sha256);w.ascii(source.archive_entry_index==UINT32_MAX?nullptr:source.archive_entry_name);w.u32(source.archive_entry_index);w.u64(source.dex.source_bytes);
        for(auto n:{source.crc_verified,source.header_consistency_verified,source.expected_digest_verified})w.u32(n);
        w.text(true,returned.value,returned.length);w.item(info.parameter_count);
        for(uint32_t i=0;i<info.parameter_count;++i){dmg_method_parameter_v1 row{};graph_ok(dmg_method_parameters_get_parameter_v1(result.get(),i,&row,sizeof(row)));
            if(row.ordinal!=i||row.name_state>DMG_PARAMETER_NAME_PRESENT)throw GraphError{DMG_INTERNAL_ERROR};
            for(auto n:{row.ordinal,row.type_index,row.name_state,row.name_string_index})w.u32(n);
            w.text(true,row.type_descriptor,row.type_descriptor_length);w.text(row.name_state==DMG_PARAMETER_NAME_PRESENT,row.name,row.name_length);
        }
        auto out=env->NewByteArray(static_cast<jsize>(w.data.size()));if(!out||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        if(!w.data.empty())env->SetByteArrayRegion(out,0,static_cast<jsize>(w.data.size()),reinterpret_cast<const jbyte*>(w.data.data()));return env->ExceptionCheck()?nullptr:out;
    }catch(const GraphError& e){native_failure(env,e.status);}catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}
