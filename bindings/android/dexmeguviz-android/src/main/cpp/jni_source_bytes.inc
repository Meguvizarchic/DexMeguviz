// Java holds the snapshot monitor through the native call and byte-array copy.
extern "C" JNIEXPORT jbyteArray JNICALL Java_io_github_jichuo1_dexmeguviz_DexSourceExport_nativeBytes(JNIEnv* env,jclass,jobject snapshot,jboolean source_set,jint source_index,jlong max_bytes) noexcept {
    try {
        if(source_index<0||max_bytes<1||max_bytes>INT32_MAX){java_exception(env,"java/lang/IllegalArgumentException","invalid source or byte limit");return nullptr;}
        const auto owner=scoped_snapshot(env,snapshot,source_set);if(!owner)return nullptr;
        const uint8_t* bytes=nullptr;uint64_t size=0;const auto status=dmg_snapshot_get_source_bytes_v1(owner->snapshot,static_cast<uint32_t>(source_index),static_cast<uint64_t>(max_bytes),&bytes,&size);
        if(status!=DMG_OK){native_failure(env,status);return nullptr;}if(size>static_cast<uint64_t>(INT32_MAX)||(!bytes&&size)){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        auto result=env->NewByteArray(static_cast<jsize>(size));if(!result||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        if(size)env->SetByteArrayRegion(result,0,static_cast<jsize>(size),reinterpret_cast<const jbyte*>(bytes));return env->ExceptionCheck()?nullptr:result;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}

// Java holds the snapshot monitor while copying a source-local symbol.
extern "C" JNIEXPORT jcharArray JNICALL Java_io_github_jichuo1_dexmeguviz_DexSourceExport_nativeSymbol(JNIEnv* env,jclass,jobject snapshot,jboolean source_set,jint source_index,jint kind,jlong index,jint max_units) noexcept {
    try {
        if(source_index<0||kind<0||kind>2||index<0||static_cast<uint64_t>(index)>UINT32_MAX||max_units<1||max_units>1048576){java_exception(env,"java/lang/IllegalArgumentException","invalid symbol or limit");return nullptr;}
        const auto owner=scoped_snapshot(env,snapshot,source_set);if(!owner)return nullptr;
        uint64_t length=0;auto status=dmg_snapshot_copy_symbol_text_v1(owner->snapshot,static_cast<uint32_t>(source_index),static_cast<uint32_t>(kind),static_cast<uint32_t>(index),static_cast<uint64_t>(max_units),nullptr,0,&length);
        if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        auto result=env->NewCharArray(static_cast<jsize>(length));if(!result||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        if(length){jchar* chars=env->GetCharArrayElements(result,nullptr);if(!chars){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}uint64_t copied=0;
            status=dmg_snapshot_copy_symbol_text_v1(owner->snapshot,static_cast<uint32_t>(source_index),static_cast<uint32_t>(kind),static_cast<uint32_t>(index),static_cast<uint64_t>(max_units),reinterpret_cast<uint16_t*>(chars),length,&copied);
            env->ReleaseCharArrayElements(result,chars,status==DMG_OK&&copied==length?0:JNI_ABORT);
            if(status!=DMG_OK){native_failure(env,status);return nullptr;}if(copied!=length){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}}
        return result;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}

// Snapshot monitor remains held across lookup and result-array creation.
extern "C" JNIEXPORT jlongArray JNICALL Java_io_github_jichuo1_dexmeguviz_DexSourceExport_nativeMemberIndices(JNIEnv* env,jclass,jobject snapshot,jboolean source_set,jint source_index,jint kind,jlong index) noexcept {
    try {
        if(source_index<0||kind<0||kind>1||index<0||static_cast<uint64_t>(index)>UINT32_MAX){java_exception(env,"java/lang/IllegalArgumentException","invalid member or source index");return nullptr;}
        const auto owner=scoped_snapshot(env,snapshot,source_set);if(!owner)return nullptr;
        dmg_member_indices_v1 value{};const auto status=dmg_snapshot_get_member_indices_v1(owner->snapshot,static_cast<uint32_t>(source_index),static_cast<uint32_t>(kind),static_cast<uint32_t>(index),&value,sizeof(value));
        if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        auto result=env->NewLongArray(3);if(!result||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        const jlong values[3]={static_cast<jlong>(value.owner_type_index),static_cast<jlong>(value.name_string_index),static_cast<jlong>(value.type_or_proto_index)};
        env->SetLongArrayRegion(result,0,3,values);return env->ExceptionCheck()?nullptr:result;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}
