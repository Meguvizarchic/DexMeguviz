// Caller holds the snapshot monitor only during each bounded static byte copy.
extern "C" JNIEXPORT jint JNICALL Java_io_github_jichuo1_dexmeguviz_DexStreamExport_nativeRead(JNIEnv* env,jclass,jobject snapshot,jboolean source_set,jint source_index,jlong offset,jbyteArray output,jint requested,jlong max_source_bytes) noexcept {
    try {
        if(source_index<0||offset<0||!output||requested<1||requested>(1<<20)||max_source_bytes<1){java_exception(env,"java/lang/IllegalArgumentException","invalid source read limits");return 0;}
        const auto length=env->GetArrayLength(output);if(env->ExceptionCheck())return 0;if(requested>length){java_exception(env,"java/lang/IllegalArgumentException","output buffer is too small");return 0;}
        const auto owner=scoped_snapshot(env,snapshot,source_set);if(!owner)return 0;
        const uint8_t* bytes=nullptr;uint64_t size=0;const auto status=dmg_snapshot_get_source_bytes_v1(owner->snapshot,static_cast<uint32_t>(source_index),static_cast<uint64_t>(max_source_bytes),&bytes,&size);
        if(status!=DMG_OK){native_failure(env,status);return 0;}
        const auto at=static_cast<uint64_t>(offset);if(at>size||(!bytes&&size)){native_failure(env,at>size?DMG_INVALID_ARGUMENT:DMG_INTERNAL_ERROR);return 0;}
        const auto count=std::min<uint64_t>(static_cast<uint64_t>(requested),size-at);if(count)env->SetByteArrayRegion(output,0,static_cast<jsize>(count),reinterpret_cast<const jbyte*>(bytes+static_cast<size_t>(at)));
        return env->ExceptionCheck()?0:static_cast<jint>(count);
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return 0;
}
