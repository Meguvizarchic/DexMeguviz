// Compiled only when the Android persistent-facts feature is explicitly enabled.
extern "C" JNIEXPORT jlong JNICALL
Java_io_github_jichuo1_dexmeguviz_PersistentCacheBridge_nativeOpen(JNIEnv* env,jclass,jobject snapshot,
    jboolean source_set,jbyteArray directory,jlong max_file,jlong max_directory,jint max_entries,jint max_records) noexcept {
    try {
        if(!snapshot||!directory){java_exception(env,"java/lang/NullPointerException","snapshot and directory are required");return 0;}
        if((source_set!=JNI_FALSE&&source_set!=JNI_TRUE)||max_file<0||max_directory<0||max_entries<0||max_records<0){native_failure(env,DMG_INVALID_ARGUMENT);return 0;}
        const auto cls=env->FindClass(source_set?"io/github/jichuo1/dexmeguviz/NativeEngine$SourceSetSnapshot":"io/github/jichuo1/dexmeguviz/NativeEngine$Snapshot");
        if(!cls||env->ExceptionCheck())return 0;
        if(!env->IsInstanceOf(snapshot,cls)){java_exception(env,"java/lang/IllegalArgumentException","snapshot type mismatch");return 0;}
        const auto field=env->GetFieldID(cls,"token","J");if(!field||env->ExceptionCheck())return 0;
        const auto snapshot_token=env->GetLongField(snapshot,field);if(env->ExceptionCheck())return 0;
        const auto owner=lookup(snapshot_token);if(!owner){native_failure(env,DMG_CLOSED);return 0;}
        if(owner->source_set!=(source_set==JNI_TRUE)){native_failure(env,DMG_UNSUPPORTED);return 0;}
        const auto length=env->GetArrayLength(directory);if(env->ExceptionCheck())return 0;
        if(length<=0||length>4096){native_failure(env,DMG_INVALID_ARGUMENT);return 0;}
        std::vector<uint8_t> bytes(static_cast<size_t>(length));env->GetByteArrayRegion(directory,0,length,reinterpret_cast<jbyte*>(bytes.data()));if(env->ExceptionCheck())return 0;
        PersistentPermit permit;if(!permit.acquire()){native_failure(env,DMG_BUDGET_EXCEEDED);return 0;}
        dmg_persistent_cache_options_v1 options{};options.struct_size=sizeof(options);options.abi_version=DMG_ABI_VERSION;
        options.directory_utf8=bytes.data();options.directory_length=bytes.size();options.max_file_bytes=static_cast<uint64_t>(max_file);
        options.max_directory_bytes=static_cast<uint64_t>(max_directory);options.max_directory_entries=static_cast<uint32_t>(max_entries);options.max_records=static_cast<uint32_t>(max_records);
        dmg_persistent_cache_v1* raw=nullptr;dmg_error error{};const auto status=dmg_persistent_cache_open_v1(owner->engine,&options,&raw,&error);
        if(status!=DMG_OK){if(raw)dmg_persistent_cache_release_v1(raw);native_failure(env,status,&error);return 0;}
        if(!raw){native_failure(env,DMG_INTERNAL_ERROR);return 0;}
        std::unique_ptr<dmg_persistent_cache_v1,PersistentDeleter> guard(raw);
        if(lookup(snapshot_token).get()!=owner.get()){native_failure(env,DMG_CLOSED);return 0;}
        auto session=std::make_shared<PersistentOwner>(owner,snapshot_token,guard.get());guard.release();
        const auto token=permit.publish(session);if(!token){native_failure(env,DMG_BUDGET_EXCEEDED);return 0;}return token;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return 0;
}
extern "C" JNIEXPORT jobject JNICALL
Java_io_github_jichuo1_dexmeguviz_PersistentCacheBridge_nativeQueryMethods(JNIEnv* env,jclass,jlong token,jbyteArray query) noexcept {
    try {
        const auto session=lookup_persistent(token);if(!session){native_failure(env,DMG_CLOSED);return nullptr;}
        return query_methods(env,session->snapshot_token,query,session->owner->source_set,session->cache,session->owner.get());
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}
extern "C" JNIEXPORT jlongArray JNICALL
Java_io_github_jichuo1_dexmeguviz_PersistentCacheBridge_nativeStatistics(JNIEnv* env,jclass,jlong token) noexcept {
    try {
        const auto session=lookup_persistent(token);if(!session){native_failure(env,DMG_CLOSED);return nullptr;}
        dmg_persistent_cache_stats_v1 stats{};const auto status=dmg_persistent_cache_get_stats_v1(session->cache,&stats,sizeof(stats));
        if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        const std::array<uint64_t,7> counters{stats.hits,stats.misses,stats.rebuilds,stats.rejected,stats.published,stats.write_failures,stats.bytes_read};
        std::array<jlong,7> copy{};for(size_t i=0;i<counters.size();++i){if(counters[i]>uint64_t(std::numeric_limits<jlong>::max())){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}copy[i]=static_cast<jlong>(counters[i]);}
        auto out=env->NewLongArray(static_cast<jsize>(copy.size()));if(!out||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        env->SetLongArrayRegion(out,0,static_cast<jsize>(copy.size()),copy.data());if(env->ExceptionCheck())return nullptr;return out;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}
extern "C" JNIEXPORT void JNICALL
Java_io_github_jichuo1_dexmeguviz_PersistentCacheBridge_nativeClose(JNIEnv* env,jclass,jlong token) noexcept {
    try {
        std::shared_ptr<PersistentOwner> owner;
        {std::lock_guard lock(registry_mutex);const auto it=persistent_sessions.find(token);if(it==persistent_sessions.end())return;owner=std::move(it->second);persistent_sessions.erase(it);}
        const auto status=dmg_persistent_cache_close_v1(owner->cache);if(status!=DMG_OK)native_failure(env,status);
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}
}
