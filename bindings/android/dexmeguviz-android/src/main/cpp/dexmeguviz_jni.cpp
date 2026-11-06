#include <jni.h>
#include "dexmeguviz/dexmeguviz.h"
#include "../../../../../../src/c_api/raw_fill.hpp"
#ifdef DMG_ANDROID_PERSISTENT_FACTS
#include "dexmeguviz/persistent_cache_v1.h"
#endif
#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {
constexpr size_t max_live_snapshots = 64;
constexpr size_t max_slot_chars = 128;
constexpr jsize max_raw_sources = 8;
constexpr uint32_t max_expanded_sources = 64;
constexpr uint64_t max_query_bytes = 65536;
constexpr uint64_t max_query_work = 100000000;
constexpr uint32_t max_query_results = 4096;
constexpr uint64_t max_output_text_units = 1048576;
constexpr size_t max_live_jobs = 64;
constexpr jint max_job_wait_ms = 60000;
struct SnapshotOwner {
    SnapshotOwner(dmg_snapshot* snapshot, dmg_engine* engine, bool set=false) noexcept : snapshot(snapshot), engine(engine), source_set(set) {}
    ~SnapshotOwner() { dmg_snapshot_release(snapshot); dmg_engine_release(engine); }
    dmg_snapshot* snapshot;
    dmg_engine* engine;
    bool source_set;
};
struct SnapshotDeleter {
    void operator()(dmg_snapshot* snapshot) const noexcept { dmg_snapshot_release(snapshot); }
};
struct EngineDeleter {
    void operator()(dmg_engine* engine) const noexcept { dmg_engine_release(engine); }
};
struct QueryDeleter { void operator()(dmg_query* p) const noexcept { dmg_query_release(p); } };
struct ResultDeleter { void operator()(dmg_result* p) const noexcept { dmg_result_release(p); } };
struct JobDeleter { void operator()(dmg_job* p) const noexcept { dmg_job_release(p); } };
std::atomic<size_t> job_slots{0};
struct JobOwner {
    JobOwner(dmg_job* value, std::shared_ptr<SnapshotOwner> snapshot,
             std::string query, std::string snapshot_id, bool entity=false, bool graph=false, bool use_graph=false,bool method_type=false,bool expand=false,bool advanced=false,uint32_t class_annotation=0,bool annotation_scoped=false,std::vector<jint> scoped_sources={}) noexcept
        : job(value), owner(std::move(snapshot)), query_id(std::move(query)), snapshot_id(std::move(snapshot_id)), entity(entity), graph(graph), use_graph(use_graph),method_type(method_type),expand(expand),advanced(advanced),class_annotation(class_annotation),annotation_scoped(annotation_scoped),scoped_sources(std::move(scoped_sources)) {}
    ~JobOwner() { dmg_job_release(job); if(owns_slot)job_slots.fetch_sub(1,std::memory_order_acq_rel); }
    dmg_job* job;
    std::shared_ptr<SnapshotOwner> owner;
    std::string query_id, snapshot_id;
    bool entity;
    bool graph;
    bool use_graph;
    bool method_type;
    bool expand;
    bool advanced;
    const uint32_t class_annotation;
    const bool annotation_scoped;
    const std::vector<jint> scoped_sources;
    std::mutex consumer;
    std::atomic<bool> delivery_failed{false};
    bool owns_slot = false;
};
std::mutex registry_mutex;
std::unordered_map<jlong, std::shared_ptr<SnapshotOwner>> registry;
uint64_t next_token = 1;
size_t opening_snapshots = 0;
std::unordered_map<jlong, std::shared_ptr<JobOwner>> jobs;
uint64_t next_job_token = 1;
// Independent, explicitly closed sessions keep compiled plans on the same
// engine while callers release each source snapshot before opening the next.
struct MethodStreamOwner {
    std::unique_ptr<dmg_engine,EngineDeleter> engine;
    std::vector<std::unique_ptr<dmg_query,QueryDeleter>> queries;
    uint64_t source_limit=0;
};
std::unordered_map<jlong,std::shared_ptr<MethodStreamOwner>> method_streams;
uint64_t next_method_stream=1;
size_t opening_method_streams=0;
struct MethodStreamPermit {
    bool held=false;
    bool acquire(){std::lock_guard lock(registry_mutex);if(method_streams.size()+opening_method_streams>=16||next_method_stream>uint64_t(std::numeric_limits<jlong>::max()))return false;++opening_method_streams;held=true;return true;}
    jlong publish(const std::shared_ptr<MethodStreamOwner>& owner){std::lock_guard lock(registry_mutex);if(!held||!opening_method_streams||next_method_stream>uint64_t(std::numeric_limits<jlong>::max()))return 0;const auto token=static_cast<jlong>(next_method_stream);if(!method_streams.emplace(token,owner).second)return 0;++next_method_stream;--opening_method_streams;held=false;return token;}
    ~MethodStreamPermit() noexcept {if(!held)return;try{std::lock_guard lock(registry_mutex);if(opening_method_streams)--opening_method_streams;}catch(...){}}
};
std::shared_ptr<MethodStreamOwner> lookup_method_stream(jlong token){std::lock_guard lock(registry_mutex);const auto it=method_streams.find(token);return it==method_streams.end()?nullptr:it->second;}

struct JobPermit {
    bool held = false;
    JobPermit() = default;
    JobPermit(const JobPermit&) = delete;
    JobPermit& operator=(const JobPermit&) = delete;
    bool acquire() {
        auto count=job_slots.load(std::memory_order_relaxed);
        while(count<max_live_jobs){
            if(job_slots.compare_exchange_weak(count,count+1,std::memory_order_acq_rel)) {held=true;return true;}
        }
        return false;
    }
    jlong publish(const std::shared_ptr<JobOwner>& owner) {
        std::lock_guard lock(registry_mutex);
        if (!held || next_job_token > uint64_t(std::numeric_limits<jlong>::max())) return 0;
        const auto token = static_cast<jlong>(next_job_token++);
        jobs.emplace(token, owner); owner->owns_slot=true; held=false; return token;
    }
    ~JobPermit() noexcept { if(held)job_slots.fetch_sub(1,std::memory_order_acq_rel); }
};

struct OpenPermit {
    bool held = false;
    OpenPermit() = default;
    OpenPermit(const OpenPermit&) = delete;
    OpenPermit& operator=(const OpenPermit&) = delete;
    bool acquire() {
        std::lock_guard lock(registry_mutex);
        if (registry.size() + opening_snapshots >= max_live_snapshots ||
            next_token > uint64_t(std::numeric_limits<jlong>::max())) return false;
        ++opening_snapshots;
        held = true;
        return true;
    }
    jlong publish(const std::shared_ptr<SnapshotOwner>& owner) {
        std::lock_guard lock(registry_mutex);
        if (!held || !opening_snapshots || next_token > uint64_t(std::numeric_limits<jlong>::max())) return 0;
        const auto token = static_cast<jlong>(next_token++);
        registry.emplace(token, owner);
        --opening_snapshots;
        held = false;
        return token;
    }
    ~OpenPermit() noexcept {
        if (!held) return;
        try {
            std::lock_guard lock(registry_mutex);
            if (opening_snapshots) --opening_snapshots;
        } catch (...) {
            // If the mutex itself fails, retain the reservation and fail closed.
        }
    }
};

void java_exception(JNIEnv* env, const char* name, const char* message) noexcept {
    if (env->ExceptionCheck()) return;
    const auto cls = env->FindClass(name);
    if (cls && !env->ExceptionCheck()) env->ThrowNew(cls, message);
}
void native_failure(JNIEnv* env, dmg_status status, const dmg_error* error = nullptr) noexcept {
    if (env->ExceptionCheck()) return;
    const char* source = error && error->message[0] ? error->message : dmg_status_name(status);
    std::array<char, 256> message{};
    for (size_t i = 0; i + 1 < message.size() && source[i]; ++i) {
        const auto ch = static_cast<unsigned char>(source[i]);
        message[i] = ch >= 0x20 && ch <= 0x7e ? static_cast<char>(ch) : '?';
    }
    const auto cls = env->FindClass("io/github/jichuo1/dexmeguviz/NativeEngine$NativeFailure");
    if (!cls || env->ExceptionCheck()) return;
    const auto ctor = env->GetMethodID(cls, "<init>", "(IJLjava/lang/String;)V");
    if (!ctor || env->ExceptionCheck()) return;
    const auto text = env->NewStringUTF(message.data());
    if (!text || env->ExceptionCheck()) return;
    const auto offset = error && error->offset <= uint64_t(std::numeric_limits<jlong>::max())
        ? static_cast<jlong>(error->offset) : 0;
    const auto object = env->NewObject(cls, ctor, static_cast<jint>(status), offset, text);
    if (!env->ExceptionCheck() && object) env->Throw(static_cast<jthrowable>(object));
}
std::shared_ptr<SnapshotOwner> lookup(jlong token) {
    std::lock_guard lock(registry_mutex);
    const auto it = registry.find(token);
    return it == registry.end() ? nullptr : it->second;
}
std::shared_ptr<JobOwner> lookup_job(jlong token) {
    std::lock_guard lock(registry_mutex);
    const auto it = jobs.find(token);
    return it == jobs.end() ? nullptr : it->second;
}
#ifdef DMG_ANDROID_PERSISTENT_FACTS
struct PersistentOwner {
    PersistentOwner(std::shared_ptr<SnapshotOwner> source,jlong source_token,dmg_persistent_cache_v1* value) noexcept
        :owner(std::move(source)),snapshot_token(source_token),cache(value){}
    ~PersistentOwner(){dmg_persistent_cache_release_v1(cache);}
    std::shared_ptr<SnapshotOwner> owner;
    jlong snapshot_token;
    dmg_persistent_cache_v1* cache;
};
struct PersistentDeleter {void operator()(dmg_persistent_cache_v1* p)const noexcept{dmg_persistent_cache_release_v1(p);}};
constexpr size_t max_live_persistent=16;
std::unordered_map<jlong,std::shared_ptr<PersistentOwner>> persistent_sessions;
uint64_t next_persistent_token=1;
size_t opening_persistent=0;
struct PersistentPermit {
    bool held=false;
    bool acquire(){std::lock_guard lock(registry_mutex);if(persistent_sessions.size()+opening_persistent>=max_live_persistent||next_persistent_token>uint64_t(std::numeric_limits<jlong>::max()))return false;++opening_persistent;held=true;return true;}
    jlong publish(const std::shared_ptr<PersistentOwner>& owner){std::lock_guard lock(registry_mutex);if(!held||!opening_persistent||next_persistent_token>uint64_t(std::numeric_limits<jlong>::max()))return 0;const auto token=static_cast<jlong>(next_persistent_token);if(!persistent_sessions.emplace(token,owner).second)return 0;++next_persistent_token;--opening_persistent;held=false;return token;}
    ~PersistentPermit() noexcept {if(!held)return;try{std::lock_guard lock(registry_mutex);if(opening_persistent)--opening_persistent;}catch(...){}}
};
std::shared_ptr<PersistentOwner> lookup_persistent(jlong token){std::lock_guard lock(registry_mutex);const auto it=persistent_sessions.find(token);return it==persistent_sessions.end()?nullptr:it->second;}
#endif
}

extern "C" JNIEXPORT jint JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_abiVersion(JNIEnv*, jclass) {
    return static_cast<jint>(dmg_abi_version());
}

extern "C" JNIEXPORT jstring JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_capabilities(JNIEnv* env, jclass) {
    return env->NewStringUTF(dmg_capabilities());
}

static jlong open_raw_dex(JNIEnv* env,jbyteArray input,jstring slot,uint64_t source_limit,uint64_t owned_limit,bool explicit_limits,dmg_engine* shared_engine=nullptr) noexcept {
    try {
        if (!input || !slot) {
            java_exception(env, "java/lang/NullPointerException", "bytes and slot are required");
            return 0;
        }
        const auto slot_size = env->GetStringLength(slot);
        if (env->ExceptionCheck()) return 0;
        if (slot_size < 1 || slot_size > static_cast<jsize>(max_slot_chars)) {
            java_exception(env, "java/lang/IllegalArgumentException", "slot must contain 1 to 128 printable ASCII characters");
            return 0;
        }
        std::array<jchar, max_slot_chars> slot_units{};
        env->GetStringRegion(slot, 0, slot_size, slot_units.data());
        if (env->ExceptionCheck()) return 0;
        std::string slot_text;
        slot_text.reserve(static_cast<size_t>(slot_size));
        for (jsize i = 0; i < slot_size; ++i) {
            const auto ch = slot_units[static_cast<size_t>(i)];
            if (ch < 0x21 || ch > 0x7e) {
                java_exception(env, "java/lang/IllegalArgumentException", "slot must contain printable ASCII without spaces");
                return 0;
            }
            slot_text.push_back(static_cast<char>(ch));
        }
        const auto length = env->GetArrayLength(input);
        if (env->ExceptionCheck()) return 0;
        if (static_cast<uint64_t>(length) > source_limit) {
            native_failure(env, DMG_BUDGET_EXCEEDED);
            return 0;
        }
        OpenPermit permit;
        if (!permit.acquire()) { native_failure(env, DMG_BUDGET_EXCEEDED); return 0; }
        dmg_engine* raw_engine = nullptr;
        dmg_error error{};
        const dmg_engine_options options{sizeof(dmg_engine_options),DMG_ABI_VERSION,owned_limit,0,source_limit,4,0};
        const auto engine_status = shared_engine?(dmg_engine_retain(shared_engine),raw_engine=shared_engine,DMG_OK):dmg_engine_create(explicit_limits?&options:nullptr, &raw_engine, &error);
        if (engine_status != DMG_OK) {
            if (raw_engine) dmg_engine_release(raw_engine);
            native_failure(env, engine_status, &error);
            return 0;
        }
        if (!raw_engine) { native_failure(env, DMG_INTERNAL_ERROR); return 0; }
        std::unique_ptr<dmg_engine, EngineDeleter> engine(raw_engine);
        dmg_snapshot* raw = nullptr;
        error = {};
        struct ArrayInput { JNIEnv* env; jbyteArray array; } source{env,input};
        const auto fill=[](void* p,uint8_t* dst,size_t n)->bool {
            auto& input=*static_cast<ArrayInput*>(p);
            input.env->GetByteArrayRegion(input.array,0,static_cast<jsize>(n),reinterpret_cast<jbyte*>(dst));
            return !input.env->ExceptionCheck();
        };
        const auto status = dexmeguviz::runtime::open_android_raw_filled(engine.get(),static_cast<uint64_t>(length),slot_text.c_str(),fill,&source,&raw,&error);
        if (status != DMG_OK) {
            if (raw) dmg_snapshot_release(raw);
            native_failure(env, status, &error);
            return 0;
        }
        if (!raw) { native_failure(env, DMG_INTERNAL_ERROR); return 0; }
        std::unique_ptr<dmg_snapshot, SnapshotDeleter> guard(raw);
        const auto owner = std::make_shared<SnapshotOwner>(guard.get(), engine.get());
        guard.release();
        engine.release();
        const auto token = permit.publish(owner);
        if (!token) { native_failure(env, DMG_BUDGET_EXCEEDED); return 0; }
        return token;
    } catch (const std::bad_alloc&) {
        native_failure(env, DMG_OUT_OF_MEMORY);
    } catch (...) {
        native_failure(env, DMG_INTERNAL_ERROR);
    }
    return 0;
}

extern "C" JNIEXPORT jlong JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeOpenRawDex(JNIEnv* env,jclass,jbyteArray input,jstring slot) noexcept {
    return open_raw_dex(env,input,slot,DMG_MAX_SOURCE_BYTES,0,false);
}
extern "C" JNIEXPORT jlong JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeOpenRawDexWithLimits(JNIEnv* env,jclass,jbyteArray input,jstring slot,jlong source_limit,jlong owned_limit) noexcept {
    if(source_limit<=0||source_limit>std::numeric_limits<jsize>::max()||owned_limit<=0){
        java_exception(env,"java/lang/IllegalArgumentException","invalid source or owned memory limit");return 0;
    }
    return open_raw_dex(env,input,slot,static_cast<uint64_t>(source_limit),static_cast<uint64_t>(owned_limit),true);
}

extern "C" JNIEXPORT jlong JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeCreateMethodStream(JNIEnv* env,jclass,jobjectArray rules,jlong source_limit,jlong owned_limit) noexcept {
    try {
        if(!rules){java_exception(env,"java/lang/NullPointerException","queries are required");return 0;}
        if(source_limit<=0||source_limit>std::numeric_limits<jsize>::max()||owned_limit<=0){java_exception(env,"java/lang/IllegalArgumentException","invalid source or owned memory limit");return 0;}
        const auto count=env->GetArrayLength(rules);if(env->ExceptionCheck())return 0;
        if(count<1||count>64){java_exception(env,"java/lang/IllegalArgumentException","expected 1 to 64 queries");return 0;}
        MethodStreamPermit permit;if(!permit.acquire()){native_failure(env,DMG_BUDGET_EXCEEDED);return 0;}
        const auto stream=std::make_shared<MethodStreamOwner>();stream->source_limit=static_cast<uint64_t>(source_limit);
        const dmg_engine_options options{sizeof(dmg_engine_options),DMG_ABI_VERSION,static_cast<uint64_t>(owned_limit),0,static_cast<uint64_t>(source_limit),4,0};
        dmg_engine* raw=nullptr;dmg_error error{};auto status=dmg_engine_create(&options,&raw,&error);
        if(status!=DMG_OK||!raw){if(raw)dmg_engine_release(raw);native_failure(env,status==DMG_OK?DMG_INTERNAL_ERROR:status,&error);return 0;}
        stream->engine.reset(raw);stream->queries.reserve(static_cast<size_t>(count));
        for(jsize i=0;i<count;++i){
            auto input=static_cast<jbyteArray>(env->GetObjectArrayElement(rules,i));if(env->ExceptionCheck())return 0;
            if(!input){java_exception(env,"java/lang/NullPointerException","query is required");return 0;}
            const auto length=env->GetArrayLength(input);if(env->ExceptionCheck()){env->DeleteLocalRef(input);return 0;}
            if(static_cast<uint64_t>(length)>max_query_bytes){env->DeleteLocalRef(input);native_failure(env,DMG_BUDGET_EXCEEDED);return 0;}
            std::vector<uint8_t> json(static_cast<size_t>(length));if(length)env->GetByteArrayRegion(input,0,length,reinterpret_cast<jbyte*>(json.data()));env->DeleteLocalRef(input);if(env->ExceptionCheck())return 0;
            dmg_query* query=nullptr;error={};status=dmg_query_compile_json(stream->engine.get(),json.data(),json.size(),&query,&error);
            if(status!=DMG_OK||!query){if(query)dmg_query_release(query);native_failure(env,status==DMG_OK?DMG_INTERNAL_ERROR:status,&error);return 0;}
            std::unique_ptr<dmg_query,QueryDeleter> held(query);dmg_query_info info{};status=dmg_query_get_info(held.get(),&info);
            if(status!=DMG_OK){native_failure(env,status);return 0;}
            if(!info.query_id||std::string_view(info.query_id).substr(0,9)!="query:v1:"||info.explicit_scope){native_failure(env,DMG_UNSUPPORTED);return 0;}
            if(info.max_results>max_query_results||info.max_work>max_query_work){native_failure(env,DMG_BUDGET_EXCEEDED);return 0;}
            stream->queries.push_back(std::move(held));
        }
        const auto token=permit.publish(stream);if(!token)native_failure(env,DMG_BUDGET_EXCEEDED);return token;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return 0;
}
extern "C" JNIEXPORT jlong JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeOpenMethodStreamDex(JNIEnv* env,jclass,jlong token,jbyteArray input,jstring slot) noexcept {
    try {const auto stream=lookup_method_stream(token);if(!stream){native_failure(env,DMG_CLOSED);return 0;}return open_raw_dex(env,input,slot,stream->source_limit,0,false,stream->engine.get());}
    catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return 0;
}
extern "C" JNIEXPORT void JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeCloseMethodStream(JNIEnv* env,jclass,jlong token) noexcept {
    try {std::lock_guard lock(registry_mutex);method_streams.erase(token);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}
}

static jlong open_sources(JNIEnv* env,jobjectArray inputs,jobjectArray slots,jintArray formats,jbooleanArray allow_no_dex) noexcept {
    try {
        if(!inputs||!slots){java_exception(env,"java/lang/NullPointerException","bytes and slots are required");return 0;}
        const auto count=env->GetArrayLength(inputs);if(env->ExceptionCheck())return 0;
        const auto slot_count=env->GetArrayLength(slots);if(env->ExceptionCheck())return 0;
        if(count<1||count>max_raw_sources||count!=slot_count){java_exception(env,"java/lang/IllegalArgumentException","expected 1 to 8 matching sources and slots");return 0;}
        std::array<jint,max_raw_sources> kinds{};std::array<jboolean,max_raw_sources> allow{};
        if(formats||allow_no_dex){
            if(!formats||!allow_no_dex){java_exception(env,"java/lang/NullPointerException","formats and allowNoDex are required");return 0;}
            const auto format_count=env->GetArrayLength(formats);if(env->ExceptionCheck())return 0;
            const auto allow_count=env->GetArrayLength(allow_no_dex);if(env->ExceptionCheck())return 0;
            if(format_count!=count||allow_count!=count){java_exception(env,"java/lang/IllegalArgumentException","source option array lengths differ");return 0;}
            env->GetIntArrayRegion(formats,0,count,kinds.data());if(env->ExceptionCheck())return 0;
            env->GetBooleanArrayRegion(allow_no_dex,0,count,allow.data());if(env->ExceptionCheck())return 0;
        }else kinds.fill(DMG_INPUT_RAW_DEX);
        for(jsize i=0;i<count;++i){
            if((kinds[i]!=DMG_INPUT_RAW_DEX&&kinds[i]!=DMG_INPUT_APK)||
               (kinds[i]==DMG_INPUT_RAW_DEX&&allow[i]!=JNI_FALSE)){
                java_exception(env,"java/lang/IllegalArgumentException","invalid format or raw DEX allowNoDex");return 0;
            }
        }
        std::array<std::array<char,max_slot_chars+1>,max_raw_sources> keys{};std::array<jsize,max_raw_sources> lengths{};uint64_t total=0;
        // All lengths and all slot identities are checked before copying any input.
        for(jsize i=0;i<count;++i){
            if(env->PushLocalFrame(4)<0){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return 0;}
            const auto bytes=static_cast<jbyteArray>(env->GetObjectArrayElement(inputs,i));
            if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
            const auto slot=static_cast<jstring>(env->GetObjectArrayElement(slots,i));
            if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
            if(!bytes||!slot){env->PopLocalFrame(nullptr);java_exception(env,"java/lang/NullPointerException","source and slot are required");return 0;}
            const auto size=env->GetArrayLength(bytes);if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
            const auto n=env->GetStringLength(slot);
            if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
            if(n<1||n>static_cast<jsize>(max_slot_chars)){env->PopLocalFrame(nullptr);java_exception(env,"java/lang/IllegalArgumentException","invalid source slot");return 0;}
            if(static_cast<uint64_t>(size)>DMG_MAX_SOURCE_BYTES-total){env->PopLocalFrame(nullptr);native_failure(env,DMG_BUDGET_EXCEEDED);return 0;}
            total+=static_cast<uint64_t>(size);lengths[static_cast<size_t>(i)]=size;
            std::array<jchar,max_slot_chars> chars{};env->GetStringRegion(slot,0,n,chars.data());
            if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
            auto& key=keys[static_cast<size_t>(i)];
            for(jsize j=0;j<n;++j){const auto c=chars[static_cast<size_t>(j)];if(c<0x21||c>0x7e){env->PopLocalFrame(nullptr);java_exception(env,"java/lang/IllegalArgumentException","invalid source slot");return 0;}key[static_cast<size_t>(j)]=static_cast<char>(c);}
            for(jsize j=0;j<i;++j)if(key==keys[static_cast<size_t>(j)]){env->PopLocalFrame(nullptr);java_exception(env,"java/lang/IllegalArgumentException","duplicate source slot");return 0;}
            env->PopLocalFrame(nullptr);
        }
        OpenPermit permit;if(!permit.acquire()){native_failure(env,DMG_BUDGET_EXCEEDED);return 0;}
        std::array<std::vector<uint8_t>,max_raw_sources> owned{};std::array<dmg_source_spec,max_raw_sources> specs{};
        for(jsize i=0;i<count;++i){
            if(env->PushLocalFrame(2)<0){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return 0;}
            const auto bytes=static_cast<jbyteArray>(env->GetObjectArrayElement(inputs,i));
            if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
            if(!bytes||env->GetArrayLength(bytes)!=lengths[static_cast<size_t>(i)]){env->PopLocalFrame(nullptr);java_exception(env,"java/lang/IllegalArgumentException","sources changed during open");return 0;}
            auto& data=owned[static_cast<size_t>(i)];data.resize(static_cast<size_t>(lengths[static_cast<size_t>(i)]));
            if(!data.empty())env->GetByteArrayRegion(bytes,0,static_cast<jsize>(data.size()),reinterpret_cast<jbyte*>(data.data()));
            if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
            auto& spec=specs[static_cast<size_t>(i)];const auto kind=static_cast<uint32_t>(kinds[static_cast<size_t>(i)]);
            spec={sizeof(dmg_source_spec),DMG_ABI_VERSION,kind,allow[static_cast<size_t>(i)]?1u:0u,data.data(),data.size(),keys[static_cast<size_t>(i)].data(),kind==DMG_INPUT_RAW_DEX?"raw-dex":"apk",nullptr};
            env->PopLocalFrame(nullptr);
        }
        dmg_error error{};dmg_engine* raw_engine=nullptr;auto status=dmg_engine_create(nullptr,&raw_engine,&error);
        if(status!=DMG_OK){if(raw_engine)dmg_engine_release(raw_engine);native_failure(env,status,&error);return 0;}
        if(!raw_engine){native_failure(env,DMG_INTERNAL_ERROR);return 0;}
        std::unique_ptr<dmg_engine,EngineDeleter> engine(raw_engine);
        const dmg_source_set_options options{sizeof(dmg_source_set_options),DMG_ABI_VERSION,"android-jni",0,max_expanded_sources,DMG_MAX_SOURCE_BYTES};
        dmg_snapshot* raw=nullptr;error={};status=dmg_snapshot_open_sources(engine.get(),specs.data(),static_cast<uint32_t>(count),&options,&raw,&error);
        if(status!=DMG_OK){if(raw)dmg_snapshot_release(raw);native_failure(env,status,&error);return 0;}
        if(!raw){native_failure(env,DMG_INTERNAL_ERROR);return 0;}
        std::unique_ptr<dmg_snapshot,SnapshotDeleter> guard(raw);
        const auto owner=std::make_shared<SnapshotOwner>(guard.get(),engine.get(),true);guard.release();engine.release();
        const auto token=permit.publish(owner);if(!token){native_failure(env,DMG_BUDGET_EXCEEDED);return 0;}return token;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return 0;
}

extern "C" JNIEXPORT jlong JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeOpenRawDexSet(JNIEnv* env,jclass,jobjectArray inputs,jobjectArray slots) noexcept {
    return open_sources(env,inputs,slots,nullptr,nullptr);
}

extern "C" JNIEXPORT jlong JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeOpenSources(JNIEnv* env,jclass,jobjectArray inputs,jobjectArray slots,jintArray formats,jbooleanArray allow_no_dex) noexcept {
    if(!formats||!allow_no_dex){java_exception(env,"java/lang/NullPointerException","formats and allowNoDex are required");return 0;}
    return open_sources(env,inputs,slots,formats,allow_no_dex);
}

static jlong open_apk_fd_sources_impl(JNIEnv* env,jintArray fds,jlongArray offsets,jlongArray lengths,jobjectArray slots,
        jbooleanArray allow_no_dex,jobjectArray expected,jlongArray limits,jobjectArray keep_alive,OpenPermit* reserved) noexcept {
    try {
        if(!fds||!offsets||!lengths||!slots||!allow_no_dex||!limits){java_exception(env,"java/lang/NullPointerException","fd inputs and limits are required");return 0;}
        const auto count=env->GetArrayLength(fds);if(env->ExceptionCheck())return 0;
        if(count<1||count>max_raw_sources||env->GetArrayLength(offsets)!=count||env->GetArrayLength(lengths)!=count||
           env->GetArrayLength(slots)!=count||env->GetArrayLength(allow_no_dex)!=count||env->GetArrayLength(limits)!=9||
           (expected&&env->GetArrayLength(expected)!=count)||(keep_alive&&env->GetArrayLength(keep_alive)!=count)){
            if(!env->ExceptionCheck())java_exception(env,"java/lang/IllegalArgumentException","invalid fd source array lengths");return 0;
        }
        if(env->ExceptionCheck())return 0;
        std::array<jint,max_raw_sources> descriptors{};std::array<jlong,max_raw_sources> at{},sizes{};
        std::array<jboolean,max_raw_sources> allow{};std::array<jlong,9> budgets{};
        env->GetIntArrayRegion(fds,0,count,descriptors.data());if(env->ExceptionCheck())return 0;
        env->GetLongArrayRegion(offsets,0,count,at.data());if(env->ExceptionCheck())return 0;
        env->GetLongArrayRegion(lengths,0,count,sizes.data());if(env->ExceptionCheck())return 0;
        env->GetBooleanArrayRegion(allow_no_dex,0,count,allow.data());if(env->ExceptionCheck())return 0;
        env->GetLongArrayRegion(limits,0,9,budgets.data());if(env->ExceptionCheck())return 0;
        constexpr jlong owned_cap=1ll<<30,source_cap=512ll<<20;
        if(budgets[0]<1||budgets[0]>owned_cap||budgets[1]<1||budgets[1]>source_cap||
           budgets[2]<1||budgets[2]>budgets[1]||budgets[3]<1||budgets[3]>8ll*source_cap||
           budgets[4]<1||budgets[4]>budgets[1]||budgets[5]<1||budgets[5]>budgets[0]||
           budgets[6]<1||budgets[6]>100000||budgets[7]<1||budgets[7]>(16ll<<20)||budgets[8]<1||budgets[8]>(8ll<<20)){
            java_exception(env,"java/lang/IllegalArgumentException","invalid fd source limits");return 0;
        }
        std::array<std::array<char,max_slot_chars+1>,max_raw_sources> keys{};
        std::array<std::array<char,65>,max_raw_sources> hashes{};std::array<bool,max_raw_sources> has_hash{};jlong total=0;
        for(jsize i=0;i<count;++i){
            if(descriptors[i]<0||at[i]<0||sizes[i]<0||at[i]>std::numeric_limits<jlong>::max()-sizes[i]||
               sizes[i]>budgets[1]||sizes[i]>budgets[2]||sizes[i]>budgets[3]-total||
               (allow[i]!=JNI_TRUE&&allow[i]!=JNI_FALSE)){
                java_exception(env,"java/lang/IllegalArgumentException","invalid fd range or input budget");return 0;
            }
            total+=sizes[i];if(env->PushLocalFrame(3)<0){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return 0;}
            const auto slot=static_cast<jstring>(env->GetObjectArrayElement(slots,i));if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
            if(!slot){env->PopLocalFrame(nullptr);java_exception(env,"java/lang/NullPointerException","slot is required");return 0;}
            const auto n=env->GetStringLength(slot);if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
            if(n<1||n>static_cast<jsize>(max_slot_chars)){env->PopLocalFrame(nullptr);java_exception(env,"java/lang/IllegalArgumentException","invalid slot");return 0;}
            std::array<jchar,max_slot_chars> chars{};env->GetStringRegion(slot,0,n,chars.data());if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
            for(jsize j=0;j<n;++j){if(chars[j]<0x21||chars[j]>0x7e){env->PopLocalFrame(nullptr);java_exception(env,"java/lang/IllegalArgumentException","invalid slot");return 0;}keys[i][j]=static_cast<char>(chars[j]);}
            for(jsize j=0;j<i;++j)if(keys[i]==keys[j]){env->PopLocalFrame(nullptr);java_exception(env,"java/lang/IllegalArgumentException","duplicate slot");return 0;}
            if(expected){
                const auto hash=static_cast<jstring>(env->GetObjectArrayElement(expected,i));if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
                if(hash){const auto size=env->GetStringLength(hash);if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
                    if(size!=64){env->PopLocalFrame(nullptr);java_exception(env,"java/lang/IllegalArgumentException","invalid expected digest");return 0;}
                    std::array<jchar,64> units{};env->GetStringRegion(hash,0,64,units.data());if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
                    for(size_t j=0;j<units.size();++j){const auto c=units[j];if(!((c>='0'&&c<='9')||(c>='a'&&c<='f'))){env->PopLocalFrame(nullptr);java_exception(env,"java/lang/IllegalArgumentException","invalid expected digest");return 0;}hashes[i][j]=static_cast<char>(c);}has_hash[i]=true;
                }
            }
            env->PopLocalFrame(nullptr);
        }
        OpenPermit local;OpenPermit& permit=reserved?*reserved:local;
        if((reserved&&!reserved->held)||(!reserved&&!permit.acquire())){native_failure(env,DMG_BUDGET_EXCEEDED);return 0;}
        dmg_error error{};dmg_engine* raw_engine=nullptr;
        const dmg_engine_options engine_options{sizeof(dmg_engine_options),DMG_ABI_VERSION,static_cast<uint64_t>(budgets[0]),0,static_cast<uint64_t>(budgets[1]),4,0};
        auto status=dmg_engine_create(&engine_options,&raw_engine,&error);if(status!=DMG_OK){if(raw_engine)dmg_engine_release(raw_engine);native_failure(env,status,&error);return 0;}
        if(!raw_engine){native_failure(env,DMG_INTERNAL_ERROR);return 0;}std::unique_ptr<dmg_engine,EngineDeleter> engine(raw_engine);
        std::array<dmg_apk_fd_spec_v1,max_raw_sources> specs{};
        for(jsize i=0;i<count;++i)specs[i]={sizeof(dmg_apk_fd_spec_v1),DMG_ABI_VERSION,descriptors[i],allow[i]?1u:0u,
            static_cast<uint64_t>(at[i]),static_cast<uint64_t>(sizes[i]),keys[i].data(),"apk",has_hash[i]?hashes[i].data():nullptr};
        const dmg_apk_fd_options_v1 options{sizeof(dmg_apk_fd_options_v1),DMG_ABI_VERSION,"android-jni",0,max_expanded_sources,
            static_cast<uint64_t>(budgets[2]),static_cast<uint64_t>(budgets[3]),static_cast<uint64_t>(budgets[4]),static_cast<uint64_t>(budgets[5]),
            static_cast<uint32_t>(budgets[6]),0,static_cast<uint64_t>(budgets[7]),static_cast<uint64_t>(budgets[8])};
        dmg_snapshot* raw=nullptr;error={};status=dmg_snapshot_open_apk_fds_v1(engine.get(),specs.data(),static_cast<uint32_t>(count),&options,&raw,&error);
        if(status!=DMG_OK){if(raw)dmg_snapshot_release(raw);native_failure(env,status,&error);return 0;}
        if(!raw){native_failure(env,DMG_INTERNAL_ERROR);return 0;}std::unique_ptr<dmg_snapshot,SnapshotDeleter> guard(raw);
        const auto owner=std::make_shared<SnapshotOwner>(guard.get(),engine.get(),true);guard.release();engine.release();
        const auto token=permit.publish(owner);if(!token){native_failure(env,DMG_BUDGET_EXCEEDED);return 0;}return token;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return 0;
}

extern "C" JNIEXPORT jlong JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeOpenApkFdSources(JNIEnv* env,jclass,jintArray fds,jlongArray offsets,
        jlongArray lengths,jobjectArray slots,jbooleanArray allow_no_dex,jobjectArray expected,jlongArray limits,jobjectArray keep_alive) noexcept {
    return open_apk_fd_sources_impl(env,fds,offsets,lengths,slots,allow_no_dex,expected,limits,keep_alive,nullptr);
}

namespace {
bool strict_utf8_path(std::string_view value) noexcept {
    if(value.empty()||value.size()>32767)return false;
    for(size_t i=0;i<value.size();){
        const auto c=static_cast<unsigned char>(value[i]);if(!c)return false;if(c<0x80){++i;continue;}
        size_t n=0;if(c>=0xc2&&c<=0xdf)n=2;else if(c>=0xe0&&c<=0xef)n=3;else if(c>=0xf0&&c<=0xf4)n=4;else return false;
        if(n>value.size()-i)return false;const auto b=static_cast<unsigned char>(value[i+1]);
        if((b&0xc0)!=0x80||(c==0xe0&&b<0xa0)||(c==0xed&&b>=0xa0)||(c==0xf0&&b<0x90)||(c==0xf4&&b>=0x90))return false;
        for(size_t j=2;j<n;++j)if((static_cast<unsigned char>(value[i+j])&0xc0)!=0x80)return false;i+=n;
    }
    return true;
}
bool path_shape(std::string_view path) noexcept {
#ifdef _WIN32
    const auto sep=[](char c){return c=='/'||c=='\\';};
    const bool drive=path.size()>=3&&((path[0]>='A'&&path[0]<='Z')||(path[0]>='a'&&path[0]<='z'))&&path[1]==':'&&sep(path[2]);
    const bool unc=path.size()>=3&&sep(path[0])&&sep(path[1])&&!sep(path[2]);
    if(!drive&&!unc)return false;
#else
    const auto sep=[](char c){return c=='/';};if(path.size()<2||path[0]!='/')return false;
#endif
    size_t start=0;for(size_t i=0;i<=path.size();++i){if(i==path.size()||sep(path[i])){
        const auto part=path.substr(start,i-start);if(part=="."||part=="..")return false;start=i+1;
    }}
    return !sep(path.back());
}
struct PathFd {
    int value=-1;
    bool close_once() noexcept {
        if(value<0)return true;const int fd=value;value=-1;
#ifdef _WIN32
        return ::_close(fd)==0;
#else
        return ::close(fd)==0;
#endif
    }
    ~PathFd(){(void)close_once();}
};
}
extern "C" JNIEXPORT void JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeClose(JNIEnv*,jclass,jlong) noexcept;
extern "C" JNIEXPORT jlong JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeOpenApkPaths(JNIEnv* env,jclass,jobjectArray paths,jobjectArray slots,
        jbooleanArray allow_no_dex,jobjectArray expected,jlongArray limits) noexcept {
    try{
        if(!paths||!slots||!allow_no_dex||!limits){java_exception(env,"java/lang/NullPointerException","paths and limits are required");return 0;}
        const auto count=env->GetArrayLength(paths);if(env->ExceptionCheck())return 0;
        if(count<1||count>max_raw_sources||env->GetArrayLength(slots)!=count||env->GetArrayLength(allow_no_dex)!=count||
           env->GetArrayLength(limits)!=9||(expected&&env->GetArrayLength(expected)!=count)){
            if(!env->ExceptionCheck())java_exception(env,"java/lang/IllegalArgumentException","invalid path source array lengths");return 0;
        }
        if(env->ExceptionCheck())return 0;
        std::array<jlong,9> budgets{};std::array<jboolean,max_raw_sources> allow{};
        env->GetLongArrayRegion(limits,0,9,budgets.data());if(env->ExceptionCheck())return 0;
        env->GetBooleanArrayRegion(allow_no_dex,0,count,allow.data());if(env->ExceptionCheck())return 0;
        constexpr jlong owned_cap=1ll<<30,source_cap=512ll<<20;
        if(budgets[0]<1||budgets[0]>owned_cap||budgets[1]<1||budgets[1]>source_cap||
           budgets[2]<1||budgets[2]>budgets[1]||budgets[3]<1||budgets[3]>8ll*source_cap||
           budgets[4]<1||budgets[4]>budgets[1]||budgets[5]<1||budgets[5]>budgets[0]||budgets[6]<1||budgets[6]>100000||
           budgets[7]<1||budgets[7]>(16ll<<20)||budgets[8]<1||budgets[8]>(8ll<<20)){
            java_exception(env,"java/lang/IllegalArgumentException","invalid fd source limits");return 0;
        }
        std::array<std::array<char,max_slot_chars+1>,max_raw_sources> keys{};
        for(jsize i=0;i<count;++i){
            if(allow[i]!=JNI_TRUE&&allow[i]!=JNI_FALSE){java_exception(env,"java/lang/IllegalArgumentException","invalid allowNoDex");return 0;}
            if(env->PushLocalFrame(3)<0){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return 0;}
            const auto slot=static_cast<jstring>(env->GetObjectArrayElement(slots,i));if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
            if(!slot){env->PopLocalFrame(nullptr);java_exception(env,"java/lang/NullPointerException","slot is required");return 0;}
            const auto n=env->GetStringLength(slot);if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
            if(n<1||n>static_cast<jsize>(max_slot_chars)){env->PopLocalFrame(nullptr);java_exception(env,"java/lang/IllegalArgumentException","invalid slot");return 0;}
            std::array<jchar,max_slot_chars> chars{};env->GetStringRegion(slot,0,n,chars.data());if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
            for(jsize j=0;j<n;++j){if(chars[j]<0x21||chars[j]>0x7e){env->PopLocalFrame(nullptr);java_exception(env,"java/lang/IllegalArgumentException","invalid slot");return 0;}keys[i][j]=static_cast<char>(chars[j]);}
            for(jsize j=0;j<i;++j)if(keys[i]==keys[j]){env->PopLocalFrame(nullptr);java_exception(env,"java/lang/IllegalArgumentException","duplicate slot");return 0;}
            if(expected){const auto hash=static_cast<jstring>(env->GetObjectArrayElement(expected,i));if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
                if(hash){const auto hash_size=env->GetStringLength(hash);if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
                    if(hash_size!=64){env->PopLocalFrame(nullptr);java_exception(env,"java/lang/IllegalArgumentException","invalid expected digest");return 0;}
                    std::array<jchar,64> units{};env->GetStringRegion(hash,0,64,units.data());if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
                    for(auto c:units)if(!((c>='0'&&c<='9')||(c>='a'&&c<='f'))){env->PopLocalFrame(nullptr);java_exception(env,"java/lang/IllegalArgumentException","invalid expected digest");return 0;}}
            }
            env->PopLocalFrame(nullptr);
        }
        OpenPermit permit;if(!permit.acquire()){native_failure(env,DMG_BUDGET_EXCEEDED);return 0;}
        std::array<PathFd,max_raw_sources> owned{};std::array<jint,max_raw_sources> numbers{};std::array<jlong,max_raw_sources> offsets{},lengths{};jlong total=0;
        for(jsize i=0;i<count;++i){
            if(env->PushLocalFrame(1)<0){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return 0;}
            const auto path=static_cast<jbyteArray>(env->GetObjectArrayElement(paths,i));if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
            if(!path){env->PopLocalFrame(nullptr);java_exception(env,"java/lang/NullPointerException","path bytes required");return 0;}
            const auto n=env->GetArrayLength(path);if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}
            if(n<1||n>32767){env->PopLocalFrame(nullptr);java_exception(env,"java/lang/IllegalArgumentException","invalid path length");return 0;}
            std::string bytes(static_cast<size_t>(n),'\0');env->GetByteArrayRegion(path,0,n,reinterpret_cast<jbyte*>(bytes.data()));
            if(env->ExceptionCheck()){env->PopLocalFrame(nullptr);return 0;}env->PopLocalFrame(nullptr);
            if(!strict_utf8_path(bytes)||!path_shape(bytes)){java_exception(env,"java/lang/IllegalArgumentException","invalid UTF-8 absolute path");return 0;}
            uint64_t size=0;
#ifdef _WIN32
            const int wide_count=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,bytes.data(),static_cast<int>(bytes.size()),nullptr,0);
            if(wide_count<=0){java_exception(env,"java/lang/IllegalArgumentException","path UTF-8 conversion failed");return 0;}
            std::wstring wide(static_cast<size_t>(wide_count),L'\0');
            if(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,bytes.data(),static_cast<int>(bytes.size()),wide.data(),wide_count)!=wide_count){java_exception(env,"java/lang/IllegalArgumentException","path UTF-8 conversion failed");return 0;}
            owned[i].value=::_wopen(wide.c_str(),_O_RDONLY|_O_BINARY|_O_NOINHERIT);struct _stat64 info{};
            if(owned[i].value<0){native_failure(env,DMG_SOURCE_MISMATCH);return 0;}
            const auto raw=::_get_osfhandle(owned[i].value);DWORD handle_flags=0;
            if(raw==-1||!GetHandleInformation(reinterpret_cast<HANDLE>(raw),&handle_flags)||(handle_flags&HANDLE_FLAG_INHERIT)){
                native_failure(env,DMG_UNSUPPORTED);return 0;
            }
            if(::_fstat64(owned[i].value,&info)!=0||(info.st_mode&_S_IFMT)!=_S_IFREG||info.st_size<0){native_failure(env,DMG_SOURCE_MISMATCH);return 0;}
            size=static_cast<uint64_t>(info.st_size);
#else
#if defined(O_CLOEXEC) && !defined(DMG_TEST_APK_PATH_NO_CLOEXEC)
            do{owned[i].value=::open(bytes.c_str(),O_RDONLY|O_CLOEXEC);}while(owned[i].value<0&&errno==EINTR);
            if(owned[i].value<0){native_failure(env,DMG_SOURCE_MISMATCH);return 0;}
            int descriptor_flags=-1;do{descriptor_flags=::fcntl(owned[i].value,F_GETFD);}while(descriptor_flags<0&&errno==EINTR);
            if(descriptor_flags<0||(descriptor_flags&FD_CLOEXEC)==0){native_failure(env,DMG_UNSUPPORTED);return 0;}
            struct stat info{};int stat_result=-1;do{stat_result=::fstat(owned[i].value,&info);}while(stat_result<0&&errno==EINTR);
            if(stat_result<0||!S_ISREG(info.st_mode)||info.st_size<0){native_failure(env,DMG_SOURCE_MISMATCH);return 0;}
            size=static_cast<uint64_t>(info.st_size);
#else
            native_failure(env,DMG_UNSUPPORTED);return 0;
#endif
#endif
            if(size>static_cast<uint64_t>(budgets[1])||size>static_cast<uint64_t>(budgets[2])||size>static_cast<uint64_t>(budgets[3]-total)){
                native_failure(env,DMG_BUDGET_EXCEEDED);return 0;
            }
            total+=static_cast<jlong>(size);numbers[i]=owned[i].value;lengths[i]=static_cast<jlong>(size);
        }
        const auto jfds=env->NewIntArray(count);if(!jfds||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return 0;}
        const auto joffsets=env->NewLongArray(count);if(!joffsets||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return 0;}
        const auto jlengths=env->NewLongArray(count);if(!jlengths||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return 0;}
        env->SetIntArrayRegion(jfds,0,count,numbers.data());if(env->ExceptionCheck())return 0;
        env->SetLongArrayRegion(joffsets,0,count,offsets.data());if(env->ExceptionCheck())return 0;
        env->SetLongArrayRegion(jlengths,0,count,lengths.data());if(env->ExceptionCheck())return 0;
        const auto token=open_apk_fd_sources_impl(env,jfds,joffsets,jlengths,slots,allow_no_dex,expected,limits,nullptr,&permit);
        bool closed=true;for(auto& descriptor:owned)if(!descriptor.close_once())closed=false;
        if(!closed){if(token)Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeClose(env,nullptr,token);
            if(!env->ExceptionCheck())native_failure(env,DMG_INTERNAL_ERROR);return 0;}
        return token;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return 0;
}

extern "C" JNIEXPORT jobject JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeSnapshotInfo(JNIEnv* env, jclass, jlong token) noexcept {
    try {
        const auto owner = lookup(token);
        if (!owner) { native_failure(env, DMG_CLOSED); return nullptr; }
        dmg_snapshot_info info{};
        const auto status = dmg_snapshot_get_info(owner->snapshot, &info);
        if (status != DMG_OK) { native_failure(env, status); return nullptr; }
        dmg_snapshot_overview overview{};
        const auto overview_status = dmg_snapshot_get_overview(owner->snapshot, &overview);
        if (overview_status != DMG_OK) { native_failure(env, overview_status); return nullptr; }
        if (overview.input_count != 1 || overview.source_count != 1 || overview.scope_complete != 0) {
            native_failure(env, DMG_INTERNAL_ERROR);
            return nullptr;
        }
        const auto cls = env->FindClass("io/github/jichuo1/dexmeguviz/NativeEngine$SnapshotInfo");
        if (!cls || env->ExceptionCheck()) return nullptr;
        const auto ctor = env->GetMethodID(cls, "<init>", "(IIIIIIJZLjava/lang/String;Ljava/lang/String;)V");
        if (!ctor || env->ExceptionCheck()) return nullptr;
        const auto digest = env->NewStringUTF(info.source_sha256);
        if (!digest || env->ExceptionCheck()) return nullptr;
        const auto identity = env->NewStringUTF(info.snapshot_id);
        if (!identity || env->ExceptionCheck()) return nullptr;
        return env->NewObject(cls, ctor, static_cast<jint>(info.dex_version), static_cast<jint>(info.string_count),
                              static_cast<jint>(info.type_count), static_cast<jint>(info.class_count),
                              static_cast<jint>(info.method_ref_count), static_cast<jint>(info.method_def_count),
                              static_cast<jlong>(info.source_bytes), JNI_FALSE, digest, identity);
    } catch (const std::bad_alloc&) {
        native_failure(env, DMG_OUT_OF_MEMORY);
    } catch (...) {
        native_failure(env, DMG_INTERNAL_ERROR);
    }
    return nullptr;
}

extern "C" JNIEXPORT void JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeClose(JNIEnv* env, jclass, jlong token) noexcept {
    try {
        std::shared_ptr<SnapshotOwner> owner;
        {
            std::lock_guard lock(registry_mutex);
            const auto it = registry.find(token);
            if (it == registry.end()) return;
            owner = std::move(it->second);
            registry.erase(it);
        }
        dmg_snapshot_close(owner->snapshot);
    } catch (const std::bad_alloc&) {
        native_failure(env, DMG_OUT_OF_MEMORY);
    } catch (...) {
        native_failure(env, DMG_INTERNAL_ERROR);
    }
}

extern "C" JNIEXPORT jobject JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeSourceSetInfo(JNIEnv* env,jclass,jlong token) noexcept {
    try{
        const auto owner=lookup(token);if(!owner){native_failure(env,DMG_CLOSED);return nullptr;}
        if(!owner->source_set){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        dmg_snapshot_overview overview{};auto status=dmg_snapshot_get_overview(owner->snapshot,&overview);
        if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        if(!overview.snapshot_id||overview.scope_complete||!overview.input_count||overview.input_count>max_raw_sources||overview.source_count>max_expanded_sources){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        const auto item_cls=env->FindClass("io/github/jichuo1/dexmeguviz/NativeEngine$RawDexSourceInfo");if(!item_cls||env->ExceptionCheck())return nullptr;
        const auto item_ctor=env->GetMethodID(item_cls,"<init>","(IIJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V");if(!item_ctor||env->ExceptionCheck())return nullptr;
        const auto input_cls=env->FindClass("io/github/jichuo1/dexmeguviz/NativeEngine$InputInfo");if(!input_cls||env->ExceptionCheck())return nullptr;
        const auto input_ctor=env->GetMethodID(input_cls,"<init>","(IIIZZJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");if(!input_ctor||env->ExceptionCheck())return nullptr;
        const auto info_cls=env->FindClass("io/github/jichuo1/dexmeguviz/NativeEngine$SourceSetInfo");if(!info_cls||env->ExceptionCheck())return nullptr;
        const auto info_ctor=env->GetMethodID(info_cls,"<init>","(Ljava/lang/String;Z[Lio/github/jichuo1/dexmeguviz/NativeEngine$RawDexSourceInfo;[Lio/github/jichuo1/dexmeguviz/NativeEngine$InputInfo;)V");if(!info_ctor||env->ExceptionCheck())return nullptr;
        const auto input_array=env->NewObjectArray(static_cast<jsize>(overview.input_count),input_cls,nullptr);
        if(!input_array||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        for(uint32_t i=0;i<overview.input_count;++i){
            dmg_input_info input{};status=dmg_snapshot_get_input_info(owner->snapshot,i,&input);
            if(status!=DMG_OK){native_failure(env,status);return nullptr;}
            if(input.input_index!=i||(input.format!=DMG_INPUT_RAW_DEX&&input.format!=DMG_INPUT_APK)||input.allow_no_dex>1||input.source_count>max_expanded_sources||!input.slot_key||!input.source_sha256||!input.content_id||input.input_bytes>uint64_t(std::numeric_limits<jlong>::max())){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
            if(env->PushLocalFrame(5)<0){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
            auto str=[&](const char* value)->jstring{if(env->ExceptionCheck())return nullptr;auto out=env->NewStringUTF(value);if(!out&&!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return out;};
            const auto slot=str(input.slot_key);const auto digest=str(input.source_sha256);const auto content=str(input.content_id);
            jobject value=nullptr;if(!env->ExceptionCheck())value=env->NewObject(input_cls,input_ctor,static_cast<jint>(i),static_cast<jint>(input.format),static_cast<jint>(input.source_count),input.allow_no_dex?JNI_TRUE:JNI_FALSE,(input.format==DMG_INPUT_APK&&input.container_metadata_checked)?JNI_TRUE:JNI_FALSE,static_cast<jlong>(input.input_bytes),slot,digest,content);
            if(value&&!env->ExceptionCheck())env->SetObjectArrayElement(input_array,static_cast<jsize>(i),value);
            const bool failed=env->ExceptionCheck()||!value;env->PopLocalFrame(nullptr);
            if(failed){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        }
        const auto array=env->NewObjectArray(static_cast<jsize>(overview.source_count),item_cls,nullptr);
        if(!array||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        for(uint32_t i=0;i<overview.source_count;++i){
            dmg_source_info source{};status=dmg_snapshot_get_source_info(owner->snapshot,i,&source);
            if(status!=DMG_OK){native_failure(env,status);return nullptr;}
            if(source.source_index!=i||source.input_index>=overview.input_count||!source.slot_key||!source.dex.source_sha256||!source.dex.content_id||!source.dex.occurrence_id||!source.logical_dex_id||!source.archive_entry_name||source.dex.source_bytes>uint64_t(std::numeric_limits<jlong>::max())||(source.archive_entry_index!=UINT32_MAX&&source.archive_entry_index>uint32_t(std::numeric_limits<jint>::max()))){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
            if(env->PushLocalFrame(9)<0){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
            auto str=[&](const char* value)->jstring{if(env->ExceptionCheck())return nullptr;auto out=env->NewStringUTF(value);if(!out&&!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return out;};
            const auto slot=str(source.slot_key);const auto digest=str(source.dex.source_sha256);const auto content=str(source.dex.content_id);
            const auto occurrence=str(source.dex.occurrence_id);const auto logical=str(source.logical_dex_id);
            const auto entry=source.archive_entry_index==UINT32_MAX?nullptr:str(source.archive_entry_name);
            jobject item=nullptr;if(!env->ExceptionCheck())item=env->NewObject(item_cls,item_ctor,static_cast<jint>(source.source_index),static_cast<jint>(source.input_index),static_cast<jlong>(source.dex.source_bytes),slot,digest,content,occurrence,logical,entry,source.archive_entry_index==UINT32_MAX?-1:static_cast<jint>(source.archive_entry_index));
            if(item&&!env->ExceptionCheck())env->SetObjectArrayElement(array,static_cast<jsize>(i),item);
            const bool failed=env->ExceptionCheck()||!item;env->PopLocalFrame(nullptr);
            if(failed){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        }
        const auto snapshot=env->NewStringUTF(overview.snapshot_id);
        if(!snapshot||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        const auto value=env->NewObject(info_cls,info_ctor,snapshot,JNI_FALSE,array,input_array);
        if(!value&&!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return value;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}

static jobject materialize_result(JNIEnv* env, const dmg_result* result, bool source_set,bool declared_scope=false) noexcept {
    try {
        dmg_query_info query_info{}; auto status=dmg_result_get_query_info(result,&query_info);
        if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        dmg_result_info info{};status=dmg_result_get_info(result,&info);
        if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        dmg_relation_info relation{};status=dmg_result_get_relation_info(result,&relation,sizeof(relation));
        if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        dmg_snapshot_overview overview{};status=dmg_result_get_overview(result,&overview);
        if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        if((!declared_scope&&info.coverage!=DMG_COVERAGE_PARTIAL) ||
           (declared_scope&&(!query_info.explicit_scope||(info.coverage!=DMG_COVERAGE_PARTIAL&&info.coverage!=DMG_COVERAGE_COMPLETE))) || info.candidates_count>max_query_results ||
           info.visited_methods>uint32_t(std::numeric_limits<jint>::max()) || info.total_methods>uint32_t(std::numeric_limits<jint>::max()) ||
           relation.unknown_rows>uint64_t(std::numeric_limits<jlong>::max()) || !overview.snapshot_id || overview.scope_complete ||
           !overview.input_count || overview.input_count>max_raw_sources || overview.source_count>max_expanded_sources || (!source_set&&(overview.input_count!=1||overview.source_count!=1))){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        const auto row_cls=env->FindClass("io/github/jichuo1/dexmeguviz/NativeEngine$MethodCandidate");
        if(!row_cls||env->ExceptionCheck())return nullptr;
        const auto row_ctor=env->GetMethodID(row_cls,"<init>",source_set?"(JJJJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;IILjava/lang/String;Ljava/lang/String;)V":"(JJJJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
        if(!row_ctor||env->ExceptionCheck())return nullptr;
        const auto result_cls=env->FindClass("io/github/jichuo1/dexmeguviz/NativeEngine$QueryResult");
        if(!result_cls||env->ExceptionCheck())return nullptr;
        const auto result_ctor=env->GetMethodID(result_cls,"<init>","(IIIIIIIJLjava/lang/String;Ljava/lang/String;[Lio/github/jichuo1/dexmeguviz/NativeEngine$MethodCandidate;)V");
        if(!result_ctor||env->ExceptionCheck())return nullptr;
        const auto rows=env->NewObjectArray(static_cast<jsize>(info.candidates_count),row_cls,nullptr);
        if(!rows||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        uint64_t units=0;
        for(uint32_t i=0;i<info.candidates_count;++i){
            dmg_method_row row{};status=dmg_result_get_method(result,i,&row);
            if(status!=DMG_OK){native_failure(env,status);return nullptr;}
            dmg_source_info origin{};
            if(source_set){status=dmg_result_get_origin(result,i,&origin);if(status!=DMG_OK){native_failure(env,status);return nullptr;}
                if(origin.source_index>=overview.source_count||origin.input_index>=overview.input_count||!origin.slot_key||!origin.dex.occurrence_id){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}}
            const uint64_t sizes[]={row.owner_length,row.name_length,row.prototype_length};
            for(const auto n:sizes){if(n>max_output_text_units-units){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}units+=n;}
            if(env->PushLocalFrame(10)<0){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
            const jchar empty=0;
            auto text=[&](uint32_t bit,const uint16_t* data,uint64_t count)->jstring{
                if(!(query_info.projection_mask&bit))return nullptr;
                if(!data&&count){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
                auto value=env->NewString(count?reinterpret_cast<const jchar*>(data):&empty,static_cast<jsize>(count));
                if(!value&&!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);
                return value;
            };
            const auto row_owner=text(DMG_PROJECT_OWNER,row.owner,row.owner_length);
            const auto row_name=env->ExceptionCheck()?nullptr:text(DMG_PROJECT_NAME,row.name,row.name_length);
            const auto row_proto=env->ExceptionCheck()?nullptr:text(DMG_PROJECT_PROTOTYPE,row.prototype,row.prototype_length);
            jstring slot=nullptr,occurrence=nullptr;
            if(source_set&&!env->ExceptionCheck()){
                slot=env->NewStringUTF(origin.slot_key);if(!slot&&!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);
                if(!env->ExceptionCheck()){occurrence=env->NewStringUTF(origin.dex.occurrence_id);if(!occurrence&&!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);}
            }
            jobject value=nullptr;
            if(!env->ExceptionCheck()) {
                if(source_set)value=env->NewObject(row_cls,row_ctor,static_cast<jlong>(row.method_index),static_cast<jlong>(row.access_flags),
                    static_cast<jlong>(row.declaration_offset),static_cast<jlong>(row.code_offset),row_owner,row_name,row_proto,
                    static_cast<jint>(origin.source_index),static_cast<jint>(origin.input_index),slot,occurrence);
                else value=env->NewObject(row_cls,row_ctor,static_cast<jlong>(row.method_index),static_cast<jlong>(row.access_flags),
                    static_cast<jlong>(row.declaration_offset),static_cast<jlong>(row.code_offset),row_owner,row_name,row_proto);
            }
            if(!env->ExceptionCheck()&&value)env->SetObjectArrayElement(rows,static_cast<jsize>(i),value);
            const bool failed=env->ExceptionCheck()||!value;
            env->PopLocalFrame(nullptr);
            if(failed){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        }
        const auto query_id=env->NewStringUTF(query_info.query_id);
        if(!query_id||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        const auto snapshot_id=env->NewStringUTF(overview.snapshot_id);
        if(!snapshot_id||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        const auto value=env->NewObject(result_cls,result_ctor,static_cast<jint>(info.execution_status),static_cast<jint>(info.coverage),
            static_cast<jint>(info.decision),static_cast<jint>(info.reason),static_cast<jint>(info.visited_methods),static_cast<jint>(info.total_methods),
            static_cast<jint>(query_info.projection_mask),static_cast<jlong>(relation.unknown_rows),query_id,snapshot_id,rows);
        if(!value&&!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);
        return value;
    } catch(const std::bad_alloc&) { native_failure(env,DMG_OUT_OF_MEMORY); }
      catch(...) { native_failure(env,DMG_INTERNAL_ERROR); }
    return nullptr;
}


extern "C" JNIEXPORT jobject JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeMethodStreamQuery(JNIEnv* env,jclass,jlong stream_token,jlong snapshot_token,jint index) noexcept {
    try {
        const auto stream=lookup_method_stream(stream_token);const auto owner=lookup(snapshot_token);
        if(!stream||!owner){native_failure(env,DMG_CLOSED);return nullptr;}
        if(owner->source_set||owner->engine!=stream->engine.get()||index<0||static_cast<size_t>(index)>=stream->queries.size()){native_failure(env,DMG_INVALID_ARGUMENT);return nullptr;}
        dmg_error error{};dmg_result* raw=nullptr;const auto status=dmg_query_execute(owner->snapshot,stream->queries[static_cast<size_t>(index)].get(),&raw,&error);
        if(status!=DMG_OK||!raw){if(raw)dmg_result_release(raw);native_failure(env,status==DMG_OK?DMG_INTERNAL_ERROR:status,&error);return nullptr;}
        std::unique_ptr<dmg_result,ResultDeleter> result(raw);return materialize_result(env,result.get(),false);
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}

static jobject query_methods(JNIEnv* env, jlong token, jbyteArray input, bool source_set
#ifdef DMG_ANDROID_PERSISTENT_FACTS
    ,dmg_persistent_cache_v1* persistent=nullptr,const SnapshotOwner* expected_owner=nullptr
#endif
    ) noexcept {
    try {
        if (!input) { java_exception(env,"java/lang/NullPointerException","queryJson is required"); return nullptr; }
        const auto owner=lookup(token);
        if (!owner) { native_failure(env,DMG_CLOSED); return nullptr; }
#ifdef DMG_ANDROID_PERSISTENT_FACTS
        if(expected_owner&&expected_owner!=owner.get()){native_failure(env,DMG_CLOSED);return nullptr;}
#endif
        if(owner->source_set!=source_set){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        const auto length=env->GetArrayLength(input);
        if (env->ExceptionCheck()) return nullptr;
        if (static_cast<uint64_t>(length)>max_query_bytes) { native_failure(env,DMG_BUDGET_EXCEEDED); return nullptr; }
        std::vector<uint8_t> json(static_cast<size_t>(length));
        if (length) env->GetByteArrayRegion(input,0,length,reinterpret_cast<jbyte*>(json.data()));
        if (env->ExceptionCheck()) return nullptr;
        dmg_error error{};dmg_query* raw_query=nullptr;
        auto status=dmg_query_compile_json(owner->engine,json.data(),json.size(),&raw_query,&error);
        if (status!=DMG_OK) { if(raw_query)dmg_query_release(raw_query);native_failure(env,status,&error);return nullptr; }
        if (!raw_query) { native_failure(env,DMG_INTERNAL_ERROR); return nullptr; }
        std::unique_ptr<dmg_query,QueryDeleter> query(raw_query);dmg_query_info query_info{};
        status=dmg_query_get_info(query.get(),&query_info);
        if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        // Restrict to the explicitly published direct method-v1 profile. An
        // explicit source sub-scope could assert completeness of this one slot;
        // this bridge intentionally cannot change the incomplete app scope.
        if(!query_info.query_id || std::string_view(query_info.query_id).substr(0,9)!="query:v1:" || query_info.explicit_scope){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        if(query_info.max_results>max_query_results || query_info.max_work>max_query_work){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        dmg_result* raw_result=nullptr;error={};
#ifdef DMG_ANDROID_PERSISTENT_FACTS
        status=persistent?dmg_persistent_cache_execute_v1(persistent,owner->snapshot,query.get(),&raw_result,&error):dmg_query_execute(owner->snapshot,query.get(),&raw_result,&error);
#else
        status=dmg_query_execute(owner->snapshot,query.get(),&raw_result,&error);
#endif
        if(status!=DMG_OK){if(raw_result)dmg_result_release(raw_result);native_failure(env,status,&error);return nullptr;}
        if(!raw_result){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        std::unique_ptr<dmg_result,ResultDeleter> result(raw_result);
        return materialize_result(env,result.get(),source_set);
    } catch(const std::bad_alloc&) { native_failure(env,DMG_OUT_OF_MEMORY); }
      catch(...) { native_failure(env,DMG_INTERNAL_ERROR); }
    return nullptr;
}

extern "C" JNIEXPORT jobject JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryMethods(JNIEnv* env,jclass,jlong token,jbyteArray input) noexcept {
    return query_methods(env,token,input,false);
}
extern "C" JNIEXPORT jobject JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQuerySourceSetMethods(JNIEnv* env,jclass,jlong token,jbyteArray input) noexcept {
    return query_methods(env,token,input,true);
}

#ifdef DMG_ANDROID_PERSISTENT_FACTS
#include "persistent_cache_jni.inc"
#endif

// A distinct entry point keeps the existing method-v1 result and Job ABI intact.
static jobject materialize_entity_result(JNIEnv* env,const dmg_result* result,bool source_set,uint32_t class_annotation=0,bool declared_scope=false) noexcept {
    try {
        dmg_query_info qi{};dmg_status status;
        if(class_annotation){dmg_query_info_v2 v{};status=dmg_result_get_query_info_v2(result,&v,sizeof(v));
            if(status==DMG_OK&&((class_annotation!=1&&class_annotation!=2)||!v.extended_capabilities||std::string_view(v.extended_capabilities)!=(class_annotation==1?"class_annotation_static":"class_annotation_static;class_annotation_string_static")||!v.legacy.query_id||!std::string_view(v.legacy.query_id).starts_with(class_annotation==1?"query:v24:":"query:v25:")))status=DMG_UNSUPPORTED;
            qi=v.legacy;
        }else status=dmg_result_get_query_info(result,&qi);
        if(status!=DMG_OK||!qi.query_id){native_failure(env,status==DMG_OK?DMG_INTERNAL_ERROR:status);return nullptr;}
        if(declared_scope&&(!class_annotation||!qi.explicit_scope)){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        dmg_relation_info info{};status=dmg_result_get_relation_info(result,&info,sizeof(info));
        if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        dmg_snapshot_overview overview{};status=dmg_result_get_overview(result,&overview);
        if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        if(info.relation>DMG_TYPE_REFS||(!declared_scope&&info.coverage!=DMG_COVERAGE_PARTIAL)||(declared_scope&&info.coverage!=DMG_COVERAGE_COMPLETE&&info.coverage!=DMG_COVERAGE_PARTIAL)||info.candidates_count>max_query_results||
           info.visited_rows>uint32_t(std::numeric_limits<jint>::max())||info.total_rows>uint32_t(std::numeric_limits<jint>::max())||
           info.unknown_rows>uint64_t(std::numeric_limits<jlong>::max())||!overview.snapshot_id||overview.scope_complete||
           !overview.input_count||overview.input_count>max_raw_sources||overview.source_count>max_expanded_sources||
           (!source_set&&(overview.input_count!=1||overview.source_count!=1))){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        // The core currently validates projection applicability at compile time.
        // Recheck here so a future core extension cannot turn a non-applicable
        // field into an apparently present empty string through this bridge.
        const uint32_t applicable=(info.relation==DMG_METHOD_DEFS||info.relation==DMG_METHOD_REFS)?
            (DMG_PROJECT_OWNER|DMG_PROJECT_NAME|DMG_PROJECT_PROTOTYPE):
            (info.relation==DMG_FIELD_DEFS||info.relation==DMG_FIELD_REFS)?
            (DMG_PROJECT_OWNER|DMG_PROJECT_NAME|DMG_PROJECT_TYPE):
            info.relation==DMG_STRING_VALUES?DMG_PROJECT_VALUE:DMG_PROJECT_TYPE;
        if(qi.projection_mask&~applicable){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        const auto row_cls=env->FindClass("io/github/jichuo1/dexmeguviz/NativeEngine$EntityCandidate");
        if(!row_cls||env->ExceptionCheck())return nullptr;
        const auto row_ctor=env->GetMethodID(row_cls,"<init>","(IIIJJJZJZJZJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
        if(!row_ctor||env->ExceptionCheck())return nullptr;
        const auto result_cls=env->FindClass("io/github/jichuo1/dexmeguviz/NativeEngine$EntityResult");
        if(!result_cls||env->ExceptionCheck())return nullptr;
        const auto result_ctor=env->GetMethodID(result_cls,"<init>","(IIIIIIIIJLjava/lang/String;Ljava/lang/String;[Lio/github/jichuo1/dexmeguviz/NativeEngine$EntityCandidate;)V");
        if(!result_ctor||env->ExceptionCheck())return nullptr;
        const auto rows=env->NewObjectArray(static_cast<jsize>(info.candidates_count),row_cls,nullptr);
        if(!rows||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        uint64_t units=0;
        for(uint32_t i=0;i<info.candidates_count;++i){
            dmg_entity_row row{};status=dmg_result_get_entity(result,i,&row,sizeof(row));
            if(status!=DMG_OK){native_failure(env,status);return nullptr;}
            dmg_source_info origin{};status=dmg_result_get_origin(result,i,&origin);
            if(status!=DMG_OK){native_failure(env,status);return nullptr;}
            if(row.relation!=info.relation||row.source_index!=origin.source_index||origin.source_index>=overview.source_count||
               origin.input_index>=overview.input_count||!origin.slot_key||!origin.dex.occurrence_id||
               row.definition_known>1||row.flags_known>1||row.code_known>1){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
            const uint64_t lengths[]={row.owner_length,row.name_length,row.prototype_length,row.type_descriptor_length,row.string_value_length};
            for(const auto n:lengths){if(n>max_output_text_units-units){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}units+=n;}
            if(env->PushLocalFrame(12)<0){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
            const jchar empty=0;
            auto text=[&](uint32_t bit,const uint16_t* value,uint64_t n)->jstring{
                if(!(qi.projection_mask&applicable&bit))return nullptr;
                if(!value&&n){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
                auto string=env->NewString(n?reinterpret_cast<const jchar*>(value):&empty,static_cast<jsize>(n));
                if(!string&&!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return string;
            };
            const auto owner_text=text(DMG_PROJECT_OWNER,row.owner,row.owner_length);
            const auto name=env->ExceptionCheck()?nullptr:text(DMG_PROJECT_NAME,row.name,row.name_length);
            const auto proto=env->ExceptionCheck()?nullptr:text(DMG_PROJECT_PROTOTYPE,row.prototype,row.prototype_length);
            const auto type=env->ExceptionCheck()?nullptr:text(DMG_PROJECT_TYPE,row.type_descriptor,row.type_descriptor_length);
            const auto value=env->ExceptionCheck()?nullptr:text(DMG_PROJECT_VALUE,row.string_value,row.string_value_length);
            const auto slot=env->ExceptionCheck()?nullptr:env->NewStringUTF(origin.slot_key);
            if(!slot&&!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);
            const auto occurrence=env->ExceptionCheck()?nullptr:env->NewStringUTF(origin.dex.occurrence_id);
            if(!occurrence&&!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);
            jobject item=nullptr;
            if(!env->ExceptionCheck())item=env->NewObject(row_cls,row_ctor,static_cast<jint>(row.relation),
                static_cast<jint>(row.source_index),static_cast<jint>(origin.input_index),static_cast<jlong>(row.local_index),
                static_cast<jlong>(row.reference_index),static_cast<jlong>(row.record_offset),static_cast<jboolean>(row.definition_known),
                static_cast<jlong>(row.definition_offset),static_cast<jboolean>(row.flags_known),static_cast<jlong>(row.access_flags),
                static_cast<jboolean>(row.code_known),static_cast<jlong>(row.code_offset),owner_text,name,proto,type,value,slot,occurrence);
            if(item&&!env->ExceptionCheck())env->SetObjectArrayElement(rows,static_cast<jsize>(i),item);
            const bool failed=env->ExceptionCheck()||!item;env->PopLocalFrame(nullptr);
            if(failed){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        }
        const auto query_id=env->NewStringUTF(qi.query_id);if(!query_id||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        const auto snapshot_id=env->NewStringUTF(overview.snapshot_id);if(!snapshot_id||env->ExceptionCheck()){if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;}
        const auto value=env->NewObject(result_cls,result_ctor,static_cast<jint>(info.relation),static_cast<jint>(info.execution_status),
            static_cast<jint>(info.coverage),static_cast<jint>(info.decision),static_cast<jint>(info.reason),static_cast<jint>(info.visited_rows),
            static_cast<jint>(info.total_rows),static_cast<jint>(qi.projection_mask),static_cast<jlong>(info.unknown_rows),query_id,snapshot_id,rows);
        if(!value&&!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return value;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}

// Only direct metadata query identities are accepted; scope completeness can
// never be promoted by caller-supplied JSON.
static bool reflection_method_uses_supported(const dmg_query_info& qi) noexcept {
    constexpr uint32_t reflection_caps = 2097152u | 8388608u;
    constexpr uint32_t allowed = 1u | 2u | 4u | 32u | 64u | 128u | 256u | reflection_caps;
    return qi.query_id && std::string_view(qi.query_id).starts_with("query:v15:") && !qi.explicit_scope &&
        (qi.required_capabilities & reflection_caps) == reflection_caps &&
        !(qi.required_capabilities & ~allowed) && qi.demand_mask && !(qi.demand_mask & ~7u);
}

static jobject query_entities(JNIEnv* env,jlong token,jbyteArray input,jboolean source_set,bool reflection_method_uses) noexcept {
    try {
        if(!input){java_exception(env,"java/lang/NullPointerException","queryJson is required");return nullptr;}
        const auto owner=lookup(token);
        if(!owner){native_failure(env,DMG_CLOSED);return nullptr;}
        if(owner->source_set!=(source_set==JNI_TRUE)){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        const auto length=env->GetArrayLength(input);if(env->ExceptionCheck())return nullptr;
        if(static_cast<uint64_t>(length)>max_query_bytes){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        std::vector<uint8_t> json(static_cast<size_t>(length));
        if(length)env->GetByteArrayRegion(input,0,length,reinterpret_cast<jbyte*>(json.data()));
        if(env->ExceptionCheck())return nullptr;
        dmg_error error{};dmg_query* raw_query=nullptr;
        auto status=dmg_query_compile_json(owner->engine,json.data(),json.size(),&raw_query,&error);
        if(status!=DMG_OK){if(raw_query)dmg_query_release(raw_query);native_failure(env,status,&error);return nullptr;}
        if(!raw_query){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        std::unique_ptr<dmg_query,QueryDeleter> query(raw_query);dmg_query_info qi{};
        status=dmg_query_get_info(query.get(),&qi);if(status!=DMG_OK){native_failure(env,status);return nullptr;}
        const std::string_view id=qi.query_id?std::string_view(qi.query_id):std::string_view{};
        constexpr uint32_t metadata_capabilities=1u|2u|4u|16u|256u;
        if(reflection_method_uses ? !reflection_method_uses_supported(qi) :
           ((id.substr(0,9)!="query:v1:"&&id.substr(0,9)!="query:v2:")||qi.explicit_scope||qi.demand_mask||
           (qi.required_capabilities&~metadata_capabilities))){
            native_failure(env,DMG_UNSUPPORTED);return nullptr;
        }
        if(qi.max_results>max_query_results||qi.max_work>max_query_work){native_failure(env,DMG_BUDGET_EXCEEDED);return nullptr;}
        dmg_result* raw_result=nullptr;error={};status=dmg_query_execute(owner->snapshot,query.get(),&raw_result,&error);
        if(status!=DMG_OK){if(raw_result)dmg_result_release(raw_result);native_failure(env,status,&error);return nullptr;}
        if(!raw_result){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        std::unique_ptr<dmg_result,ResultDeleter> result(raw_result);
        return materialize_entity_result(env,result.get(),owner->source_set);
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}

extern "C" JNIEXPORT jobject JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryEntities(
    JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set) noexcept {
    return query_entities(env,token,input,source_set,false);
}

extern "C" JNIEXPORT jobject JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeQueryReflectionMethodUses(
    JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set) noexcept {
    return query_entities(env,token,input,source_set,true);
}

// Both graph entry points accept only profiles whose C getters preserve all
// metadata, bindings, links and witnesses used by the Java graph wire format.
static bool graph_query_supported(const dmg_query_info& info) noexcept {
    if (!info.query_id || info.explicit_scope) return false;
    constexpr uint32_t graph_caps = 1u|2u|4u|16u|256u|512u|1024u|2048u;
    constexpr uint32_t reflection_caps = 2097152u|4194304u;
    constexpr uint32_t body_caps = 32u|64u|128u;
    constexpr uint32_t reflection_body_relational = 33554432u;
    const std::string_view id(info.query_id);
    if (id.starts_with("query:v3:")) return !info.demand_mask && (info.required_capabilities & ~graph_caps) == 0;
    if (id.starts_with("query:v14:")) return !info.demand_mask && (info.required_capabilities & reflection_caps) == reflection_caps &&
        (info.required_capabilities & ~(graph_caps|reflection_caps)) == 0;
    if (id.starts_with("query:v17:")) return info.demand_mask && !(info.demand_mask & ~7u) &&
        (info.required_capabilities & (reflection_caps|reflection_body_relational)) == (reflection_caps|reflection_body_relational) &&
        (info.required_capabilities & ~(graph_caps|reflection_caps|body_caps|reflection_body_relational)) == 0;
    return false;
}

static bool advanced_supported(const dmg_query_info& q) noexcept {
    if(!q.query_id)return false;const std::string_view id(q.query_id);
    constexpr uint32_t base=1u|2u|4u|8u|16u|256u|512u|1024u|2048u;
    const uint32_t bit=id.starts_with("query:v6:")?16384u:id.starts_with("query:v7:")?32768u:id.starts_with("query:v8:")?65536u:id.starts_with("query:v11:")?524288u:0u;
    return bit&&(q.required_capabilities&bit)&&(q.required_capabilities&~(base|bit))==0&&(bit==32768u?(q.demand_mask&~8u)==0:q.demand_mask==0u);
}
static bool method_type_supported(const dmg_query_info& q) noexcept {
    constexpr uint32_t caps=1u|2u|4u|8u|32u|64u|128u|1073741824u;
    return q.query_id&&std::string_view(q.query_id).starts_with("query:v22:")&&(q.required_capabilities&1073741824u)&&!(q.required_capabilities&~caps)&&
        !(q.demand_mask&~(256u|1u|2u|4u));
}
static bool expand_supported(const dmg_query_info& q) noexcept {
    return q.query_id&&std::string_view(q.query_id).starts_with("query:v5:")&&(q.required_capabilities&8192u)&&!(q.required_capabilities&0xffffc000u)&&!(q.demand_mask&~7u);
}
static bool opcode_job_supported(const dmg_query_info& info) noexcept {
    constexpr uint32_t caps=1u|2u|4u|32u|64u|128u|0x80000000u;
    return info.query_id&&std::string_view(info.query_id).starts_with("query:v23:")&&!info.explicit_scope&&
        (info.required_capabilities&0x80000000u)&&!(info.required_capabilities&~caps)&&
        (info.demand_mask&512u)&&!(info.demand_mask&~(512u|1u|2u|4u));
}
namespace { bool use_graph_supported(const dmg_query_info&); bool type_use_graph_supported(const dmg_query_info&); bool inherited_use_graph_supported(const dmg_query_info&); bool interface_use_graph_supported(const dmg_query_info&); }
static jlong start_job(JNIEnv* env,jlong token,jbyteArray input,jboolean source_set,jint batch_size,jint queue_size,jlong deadline_ms,bool entity,bool graph=false,bool reflection_method_uses=false,bool use_graph=false,bool type_use=false,bool method_type=false,bool expand=false,bool advanced=false,bool inherited_use=false,bool interface_use=false,bool opcode=false,uint32_t class_annotation=0) noexcept {
    try {
        if(!input){java_exception(env,"java/lang/NullPointerException","queryJson is required");return 0;}
        if(batch_size<1||batch_size>4096||queue_size<1||queue_size>16||deadline_ms<0||deadline_ms>86400000){
            java_exception(env,"java/lang/IllegalArgumentException","invalid job limits");return 0;
        }
        const auto owner=lookup(token);
        if(!owner){native_failure(env,DMG_CLOSED);return 0;}
        if(owner->source_set!=(source_set==JNI_TRUE)){native_failure(env,DMG_UNSUPPORTED);return 0;}
        const auto length=env->GetArrayLength(input);if(env->ExceptionCheck())return 0;
        if(static_cast<uint64_t>(length)>max_query_bytes){native_failure(env,DMG_BUDGET_EXCEEDED);return 0;}
        JobPermit permit;if(!permit.acquire()){native_failure(env,DMG_BUDGET_EXCEEDED);return 0;}
        std::vector<uint8_t> json(static_cast<size_t>(length));
        if(length)env->GetByteArrayRegion(input,0,length,reinterpret_cast<jbyte*>(json.data()));
        if(env->ExceptionCheck())return 0;
        dmg_error error{};dmg_query* raw_query=nullptr;
        auto status=dmg_query_compile_json(owner->engine,json.data(),json.size(),&raw_query,&error);
        if(status!=DMG_OK){if(raw_query)dmg_query_release(raw_query);native_failure(env,status,&error);return 0;}
        if(!raw_query){native_failure(env,DMG_INTERNAL_ERROR);return 0;}
        std::unique_ptr<dmg_query,QueryDeleter> query(raw_query);dmg_query_info info{};dmg_query_info_v2 extended{};
        if(class_annotation){status=dmg_query_get_info_v2(query.get(),&extended,sizeof(extended));info=extended.legacy;}
        else status=dmg_query_get_info(query.get(),&info);
        if(status!=DMG_OK){native_failure(env,status);return 0;}
        const std::string_view id=info.query_id?std::string_view(info.query_id):std::string_view{};
        constexpr uint32_t metadata_capabilities=1u|2u|4u|16u|256u;

        if((info.explicit_scope&&!type_use&&!method_type&&!expand&&!advanced&&!inherited_use&&!interface_use) || (class_annotation ? (!entity||graph||reflection_method_uses||use_graph||type_use||method_type||expand||advanced||inherited_use||interface_use||opcode||(class_annotation!=1&&class_annotation!=2)||!info.query_id||!id.starts_with(class_annotation==1?"query:v24:":"query:v25:")||!extended.extended_capabilities||std::string_view(extended.extended_capabilities)!=(class_annotation==1?"class_annotation_static":"class_annotation_static;class_annotation_string_static")||info.explicit_scope||info.demand_mask||info.intent>DMG_UNIQUE||(info.required_capabilities&~(2u|4u|256u))||(info.required_capabilities&(2u|256u))!=(2u|256u)||(info.projection_mask&~DMG_PROJECT_TYPE)) : opcode ? !opcode_job_supported(info) : interface_use ? !interface_use_graph_supported(info) : inherited_use ? !inherited_use_graph_supported(info) : advanced ? !advanced_supported(info) : expand ? !expand_supported(info) : method_type ? !method_type_supported(info) : type_use ? !type_use_graph_supported(info) : use_graph ? (!use_graph_supported(info) || (id.substr(0,9)!="query:v4:" && id.substr(0,9)!="query:v9:")) : reflection_method_uses ? !reflection_method_uses_supported(info) : graph ?
            !graph_query_supported(info) :
            (entity ? ((id.substr(0,9)!="query:v1:"&&id.substr(0,9)!="query:v2:")||info.demand_mask||(info.required_capabilities&~metadata_capabilities)) :
            id.substr(0,9)!="query:v1:"))){native_failure(env,DMG_UNSUPPORTED);return 0;}
        if(info.max_results>max_query_results||info.max_work>max_query_work){native_failure(env,DMG_BUDGET_EXCEEDED);return 0;}
        dmg_snapshot_overview overview{};status=dmg_snapshot_get_overview(owner->snapshot,&overview);
        if(status!=DMG_OK){native_failure(env,status);return 0;}
        if(!overview.snapshot_id||overview.scope_complete){native_failure(env,DMG_INTERNAL_ERROR);return 0;}
        std::string query_id(info.query_id),snapshot_id(overview.snapshot_id);
        const dmg_job_options options{sizeof(dmg_job_options),DMG_ABI_VERSION,static_cast<uint32_t>(batch_size),
                                      static_cast<uint32_t>(queue_size),static_cast<uint64_t>(deadline_ms)};
        dmg_job* raw_job=nullptr;error={};status=dmg_job_start(owner->snapshot,query.get(),&options,&raw_job,&error);
        if(status!=DMG_OK){if(raw_job)dmg_job_release(raw_job);native_failure(env,status,&error);return 0;}
        if(!raw_job){native_failure(env,DMG_INTERNAL_ERROR);return 0;}
        std::unique_ptr<dmg_job,JobDeleter> guard(raw_job);
        const auto job=std::make_shared<JobOwner>(guard.get(),owner,std::move(query_id),std::move(snapshot_id),entity,graph,use_graph||type_use||inherited_use||interface_use,method_type,expand,advanced,class_annotation);guard.release();
        const auto result=permit.publish(job);if(!result){native_failure(env,DMG_BUDGET_EXCEEDED);return 0;}return result;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return 0;
}

extern "C" JNIEXPORT jlong JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartMethodJob(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set,jint batch_size,jint queue_size,jlong deadline_ms) noexcept {
    return start_job(env,token,input,source_set,batch_size,queue_size,deadline_ms,false);
}
extern "C" JNIEXPORT jlong JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartOpcodeJob(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set,jint batch_size,jint queue_size,jlong deadline_ms) noexcept {
    return start_job(env,token,input,source_set,batch_size,queue_size,deadline_ms,false,false,false,false,false,false,false,false,false,false,true);
}
extern "C" JNIEXPORT jlong JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartClassAnnotationJob(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set,jint batch_size,jint queue_size,jlong deadline_ms) noexcept {
    return start_job(env,token,input,source_set,batch_size,queue_size,deadline_ms,true,false,false,false,false,false,false,false,false,false,false,true);
}
extern "C" JNIEXPORT jlong JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartClassAnnotationStringJob(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set,jint batch_size,jint queue_size,jlong deadline_ms) noexcept {
    return start_job(env,token,input,source_set,batch_size,queue_size,deadline_ms,true,false,false,false,false,false,false,false,false,false,false,2);
}
extern "C" JNIEXPORT jlong JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartEntityJob(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set,jint batch_size,jint queue_size,jlong deadline_ms) noexcept {
    return start_job(env,token,input,source_set,batch_size,queue_size,deadline_ms,true);
}

extern "C" JNIEXPORT jlong JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartReflectionMethodUsesJob(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set,jint batch_size,jint queue_size,jlong deadline_ms) noexcept {
    return start_job(env,token,input,source_set,batch_size,queue_size,deadline_ms,true,false,true);
}

extern "C" JNIEXPORT jlong JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeStartGraphJob(JNIEnv* env,jclass,jlong token,jbyteArray input,jboolean source_set,jint batch_size,jint queue_size,jlong deadline_ms) noexcept {
    return start_job(env,token,input,source_set,batch_size,queue_size,deadline_ms,false,true);
}

extern "C" JNIEXPORT jobject JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeJobNext(JNIEnv* env,jclass,jlong token,jint timeout_ms) noexcept {
    try {
        if(timeout_ms<0||timeout_ms>max_job_wait_ms){java_exception(env,"java/lang/IllegalArgumentException","invalid wait timeout");return nullptr;}
        const auto job=lookup_job(token);if(!job){native_failure(env,DMG_CLOSED);return nullptr;}
        if(job->entity||job->graph||job->use_graph||job->method_type){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        if(job->delivery_failed.load(std::memory_order_acquire)){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        std::unique_lock lock(job->consumer,std::try_to_lock);
        if(!lock.owns_lock()){java_exception(env,"java/lang/IllegalStateException","only one batch consumer is allowed");return nullptr;}
        // Another consumer may have failed delivery between our first check
        // and acquisition; never advance a poisoned stream.
        if(job->delivery_failed.load(std::memory_order_acquire)){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        dmg_batch* raw=nullptr;dmg_error error{};
        const auto status=dmg_job_next(job->job,static_cast<uint32_t>(timeout_ms),&raw,&error);
        std::unique_ptr<dmg_result,ResultDeleter> batch(raw);
        jint kind=0;jobject copied=nullptr;
        if(status==DMG_NOT_READY)kind=1;
        else if(status==DMG_END_OF_STREAM)kind=2;
        else if(status!=DMG_OK){native_failure(env,status,&error);return nullptr;}
        else if(!batch){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        else {
            copied=materialize_result(env,batch.get(),job->owner->source_set);
            if(!copied||env->ExceptionCheck()){
                job->delivery_failed.store(true,std::memory_order_release);dmg_job_cancel(job->job);
                if(!env->ExceptionCheck())native_failure(env,DMG_INTERNAL_ERROR);return nullptr;
            }
        }
        const auto cls=env->FindClass("io/github/jichuo1/dexmeguviz/NativeEngine$JobPoll");
        const auto ctor=cls&&!env->ExceptionCheck()?env->GetMethodID(cls,"<init>","(ILio/github/jichuo1/dexmeguviz/NativeEngine$QueryResult;)V"):nullptr;
        jobject value=nullptr;if(ctor&&!env->ExceptionCheck())value=env->NewObject(cls,ctor,kind,copied);
        if(!value||env->ExceptionCheck()){
            if(batch){job->delivery_failed.store(true,std::memory_order_release);dmg_job_cancel(job->job);}
            if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;
        }
        return value;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}

static dmg_status verify_annotation_scoped_batch(const JobOwner& job,const dmg_result* result) noexcept {
    dmg_query_info_v2 query{};auto status=dmg_result_get_query_info_v2(result,&query,sizeof(query));if(status!=DMG_OK)return status;
    if((job.class_annotation!=1&&job.class_annotation!=2)||!query.legacy.query_id||job.query_id!=query.legacy.query_id||!query.legacy.explicit_scope||!query.extended_capabilities||
       std::string_view(query.extended_capabilities)!=(job.class_annotation==1?"class_annotation_static":"class_annotation_static;class_annotation_string_static"))return DMG_INTERNAL_ERROR;
    dmg_snapshot_overview overview{};status=dmg_result_get_overview(result,&overview);if(status!=DMG_OK)return status;
    if(!overview.snapshot_id||job.snapshot_id!=overview.snapshot_id)return DMG_INTERNAL_ERROR;
    dmg_query_profile profile{};status=dmg_result_get_profile(result,&profile);if(status!=DMG_OK)return status;
    if(profile.scope_complete!=1||profile.scope_source_count!=job.scoped_sources.size())return DMG_INTERNAL_ERROR;
    for(uint32_t i=0;i<profile.scope_source_count;++i){uint32_t source=0;status=dmg_result_get_scope_source(result,i,&source);if(status!=DMG_OK||source!=static_cast<uint32_t>(job.scoped_sources[i]))return DMG_INTERNAL_ERROR;}
    dmg_relation_info relation{};status=dmg_result_get_relation_info(result,&relation,sizeof(relation));if(status!=DMG_OK)return status;
    if(relation.relation!=DMG_CLASS_DEFS||relation.coverage!=DMG_COVERAGE_PARTIAL||relation.decision!=DMG_NOT_APPLICABLE||relation.candidates_count>max_query_results)return DMG_INTERNAL_ERROR;
    for(uint32_t i=0;i<relation.candidates_count;++i){dmg_entity_row row{};status=dmg_result_get_entity(result,i,&row,sizeof(row));
        if(status!=DMG_OK||std::find(job.scoped_sources.begin(),job.scoped_sources.end(),static_cast<jint>(row.source_index))==job.scoped_sources.end())return DMG_INTERNAL_ERROR;}
    return DMG_OK;
}
static dmg_status verify_annotation_terminal_scope(const JobOwner& job) noexcept {
    dmg_job_terminal_scope_v1 scope{};auto status=dmg_job_get_terminal_scope_v1(job.job,&scope,sizeof(scope));if(status!=DMG_OK)return status;
    if(scope.scope_complete!=1||scope.source_count!=job.scoped_sources.size())return DMG_INTERNAL_ERROR;
    for(uint32_t i=0;i<scope.source_count;++i){uint32_t source=0;status=dmg_job_get_terminal_scope_source_v1(job.job,i,&source);if(status!=DMG_OK||source!=static_cast<uint32_t>(job.scoped_sources[i]))return DMG_INTERNAL_ERROR;}
    return DMG_OK;
}

extern "C" JNIEXPORT jobject JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeEntityJobNext(JNIEnv* env,jclass,jlong token,jint timeout_ms) noexcept {
    try {
        if(timeout_ms<0||timeout_ms>max_job_wait_ms){java_exception(env,"java/lang/IllegalArgumentException","invalid wait timeout");return nullptr;}
        const auto job=lookup_job(token);if(!job){native_failure(env,DMG_CLOSED);return nullptr;}
        if(!job->entity||job->graph||job->use_graph||job->advanced){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        if(job->delivery_failed.load(std::memory_order_acquire)){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        std::unique_lock lock(job->consumer,std::try_to_lock);
        if(!lock.owns_lock()){java_exception(env,"java/lang/IllegalStateException","only one batch consumer is allowed");return nullptr;}
        // Another consumer may have failed delivery between our first check
        // and acquisition; never advance a poisoned stream.
        if(job->delivery_failed.load(std::memory_order_acquire)){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        dmg_batch* raw=nullptr;dmg_error error{};
        const auto status=dmg_job_next(job->job,static_cast<uint32_t>(timeout_ms),&raw,&error);
        std::unique_ptr<dmg_result,ResultDeleter> batch(raw);
        jint kind=0;jobject copied=nullptr;
        if(status==DMG_NOT_READY)kind=1;
        else if(status==DMG_END_OF_STREAM)kind=2;
        else if(status!=DMG_OK){native_failure(env,status,&error);return nullptr;}
        else if(!batch){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        else {
            if(job->annotation_scoped){const auto check=verify_annotation_scoped_batch(*job,batch.get());if(check!=DMG_OK){job->delivery_failed.store(true,std::memory_order_release);dmg_job_cancel(job->job);native_failure(env,check);return nullptr;}}
            copied=materialize_entity_result(env,batch.get(),job->owner->source_set,job->class_annotation,job->annotation_scoped);
            if(!copied||env->ExceptionCheck()){
                job->delivery_failed.store(true,std::memory_order_release);dmg_job_cancel(job->job);
                if(!env->ExceptionCheck())native_failure(env,DMG_INTERNAL_ERROR);return nullptr;
            }
        }
        const auto cls=env->FindClass("io/github/jichuo1/dexmeguviz/NativeEngine$EntityJobPoll");
        const auto ctor=cls&&!env->ExceptionCheck()?env->GetMethodID(cls,"<init>","(ILio/github/jichuo1/dexmeguviz/NativeEngine$EntityResult;)V"):nullptr;
        jobject value=nullptr;if(ctor&&!env->ExceptionCheck())value=env->NewObject(cls,ctor,kind,copied);
        if(!value||env->ExceptionCheck()){
            if(batch){job->delivery_failed.store(true,std::memory_order_release);dmg_job_cancel(job->job);}
            if(!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return nullptr;
        }
        return value;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}

extern "C" JNIEXPORT jobject JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeJobStatus(JNIEnv* env,jclass,jlong token,jint timeout_ms) noexcept {
    try {
        if(timeout_ms< -1||timeout_ms>max_job_wait_ms){java_exception(env,"java/lang/IllegalArgumentException","invalid wait timeout");return nullptr;}
        const auto job=lookup_job(token);if(!job){native_failure(env,DMG_CLOSED);return nullptr;}
        if(job->delivery_failed.load(std::memory_order_acquire)){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        if(job->use_graph||job->expand){native_failure(env,DMG_UNSUPPORTED);return nullptr;}
        dmg_relation_job_status state{};
        const auto status=timeout_ms<0?dmg_job_get_relation_status(job->job,&state,sizeof(state)):
            dmg_job_wait_relation(job->job,static_cast<uint32_t>(timeout_ms),&state,sizeof(state));
        if(status!=DMG_OK&&status!=DMG_NOT_READY){native_failure(env,status);return nullptr;}
        // A batch delivery may have failed while the status call was waiting.
        // The status snapshot does not certify future concurrent deliveries.
        if(job->delivery_failed.load(std::memory_order_acquire)){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        if(job->annotation_scoped&&state.terminal&&state.outcome.execution_status==DMG_OK){const auto check=verify_annotation_terminal_scope(*job);if(check!=DMG_OK){job->delivery_failed.store(true,std::memory_order_release);native_failure(env,check);return nullptr;}}
        if(state.outcome.candidates_count>uint32_t(std::numeric_limits<jint>::max())||
           state.outcome.visited_rows>uint32_t(std::numeric_limits<jint>::max())||
           state.outcome.total_rows>uint32_t(std::numeric_limits<jint>::max())||
           state.outcome.unknown_rows>uint64_t(std::numeric_limits<jlong>::max())||
           state.error.offset>uint64_t(std::numeric_limits<jlong>::max())){native_failure(env,DMG_INTERNAL_ERROR);return nullptr;}
        const auto cls=env->FindClass("io/github/jichuo1/dexmeguviz/NativeEngine$JobStatus");
        if(!cls||env->ExceptionCheck())return nullptr;
        const auto ctor=env->GetMethodID(cls,"<init>","(IZIIIIIIIJJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
        if(!ctor||env->ExceptionCheck())return nullptr;
        std::array<char,256> message{};for(size_t i=0;i+1<message.size()&&state.error.message[i];++i){const auto ch=static_cast<unsigned char>(state.error.message[i]);message[i]=ch>=0x20&&ch<=0x7e?static_cast<char>(ch):'?';}
        const auto query=env->NewStringUTF(job->query_id.c_str());if(!query||env->ExceptionCheck())return nullptr;
        const auto snapshot=env->NewStringUTF(job->snapshot_id.c_str());if(!snapshot||env->ExceptionCheck())return nullptr;
        const auto detail=env->NewStringUTF(message.data());if(!detail||env->ExceptionCheck())return nullptr;
        const auto& o=state.outcome;
        auto value=env->NewObject(cls,ctor,static_cast<jint>(state.lifecycle),state.terminal?JNI_TRUE:JNI_FALSE,
            static_cast<jint>(o.execution_status),static_cast<jint>(o.coverage),static_cast<jint>(o.decision),static_cast<jint>(o.reason),
            static_cast<jint>(o.candidates_count),static_cast<jint>(o.visited_rows),static_cast<jint>(o.total_rows),
            static_cast<jlong>(o.unknown_rows),static_cast<jlong>(state.error.offset),query,snapshot,detail);
        if(!value&&!env->ExceptionCheck())native_failure(env,DMG_OUT_OF_MEMORY);return value;
    }catch(const std::bad_alloc&){native_failure(env,DMG_OUT_OF_MEMORY);}catch(...){native_failure(env,DMG_INTERNAL_ERROR);}return nullptr;
}

extern "C" JNIEXPORT void JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeJobCancel(JNIEnv* env,jclass,jlong token) noexcept {
    try {const auto job=lookup_job(token);if(!job){native_failure(env,DMG_CLOSED);return;}dmg_job_cancel(job->job);}
    catch(...){native_failure(env,DMG_INTERNAL_ERROR);}
}
extern "C" JNIEXPORT void JNICALL
Java_io_github_jichuo1_dexmeguviz_NativeEngine_nativeJobClose(JNIEnv* env,jclass,jlong token) noexcept {
    try {
        std::shared_ptr<JobOwner> job;
        {std::lock_guard lock(registry_mutex);const auto it=jobs.find(token);if(it==jobs.end())return;job=std::move(it->second);jobs.erase(it);}
        dmg_job_cancel(job->job);
    }catch(...){native_failure(env,DMG_INTERNAL_ERROR);}
}

#include "scoped_method_jni.inc"

#include "jni_graph.inc"
#include "jni_use_graph.inc"
#include "jni_method_type.inc"



#include "jni_expand.inc"

#include "jni_advanced.inc"

#include "jni_method_calls.inc"
#include "jni_method_parameters.inc"
#include "jni_method_facts.inc"
#include "jni_annotations.inc"
#include "jni_source_bytes.inc"
#include "jni_opcode_query.inc"
#include "jni_scoped_opcode.inc"
#include "jni_stream_export.inc"
#include "jni_class_annotation_query.inc"
#include "jni_scoped_class_annotation_query.inc"
#include "jni_class_annotation_string_query.inc"
#include "jni_scoped_class_annotation_string_query.inc"
#include "jni_scoped_class_annotation_job.inc"

#include "jni_method_batch.inc"
