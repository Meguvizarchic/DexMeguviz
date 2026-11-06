#include <jni.h>
#include "dexmeguviz/fast_query_v1.h"
#include "native_apk_scan.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace {
constexpr uint32_t max_wire_bytes=8u<<20;
constexpr uint32_t max_archive_wire_bytes=64u<<20;
std::mutex gate;
struct PlanOwner {dmg_fast_plans_v1* value=nullptr;~PlanOwner(){dmg_fast_plans_release_v1(value);}};
std::unordered_map<jlong,std::shared_ptr<PlanOwner>> sessions;
uint64_t next_token=1;size_t opening=0;
struct Permit {
 bool held=false;
 bool acquire(){std::lock_guard lock(gate);if(sessions.size()+opening>=32||next_token>uint64_t(std::numeric_limits<jlong>::max()))return false;++opening;held=true;return true;}
 jlong publish(const std::shared_ptr<PlanOwner>& p){std::lock_guard lock(gate);if(!held||next_token>uint64_t(std::numeric_limits<jlong>::max()))return 0;const auto id=static_cast<jlong>(next_token);if(!sessions.emplace(id,p).second)return 0;++next_token;--opening;held=false;return id;}
 ~Permit(){if(held){std::lock_guard lock(gate);--opening;}}
};
std::shared_ptr<PlanOwner> lookup(jlong token){std::lock_guard lock(gate);const auto it=sessions.find(token);return it==sessions.end()?nullptr:it->second;}
void exception(JNIEnv* env,const char* cls,const char* msg){if(env->ExceptionCheck())return;const auto c=env->FindClass(cls);if(c&&!env->ExceptionCheck())env->ThrowNew(c,msg);}
void fail(JNIEnv* env,dmg_status code,int rule,const dmg_error* error=nullptr){
 if(env->ExceptionCheck())return;const auto cls=env->FindClass("io/github/jichuo1/dexmeguviz/FastDexQuery$Failure");if(!cls||env->ExceptionCheck())return;
 const auto ctor=env->GetMethodID(cls,"<init>","(IIJLjava/lang/String;)V");if(!ctor||env->ExceptionCheck())return;
 const char* raw=error&&error->message[0]?error->message:dmg_status_name(code);std::array<char,256> text{};
 for(size_t i=0;i+1<text.size()&&raw[i];++i){const auto c=static_cast<unsigned char>(raw[i]);text[i]=c>=32&&c<=126?static_cast<char>(c):'?';}
 const auto msg=env->NewStringUTF(text.data());if(!msg||env->ExceptionCheck())return;const auto offset=error&&error->offset<=uint64_t(std::numeric_limits<jlong>::max())?static_cast<jlong>(error->offset):0;
 const auto value=env->NewObject(cls,ctor,static_cast<jint>(code),static_cast<jint>(rule),offset,msg);if(value&&!env->ExceptionCheck())env->Throw(static_cast<jthrowable>(value));
}
struct Wire {
 std::vector<uint8_t> bytes;size_t limit;
 explicit Wire(size_t n):limit(n){}
 void need(size_t n){if(n>limit-bytes.size())throw std::length_error("fast wire limit");}
 void u32(uint32_t v){need(4);for(unsigned i=0;i<4;++i)bytes.push_back(static_cast<uint8_t>(v>>(i*8)));}
 void u64(uint64_t v){need(8);for(unsigned i=0;i<8;++i)bytes.push_back(static_cast<uint8_t>(v>>(i*8)));}
 void text(const uint16_t* s,uint32_t n){if(n&&s==nullptr)throw std::runtime_error("null text");need(4+size_t(n)*2);u32(n);for(uint32_t i=0;i<n;++i){bytes.push_back(static_cast<uint8_t>(s[i]));bytes.push_back(static_cast<uint8_t>(s[i]>>8));}}
 void raw(const std::vector<uint8_t>& data){need(data.size());bytes.insert(bytes.end(),data.begin(),data.end());}
 void ascii(const char* s){if(!s)throw std::runtime_error("null query id");size_t n=0;while(n<=1024&&s[n])++n;if(n>1024)throw std::length_error("query id");need(4+n);u32(static_cast<uint32_t>(n));bytes.insert(bytes.end(),s,s+n);}
};
struct ResultsOwner {dmg_fast_results_v1* value=nullptr;~ResultsOwner(){dmg_fast_results_release_v1(value);}};
}
extern "C" JNIEXPORT jlong JNICALL Java_io_github_jichuo1_dexmeguviz_FastDexQuery_nativeCompile(JNIEnv* env,jclass,jobjectArray inputs,jbooleanArray captures) noexcept {
 try{
  if(!inputs||!captures){exception(env,"java/lang/NullPointerException","queries and flags are required");return 0;}
  const auto count=env->GetArrayLength(inputs);if(env->ExceptionCheck())return 0;const auto flags_count=env->GetArrayLength(captures);if(env->ExceptionCheck())return 0;
  if(count<1||count>16||count!=flags_count){exception(env,"java/lang/IllegalArgumentException","expected one to sixteen matching queries and flags");return 0;}
  std::array<jboolean,16> flags{};env->GetBooleanArrayRegion(captures,0,count,flags.data());if(env->ExceptionCheck())return 0;
  Permit permit;if(!permit.acquire()){fail(env,DMG_BUDGET_EXCEEDED,-1);return 0;}
  std::vector<std::vector<uint8_t>> data(static_cast<size_t>(count));std::vector<dmg_fast_rule_v1> rules;rules.reserve(static_cast<size_t>(count));uint64_t total=0;
  for(jsize i=0;i<count;++i){auto arr=static_cast<jbyteArray>(env->GetObjectArrayElement(inputs,i));if(env->ExceptionCheck())return 0;if(!arr){exception(env,"java/lang/NullPointerException","query is required");return 0;}
   const auto n=env->GetArrayLength(arr);if(env->ExceptionCheck()){env->DeleteLocalRef(arr);return 0;}
   if(n<0||n>65536||static_cast<uint64_t>(n)>1048576-total){env->DeleteLocalRef(arr);fail(env,DMG_BUDGET_EXCEEDED,i);return 0;}total+=static_cast<uint64_t>(n);
   auto& bytes=data[static_cast<size_t>(i)];bytes.resize(static_cast<size_t>(n));if(n)env->GetByteArrayRegion(arr,0,n,reinterpret_cast<jbyte*>(bytes.data()));env->DeleteLocalRef(arr);if(env->ExceptionCheck())return 0;
   rules.push_back({bytes.data(),bytes.size(),flags[static_cast<size_t>(i)]?1u:0u});
  }
  auto owner=std::make_shared<PlanOwner>();uint32_t index=UINT32_MAX;dmg_error error{};const auto status=dmg_fast_compile_v1(rules.data(),static_cast<uint32_t>(rules.size()),&owner->value,&index,&error);
  if(status!=DMG_OK||!owner->value){fail(env,status==DMG_OK?DMG_INTERNAL_ERROR:status,index==UINT32_MAX?-1:static_cast<int>(index),&error);return 0;}
  const auto id=permit.publish(owner);if(!id)fail(env,DMG_BUDGET_EXCEEDED,-1);return id;
 }catch(const std::bad_alloc&){fail(env,DMG_OUT_OF_MEMORY,-1);}catch(...){fail(env,DMG_INTERNAL_ERROR,-1);}return 0;
}
extern "C" JNIEXPORT jbyteArray JNICALL Java_io_github_jichuo1_dexmeguviz_FastDexQuery_nativeScan(JNIEnv* env,jclass,jlong token,jbyteArray input,jlong max_dex,jint rows,jint calls,jlong text,jint code,jint instructions,jint max_wire) noexcept {
 try{
  if(!input){exception(env,"java/lang/NullPointerException","dex is required");return nullptr;}
  if(max_dex<=0||max_dex>std::numeric_limits<jsize>::max()||rows<1||rows>65536||calls<0||calls>100000||text<1||text>1048576||code<1||code>1048576||instructions<1||instructions>1048576||max_wire<1||static_cast<uint32_t>(max_wire)>max_wire_bytes){exception(env,"java/lang/IllegalArgumentException","invalid fast scan limits");return nullptr;}
  auto owner=lookup(token);if(!owner){fail(env,DMG_CLOSED,-1);return nullptr;}
  const auto n=env->GetArrayLength(input);if(env->ExceptionCheck())return nullptr;if(static_cast<uint64_t>(n)>static_cast<uint64_t>(max_dex)){fail(env,DMG_BUDGET_EXCEEDED,-1);return nullptr;}
  std::vector<uint8_t> dex(static_cast<size_t>(n));if(n)env->GetByteArrayRegion(input,0,n,reinterpret_cast<jbyte*>(dex.data()));if(env->ExceptionCheck())return nullptr;
  const dmg_fast_limits_v1 limits{sizeof(limits),DMG_ABI_VERSION,static_cast<uint64_t>(max_dex),static_cast<uint32_t>(rows),static_cast<uint32_t>(calls),static_cast<uint64_t>(text),static_cast<uint32_t>(code),static_cast<uint32_t>(instructions),1,0};
  ResultsOwner results;uint32_t failed=UINT32_MAX;dmg_error error{};const auto status=dmg_fast_scan_v1(owner->value,dex.data(),dex.size(),&limits,&results.value,&failed,&error);
  if(status!=DMG_OK||!results.value){fail(env,status==DMG_OK?DMG_INTERNAL_ERROR:status,failed==UINT32_MAX?-1:static_cast<int>(failed),&error);return nullptr;}
  Wire wire(static_cast<size_t>(max_wire));wire.u32(0x31514644);uint32_t count=0;if(dmg_fast_results_count_v1(results.value,&count)!=DMG_OK){fail(env,DMG_INTERNAL_ERROR,-1);return nullptr;}wire.u32(count);
  for(uint32_t i=0;i<count;++i){dmg_fast_rule_info_v1 info{};if(dmg_fast_rule_info_get_v1(results.value,i,&info)!=DMG_OK){fail(env,DMG_INTERNAL_ERROR,-1);return nullptr;}
   wire.u32(info.relation);wire.u32(info.execution_status);wire.u32(info.unknown_rows);wire.u32(info.result_limit);wire.u32(info.caller_asserted_exhaustive);wire.u64(info.selected_methods_visited);wire.u64(info.selected_bodies_decoded);wire.u64(info.class_defs_visited);wire.ascii(info.query_id);wire.u32(info.candidates_count);
   if(info.relation==1){for(uint32_t j=0;j<info.candidates_count;++j){dmg_fast_class_v1 row{};if(dmg_fast_class_get_v1(results.value,i,j,&row)!=DMG_OK){fail(env,DMG_INTERNAL_ERROR,-1);return nullptr;}
     wire.u32(row.local_index);wire.u32(row.type_index);wire.u32(row.definition_offset);wire.u32(row.access_flags);wire.text(row.descriptor,row.descriptor_length);}continue;}
   if(info.relation!=0){fail(env,DMG_INTERNAL_ERROR,-1);return nullptr;}
   for(uint32_t j=0;j<info.candidates_count;++j){dmg_fast_method_v1 row{};if(dmg_fast_method_get_v1(results.value,i,j,&row)!=DMG_OK){fail(env,DMG_INTERNAL_ERROR,-1);return nullptr;}
    wire.u32(row.method_ref);wire.u32(row.access_flags);wire.u32(row.declaration_offset);wire.u32(row.code_offset);wire.text(row.owner,row.owner_length);wire.text(row.name,row.name_length);wire.text(row.prototype,row.prototype_length);wire.u32(row.call_count);
    for(uint32_t k=0;k<row.call_count;++k){dmg_fast_call_v1 call{};if(dmg_fast_call_get_v1(results.value,i,j,k,&call)!=DMG_OK){fail(env,DMG_INTERNAL_ERROR,-1);return nullptr;}
     wire.u32(call.pc);wire.u32(call.target_ref);wire.u32(call.extra_proto);wire.u32(call.opcode);wire.u32(call.reference_kind);wire.text(call.owner,call.owner_length);wire.text(call.name,call.name_length);wire.text(call.prototype,call.prototype_length);wire.text(call.extra_prototype,call.extra_prototype_length);}
   }
  }
  const auto size=static_cast<jsize>(wire.bytes.size());auto out=env->NewByteArray(size);if(!out||env->ExceptionCheck())return nullptr;if(size)env->SetByteArrayRegion(out,0,size,reinterpret_cast<const jbyte*>(wire.bytes.data()));return env->ExceptionCheck()?nullptr:out;
 }catch(const std::length_error&){fail(env,DMG_BUDGET_EXCEEDED,-1);}catch(const std::bad_alloc&){fail(env,DMG_OUT_OF_MEMORY,-1);}catch(...){fail(env,DMG_INTERNAL_ERROR,-1);}return nullptr;
}
extern "C" JNIEXPORT void JNICALL Java_io_github_jichuo1_dexmeguviz_FastDexQuery_nativeClose(JNIEnv* env,jclass,jlong token) noexcept {
 try{std::lock_guard lock(gate);sessions.erase(token);}catch(...){fail(env,DMG_INTERNAL_ERROR,-1);}
}

namespace {
std::u16string jchars(JNIEnv* env,jstring value){
 if(!value)throw std::invalid_argument("null string");const auto n=env->GetStringLength(value);const auto* ptr=env->GetStringChars(value,nullptr);if(!ptr)throw std::bad_alloc();
 try{std::u16string out(reinterpret_cast<const char16_t*>(ptr),static_cast<size_t>(n));env->ReleaseStringChars(value,ptr);return out;}catch(...){env->ReleaseStringChars(value,ptr);throw;}
}
std::filesystem::path native_path(const std::u16string& p){
 if(p.empty()||p.find(u'\0')!=std::u16string::npos)throw std::invalid_argument("invalid path");
#ifdef _WIN32
 return std::filesystem::path(std::wstring(p.begin(),p.end()));
#else
 std::string out;for(size_t i=0;i<p.size();++i){uint32_t c=p[i];if(c>=0xd800&&c<=0xdbff){if(++i>=p.size()||p[i]<0xdc00||p[i]>0xdfff)throw std::invalid_argument("invalid path UTF-16");c=0x10000+((c-0xd800)<<10)+(p[i]-0xdc00);}else if(c>=0xdc00&&c<=0xdfff)throw std::invalid_argument("invalid path UTF-16");
 if(c<0x80)out.push_back(char(c));else if(c<0x800){out.push_back(char(0xc0|(c>>6)));out.push_back(char(0x80|(c&63)));}else if(c<0x10000){out.push_back(char(0xe0|(c>>12)));out.push_back(char(0x80|((c>>6)&63)));out.push_back(char(0x80|(c&63)));}else{out.push_back(char(0xf0|(c>>18)));out.push_back(char(0x80|((c>>12)&63)));out.push_back(char(0x80|((c>>6)&63)));out.push_back(char(0x80|(c&63)));}}
 return std::filesystem::path(out);
#endif
}
uint64_t bound(jlong n){if(n<0)throw std::invalid_argument("negative limit");return static_cast<uint64_t>(n);}
uint32_t bound32(jlong n){const auto v=bound(n);if(v>UINT32_MAX)throw std::invalid_argument("oversized limit");return static_cast<uint32_t>(v);}
}
extern "C" JNIEXPORT jbyteArray JNICALL Java_io_github_jichuo1_dexmeguviz_FastDexQuery_nativeScanArchives(JNIEnv* env,jclass,jlong token,jobjectArray paths,jobjectArray slots,jbooleanArray allow,jlongArray source_limits,jlongArray query_limits,jboolean digest,jint max_wire) noexcept {
 try{
  if(!paths||!slots||!allow||!source_limits||!query_limits)throw std::invalid_argument("null archive arguments");
  const auto n=env->GetArrayLength(paths);if(n<1||n>1024||env->GetArrayLength(slots)!=n||env->GetArrayLength(allow)!=n||env->GetArrayLength(source_limits)!=13||env->GetArrayLength(query_limits)!=7||max_wire<1||static_cast<uint32_t>(max_wire)>max_archive_wire_bytes)throw std::invalid_argument("invalid archive dimensions");
  auto owner=lookup(token);if(!owner){fail(env,DMG_CLOSED,-1);return nullptr;}
  std::array<jlong,13> a{};std::array<jlong,7> q{};std::vector<jboolean> allowed(static_cast<size_t>(n));
  env->GetLongArrayRegion(source_limits,0,13,a.data());env->GetLongArrayRegion(query_limits,0,7,q.data());env->GetBooleanArrayRegion(allow,0,n,allowed.data());if(env->ExceptionCheck())return nullptr;
  native_apk_candidate::Limits lim{bound32(a[0]),bound32(a[1]),bound32(a[2]),bound32(a[3]),bound32(a[4]),bound(a[5]),bound(a[6]),bound(a[7]),bound(a[8]),bound(a[9]),bound(a[10]),bound(a[11]),bound(a[12]),digest==JNI_TRUE};
  dmg_fast_limits_v1 sl{sizeof(sl),DMG_ABI_VERSION,bound(q[0]),bound32(q[1]),bound32(q[2]),bound(q[3]),bound32(q[4]),bound32(q[5]),1,0};
  const auto each_wire=bound(q[6]);if(!each_wire||each_wire>max_wire_bytes)throw std::invalid_argument("invalid per-source wire limit");
  std::vector<native_apk_candidate::Input> inputs;inputs.reserve(static_cast<size_t>(n));
  for(jsize i=0;i<n;++i){auto path=static_cast<jstring>(env->GetObjectArrayElement(paths,i));auto slot=static_cast<jstring>(env->GetObjectArrayElement(slots,i));if(env->ExceptionCheck())return nullptr;
   auto path_data=jchars(env,path),slot_data=jchars(env,slot);env->DeleteLocalRef(path);env->DeleteLocalRef(slot);inputs.push_back({native_path(path_data),std::move(slot_data),allowed[static_cast<size_t>(i)]==JNI_TRUE});}
  auto result=native_apk_candidate::scan(inputs,lim,owner->value,sl);Wire wire(static_cast<size_t>(max_wire));wire.u32(0x31415044);wire.u32(static_cast<uint32_t>(result.inputs.size()));
  for(const auto& input:result.inputs){wire.u32(input.sources);wire.u64(input.archive_bytes);wire.u64(input.dex_bytes);wire.u64(input.compressed_bytes);}
  wire.u32(static_cast<uint32_t>(result.ordered.size()));for(const auto& item:result.ordered){const auto& source=item.source;
   wire.u32(source.input_index);wire.u32(source.central_index);wire.u32(source.ordinal);wire.u64(source.size);wire.u64(source.compressed_size);wire.u32(source.crc);wire.ascii(item.matched_sha256.c_str());
   Wire one(static_cast<size_t>(each_wire));
one.u32(0x31514644);uint32_t count=0;if(dmg_fast_results_count_v1(item.result.get(),&count)!=DMG_OK){fail(env,DMG_INTERNAL_ERROR,-1);return nullptr;}one.u32(count);
  for(uint32_t i=0;i<count;++i){dmg_fast_rule_info_v1 info{};if(dmg_fast_rule_info_get_v1(item.result.get(),i,&info)!=DMG_OK){fail(env,DMG_INTERNAL_ERROR,-1);return nullptr;}
   one.u32(info.relation);one.u32(info.execution_status);one.u32(info.unknown_rows);one.u32(info.result_limit);one.u32(info.caller_asserted_exhaustive);one.u64(info.selected_methods_visited);one.u64(info.selected_bodies_decoded);one.u64(info.class_defs_visited);one.ascii(info.query_id);one.u32(info.candidates_count);
   if(info.relation==1){for(uint32_t j=0;j<info.candidates_count;++j){dmg_fast_class_v1 row{};if(dmg_fast_class_get_v1(item.result.get(),i,j,&row)!=DMG_OK){fail(env,DMG_INTERNAL_ERROR,-1);return nullptr;}
     one.u32(row.local_index);one.u32(row.type_index);one.u32(row.definition_offset);one.u32(row.access_flags);one.text(row.descriptor,row.descriptor_length);}continue;}
   if(info.relation!=0){fail(env,DMG_INTERNAL_ERROR,-1);return nullptr;}
   for(uint32_t j=0;j<info.candidates_count;++j){dmg_fast_method_v1 row{};if(dmg_fast_method_get_v1(item.result.get(),i,j,&row)!=DMG_OK){fail(env,DMG_INTERNAL_ERROR,-1);return nullptr;}
    one.u32(row.method_ref);one.u32(row.access_flags);one.u32(row.declaration_offset);one.u32(row.code_offset);one.text(row.owner,row.owner_length);one.text(row.name,row.name_length);one.text(row.prototype,row.prototype_length);one.u32(row.call_count);
    for(uint32_t k=0;k<row.call_count;++k){dmg_fast_call_v1 call{};if(dmg_fast_call_get_v1(item.result.get(),i,j,k,&call)!=DMG_OK){fail(env,DMG_INTERNAL_ERROR,-1);return nullptr;}
     one.u32(call.pc);one.u32(call.target_ref);one.u32(call.extra_proto);one.u32(call.opcode);one.u32(call.reference_kind);one.text(call.owner,call.owner_length);one.text(call.name,call.name_length);one.text(call.prototype,call.prototype_length);one.text(call.extra_prototype,call.extra_prototype_length);}
   }
  }

   wire.u32(static_cast<uint32_t>(one.bytes.size()));wire.raw(one.bytes);
  }
  auto out=env->NewByteArray(static_cast<jsize>(wire.bytes.size()));if(!out||env->ExceptionCheck())return nullptr;if(!wire.bytes.empty())env->SetByteArrayRegion(out,0,static_cast<jsize>(wire.bytes.size()),reinterpret_cast<const jbyte*>(wire.bytes.data()));return env->ExceptionCheck()?nullptr:out;
 }catch(const native_apk_candidate::FastFailure& e){fail(env,e.status,e.rule==UINT32_MAX?-1:static_cast<int>(e.rule),&e.detail);}catch(const std::length_error&){fail(env,DMG_BUDGET_EXCEEDED,-1);}catch(const std::bad_alloc&){fail(env,DMG_OUT_OF_MEMORY,-1);}catch(const std::invalid_argument& e){exception(env,"java/lang/IllegalArgumentException",e.what());}catch(const std::exception& e){exception(env,"java/io/IOException",e.what());}catch(...){fail(env,DMG_INTERNAL_ERROR,-1);}return nullptr;
}
