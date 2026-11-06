#include "native_apk_scan.hpp"
#include "miniz.h"
#include "source/sha256.hpp"
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <fstream>
#include <limits>
#include <mutex>
#include <set>
#include <stdexcept>
#include <thread>
#include <cstdlib>
#include <cstddef>

namespace native_apk_candidate {
namespace {
[[noreturn]] void fail(const char* s){throw std::runtime_error(s);}
void add(uint64_t& v,uint64_t n,uint64_t cap){if(n>cap || v>cap-n)fail("source-set byte limit");v+=n;}
struct alignas(std::max_align_t) AllocHeader { size_t bytes; };
struct Alloc { uint64_t used=0,limit=0; };
void* alloc(void* opaque,size_t n,size_t size){
 auto& a=*static_cast<Alloc*>(opaque);if(size && n>SIZE_MAX/size)return nullptr;size_t bytes=n*size;
 if(bytes>SIZE_MAX-sizeof(AllocHeader) || bytes>a.limit || a.used>a.limit-bytes)return nullptr;
 auto* h=static_cast<AllocHeader*>(std::malloc(sizeof(AllocHeader)+bytes));if(!h)return nullptr;
 h->bytes=bytes;a.used+=bytes;void* p=h+1;std::memset(p,0,bytes);return p;
}
void release(void* opaque,void* ptr){if(!ptr)return;auto* h=static_cast<AllocHeader*>(ptr)-1;auto& a=*static_cast<Alloc*>(opaque);a.used-=h->bytes;std::free(h);}
void* reallocate(void* opaque,void* ptr,size_t n,size_t size){
 if(!ptr)return alloc(opaque,n,size);if(size&&n>SIZE_MAX/size)return nullptr;auto bytes=n*size;
 auto& a=*static_cast<Alloc*>(opaque);auto* h=static_cast<AllocHeader*>(ptr)-1;const auto prior=h->bytes;
 if(bytes>SIZE_MAX-sizeof(AllocHeader)||bytes>a.limit||a.used-prior>a.limit-bytes)return nullptr;
 auto* next=static_cast<AllocHeader*>(std::realloc(h,sizeof(AllocHeader)+bytes));if(!next)return nullptr;
 next->bytes=bytes;a.used=a.used-prior+bytes;return next+1;
}
struct Reader {
 std::ifstream file;Alloc memory;mz_zip_archive zip{};bool open=false;
 static size_t read(void* ctx,mz_uint64 offset,void* data,size_t count){
  auto& f=static_cast<Reader*>(ctx)->file;if(offset>uint64_t(std::numeric_limits<std::streamoff>::max())||count>size_t(std::numeric_limits<std::streamsize>::max()))return 0;
  f.clear();f.seekg(static_cast<std::streamoff>(offset));if(!f)return 0;f.read(static_cast<char*>(data),static_cast<std::streamsize>(count));return static_cast<size_t>(f.gcount());
 }
 Reader(const std::filesystem::path& p,uint64_t size,uint64_t cap):file(p,std::ios::binary),memory{0,cap}{
  if(!file)fail("open archive");zip.m_pRead=read;zip.m_pIO_opaque=this;zip.m_pAlloc=alloc;zip.m_pRealloc=reallocate;zip.m_pFree=release;zip.m_pAlloc_opaque=&memory;
  if(!mz_zip_reader_init(&zip,size,0))fail("unsupported, corrupt or over-budget ZIP directory");open=true;
 }
 ~Reader(){if(open)mz_zip_reader_end(&zip);}
 Reader(const Reader&)=delete;Reader& operator=(const Reader&)=delete;
};
struct Identity {std::filesystem::path canonical;uint64_t size;std::filesystem::file_time_type modified;};
Identity identity(const std::filesystem::path& p){
 if(!std::filesystem::is_regular_file(p))fail("archive is not a regular file");return {std::filesystem::canonical(p),std::filesystem::file_size(p),std::filesystem::last_write_time(p)};
}
bool same(const Identity&a,const Identity&b){return a.canonical==b.canonical&&a.size==b.size&&a.modified==b.modified;}
uint32_t ordinal(const std::string& name){
 if(name=="classes.dex")return 1;if(name.size()<12||name.compare(0,7,"classes")||name.compare(name.size()-4,4,".dex"))return 0;
 auto n=name.substr(7,name.size()-11);if(n.empty())return 0;for(char c:n)if(c<'0'||c>'9')return 0;
 if(n[0]=='0')fail("noncanonical DEX ordinal");uint64_t v=0;for(char c:n){v=v*10+unsigned(c-'0');if(v>INT32_MAX)fail("DEX ordinal overflow");}
 if(v<2)fail("noncanonical DEX ordinal");return uint32_t(v);
}
struct Task {Source source;};
struct Gate {
 std::mutex m;std::condition_variable cv;uint64_t active=0,cap;bool stopped=false;
 explicit Gate(uint64_t c):cap(c){}
 bool acquire(uint64_t size){std::unique_lock<std::mutex> lock(m);cv.wait(lock,[&]{return stopped || size<=cap-active;});if(stopped)return false;active+=size;return true;}
 void drop(uint64_t size){std::lock_guard<std::mutex> lock(m);active-=size;cv.notify_all();}
 void stop(){std::lock_guard<std::mutex> lock(m);stopped=true;cv.notify_all();}
};
struct Lease {Gate& g;uint64_t n;~Lease(){g.drop(n);}};
}
Response scan(const std::vector<Input>& inputs,const Limits& l,const dmg_fast_plans_v1* plans,const dmg_fast_limits_v1& scan_limits){
 // Validate even if every explicitly permitted input is resource-only.
 if(scan_limits.struct_size!=sizeof(scan_limits)||scan_limits.abi_version!=DMG_ABI_VERSION||
    scan_limits.caller_asserts_valid_sorted_dex!=1||scan_limits.reserved||!scan_limits.max_dex_bytes||
    !scan_limits.max_total_rows||scan_limits.max_total_rows>65536||scan_limits.max_total_calls>100000||
    !scan_limits.max_output_utf16_units||scan_limits.max_output_utf16_units>1048576||
    !scan_limits.max_code_units||scan_limits.max_code_units>1048576||
    !scan_limits.max_instructions||scan_limits.max_instructions>1048576)fail("invalid fast scan limits");
 if(!plans||inputs.empty()||inputs.size()>l.max_inputs||l.workers<1||l.workers>32||!l.max_sources_per_input||!l.max_entries_per_input||!l.max_archive_bytes_per_input||!l.max_archive_bytes||!l.max_dex_bytes_per_input||!l.max_one_dex_bytes||!l.max_inflight_dex_bytes||!l.max_zip_metadata_bytes_per_reader||!l.max_total_rows)fail("invalid input or limits");
 Response out;std::vector<Task> tasks;std::vector<Identity> ids;std::set<std::u16string> slots;
 for(uint32_t i=0;i<inputs.size();++i){
  auto& input=inputs[i];if(input.slot.empty()||input.slot.size()>4096||input.slot.find(u'\0')!=std::u16string::npos||!slots.insert(input.slot).second)fail("invalid or duplicate slot");
  auto id=identity(input.apk);if(!id.size||id.size>l.max_archive_bytes_per_input)fail("archive byte limit");add(out.archive_bytes,id.size,l.max_archive_bytes);ids.push_back(id);
  Reader r(input.apk,id.size,l.max_zip_metadata_bytes_per_reader);auto count=mz_zip_reader_get_num_files(&r.zip);if(count>l.max_entries_per_input)fail("ZIP entry limit");
  std::vector<Task> per;std::set<std::string> names;uint64_t total=0,compressed=0;
  for(uint32_t j=0;j<count;++j){
   auto needed=mz_zip_reader_get_filename(&r.zip,j,nullptr,0);if(!needed||needed>65536)fail("ZIP filename");std::vector<char> n(needed);
   if(mz_zip_reader_get_filename(&r.zip,j,n.data(),needed)!=needed||std::strlen(n.data())!=needed-1)fail("ZIP filename encoding");
   std::string name(n.data());auto ord=ordinal(name);if(!ord)continue;
   mz_zip_archive_file_stat st{};if(!names.insert(name).second||!mz_zip_reader_file_stat(&r.zip,j,&st)||st.m_is_directory||!mz_zip_reader_is_file_supported(&r.zip,j)||
    (st.m_method!=0&&st.m_method!=8)||st.m_uncomp_size==0||st.m_comp_size==0||(st.m_method==0&&st.m_comp_size!=st.m_uncomp_size)||st.m_uncomp_size>l.max_one_dex_bytes||st.m_uncomp_size>l.max_inflight_dex_bytes||st.m_comp_size>id.size||per.size()>=l.max_sources_per_input||tasks.size()+per.size()>=l.max_sources)fail("DEX entry or source limit");
   add(total,st.m_uncomp_size,l.max_dex_bytes_per_input);add(out.dex_bytes,st.m_uncomp_size,l.max_dex_bytes);
   add(compressed,st.m_comp_size,UINT64_MAX);add(out.compressed_bytes,st.m_comp_size,UINT64_MAX);
   per.push_back({{input.slot,i,j,ord,st.m_uncomp_size,st.m_comp_size,st.m_crc32}});
  }
  if(per.empty()&&!input.allow_no_dex)fail("no DEX entries");std::sort(per.begin(),per.end(),[](const Task&a,const Task&b){return a.source.ordinal<b.source.ordinal;});
  out.inputs.push_back({input.slot,static_cast<uint32_t>(per.size()),id.size,total,compressed});
  tasks.insert(tasks.end(),per.begin(),per.end());
 }
 std::vector<Item> staged(tasks.size());std::atomic<size_t> next{0};Gate gate(l.max_inflight_dex_bytes);std::mutex errors_mutex,rows_mutex;std::exception_ptr first;uint64_t rows=0;
 auto worker=[&]{
  try{
   std::unique_ptr<Reader> reader;uint32_t current=UINT32_MAX;
   for(;;){auto index=next.fetch_add(1);if(index>=tasks.size())break;auto& source=tasks[index].source;if(!gate.acquire(source.size))break;Lease lease{gate,source.size};
    if(current!=source.input_index){reader=std::make_unique<Reader>(inputs[source.input_index].apk,ids[source.input_index].size,l.max_zip_metadata_bytes_per_reader);current=source.input_index;}
    if(source.size>SIZE_MAX)fail("DEX is too large");std::vector<uint8_t> bytes(size_t(source.size));std::vector<uint8_t> io(65536);
    if(!mz_zip_reader_extract_to_mem_no_alloc(&reader->zip,source.central_index,bytes.data(),bytes.size(),0,io.data(),io.size()))fail("DEX extraction or CRC failure");
    dmg_fast_results_v1* raw=nullptr;uint32_t failed=UINT32_MAX;dmg_error err{};auto status=dmg_fast_scan_v1(plans,bytes.data(),bytes.size(),&scan_limits,&raw,&failed,&err);
    std::unique_ptr<dmg_fast_results_v1,ResultDeleter> result(raw);if(status!=DMG_OK||!result)throw FastFailure(status==DMG_OK?DMG_INTERNAL_ERROR:status,failed,err);
    uint32_t count=0;if(dmg_fast_results_count_v1(raw,&count)!=DMG_OK)fail("fast result count");uint64_t own_rows=0;
    for(uint32_t rule=0;rule<count;++rule){dmg_fast_rule_info_v1 info{};if(dmg_fast_rule_info_get_v1(raw,rule,&info)!=DMG_OK)fail("fast rule result");add(own_rows,info.candidates_count,l.max_total_rows);}
    {std::lock_guard<std::mutex> lock(rows_mutex);add(rows,own_rows,l.max_total_rows);}
    std::string digest;if(l.digest_matched_sources&&own_rows)digest=dexmeguviz::sha256(std::span<const uint8_t>(bytes));
    staged[index]={source,std::move(digest),std::move(result)};
   }
  }catch(...){std::lock_guard<std::mutex> lock(errors_mutex);if(!first)first=std::current_exception();gate.stop();}
 };
 std::vector<std::thread> workers;try{for(uint32_t i=0;i<std::min<size_t>(l.workers,tasks.size());++i)workers.emplace_back(worker);}catch(...){gate.stop();for(auto& t:workers)t.join();throw;}
 for(auto& t:workers)t.join();if(first)std::rethrow_exception(first);
 for(size_t i=0;i<inputs.size();++i)if(!same(ids[i],identity(inputs[i].apk)))fail("APK identity changed during scan");
 out.ordered=std::move(staged);return out;
}
}
