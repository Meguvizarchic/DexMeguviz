#include "runtime.hpp"
#include "raw_fill.hpp"
#include "source/sha256.hpp"
#include "format/dex041/container.hpp"
#include <charconv>
#include <limits>
#ifdef DMG_TEST_APK_FD_READ_BARRIER
#include <atomic>
namespace dexmeguviz::runtime { std::atomic<void(*)(uint64_t)> test_apk_fd_read_barrier{nullptr}; }
#endif
#if !defined(_WIN32) && defined(DMG_TEST_APK_FD_DUP_BARRIER)
#include <atomic>
namespace dexmeguviz::runtime { std::atomic<void(*)(int)> test_apk_fd_dup_barrier{nullptr}; }
#endif
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cerrno>
#endif
using namespace dexmeguviz;
using namespace dexmeguviz::runtime;
namespace {
std::string_view bounded(const char* p,std::string_view fallback={}){
    if(!p)return fallback;size_t n=0;while(n<=4096&&p[n])++n;
    if(n>4096)throw BudgetExceeded();return {p,n};
}
void number(std::pmr::string& out,uint64_t value){char buffer[32];auto r=std::to_chars(buffer,buffer+32,value);out.append(buffer,r.ptr);}
void frame(std::pmr::string& out,std::string_view text){number(out,text.size());out.push_back(':');out.append(text);}
void prepare(Source& s,const dmg_open_options& o,const std::pmr::string* same_owned_input_digest=nullptr){
    auto bytes=s.view();auto* resource=&s.engine->source_resource;
    // This digest is only supplied for the same privately owned bytes moved into s.
    if(same_owned_input_digest)s.digest=*same_owned_input_digest;
    else s.digest=sha256<std::pmr::string>(bytes,resource);
    if(o.expected_sha256&&bounded(o.expected_sha256)!=s.digest)throw Stop{DMG_SOURCE_MISMATCH};
    s.expected_verified=s.expected_verified||o.expected_sha256!=nullptr;
    s.slot_key=bounded(o.slot_key,"0");if(s.role.empty())s.role="raw-dex";
    s.facts=read_metadata(bytes,&s.engine->fact_resource);s.content="sha256:raw-dex:v1:";number(s.content,bytes.size());s.content+=':';s.content+=s.digest;
    const auto ns=bounded(o.source_namespace,"default"),slot=bounded(o.slot_key,"0");
    s.logical="logical-dex:v1:";frame(s.logical,s.content);s.logical+="header-offset:0";
    std::pmr::string scratch("dmg:occurrence:v2:",&s.engine->scratch_resource);frame(scratch,ns);
    frame(scratch,s.entry_index==UINT32_MAX?"raw-input":"archive-entry");frame(scratch,slot);frame(scratch,s.role);frame(scratch,s.entry_name);frame(scratch,s.content);
    s.occurrence="occurrence:v2:";s.occurrence+=sha256<std::pmr::string>({reinterpret_cast<const uint8_t*>(scratch.data()),scratch.size()},resource);
    scratch="dmg:snapshot:metadata-v0:ordered:1:";frame(scratch,ns);frame(scratch,s.occurrence);
    s.snapshot="snapshot:v1:";s.snapshot+=sha256<std::pmr::string>({reinterpret_cast<const uint8_t*>(scratch.data()),scratch.size()},resource);
}
void finish_dataset(Dataset& d){
    std::pmr::string identity("dmg:snapshot:source-set-v1:",&d.engine->scratch_resource);
    frame(identity,d.namespace_key);frame(identity,d.scope_complete?"complete":"incomplete");
    std::pmr::string count(&d.engine->scratch_resource);number(count,d.inputs.size());frame(identity,count);
    for(const auto& input:d.inputs){
        frame(identity,input.slot);frame(identity,input.role);count.clear();number(count,input.format);frame(identity,count);
        frame(identity,input.allow_no_dex?"1":"0");frame(identity,input.content);
        if(input.bytes>UINT64_MAX-d.input_bytes)throw BudgetExceeded();d.input_bytes+=input.bytes;
    }
    count.clear();number(count,d.sources.size());frame(identity,count);
    for(const auto& source:d.sources){
        frame(identity,source->occurrence);const auto& f=source->facts;
        const auto extent=source->facts.dex_version==41?source->facts.logical_file_size:source->view().size();if(extent>UINT64_MAX-d.dex_bytes)throw BudgetExceeded();d.dex_bytes+=extent;
        d.strings+=f.string_count;d.types+=f.type_count;d.classes+=f.class_count;d.method_refs+=f.method_ref_count;d.methods+=f.methods.size();
        if(d.methods>UINT32_MAX)throw BudgetExceeded();
    }
    d.snapshot_id="snapshot:v2:";d.snapshot_id+=sha256<std::pmr::string>({reinterpret_cast<const uint8_t*>(identity.data()),identity.size()},&d.engine->source_resource);
}
uint32_t dex_ordinal(std::string_view name,bool& invalid)noexcept{
    if(name=="classes.dex")return 1;
    if(!name.starts_with("classes")||!name.ends_with(".dex"))return 0;
    const auto number_text=name.substr(7,name.size()-11);if(number_text.empty())return 0;
    for(char c:number_text)if(c<'0'||c>'9')return 0;
    if(number_text[0]=='0'){invalid=true;return 0;}uint32_t ordinal=0;
    for(char c:number_text){if(ordinal>(UINT32_MAX-static_cast<uint32_t>(c-'0'))/10){invalid=true;return 0;}ordinal=ordinal*10+static_cast<uint32_t>(c-'0');}
    if(ordinal<2){invalid=true;return 0;}return ordinal;
}
struct Selection {bool invalid=false;};
bool select_dex(void* context,std::string_view name,uint32_t)noexcept{return dex_ordinal(name,static_cast<Selection*>(context)->invalid)!=0;}
void validate(const std::shared_ptr<EngineState>& e,const dmg_open_options* o,uint64_t length){
    if(!o||o->struct_size!=sizeof(*o)||o->abi_version!=DMG_ABI_VERSION)throw Stop{DMG_INVALID_ARGUMENT};admit(e);
    const uint64_t limit=o->max_source_bytes?o->max_source_bytes:e->max_source_bytes;
    if(length>limit||length>e->max_source_bytes||length>SIZE_MAX)throw BudgetExceeded();
}
void read_fd_bytes(std::pmr::vector<uint8_t>& bytes,int32_t fd,uint64_t offset,uint64_t length,bool validate_before_allocation=false){
    if(offset>INT64_MAX||length>uint64_t(INT64_MAX)-offset)throw Stop{DMG_INVALID_ARGUMENT};
    if(!validate_before_allocation)bytes.resize(static_cast<size_t>(length));
#ifdef _WIN32
    struct InvalidParameterGuard {
        _invalid_parameter_handler old;
        InvalidParameterGuard():old(_set_thread_local_invalid_parameter_handler([](const wchar_t*,const wchar_t*,const wchar_t*,unsigned,uintptr_t){})){}
        ~InvalidParameterGuard(){_set_thread_local_invalid_parameter_handler(old);}
    } invalid_guard;
    const auto raw=_get_osfhandle(fd);if(raw==-1)throw Stop{DMG_INVALID_ARGUMENT};
    const HANDLE original=reinterpret_cast<HANDLE>(raw);if(GetFileType(original)!=FILE_TYPE_DISK)throw Stop{DMG_INVALID_ARGUMENT};
    struct OwnedHandle {HANDLE value=INVALID_HANDLE_VALUE;~OwnedHandle(){if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);}};
    OwnedHandle copy{ReOpenFile(original,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,FILE_FLAG_OVERLAPPED)};
    if(copy.value==INVALID_HANDLE_VALUE)throw Stop{DMG_INVALID_ARGUMENT};
    if(validate_before_allocation){BY_HANDLE_FILE_INFORMATION info{};if(GetFileType(copy.value)!=FILE_TYPE_DISK||!GetFileInformationByHandle(copy.value,&info)||(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY))throw Stop{DMG_INVALID_ARGUMENT};}
    LARGE_INTEGER size{};if(!GetFileSizeEx(copy.value,&size)||size.QuadPart<0||offset+length>static_cast<uint64_t>(size.QuadPart))throw Stop{DMG_INVALID_ARGUMENT};
    if(validate_before_allocation)bytes.resize(static_cast<size_t>(length));
    for(uint64_t done=0;done<length;){
        DWORD count=static_cast<DWORD>(std::min<uint64_t>(65536,length-done)),read=0;OVERLAPPED op{};const auto at=offset+done;op.Offset=static_cast<DWORD>(at);op.OffsetHigh=static_cast<DWORD>(at>>32);
        if(!ReadFile(copy.value,bytes.data()+done,count,&read,&op)){if(GetLastError()!=ERROR_IO_PENDING||!GetOverlappedResult(copy.value,&op,&read,TRUE))throw Stop{DMG_SOURCE_MISMATCH};}
        if(read!=count)throw Stop{DMG_SOURCE_MISMATCH};done+=read;
#ifdef DMG_TEST_APK_FD_READ_BARRIER
        if(const auto hook=test_apk_fd_read_barrier.load(std::memory_order_acquire))hook(done);
#endif
    }
#else
    if(offset>static_cast<uint64_t>(std::numeric_limits<off_t>::max())||length>static_cast<uint64_t>(std::numeric_limits<off_t>::max())-offset)throw Stop{DMG_UNSUPPORTED};
    int duplicated=-1;
    if(validate_before_allocation){
#if defined(F_DUPFD_CLOEXEC) && !defined(DMG_TEST_APK_NO_CLOEXEC)
        do { duplicated=::fcntl(fd,F_DUPFD_CLOEXEC,0); } while(duplicated<0&&errno==EINTR);
        if(duplicated<0){
            if(errno==EINVAL||errno==ENOSYS||errno==EPERM)throw Stop{DMG_UNSUPPORTED};
            if(errno==EMFILE||errno==ENFILE)throw BudgetExceeded();
            if(errno==ENOMEM)throw std::bad_alloc();
            if(errno==EBADF)throw Stop{DMG_INVALID_ARGUMENT};
            throw Stop{DMG_INTERNAL_ERROR};
        }
#else
        throw Stop{DMG_UNSUPPORTED};
#endif
    }else duplicated=::dup(fd); // Preserve legacy raw-fd behavior.
    struct OwnedFd{int value;~OwnedFd(){if(value>=0)::close(value);}}copy{duplicated};if(copy.value<0)throw Stop{DMG_INVALID_ARGUMENT};
#ifdef DMG_TEST_APK_FD_DUP_BARRIER
    if(validate_before_allocation)if(const auto hook=test_apk_fd_dup_barrier.load(std::memory_order_acquire))hook(copy.value);
#endif
    struct stat info{};if(fstat(copy.value,&info)||!S_ISREG(info.st_mode)||info.st_size<0||offset+length>static_cast<uint64_t>(info.st_size))throw Stop{DMG_INVALID_ARGUMENT};
    if(validate_before_allocation)bytes.resize(static_cast<size_t>(length));
    for(uint64_t done=0;done<length;){const size_t count=static_cast<size_t>(std::min<uint64_t>(65536,length-done));auto n=pread(copy.value,bytes.data()+done,count,static_cast<off_t>(offset+done));if(n<0&&errno==EINTR)continue;if(n<=0)throw Stop{DMG_SOURCE_MISMATCH};done+=static_cast<uint64_t>(n);
#ifdef DMG_TEST_APK_FD_READ_BARRIER
        if(const auto hook=test_apk_fd_read_barrier.load(std::memory_order_acquire))hook(done);
#endif
    }
#endif
}
}
namespace dexmeguviz::runtime {
dmg_status open_android_raw_filled(dmg_engine* engine,uint64_t size,const char* slot_key,RawFill fill,void* context,dmg_snapshot** out,dmg_error* error) noexcept {
    if(out)*out=nullptr;
    return guard([&]()->dmg_status{
        if(!engine||!slot_key||!fill||!out)return DMG_INVALID_ARGUMENT;
        const auto e=engine->owner;admit(e);
        if(size>e->max_source_bytes||size>SIZE_MAX)throw BudgetExceeded();
        const auto slot=bounded(slot_key);if(slot.empty())return DMG_INVALID_ARGUMENT;
        auto dataset=state<Dataset>(e);dataset->namespace_key="android-jni";dataset->scope_complete=false;
        dataset->inputs.reserve(1);dataset->inputs.emplace_back(&e->source_resource);auto& input=dataset->inputs.back();
        auto source=state<Source>(e);source->bytes.resize(static_cast<size_t>(size));
        if(size&&!fill(context,source->bytes.data(),static_cast<size_t>(size)))return DMG_INTERNAL_ERROR;
        input.slot=slot;input.role="raw-dex";input.bytes=size;input.format=DMG_INPUT_RAW_DEX;
        input.digest=sha256<std::pmr::string>(source->view(),&e->source_resource);
        input.content="sha256:raw-dex:v1:";number(input.content,size);input.content+=':';input.content+=input.digest;
        source->input_index=0;source->role=input.role;
        const dmg_open_options open{sizeof(dmg_open_options),DMG_ABI_VERSION,e->max_source_bytes,dataset->namespace_key.c_str(),input.slot.c_str(),nullptr};
        prepare(*source,open,&input.digest);dataset->sources.push_back(std::move(source));input.source_count=1;input.container_checked=true;
        finish_dataset(*dataset);*out=handle<dmg_snapshot>(e,std::move(dataset));return DMG_OK;
    },error);
}
std::shared_ptr<Dataset> single_source(const std::shared_ptr<Source>& s,const char* ns){
    auto dataset=state<Dataset>(s->engine);dataset->namespace_key=bounded(ns,"default");dataset->sources.push_back(s);
    dataset->inputs.emplace_back(&s->engine->source_resource);auto& input=dataset->inputs.back();
    input.slot=s->slot_key;input.role=s->role;input.digest=s->digest;input.content=s->content;input.bytes=s->view().size();
    input.source_count=1;input.expected_verified=s->expected_verified;input.container_checked=true;
    finish_dataset(*dataset);return dataset;
}
}
extern "C" {
dmg_status dmg_snapshot_open_copy_in(dmg_engine* e,const uint8_t* data,uint64_t size,const dmg_open_options* o,dmg_snapshot** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{if(!e||!out||(!data&&size))return DMG_INVALID_ARGUMENT;validate(e->owner,o,size);auto s=state<Source>(e->owner);if(size)s->bytes.assign(data,data+static_cast<size_t>(size));prepare(*s,*o);*out=handle<dmg_snapshot>(e->owner,single_source(s,o->source_namespace));return DMG_OK;},error);
}
dmg_status dmg_snapshot_open_copy(const uint8_t* data,uint64_t size,const dmg_open_options* o,dmg_snapshot** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{if(!out||!o||(!data&&size))return DMG_INVALID_ARGUMENT;if(size>DMG_MAX_SOURCE_BYTES)throw BudgetExceeded();auto e=make_engine();validate(e,o,size);auto s=state<Source>(e);if(size)s->bytes.assign(data,data+static_cast<size_t>(size));prepare(*s,*o);*out=handle<dmg_snapshot>(e,single_source(s,o->source_namespace));return DMG_OK;},error);
}
dmg_status dmg_snapshot_open_borrowed(dmg_engine* e,const uint8_t* data,uint64_t size,const dmg_buffer_lease* lease,const dmg_open_options* o,dmg_snapshot** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{
        if(!e||!out||(!data&&size)||!lease||lease->struct_size!=sizeof(*lease)||lease->abi_version!=DMG_ABI_VERSION||!lease->retain||!lease->release||lease->immutable!=1||lease->reserved)return DMG_INVALID_ARGUMENT;
        validate(e->owner,o,size);auto s=state<Source>(e->owner);e->owner->account.reserve_borrowed(size);
        try{lease->retain(lease->context);}catch(...){e->owner->account.release_borrowed(size);throw;}
        s->lease=*lease;s->borrowed=data;s->borrowed_size=size;prepare(*s,*o);*out=handle<dmg_snapshot>(e->owner,single_source(s,o->source_namespace));return DMG_OK;
    },error);
}
dmg_status dmg_snapshot_open_fd(dmg_engine* e,int32_t fd,uint64_t offset,uint64_t length,const dmg_open_options* o,dmg_snapshot** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{if(!e||!out||fd<0)return DMG_INVALID_ARGUMENT;validate(e->owner,o,length);auto s=state<Source>(e->owner);read_fd_bytes(s->bytes,fd,offset,length);prepare(*s,*o);*out=handle<dmg_snapshot>(e->owner,single_source(s,o->source_namespace));return DMG_OK;},error);
}
dmg_status dmg_snapshot_open_sources(dmg_engine* engine,const dmg_source_spec* specs,uint32_t count,const dmg_source_set_options* options,dmg_snapshot** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{
        if(!engine||!out||!specs||!count||count>64||!options||options->struct_size!=sizeof(*options)||options->abi_version!=DMG_ABI_VERSION||options->scope_complete>1||!options->max_sources||options->max_sources>1024)return DMG_INVALID_ARGUMENT;
        admit(engine->owner);const auto e=engine->owner;auto dataset=state<Dataset>(e);
        dataset->namespace_key=bounded(options->source_namespace,"default");dataset->scope_complete=options->scope_complete!=0;
        const uint64_t max_dex_bytes=options->max_total_dex_bytes?options->max_total_dex_bytes:e->max_source_bytes;
        uint64_t dex_bytes=0;dataset->inputs.reserve(count);
        for(uint32_t input_index=0;input_index<count;++input_index){
            const auto& spec=specs[input_index];
            if(spec.struct_size!=sizeof(spec)||spec.abi_version!=DMG_ABI_VERSION||spec.format>DMG_INPUT_APK||spec.allow_no_dex>1||(!spec.data&&spec.size)||!spec.slot_key)return DMG_INVALID_ARGUMENT;
            if(spec.size>e->max_source_bytes||spec.size>SIZE_MAX)throw BudgetExceeded();
            const auto slot=bounded(spec.slot_key);if(slot.empty())return DMG_INVALID_ARGUMENT;
            for(const auto& existing:dataset->inputs)if(existing.slot==slot)return DMG_INVALID_ARGUMENT;
            std::pmr::vector<uint8_t> owned(&e->source_resource);if(spec.size)owned.assign(spec.data,spec.data+static_cast<size_t>(spec.size));
            dataset->inputs.emplace_back(&e->source_resource);auto& input=dataset->inputs.back();
            input.slot=slot;input.role=bounded(spec.role,"source");input.allow_no_dex=spec.allow_no_dex!=0;input.bytes=owned.size();
            input.digest=sha256<std::pmr::string>(owned,&e->source_resource);
            if(spec.expected_sha256&&bounded(spec.expected_sha256)!=input.digest)throw Stop{DMG_SOURCE_MISMATCH};input.expected_verified=spec.expected_sha256!=nullptr;
            input.format=spec.format==DMG_INPUT_AUTO?(owned.size()>=2&&owned[0]=='P'&&owned[1]=='K'?DMG_INPUT_APK:DMG_INPUT_RAW_DEX):spec.format;
            input.content=input.format==DMG_INPUT_APK?"sha256:apk:v1:":"sha256:raw-dex:v1:";number(input.content,input.bytes);input.content+=':';input.content+=input.digest;
            if(input.format==DMG_INPUT_RAW_DEX){
                if(dataset->sources.size()>=options->max_sources||owned.size()>max_dex_bytes-dex_bytes)throw BudgetExceeded();
                auto source=state<Source>(e);source->bytes=std::move(owned);source->input_index=input_index;source->role=input.role;source->expected_verified=input.expected_verified;
                const dmg_open_options open{sizeof(dmg_open_options),DMG_ABI_VERSION,e->max_source_bytes,dataset->namespace_key.c_str(),input.slot.c_str(),nullptr};prepare(*source,open,&input.digest);
                dex_bytes+=source->view().size();dataset->sources.push_back(std::move(source));input.source_count=1;input.container_checked=true;
            }else{
                archive::Limits limits;limits.max_archive_bytes=e->max_source_bytes;limits.max_entry_output_bytes=e->max_source_bytes;limits.max_total_output_bytes=max_dex_bytes-dex_bytes;
                Selection selection;auto entries=archive::read(owned,limits,&e->source_resource,{}, {select_dex,&selection});
                // Entries own verified bytes; the compressed input is no longer needed by the dataset.
                {std::pmr::vector<uint8_t> released(&e->source_resource);owned.swap(released);}
                if(selection.invalid)throw ReadError(ReadCode::corrupt,0,"noncanonical classesN.dex entry");
                if(entries.empty()&&!input.allow_no_dex)throw ReadError(ReadCode::corrupt,0,"APK code source contains no canonical DEX entries");
                if(entries.size()>options->max_sources-dataset->sources.size())throw BudgetExceeded();
                std::sort(entries.begin(),entries.end(),[](const auto& a,const auto& b){bool ignored=false;return dex_ordinal(a.name,ignored)<dex_ordinal(b.name,ignored);});
                for(auto& entry:entries){
                    auto source=state<Source>(e);source->bytes=std::move(entry.bytes);source->input_index=input_index;source->role=input.role;
                    source->entry_index=entry.index;source->entry_name=entry.name;source->archive_digest=input.digest;source->crc_verified=entry.crc_verified;source->header_verified=entry.header_consistency_verified;source->expected_verified=input.expected_verified;
                    const dmg_open_options open{sizeof(dmg_open_options),DMG_ABI_VERSION,e->max_source_bytes,dataset->namespace_key.c_str(),input.slot.c_str(),nullptr};
                    try{prepare(*source,open);}catch(const ReadError& failure){throw ReadError(failure.code,failure.offset,"DEX entry "+std::string(source->entry_name)+": "+failure.what());}
                    dex_bytes+=source->view().size();dataset->sources.push_back(std::move(source));++input.source_count;
                }
                input.container_checked=true;
            }
        }
        finish_dataset(*dataset);*out=handle<dmg_snapshot>(e,std::move(dataset));return DMG_OK;
    },error);
}
dmg_status dmg_snapshot_open_apk_fds_v1(dmg_engine* engine,const dmg_apk_fd_spec_v1* specs,uint32_t count,const dmg_apk_fd_options_v1* options,dmg_snapshot** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{
        if(!engine||!out||!specs||!count||count>8||!options||options->struct_size!=sizeof(*options)||
           options->abi_version!=DMG_ABI_VERSION||options->scope_complete>1||!options->max_sources||options->max_sources>64||
           !options->max_archive_bytes||!options->max_total_archive_bytes||!options->max_dex_bytes||!options->max_total_dex_bytes||
           !options->max_entries||options->max_entries>100000||options->reserved||
           !options->max_central_directory_bytes||options->max_central_directory_bytes>(16ull<<20)||
           !options->max_total_name_bytes||options->max_total_name_bytes>(8ull<<20))return DMG_INVALID_ARGUMENT;
        admit(engine->owner);const auto e=engine->owner;
        // Validate fd numbers, scalar bounds and slot identities before
        // reading. Descriptor validity is checked when each fd is opened.
        uint64_t total_archives=0;
        for(uint32_t i=0;i<count;++i){
            const auto& spec=specs[i];
            if(spec.struct_size!=sizeof(spec)||spec.abi_version!=DMG_ABI_VERSION||spec.fd<0||spec.allow_no_dex>1||!spec.slot_key||
               spec.offset>INT64_MAX||spec.length>uint64_t(INT64_MAX)-spec.offset)return DMG_INVALID_ARGUMENT;
            const auto slot=bounded(spec.slot_key);if(slot.empty())return DMG_INVALID_ARGUMENT;
            for(uint32_t j=0;j<i;++j)if(slot==bounded(specs[j].slot_key))return DMG_INVALID_ARGUMENT;
            if(spec.length>options->max_archive_bytes||spec.length>e->max_source_bytes||spec.length>SIZE_MAX||
               spec.length>options->max_total_archive_bytes-total_archives)throw BudgetExceeded();
            total_archives+=spec.length;
            (void)bounded(spec.role,"source");if(spec.expected_sha256)(void)bounded(spec.expected_sha256);
        }
        auto dataset=state<Dataset>(e);dataset->namespace_key=bounded(options->source_namespace,"default");
        dataset->scope_complete=options->scope_complete!=0;dataset->inputs.reserve(count);uint64_t dex_bytes=0;
        for(uint32_t input_index=0;input_index<count;++input_index){
            const auto& spec=specs[input_index];std::pmr::vector<uint8_t> owned(&e->source_resource);
            read_fd_bytes(owned,spec.fd,spec.offset,spec.length,true);
            dataset->inputs.emplace_back(&e->source_resource);auto& input=dataset->inputs.back();
            input.slot=bounded(spec.slot_key);input.role=bounded(spec.role,"source");input.allow_no_dex=spec.allow_no_dex!=0;
            input.bytes=owned.size();input.digest=sha256<std::pmr::string>(owned,&e->source_resource);
            if(spec.expected_sha256&&bounded(spec.expected_sha256)!=input.digest)throw Stop{DMG_SOURCE_MISMATCH};
            input.expected_verified=spec.expected_sha256!=nullptr;input.format=DMG_INPUT_APK;
            input.content="sha256:apk:v1:";number(input.content,input.bytes);input.content+=':';input.content+=input.digest;
            archive::Limits limits;limits.max_archive_bytes=options->max_archive_bytes;
            limits.max_entry_output_bytes=std::min(options->max_dex_bytes,e->max_source_bytes);
            limits.max_total_output_bytes=options->max_total_dex_bytes-dex_bytes;limits.max_entries=options->max_entries;
            limits.max_central_directory_bytes=options->max_central_directory_bytes;limits.max_total_name_bytes=options->max_total_name_bytes;
            Selection selection;auto entries=archive::read(owned,limits,&e->source_resource,{}, {select_dex,&selection});
            {std::pmr::vector<uint8_t> released(&e->source_resource);owned.swap(released);}
            if(selection.invalid)throw ReadError(ReadCode::corrupt,0,"noncanonical classesN.dex entry");
            if(entries.empty()&&!input.allow_no_dex)throw ReadError(ReadCode::corrupt,0,"APK code source contains no canonical DEX entries");
            if(entries.size()>options->max_sources-dataset->sources.size())throw BudgetExceeded();
            std::sort(entries.begin(),entries.end(),[](const auto& a,const auto& b){bool ignored=false;return dex_ordinal(a.name,ignored)<dex_ordinal(b.name,ignored);});
            for(auto& entry:entries){
                auto source=state<Source>(e);source->bytes=std::move(entry.bytes);source->input_index=input_index;source->role=input.role;
                source->entry_index=entry.index;source->entry_name=entry.name;source->archive_digest=input.digest;
                source->crc_verified=entry.crc_verified;source->header_verified=entry.header_consistency_verified;source->expected_verified=input.expected_verified;
                const dmg_open_options open{sizeof(dmg_open_options),DMG_ABI_VERSION,e->max_source_bytes,dataset->namespace_key.c_str(),input.slot.c_str(),nullptr};
                try{prepare(*source,open);}catch(const ReadError& failure){throw ReadError(failure.code,failure.offset,"DEX entry "+std::string(source->entry_name)+": "+failure.what());}
                dex_bytes+=source->view().size();dataset->sources.push_back(std::move(source));++input.source_count;
            }
            input.container_checked=true;
        }
        finish_dataset(*dataset);*out=handle<dmg_snapshot>(e,std::move(dataset));return DMG_OK;
    },error);
}
}

extern "C" {
const char* dmg_dex041_capability_v1(){return "experimental-dex041-container-v1";}
dmg_status dmg_snapshot_open_dex041_copy_v1(dmg_engine* engine,const uint8_t* data,uint64_t size,const dmg_dex041_open_options_v1* options,dmg_snapshot** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{
        if(!engine||!out||!options||(!data&&size)||options->struct_size!=sizeof(*options)||options->abi_version!=DMG_ABI_VERSION||options->experimental_041!=1||options->scope_complete>1||!options->max_logical_dex||options->max_logical_dex>1024)return DMG_INVALID_ARGUMENT;
        const dmg_open_options standard{sizeof(dmg_open_options),DMG_ABI_VERSION,options->max_container_bytes,options->source_namespace,options->slot_key,options->expected_sha256};validate(engine->owner,&standard,size);
        auto storage=state<Source>(engine->owner);if(size)storage->bytes.assign(data,data+static_cast<size_t>(size));auto* memory=&engine->owner->source_resource;
        storage->digest=sha256<std::pmr::string>(storage->view(),memory);if(options->expected_sha256&&bounded(options->expected_sha256)!=storage->digest)return DMG_SOURCE_MISMATCH;
        storage->content="sha256:dex041-container:v1:";number(storage->content,size);storage->content+=':';storage->content+=storage->digest;
        const auto headers=dex041::enumerate(storage->view(),&engine->owner->scratch_resource,options->max_logical_dex);
        auto dataset=state<Dataset>(engine->owner);dataset->namespace_key=bounded(options->source_namespace,"default");dataset->scope_complete=options->scope_complete!=0;
        dataset->inputs.emplace_back(memory);auto& input=dataset->inputs.back();input.format=DMG_INPUT_DEX041_EXPERIMENTAL;input.slot=bounded(options->slot_key,"0");input.role="dex041-container";input.digest=storage->digest;input.content=storage->content;input.bytes=size;input.source_count=static_cast<uint32_t>(headers.size());input.container_checked=true;input.expected_verified=options->expected_sha256!=nullptr;
        for(const auto& header:headers){auto source=state<Source>(engine->owner);source->physical_owner=storage;source->facts=read_metadata_041(source->view(),header.offset,&engine->owner->fact_resource);source->digest=storage->digest;source->content=storage->content;source->slot_key=input.slot;source->role=input.role;source->input_index=0;source->expected_verified=input.expected_verified; // ZIP header-consistency evidence remains false for this raw container.
            source->logical="logical-dex:041-v1:";frame(source->logical,source->content);source->logical+="header-offset:";number(source->logical,header.offset);
            std::pmr::string identity("dmg:occurrence:041-v1:",&engine->owner->scratch_resource);frame(identity,dataset->namespace_key);frame(identity,input.slot);frame(identity,input.role);frame(identity,source->logical);source->occurrence="occurrence:041-v1:";source->occurrence+=sha256<std::pmr::string>({reinterpret_cast<const uint8_t*>(identity.data()),identity.size()},memory);
            identity="dmg:logical-snapshot:041-v1:";frame(identity,dataset->namespace_key);frame(identity,source->occurrence);source->snapshot="snapshot:041-logical-v1:";source->snapshot+=sha256<std::pmr::string>({reinterpret_cast<const uint8_t*>(identity.data()),identity.size()},memory);dataset->sources.push_back(std::move(source));
        }
        finish_dataset(*dataset);*out=handle<dmg_snapshot>(engine->owner,std::move(dataset));return DMG_OK;
    },error);
}
dmg_status dmg_snapshot_get_dex041_source_info_v1(const dmg_snapshot* snapshot,uint32_t index,dmg_dex041_source_info_v1* out,uint32_t size){
    if(!snapshot||!out||size!=sizeof(*out)||index>=snapshot->dataset->sources.size())return DMG_INVALID_ARGUMENT;const auto& source=*snapshot->dataset->sources[index];if(source.facts.dex_version!=41)return DMG_UNSUPPORTED;
    *out={index,source.facts.header_offset,source.facts.logical_file_size,source.facts.container_size,source.content.c_str(),source.logical.c_str(),source.occurrence.c_str()};return DMG_OK;
}
dmg_status dmg_result_get_dex041_source_info_v1(const dmg_result* result,uint32_t index,dmg_dex041_source_info_v1* out,uint32_t size){
    if(!result||!out||size!=sizeof(*out)||index>=result->dataset->sources.size())return DMG_INVALID_ARGUMENT;const auto& source=*result->dataset->sources[index];if(source.facts.dex_version!=41)return DMG_UNSUPPORTED;
    *out={index,source.facts.header_offset,source.facts.logical_file_size,source.facts.container_size,source.content.c_str(),source.logical.c_str(),source.occurrence.c_str()};return DMG_OK;
}
}
