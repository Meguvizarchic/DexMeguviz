#include "persistent.hpp"
#include "source/sha256.hpp"
#include <algorithm>
#include <atomic>
#include <bit>
#include <chrono>
#include <fstream>
#include <limits>
#include <system_error>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace dexmeguviz::cache {
namespace {
using Bytes=std::pmr::vector<uint8_t>;
constexpr uint32_t format_version=1,parser_version=1,fact_version=1;
bool standard_dex(uint32_t version)noexcept{return version==35||version==37||version==38||version==39||version==40;}
bool valid_snapshot_id(std::string_view id)noexcept{
    constexpr std::string_view prefix="snapshot:v2:";
    if(id.size()!=prefix.size()+64||!id.starts_with(prefix))return false;
    return std::all_of(id.begin()+static_cast<std::ptrdiff_t>(prefix.size()),id.end(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');});
}
struct BadCache {};
void require(bool b){if(!b)throw BadCache{};}
void check(bool(*cancel)(void*)noexcept,void* ctx){if(cancel&&cancel(ctx))throw instructions::DecodeError(instructions::DecodeCode::cancelled,0,0,"persistent facts cancelled");}
void u32(Bytes& b,uint32_t x){for(unsigned i=0;i<4;++i)b.push_back(static_cast<uint8_t>(x>>(8*i)));}
void u64(Bytes& b,uint64_t x){for(unsigned i=0;i<8;++i)b.push_back(static_cast<uint8_t>(x>>(8*i)));}
void frame(Bytes& b,std::string_view s){u64(b,s.size());b.insert(b.end(),s.begin(),s.end());}
void text16(Bytes& b,std::u16string_view s){u64(b,s.size());for(uint16_t c:s){b.push_back(static_cast<uint8_t>(c));b.push_back(static_cast<uint8_t>(c>>8));}}
struct Reader {
    std::span<const uint8_t> b;size_t at=0;
    uint64_t n(unsigned bytes){require(at<=b.size()&&bytes<=b.size()-at);uint64_t n=0;for(unsigned i=0;i<bytes;++i)n|=uint64_t(b[at++])<<(8*i);return n;}
    uint32_t u32(){return static_cast<uint32_t>(n(4));}
    uint64_t u64(){return n(8);}
    bool done()const{return at==b.size();}
};
bool safe(const std::filesystem::path& p){
#ifdef _WIN32
    const auto a=GetFileAttributesW(p.c_str());return a!=INVALID_FILE_ATTRIBUTES&&!(a&FILE_ATTRIBUTE_REPARSE_POINT);
#else
    std::error_code ec;return !std::filesystem::is_symlink(std::filesystem::symlink_status(p,ec))&&!ec;
#endif
}
void safe_ancestors(const std::filesystem::path& path){
    for(auto p=path;!p.empty();p=p.parent_path()){
        if(std::filesystem::exists(p)&&!safe(p))throw std::invalid_argument("persistent directory traverses a link");
        if(p==p.parent_path())break;
    }
}
// Nonblocking cross-process publication lock. Its zero-byte backing file is
// retained; OS close releases the lock even if the process exits unexpectedly.
class WriterLock {
#ifdef _WIN32
    HANDLE file=INVALID_HANDLE_VALUE;
#else
    int file=-1;
#endif
public:
    explicit WriterLock(const std::filesystem::path& directory){
        const auto path=directory/".writer.lock";
        if(std::filesystem::exists(path)&&!safe(path))throw BadCache{};
#ifdef _WIN32
        file=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
        if(file==INVALID_HANDLE_VALUE)throw BadCache{};
        OVERLAPPED overlapped{};if(!LockFileEx(file,LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY,0,1,0,&overlapped)){CloseHandle(file);file=INVALID_HANDLE_VALUE;throw BadCache{};}
#else
        file=::open(path.c_str(),O_RDWR|O_CREAT|O_NOFOLLOW,0600);if(file<0)throw BadCache{};
        if(::flock(file,LOCK_EX|LOCK_NB)){::close(file);file=-1;throw BadCache{};}
#endif
    }
    ~WriterLock(){
#ifdef _WIN32
        if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);
#else
        if(file>=0)::close(file);
#endif
    }
    WriterLock(const WriterLock&)=delete;WriterLock& operator=(const WriterLock&)=delete;
};
using Sections=std::pmr::vector<Bytes>;
Bytes envelope(uint32_t kind,const Sections& s,std::pmr::memory_resource* m,uint64_t cap){
    uint64_t size=64+uint64_t(s.size())*24+64;for(const auto& part:s){require(part.size()<=cap&&size<=cap-part.size());size+=part.size();}
    require(size<=cap&&s.size()<=16);Bytes out(m);out.reserve(static_cast<size_t>(size));
    for(char c:std::string_view("DMGFC001"))out.push_back(c);
    u32(out,format_version);u32(out,parser_version);u32(out,fact_version);u32(out,kind);u32(out,static_cast<uint32_t>(s.size()));u32(out,1);
    u64(out,size);u64(out,64+uint64_t(s.size())*24);u64(out,0x01020304);u64(out,0);
    uint64_t offset=64+uint64_t(s.size())*24;
    for(uint32_t i=0;i<s.size();++i){u32(out,i+1);u32(out,1);u64(out,offset);u64(out,s[i].size());offset+=s[i].size();}
    for(const auto& part:s)out.insert(out.end(),part.begin(),part.end());const auto digest=sha256(std::span(out));out.insert(out.end(),digest.begin(),digest.end());return out;
}
std::pmr::vector<std::span<const uint8_t>> sections(std::span<const uint8_t> bytes,uint32_t kind,uint32_t count,std::pmr::memory_resource* m){
    require(bytes.size()>=128&&std::string_view(reinterpret_cast<const char*>(bytes.data()),8)=="DMGFC001");
    require(sha256(bytes.first(bytes.size()-64))==std::string_view(reinterpret_cast<const char*>(bytes.data()+bytes.size()-64),64));
    Reader h{bytes};h.at=8;require(h.u32()==format_version&&h.u32()==parser_version&&h.u32()==fact_version&&h.u32()==kind&&h.u32()==count&&h.u32()==1);
    require(h.u64()==bytes.size());uint64_t expected=64+uint64_t(count)*24;require(h.u64()==expected&&h.u64()==0x01020304&&h.u64()==0);
    std::pmr::vector<std::span<const uint8_t>> out(m);out.reserve(count);
    for(uint32_t i=0;i<count;++i){require(h.u32()==i+1&&h.u32()==1);const auto offset=h.u64(),length=h.u64();require(offset==expected&&offset<=bytes.size()-64&&length<=bytes.size()-64-offset);out.push_back(bytes.subspan(static_cast<size_t>(offset),static_cast<size_t>(length)));expected+=length;}
    require(expected==bytes.size()-64);return out;
}
Bytes method_key(std::span<const uint8_t> dex,uint32_t ordinal,uint32_t mask,std::pmr::memory_resource* m){
    Bytes key(m);frame(key,"DexMeguviz:physical-method-facts:v1");u32(key,parser_version);u32(key,fact_version);frame(key,sha256(dex));u64(key,dex.size());u32(key,ordinal);u32(key,mask);return key;
}
template<class V,class Fn> Bytes records(const V& rows,Fn fields,std::pmr::memory_resource* m,bool(*cancel)(void*)noexcept,void* ctx){Bytes out(m);u64(out,rows.size());uint64_t i=0;for(const auto& row:rows){if((i++&255)==0)check(cancel,ctx);for(uint64_t n:fields(row))u64(out,n);}return out;}
Sections encode_method(const Bytes& key,const facts::MethodFacts& f,std::pmr::memory_resource* m,bool(*cancel)(void*)noexcept,void* ctx){
    Sections s(m);s.emplace_back(key);Bytes meta(m);for(uint64_t n:{uint64_t(f.method_index),uint64_t(f.code_offset),uint64_t(f.has_body),uint64_t(f.instruction_checked),uint64_t(f.decoded_code_units),f.validation_work,uint64_t(f.requested_mask)})u64(meta,n);s.push_back(std::move(meta));
    s.push_back(records(f.string_uses,[](auto x){return std::array<uint64_t,3>{x.pc,x.string_index,x.opcode};},m,cancel,ctx));
    s.push_back(records(f.invoke_sites,[](auto x){return std::array<uint64_t,5>{x.pc,x.index,x.extra_proto,x.opcode,uint64_t(x.reference_kind)};},m,cancel,ctx));
    s.push_back(records(f.field_uses,[](auto x){return std::array<uint64_t,3>{x.pc,x.field_index,x.opcode};},m,cancel,ctx));
    s.push_back(records(f.numeric_literals,[](auto x){return std::array<uint64_t,5>{x.pc,x.bits,x.opcode,x.width_bits,uint64_t(x.kind)};},m,cancel,ctx));
    s.push_back(records(f.array_elements,[](auto x){return std::array<uint64_t,5>{x.pc,x.payload_pc,x.element_index,x.bits,x.width_bytes};},m,cancel,ctx));
    s.push_back(records(f.switch_cases,[](auto x){return std::array<uint64_t,6>{x.pc,x.payload_pc,x.target_pc,x.case_index,uint32_t(x.key),uint64_t(x.payload_kind)};},m,cancel,ctx));
    s.push_back(records(f.branches,[](auto x){return std::array<uint64_t,4>{x.pc,x.target_pc,x.opcode,uint64_t(x.kind)};},m,cancel,ctx));
    s.push_back(records(f.method_constants,[](auto x){return std::array<uint64_t,5>{x.pc,x.index,x.destination,x.opcode,uint64_t(x.domain)};},m,cancel,ctx));
    s.push_back(records(f.type_uses,[](auto x){return std::array<uint64_t,3>{x.pc,x.type_index,x.opcode};},m,cancel,ctx));return s;
}
facts::MethodFacts decode_method(std::span<const uint8_t> bytes,const Bytes& key,std::span<const uint8_t> dex,const Facts& meta,uint32_t ordinal,uint32_t mask,std::pmr::memory_resource* m,const Limits& limits,bool(*cancel)(void*)noexcept,void* context){
    auto s=sections(bytes,1,11,m);require(std::equal(s[0].begin(),s[0].end(),key.begin(),key.end()));Reader h{s[1]};facts::MethodFacts f(m);
    auto narrow=[](uint64_t x){require(x<=UINT32_MAX);return static_cast<uint32_t>(x);};auto byte=[](uint64_t x){require(x<=255);return static_cast<uint8_t>(x);};
    f.method_index=narrow(h.u64());f.code_offset=narrow(h.u64());auto body=h.u64(),checked=h.u64();require(body<=1&&checked<=1);f.has_body=body!=0;f.instruction_checked=checked!=0;f.decoded_code_units=narrow(h.u64());f.validation_work=h.u64();f.requested_mask=narrow(h.u64());
    const auto& method=meta.methods[ordinal];require(h.done()&&f.method_index==method.method_index&&f.code_offset==method.code_offset&&f.requested_mask==mask&&f.has_body==(method.code_offset!=0)&&f.instruction_checked==(f.has_body&&mask!=0));
    if(f.instruction_checked){require(uint64_t(f.code_offset)+16<=dex.size());Reader code{dex};code.at=f.code_offset+12;require(code.u32()==f.decoded_code_units);}else require(f.decoded_code_units==0&&f.validation_work==0);
    auto pc=[&](uint64_t n){auto p=narrow(n);require(p<f.decoded_code_units);return p;};
    auto opcode=[&](uint32_t p,uint64_t n){auto op=byte(n);const uint64_t at=uint64_t(f.code_offset)+16+uint64_t(p)*2;require(at<dex.size()&&dex[at]==op);return op;};
    auto read=[&](uint32_t section,uint32_t demand,uint32_t width,auto emit){Reader r{s[section]};const auto count=r.u64();require(count<=limits.max_records&&(mask&demand||count==0)&&count<=(s[section].size()-8)/(width*8)&&s[section].size()==8+count*width*8);uint32_t last=0;
        for(uint64_t i=0;i<count;++i){if((i&255)==0)check(cancel,context);std::array<uint64_t,6> v{};for(uint32_t j=0;j<width;++j)v[j]=r.u64();const auto current=pc(v[0]);require(!i||current>=last);last=current;emit(v,current);}require(r.done());};
    read(2,1,3,[&](auto v,auto p){require(v[1]<meta.strings.size());auto op=opcode(p,v[2]);require(op==0x1a||op==0x1b);f.string_uses.push_back({p,narrow(v[1]),op});});
    read(3,2,5,[&](auto v,auto p){require(v[4]<=2);auto kind=static_cast<instructions::ReferenceKind>(v[4]);require(v[1]<(kind==instructions::ReferenceKind::call_site?meta.call_site_count:meta.method_refs.size()));require(kind==instructions::ReferenceKind::method_and_proto?v[2]<meta.prototypes.size():v[2]==UINT32_MAX);auto op=opcode(p,v[3]);require(kind==instructions::ReferenceKind::method?(op>=0x6e&&op<=0x72)||(op>=0x74&&op<=0x78):kind==instructions::ReferenceKind::call_site?(op==0xfc||op==0xfd):(op==0xfa||op==0xfb));f.invoke_sites.push_back({p,narrow(v[1]),narrow(v[2]),op,kind});});
    read(4,4,3,[&](auto v,auto p){require(v[1]<meta.field_refs.size());auto op=opcode(p,v[2]);require(op>=0x52&&op<=0x6d);f.field_uses.push_back({p,narrow(v[1]),op});});
    read(5,8,5,[&](auto v,auto p){require((v[3]==32||v[3]==64)&&v[4]<=1);f.numeric_literals.push_back({p,v[1],opcode(p,v[2]),byte(v[3]),static_cast<instructions::NumericKind>(v[4])});});
    read(6,16,5,[&](auto v,auto p){require(v[4]==1||v[4]==2||v[4]==4||v[4]==8);f.array_elements.push_back({p,pc(v[1]),narrow(v[2]),v[3],byte(v[4])});});
    read(7,32,6,[&](auto v,auto p){require(v[5]==1||v[5]==2);f.switch_cases.push_back({p,pc(v[1]),pc(v[2]),narrow(v[3]),std::bit_cast<int32_t>(narrow(v[4])),static_cast<instructions::PayloadKind>(v[5])});});
    read(8,64,4,[&](auto v,auto p){require(v[3]<=1);f.branches.push_back({p,pc(v[1]),opcode(p,v[2]),static_cast<instructions::BranchKind>(v[3])});});
    read(9,128,5,[&](auto v,auto p){require(v[4]<=1&&v[1]<(v[4]==0?meta.method_handle_count:meta.prototypes.size()));auto op=opcode(p,v[3]);require(op==(v[4]==0?0xfe:0xff));require(v[2]<=UINT16_MAX);f.method_constants.push_back({p,narrow(v[1]),narrow(v[2]),op,static_cast<instructions::ConstantDomain>(v[4])});});
    read(10,256,3,[&](auto v,auto p){require(v[1]<meta.types.size());auto op=opcode(p,v[2]);require(op==0x1c||op==0x1f||op==0x20||op==0x22||op==0x23||op==0x24||op==0x25);f.type_uses.push_back({p,narrow(v[1]),op});});return f;
}
}
PersistentFacts::PersistentFacts(std::filesystem::path path,Limits limits):directory_(std::filesystem::absolute(path).lexically_normal()),limits_(limits){
    if(!limits.max_file_bytes||limits.max_file_bytes>(256u<<20)||limits.max_directory_bytes<limits.max_file_bytes||limits.max_directory_entries<2||limits.max_directory_entries>65536||!limits.max_records||limits.max_records>1'048'576)throw std::invalid_argument("invalid persistent cache limits");
    safe_ancestors(directory_);std::filesystem::create_directories(directory_);safe_ancestors(directory_);
}
bool PersistentFacts::read(std::string_view key,Bytes& bytes,bool(*cancel)(void*)noexcept,void* ctx){
    try{check(cancel,ctx);safe_ancestors(directory_);std::vector<std::filesystem::path> candidates;uint32_t count=0;
        for(const auto& entry:std::filesystem::directory_iterator(directory_)){check(cancel,ctx);if(++count>limits_.max_directory_entries)return false;const auto name=entry.path().filename().string();if(name.starts_with(key)&&name.ends_with(".shard")&&safe(entry.path())&&entry.is_regular_file())candidates.push_back(entry.path());}
        std::sort(candidates.rbegin(),candidates.rend());
        for(const auto& path:candidates){check(cancel,ctx);std::error_code ec;const auto size=std::filesystem::file_size(path,ec);if(ec||size<128||size>limits_.max_file_bytes){++stats_.rejected;continue;}bytes.resize(static_cast<size_t>(size));std::ifstream in(path,std::ios::binary);bool okay=bool(in);
            for(size_t at=0;okay&&at<bytes.size();){check(cancel,ctx);const auto n=std::min<size_t>(65536,bytes.size()-at);in.read(reinterpret_cast<char*>(bytes.data()+at),static_cast<std::streamsize>(n));okay=in.gcount()==static_cast<std::streamsize>(n);at+=n;stats_.bytes_read+=n;}
            if(okay&&in.peek()==std::char_traits<char>::eof()&&sha256(std::span(bytes).first(bytes.size()-64))==std::string_view(reinterpret_cast<const char*>(bytes.data()+bytes.size()-64),64))return true;++stats_.rejected;
        }
    }catch(const instructions::DecodeError&){throw;}catch(...){++stats_.rejected;}bytes.clear();return false;
}
void PersistentFacts::publish(std::string_view key,std::span<const uint8_t> bytes,bool(*cancel)(void*)noexcept,void* ctx){
    try{check(cancel,ctx);safe_ancestors(directory_);WriterLock lock(directory_);uint64_t used=0;uint32_t count=0;
        for(const auto& entry:std::filesystem::directory_iterator(directory_)){check(cancel,ctx);if(++count>=limits_.max_directory_entries-1)throw BadCache{};if(!safe(entry.path())||!entry.is_regular_file())throw BadCache{};auto size=entry.file_size();require(size<=limits_.max_directory_bytes-used);used+=size;}
        require(bytes.size()<=limits_.max_file_bytes&&bytes.size()<=(limits_.max_directory_bytes-used)/2);
        static std::atomic<uint64_t> sequence{0};const auto now=std::chrono::system_clock::now().time_since_epoch().count();
        const auto name=std::string(key)+"."+std::to_string(now)+"."+std::to_string(sequence.fetch_add(1));
        const auto pending=directory_/(name+".pending"),final=directory_/(name+".shard");
#ifdef _WIN32
        HANDLE file=CreateFileW(pending.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);if(file==INVALID_HANDLE_VALUE)throw BadCache{};
        try{for(size_t at=0;at<bytes.size();){check(cancel,ctx);DWORD written=0;const auto n=static_cast<DWORD>(std::min<size_t>(65536,bytes.size()-at));if(!WriteFile(file,bytes.data()+at,n,&written,nullptr)||written!=n)throw BadCache{};at+=n;}if(!FlushFileBuffers(file))throw BadCache{};}catch(...){CloseHandle(file);throw;}if(!CloseHandle(file))throw BadCache{};
#else
        int file=::open(pending.c_str(),O_WRONLY|O_CREAT|O_EXCL,0600);if(file<0)throw BadCache{};
        try{for(size_t at=0;at<bytes.size();){check(cancel,ctx);const auto n=::write(file,bytes.data()+at,std::min<size_t>(65536,bytes.size()-at));if(n<=0)throw BadCache{};at+=static_cast<size_t>(n);}if(::fsync(file))throw BadCache{};}catch(...){::close(file);throw;}if(::close(file))throw BadCache{};
#endif
        check(cancel,ctx);safe_ancestors(directory_);
        // Atomic new directory entry; never overwrite or remove another shard.
        // Pending remains intentionally, including on successful publication.
        std::filesystem::create_hard_link(pending,final);++stats_.published;
    }catch(const instructions::DecodeError&){throw;}catch(...){++stats_.write_failures;}
}
facts::MethodFacts PersistentFacts::collect(std::span<const uint8_t> dex,const Facts& meta,uint32_t ordinal,uint32_t mask,std::pmr::memory_resource* memory,bool(*cancel)(void*)noexcept,void* ctx,uint64_t remaining){
    if(!memory)throw std::invalid_argument("null persistent fact resource");
    if(mask&instructions::opcode_list)throw instructions::DecodeError(instructions::DecodeCode::unsupported,0,0,"opcode output is not serialized in persistent facts");
    if(!standard_dex(meta.dex_version)||ordinal>=meta.methods.size()||(mask&~facts::supported_demands))return facts::collect_method(dex,meta,ordinal,mask,memory,cancel,ctx,remaining);
    check(cancel,ctx);Bytes key(memory);std::string id;
    try{key=method_key(dex,ordinal,mask,memory);id=sha256(std::span(key));Bytes bytes(memory);if(read(id,bytes,cancel,ctx)){
        auto result=decode_method(bytes,key,dex,meta,ordinal,mask,memory,limits_,cancel,ctx);
        if(result.validation_work<=remaining){check(cancel,ctx);++stats_.hits;return result;}++stats_.rejected;
    }}catch(const instructions::DecodeError&){throw;}catch(...){++stats_.rejected;}
    key.clear();++stats_.misses;auto result=facts::collect_method(dex,meta,ordinal,mask,memory,cancel,ctx,remaining);++stats_.rebuilds;
    try{key=method_key(dex,ordinal,mask,memory);if(id.empty())id=sha256(std::span(key));auto s=encode_method(key,result,memory,cancel,ctx);auto bytes=envelope(1,s,memory,limits_.max_file_bytes);publish(id,bytes,cancel,ctx);}catch(const instructions::DecodeError&){throw;}catch(...){++stats_.write_failures;}
    return result;
}
Resolution PersistentFacts::resolve_method(const Scope& scope,std::u16string_view owner,std::u16string_view name,std::u16string_view proto,std::pmr::memory_resource* memory,uint64_t max_work,bool(*cancel)(void*)noexcept,void* ctx){
    if(!memory||!max_work||scope.sources.size()>1024||(!scope.snapshot_id.empty()&&!valid_snapshot_id(scope.snapshot_id)))throw std::invalid_argument("invalid resolution scope or declared snapshot ID");
    Resolution result(memory);result.declared_complete=scope.declared_complete;bool cacheable=true;Bytes key(memory);
    frame(key,scope.snapshot_id.empty()?"DexMeguviz:resolution-negative-domain:v1":"DexMeguviz:resolution-negative-domain:v2");
    u32(key,parser_version);u32(key,fact_version);frame(key,scope.name_space);frame(key,scope.model_version);u32(key,scope.declared_complete?1:0);
    if(!scope.snapshot_id.empty())frame(key,scope.snapshot_id);
    u32(key,static_cast<uint32_t>(scope.sources.size()));
    for(const auto& source:scope.sources){check(cancel,ctx);if(!source.facts)throw std::invalid_argument("missing scope facts");cacheable=cacheable&&standard_dex(source.facts->dex_version);frame(key,source.slot);frame(key,source.role);frame(key,sha256(source.bytes));u64(key,source.bytes.size());}
    text16(key,owner);text16(key,name);text16(key,proto);result.dependency_digest=cacheable?sha256(std::span(key)):std::string{};
    auto matches=[&](Definition d){require(d.source<scope.sources.size());const auto& facts=*scope.sources[d.source].facts;require(d.ordinal<facts.methods.size());const auto& m=facts.methods[d.ordinal];return m.owner==owner&&m.name==name&&m.prototype==proto;};
    try{Bytes bytes(memory);if(cacheable&&read(result.dependency_digest,bytes,cancel,ctx)){auto s=sections(bytes,2,2,memory);require(std::equal(s[0].begin(),s[0].end(),key.begin(),key.end()));Reader r{s[1]};const auto count=r.u64();require(count<=limits_.max_records&&s[1].size()==8+count*8);result.definitions.reserve(static_cast<size_t>(count));uint64_t last=0;
            for(uint64_t i=0;i<count;++i){check(cancel,ctx);Definition d{r.u32(),r.u32()};const uint64_t identity=(uint64_t(d.source)<<32)|d.ordinal;require((!i||identity>last)&&matches(d));last=identity;result.definitions.push_back(d);}require(r.done());uint64_t logical_work=0;for(const auto& source:scope.sources){require(source.facts->methods.size()<=max_work-logical_work);logical_work+=source.facts->methods.size();}result.cache_hit=true;++stats_.hits;return result;}}
    catch(const instructions::DecodeError&){throw;}catch(...){result.definitions.clear();++stats_.rejected;}
    ++stats_.misses;uint64_t work=0;
    for(uint32_t source=0;source<scope.sources.size();++source)for(uint32_t method=0;method<scope.sources[source].facts->methods.size();++method){check(cancel,ctx);if(work++>=max_work)throw instructions::DecodeError(instructions::DecodeCode::budget,0,0,"resolution work limit");if(matches({source,method})){if(result.definitions.size()>=limits_.max_records)throw instructions::DecodeError(instructions::DecodeCode::budget,0,0,"resolution record limit");result.definitions.push_back({source,method});}}
    ++stats_.rebuilds;try{if(!cacheable)return result;Sections s(memory);s.emplace_back(key);Bytes rows(memory);u64(rows,result.definitions.size());for(auto d:result.definitions){u32(rows,d.source);u32(rows,d.ordinal);}s.push_back(std::move(rows));auto bytes=envelope(2,s,memory,limits_.max_file_bytes);publish(result.dependency_digest,bytes,cancel,ctx);}catch(const instructions::DecodeError&){throw;}catch(...){++stats_.write_failures;}return result;
}
}
