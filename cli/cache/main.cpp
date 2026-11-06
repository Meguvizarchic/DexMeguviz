#include "cache/persistent.hpp"
#include "execution/reference/evaluate.hpp"
#include "execution/reference/facts_cache.hpp"
#include "json.hpp"
#ifdef DMG_CACHE_SOURCESET_TOOL
#include "c_api/runtime.hpp"
#endif
#include <fstream>
#include <iostream>

namespace {
using namespace dexmeguviz;
class BoundedMemory final:public std::pmr::memory_resource {
    size_t used=0;static constexpr size_t limit=256u<<20;
    void* do_allocate(size_t bytes,size_t alignment)override{if(bytes>limit-used)throw std::bad_alloc{};auto p=std::pmr::new_delete_resource()->allocate(bytes,alignment);used+=bytes;return p;}
    void do_deallocate(void* p,size_t bytes,size_t alignment)override{std::pmr::new_delete_resource()->deallocate(p,bytes,alignment);used-=bytes;}
    bool do_is_equal(const std::pmr::memory_resource& other)const noexcept override{return this==&other;}
};
std::vector<uint8_t> file(const std::filesystem::path& path,size_t cap){const auto size=std::filesystem::file_size(path);if(size>cap)throw std::runtime_error("input exceeds cap");std::vector<uint8_t> out(static_cast<size_t>(size));std::ifstream f(path,std::ios::binary);f.read(reinterpret_cast<char*>(out.data()),static_cast<std::streamsize>(size));if(f.gcount()!=static_cast<std::streamsize>(size)||f.peek()!=std::char_traits<char>::eof())throw std::runtime_error("input read failed or changed");return out;}
const dmg_cli::Json* field(const dmg_cli::Json& j,std::u16string_view key){for(const auto& [k,v]:j.object)if(k==key)return &v;return nullptr;}
std::u16string symbol(const dmg_cli::Json& j,std::u16string_view key){auto p=field(j,key);if(!p||p->kind!=dmg_cli::Json::Kind::string)throw std::runtime_error("symbol field missing");return std::u16string(p->string);}
std::string ascii(const dmg_cli::Json& j,std::u16string_view key,std::string fallback){auto p=field(j,key);if(!p)return fallback;if(p->kind!=dmg_cli::Json::Kind::string)throw std::runtime_error("scope string required");std::string out;for(auto c:p->string){if(c>127)throw std::runtime_error("tool scope labels require ASCII; C++ API accepts byte strings");out.push_back(static_cast<char>(c));}return out;}
#ifdef DMG_CACHE_SOURCESET_TOOL
#include "source_set_mode.inc"
#endif
int run(const std::vector<std::filesystem::path>& args){
#ifdef DMG_CACHE_SOURCESET_TOOL
    return run_sources(args);
#else
    if(args.size()<5)throw std::runtime_error("usage: dexmeguviz_cache CACHE_DIR QUERY.json SYMBOL.json DEX [DEX...]");
    BoundedMemory memory;cache::PersistentFacts disk(args[1]);auto query_bytes=file(args[2],65536),symbol_bytes=file(args[3],65536);
    auto query=query::compile({reinterpret_cast<const char*>(query_bytes.data()),query_bytes.size()},&memory,&memory);
    auto spec=dmg_cli::JsonReader({reinterpret_cast<const char*>(symbol_bytes.data()),symbol_bytes.size()}).parse();if(spec.kind!=dmg_cli::Json::Kind::object)throw std::runtime_error("symbol object required");
    auto owner=symbol(spec,u"owner"),name=symbol(spec,u"name"),proto=symbol(spec,u"prototype");auto ns=ascii(spec,u"namespace","persistent-tool"),model=ascii(spec,u"model","static-method-symbol-v1");
    const auto snapshot=ascii(spec,u"snapshot_id","");if(field(spec,u"snapshot_id")&&snapshot.empty())throw std::runtime_error("declared snapshot_id cannot be empty");
    bool complete=true;if(auto p=field(spec,u"complete")){if(p->kind!=dmg_cli::Json::Kind::boolean)throw std::runtime_error("complete boolean required");complete=p->boolean;}
    if(args.size()-4>1024)throw std::runtime_error("too many sources");
    std::vector<std::vector<uint8_t>> sources;std::vector<Facts> facts;std::vector<std::string> owned_slots;sources.reserve(args.size()-4);facts.reserve(args.size()-4);owned_slots.reserve(args.size()-4);uint64_t total=0;
    for(size_t i=4;i<args.size();++i){auto bytes=file(args[i],64u<<20);if(bytes.size()>(256u<<20)-total)throw std::runtime_error("aggregate input exceeds cap");total+=bytes.size();sources.push_back(std::move(bytes));facts.push_back(read_metadata(sources.back(),&memory));owned_slots.push_back("source"+std::to_string(i-4));}
    std::vector<reference::SourceView> views;std::vector<std::string_view> slots;std::vector<cache::ScopeSource> dependencies;
    for(uint32_t i=0;i<sources.size();++i){views.push_back({i,i,&facts[i],sources[i]});slots.push_back(owned_slots[i]);dependencies.push_back({owned_slots[i],"raw",sources[i],&facts[i]});}
    const auto resolved=disk.resolve_method({ns,model,complete,dependencies,snapshot},owner,name,proto,&memory);const auto before=disk.statistics();
    reference::FactsCache cache(views,&memory,0,&disk);reference::Progress progress{};auto result=reference::execute({views,slots,complete},query,progress,&memory,{},{},&cache);const auto after=disk.statistics();
    std::cout<<"{\"scope_complete\":"<<(complete?"true":"false")<<",\"snapshot_domain_bound\":"<<(!snapshot.empty()?"true":"false")<<",\"resolution_cache_hit\":"<<(resolved.cache_hit?"true":"false")<<",\"dependency_digest\":\""<<resolved.dependency_digest<<"\",\"definitions\":[";
    bool comma=false;for(auto d:resolved.definitions){if(comma)std::cout<<',';comma=true;std::cout<<"{\"source\":"<<d.source<<",\"ordinal\":"<<d.ordinal<<'}';}
    std::cout<<"],\"query_id\":\""<<query.id<<"\",\"query_cache_hits\":"<<after.hits-before.hits<<",\"query_cache_rebuilds\":"<<after.rebuilds-before.rebuilds<<",\"work_units\":"<<progress.profile.work_units<<",\"candidates\":[";
    comma=false;for(const auto& row:result.rows){if(comma)std::cout<<',';comma=true;std::cout<<"{\"source\":"<<row.source_index<<",\"ordinal\":"<<row.method_ordinal<<",\"relation\":"<<static_cast<uint32_t>(row.relation)<<'}';}
    std::cout<<"],\"unknown_rows\":"<<progress.profile.unknown_rows<<",\"result_limit\":"<<(result.result_limit?"true":"false")<<",\"cache_rejected\":"<<after.rejected<<",\"cache_write_failures\":"<<after.write_failures<<"}\n";return 0;
#endif
}
}
#ifdef _WIN32
int wmain(int argc,wchar_t** argv){try{std::vector<std::filesystem::path> args;for(int i=0;i<argc;++i)args.emplace_back(argv[i]);return run(args);}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 2;}}
#else
int main(int argc,char** argv){try{std::vector<std::filesystem::path> args;for(int i=0;i<argc;++i)args.emplace_back(argv[i]);return run(args);}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 2;}}
#endif
