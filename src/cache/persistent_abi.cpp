#include "dexmeguviz/persistent_cache_v1.h"
#include "cache/persistent.hpp"
#include "c_api/runtime.hpp"
#include "execution/reference/facts_cache.hpp"
#include <algorithm>
#include <filesystem>
#include <mutex>

using namespace dexmeguviz;
using namespace dexmeguviz::runtime;

struct dmg_persistent_cache_v1 {
    std::atomic<uint32_t> references{1};
    std::atomic<bool> closed{false};
    std::shared_ptr<EngineState> owner;
    std::mutex operation;
    cache::PersistentFacts provider;
    dmg_persistent_cache_v1(std::shared_ptr<EngineState> engine,std::filesystem::path path,cache::Limits limits)
        :owner(std::move(engine)),provider(std::move(path),limits){}
};

namespace {
bool valid_utf8_path(const uint8_t* s,size_t size)noexcept{
    for(size_t i=0;i<size;){
        const uint8_t c=s[i++];if(c==0)return false;if(c<0x80)continue;
        uint32_t cp=0;size_t extra=0;
        if(c>=0xc2&&c<=0xdf){cp=c&0x1f;extra=1;}
        else if(c>=0xe0&&c<=0xef){cp=c&0x0f;extra=2;}
        else if(c>=0xf0&&c<=0xf4){cp=c&0x07;extra=3;}
        else return false;
        if(extra>size-i)return false;
        for(size_t n=0;n<extra;++n){const uint8_t next=s[i++];if((next&0xc0)!=0x80)return false;cp=(cp<<6)|(next&0x3f);}
        if((extra==2&&cp<0x800)||(extra==3&&cp<0x10000)||(cp>=0xd800&&cp<=0xdfff)||cp>0x10ffff)return false;
    }
    return true;
}
}
extern "C" {
dmg_status dmg_persistent_cache_open_v1(dmg_engine* engine,const dmg_persistent_cache_options_v1* options,
    dmg_persistent_cache_v1** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{
        if(!engine||!options||!out||options->struct_size!=sizeof(*options)||options->abi_version!=DMG_ABI_VERSION||options->reserved||
           !options->directory_utf8||!options->directory_length||options->directory_length>4096)return DMG_INVALID_ARGUMENT;
        const auto length=static_cast<size_t>(options->directory_length);
        if(!valid_utf8_path(options->directory_utf8,length))return DMG_INVALID_ARGUMENT;
        cache::Limits limits;
        if(options->max_file_bytes)limits.max_file_bytes=options->max_file_bytes;
        if(options->max_directory_bytes)limits.max_directory_bytes=options->max_directory_bytes;
        if(options->max_directory_entries)limits.max_directory_entries=options->max_directory_entries;
        if(options->max_records)limits.max_records=options->max_records;
        if(!limits.max_file_bytes||limits.max_file_bytes>(256uLL<<20)||limits.max_directory_bytes<limits.max_file_bytes||
           limits.max_directory_bytes>(4uLL<<30)||limits.max_directory_entries<2||limits.max_directory_entries>65536||
           !limits.max_records||limits.max_records>1'048'576)return DMG_INVALID_ARGUMENT;
        admit(engine->owner);
        std::u8string encoded;encoded.reserve(length);
        for(size_t i=0;i<length;++i)encoded.push_back(static_cast<char8_t>(options->directory_utf8[i]));
        const auto path=std::filesystem::path(encoded);
        *out=handle<dmg_persistent_cache_v1>(engine->owner,path,limits);return DMG_OK;
    },error);
}
void dmg_persistent_cache_retain_v1(dmg_persistent_cache_v1* c){if(c)c->references.fetch_add(1,std::memory_order_relaxed);}
void dmg_persistent_cache_release_v1(dmg_persistent_cache_v1* c){if(c&&c->references.fetch_sub(1,std::memory_order_acq_rel)==1)destroy(c);}
dmg_status dmg_persistent_cache_close_v1(dmg_persistent_cache_v1* c){if(!c)return DMG_INVALID_ARGUMENT;c->closed.store(true,std::memory_order_release);return DMG_OK;}
dmg_status dmg_persistent_cache_get_stats_v1(dmg_persistent_cache_v1* c,dmg_persistent_cache_stats_v1* out,uint32_t out_size){
    return guard([&]()->dmg_status{
        if(!c||!out||out_size!=sizeof(*out))return DMG_INVALID_ARGUMENT;
        std::lock_guard lock(c->operation);const auto s=c->provider.statistics();
        *out={s.hits,s.misses,s.rebuilds,s.rejected,s.published,s.write_failures,s.bytes_read};return DMG_OK;
    });
}
dmg_status dmg_persistent_cache_execute_v1(dmg_persistent_cache_v1* c,dmg_snapshot* snapshot,dmg_query* query,
    dmg_result** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{
        if(!c||!snapshot||!query||!out||c->owner!=snapshot->owner||c->owner!=query->owner||
           !query->query||!query->query->plan)return DMG_INVALID_ARGUMENT;
        std::lock_guard lock(c->operation);
        if(c->closed.load(std::memory_order_acquire)||snapshot->closed.load(std::memory_order_acquire))return DMG_CLOSED;
        admit(c->owner);
        const auto dataset=snapshot->dataset;const auto state=query->query;
        if(!dataset||dataset->engine!=c->owner||state->engine!=c->owner)return DMG_INVALID_ARGUMENT;
        Control control;reference::Progress progress;auto* scratch=&c->owner->scratch_resource;
        std::pmr::vector<reference::SourceView> sources(scratch);std::pmr::vector<std::string_view> slots(scratch);
        sources.reserve(dataset->sources.size());slots.reserve(dataset->inputs.size());
        for(uint32_t i=0;i<dataset->sources.size();++i){const auto& s=*dataset->sources[i];sources.push_back({i,s.input_index,&s.facts,s.view()});}
        for(const auto& input:dataset->inputs)slots.push_back(input.slot);
        // Reuse physical method facts only; no query result, negative decision,
        // runtime binding or caller-declared snapshot ID is read from disk.
        reference::FactsCache facts(sources,scratch,0,&c->provider);
        auto evaluated=reference::execute({sources,slots,dataset->scope_complete},*state->plan,progress,scratch,{},{},&facts);
        auto result=materialize_evaluated(c->owner,dataset,state,evaluated,progress,control);
        *out=result.release();return DMG_OK;
    },error);
}
}
