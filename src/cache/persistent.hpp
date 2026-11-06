#pragma once
#include "method_provider.hpp"
#include <filesystem>
#include <string>

namespace dexmeguviz::cache {
struct Limits {
    uint64_t max_file_bytes=64u<<20, max_directory_bytes=256u<<20;
    uint32_t max_directory_entries=2048, max_records=1'048'576;
};
struct Statistics {uint64_t hits=0,misses=0,rebuilds=0,rejected=0,published=0,write_failures=0,bytes_read=0;};
struct ScopeSource {
    std::string_view slot,role;
    std::span<const uint8_t> bytes;
    const Facts* facts=nullptr;
};
struct Scope {
    std::string_view name_space,model_version;
    bool declared_complete=false;
    std::span<const ScopeSource> sources;
    // Optional caller-declared identity from the currently opened SourceSet.
    // It binds invalidation to all input slots, including zero-DEX resources;
    // it is not authenticated here and cannot establish a runtime origin.
    std::string_view snapshot_id{};
};
struct Definition {uint32_t source=0,ordinal=0;bool operator==(const Definition&)const=default;};
struct Resolution {
    explicit Resolution(std::pmr::memory_resource* r):definitions(r){}
    std::pmr::vector<Definition> definitions;
    bool declared_complete=false,cache_hit=false;
    std::string dependency_digest;
};
// Caller explicitly selects a private directory whose writers it trusts.
// File checksums detect damage, not authenticated hostile replacement.
// No process pointers, class loaders or runtime bindings are persisted.
class PersistentFacts final:public MethodProvider {
public:
    explicit PersistentFacts(std::filesystem::path directory,Limits limits={});
    facts::MethodFacts collect(std::span<const uint8_t>,const Facts&,uint32_t,uint32_t,
        std::pmr::memory_resource*,bool(*)(void*)noexcept,void*,uint64_t) override;
    Resolution resolve_method(const Scope&,std::u16string_view owner,std::u16string_view name,
        std::u16string_view prototype,std::pmr::memory_resource*,uint64_t max_work=100'000'000,
        bool(*cancelled)(void*)noexcept=nullptr,void* context=nullptr);
    Statistics statistics()const noexcept{return stats_;}
private:
    std::filesystem::path directory_;Limits limits_;Statistics stats_;
    bool read(std::string_view key,std::pmr::vector<uint8_t>&,bool(*)(void*)noexcept,void*);
    void publish(std::string_view key,std::span<const uint8_t>,bool(*)(void*)noexcept,void*);
};
}
