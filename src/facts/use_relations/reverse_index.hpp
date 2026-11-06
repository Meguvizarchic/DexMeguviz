#pragma once
#include "facts/use_relations/use_scan.hpp"
#include <cstdint>
#include <memory_resource>
#include <list>
#include <mutex>
#include <vector>

namespace dexmeguviz::facts {
struct ReverseLimits {uint64_t max_work,max_index_bytes;uint32_t max_records;};
struct ReverseStats {uint64_t attempts=0,builds=0,failures=0,reuses=0,published=0,records=0;};
struct ReverseKey {TargetDomain domain;uint32_t target_index,extra_proto;};
struct ReverseEvent {
    uint32_t source_index,use_kind,caller_ordinal,caller_method_ref,dex_pc,opcode,code_offset,target_domain,target_index,extra_proto;
};
struct ReversePage {
    uint64_t total=0;
    std::pmr::vector<ReverseEvent> rows;
    explicit ReversePage(std::pmr::memory_resource* resource):rows(resource){}
};
class ReverseRegistry {
    struct Entry {
        uint32_t source_index;UseKind kind;uint64_t work=0;
        std::pmr::vector<UseRecord> rows;
        Entry(uint32_t source,UseKind type,std::pmr::memory_resource* resource):source_index(source),kind(type),rows(resource){}
        Entry(Entry&&) noexcept=default;Entry& operator=(Entry&&)=delete;
        Entry(const Entry&)=delete;Entry& operator=(const Entry&)=delete;
    };
    std::pmr::memory_resource* facts_;std::pmr::memory_resource* scratch_;
    std::timed_mutex mutex_;std::pmr::list<Entry> entries_;ReverseStats stats_;
public:
    ReverseRegistry(std::pmr::memory_resource* facts,std::pmr::memory_resource* scratch):facts_(facts),scratch_(scratch),entries_(facts){}
    ReverseRegistry(const ReverseRegistry&)=delete;ReverseRegistry& operator=(const ReverseRegistry&)=delete;
    ReverseStats profile();
    uint64_t lookup(std::span<const uint8_t> bytes,const Facts& metadata,uint32_t source_index,UseKind kind,
        ReverseKey key,ReverseLimits limits,UseScanCancel cancel,cache::MethodProvider* provider=nullptr);
    ReversePage page(std::span<const uint8_t> bytes,const Facts& metadata,uint32_t source_index,UseKind kind,
        ReverseKey key,uint64_t offset,uint32_t capacity,ReverseLimits limits,UseScanCancel cancel,cache::MethodProvider* provider=nullptr);
private:
    ReversePage select(std::span<const uint8_t> bytes,const Facts& metadata,uint32_t source_index,UseKind kind,
        ReverseKey key,uint64_t offset,uint32_t capacity,bool include_page,ReverseLimits limits,UseScanCancel cancel,cache::MethodProvider* provider);
};
}
