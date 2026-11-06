#pragma once
#include "format/reader.hpp"
#include <cstdint>
#include <exception>
#include <memory_resource>
#include <span>
#include <vector>

namespace dexmeguviz::cache {class MethodProvider;}
namespace dexmeguviz::facts {
enum class UseKind:uint32_t {string_use,invoke_site,field_use,type_use};
enum class TargetDomain:uint32_t {string_value,field_ref,method_ref,method_and_proto,call_site,type_ref};
struct UseKey {
    uint32_t source_index,caller_ordinal,dex_pc;
    UseKind kind;
    bool operator==(const UseKey&)const=default;
};
struct UseRecord {
    UseKey key;
    uint32_t caller_method_ref,code_offset,target_index,extra_proto;
    uint8_t opcode;
    TargetDomain target_domain;
};
struct UseScanLimits {uint64_t max_work=100'000'000;uint32_t max_records=100'000;};
struct UseScanCancel {bool(*requested)(void*)noexcept=nullptr;void* context=nullptr;};
struct UseScanProgress {
    uint32_t total_methods=0,attempted_methods=0,visited_methods=0,no_body_methods=0,decoded_methods=0;
    uint64_t emitted_events=0,code_units=0,validation_work=0,work_units=0;
};
struct UseScanResult {
    std::pmr::vector<UseRecord> rows;
    explicit UseScanResult(std::pmr::memory_resource* resource):rows(resource){}
};
// Internal streaming hooks. A method callback sees records only after the
// entire method and its accounting have completed. The budget callback gives
// the remaining shared work after accounting for unmerged scan work. The
// callbacks must be supplied together, or both omitted for legacy behavior.
struct UseScanHooks {
    uint64_t (*remaining)(void*) noexcept=nullptr;
    void (*method_complete)(void*,std::span<const UseRecord>,const UseScanProgress&)=nullptr;
    void* context=nullptr;
    bool discard_after_callback=false; // only after a fully checked method is consumed
};
struct UseScanError final:std::exception {
    enum class Code {invalid,unsupported,budget,cancelled};
    Code code;const char* message;
    UseScanError(Code value,const char* text)noexcept:code(value),message(text){}
    const char* what()const noexcept override{return message;}
};

// bytes and metadata must represent the same immutable logical DEX. The caller
// retains them during the call and keeps resource alive until Result is freed.
// No Result is returned on failure. total_methods is the size of the scan
// scope; attempted_methods includes a started method even if it fails.
// visited_methods, no_body_methods, decoded_methods, emitted_events,
// code_units and validation_work count fully completed methods only.
// work_units also includes successfully completed collector work and appends
// from an unfinished method. Work inside a decoder that throws is not
// observable in its current API and is not estimated here.
// Decoder exceptions (including error PC/offset) and allocation failures pass
// through unchanged. Zero limits and a null resource are invalid.
UseScanResult collect_uses(std::span<const uint8_t> bytes,const Facts& metadata,
    uint32_t source_index,UseKind kind,UseScanProgress& progress,
    std::pmr::memory_resource* resource,UseScanLimits limits={},UseScanCancel cancel={},UseScanHooks hooks={},cache::MethodProvider* provider=nullptr);
}
