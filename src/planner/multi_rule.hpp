#pragma once
#include "execution/reference/evaluate.hpp"
#include "execution/reference/facts_cache.hpp"
#include <cstddef>
#include <memory_resource>
#include <optional>
#include <span>
#include <string_view>

namespace dexmeguviz::planner {
// Internal experimental API. The caller keeps dataset bytes, plans and every
// rule resource alive until the returned outcomes are destroyed. Cache bytes
// must be reserved and accounted before entry; they cannot overlap inputs,
// plan backing storage or any resource-owned storage. Known source/descriptor
// ranges are checked, but complete allocator ownership is not yet provable.
struct Rule {
    std::string_view rule_id;
    const query::Plan* plan=nullptr;
    std::pmr::memory_resource* memory=nullptr;
    reference::Cancel cancel{};
    // Internal-only attestation: deallocation order is irrelevant to this
    // resource and allocation behavior is independent of returned addresses.
    // An unchecked external caller must never be allowed to set this flag.
    bool allocation_replay_safe=false;
};
// result_available means a readable Result was produced; its result_limit,
// scope_complete and unknown_rows still decide whether coverage is complete.
enum class OutcomeCode { result_available,invalid,unsupported,budget,cancelled,source_mismatch,corrupt,out_of_memory,internal };
struct Outcome {
    std::pmr::string rule_id;
    OutcomeCode code=OutcomeCode::internal;
    uint64_t error_offset=0;uint32_t error_pc=0;
    reference::Progress progress;
    std::optional<reference::Result> result;
    explicit Outcome(std::pmr::memory_resource* r):rule_id(r){}
};
struct MultiResult {
    std::pmr::vector<Outcome> rules;
    reference::SharedFactsProfile shared;
    bool fused_methods_used=false;
    explicit MultiResult(std::pmr::memory_resource* r):rules(r){}
};
// Input validation and coordinator allocation complete before any rule runs.
// Rules execute in order, each with its own progress and errors. Cache is
// confined to this call; direct plans and eligible single-Scan Filter/Label
// graphs with no cancel callback may use it. Other rules use the scalar path. Cache work and reserved bytes
// are bounded separately from each rule's preserved logical max_work. Reported
// cache_work_charged includes conservative replay cleanup reservations.
MultiResult execute(const reference::DatasetView& dataset,std::span<const Rule> rules,
    std::pmr::memory_resource* coordinator,std::span<std::byte> reserved_cache,
    uint64_t max_cache_work,bool fused_methods=false);
}
