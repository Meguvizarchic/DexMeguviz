#pragma once
#include "format/instructions/decoder.hpp"
#include "format/reader.hpp"
#include <memory_resource>
#include <span>
#include <vector>

namespace dexmeguviz::analysis::cfg {
// Structural edges only: no path feasibility, ART verification or actual
// exception dispatch is inferred. Missing fallthrough edges have no target.
enum class EdgeKind : uint8_t { fallthrough, branch, conditional_taken, conditional_fallthrough,
    switch_case, switch_default, fallthrough_to_payload, fallthrough_past_end, exception_handler };
enum class Terminal : uint8_t { ordinary, jump, conditional, switch_op, return_op, throw_op };
inline constexpr uint32_t no_target = UINT32_MAX;
struct Edge {
    uint32_t from_block, to_block, source_pc, target_pc;
    EdgeKind kind;
    int32_t switch_key = 0;
    uint32_t switch_case_index = 0, payload_pc = no_target;
    // For exception_handler only: no_target denotes catch-all, otherwise a
    // source-local type_id. Order is the encoded position in the handler list.
    uint32_t catch_type_index = no_target, catch_order = 0;
};
struct Block {
    uint32_t start_pc, end_pc, last_pc, first_edge, edge_count;
    Terminal terminal;
    bool reachable = false;
};
struct Options {
    uint64_t max_decode_work = 1'000'000;
    uint64_t max_graph_work = 8'000'000;
    uint32_t max_blocks = 1'000'000, max_edges = 1'000'000;
    bool (*cancelled)(void*) noexcept = nullptr;
    void* cancel_context = nullptr;
    bool include_exception_edges = false;
};
struct Result {
    explicit Result(std::pmr::memory_resource* resource = std::pmr::get_default_resource())
        : blocks(resource), edges(resource) {}
    bool has_body = false;
    // True only for the reachable ordinary-flow graph: no reachable
    // fallthrough to payload or beyond the instruction stream. Exception
    // edges are conservative and do not prove complete runtime dispatch.
    bool reachable_flow_complete = false;
    bool has_exception_regions = false;
    bool exception_edges_included = false;
    uint32_t code_units = 0;
    uint64_t decode_work = 0, graph_work = 0;
    std::pmr::vector<Block> blocks;
    std::pmr::vector<Edge> edges;
};
// These inputs must be the same immutable checked DEX snapshot. Nothing is
// cached or evaluated by default. Both PMR resources must outlive results.
Result build(std::span<const uint8_t> dex, const Facts& metadata, uint32_t method_ordinal,
             const Options& options = {}, std::pmr::memory_resource* resource = std::pmr::get_default_resource());
// code_item extent and reference bounds must originate from the checked reader.
Result build_checked(const instructions::DecodeInput& input, const Options& options = {},
                     std::pmr::memory_resource* resource = std::pmr::get_default_resource());
}
