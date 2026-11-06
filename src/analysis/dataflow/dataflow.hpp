#pragma once
#include "analysis/cfg/cfg.hpp"
#include <cstdint>
#include <memory_resource>
#include <span>
#include <vector>

namespace dexmeguviz::analysis::dataflow {
inline constexpr uint32_t no_single_definition = UINT32_MAX;
// One structural use. A known constant is a 32-bit bit pattern, not a type.
// no_single_definition includes entry values and multiple reaching definitions.
struct Use {
    uint32_t pc, register_index, operand_index, definition_pc, constant_bits;
    bool constant_known;
};
struct Options {
    uint64_t max_decode_work = 2'000'000, max_graph_work = 8'000'000, max_analysis_work = 16'000'000;
    uint64_t max_state_cells = 1'000'000;
    uint32_t max_uses = 1'000'000;
    bool (*cancelled)(void*) noexcept = nullptr;
    void* cancel_context = nullptr;
    // Opt-in only: read argument words, treat return values as Unknown, and
    // make no claim about heap state, dispatch or whether a call returns.
    bool allow_opaque_invokes = false;
    // Conservative register-word transfers for object/wide/heap/float forms.
    // No heap alias, object identity, runtime type or wide-value lattice.
    bool allow_conservative_registers = false;
    // Separately opt in to conservative handler edges. Requires the mode above.
    bool include_exception_edges = false;
};
struct Result {
    explicit Result(std::pmr::memory_resource* resource = std::pmr::get_default_resource()) : uses(resource) {}
    bool has_body = false;
    bool conservative_registers = false, exception_edges_included = false;
    uint32_t registers = 0;
    uint64_t decode_work = 0, graph_work = 0, analysis_work = 0;
    std::pmr::vector<Use> uses;
};
// Internal opt-in analysis: only explicitly modeled instructions are accepted;
// the source bytes and metadata must identify the same immutable checked DEX.
Result analyze(std::span<const uint8_t> dex, const Facts& metadata, uint32_t method_ordinal,
               const Options& options = {}, std::pmr::memory_resource* resource = std::pmr::get_default_resource());
Result analyze_checked(const instructions::DecodeInput& input, const Options& options = {},
                       std::pmr::memory_resource* resource = std::pmr::get_default_resource());
}
