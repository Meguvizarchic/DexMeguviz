#pragma once
#include "analysis/cfg/cfg.hpp"
#include <array>
#include <string>

namespace dexmeguviz::analysis::correspondence {
struct Options {
    uint64_t max_decode_work=2'000'000,max_graph_work=8'000'000,max_summary_work=8'000'000;
    uint32_t max_tokens=2'000'000;
    bool (*cancelled)(void*) noexcept=nullptr;void* cancel_context=nullptr;
};
// Versioned structural features, not semantic equivalence or runtime identity.
struct Summary {
    explicit Summary(std::pmr::memory_resource* r=std::pmr::get_default_resource())
        : tokens(r),prototype(r),digest(r){}
    static constexpr uint32_t version=1;
    uint32_t method_ordinal=0,code_offset=0,instructions=0,blocks=0,edges=0;
    bool has_body=false,ordinary_flow_complete=false,exception_regions=false;
    uint64_t decode_work=0,graph_work=0,summary_work=0;
    std::array<uint32_t,256> opcodes{};std::array<uint32_t,9> edge_kinds{};
    std::pmr::vector<uint32_t> tokens;
    std::pmr::u16string prototype;
    std::pmr::string digest;
};
Summary summarize(std::span<const uint8_t> dex,const Facts& metadata,uint32_t method_ordinal,
                  const Options& options={},std::pmr::memory_resource* resource=std::pmr::get_default_resource());
struct Candidate {uint32_t source_index,method_ordinal;const Summary* summary;};
struct Ranked {
    uint32_t source_index,method_ordinal,score,normalized_sequence,opcode_overlap,edge_overlap,prototype_match;
    bool exact_structural_sequence;
};
// Score in [0,10000] is an explained heuristic, never a probability or acceptance.
std::pmr::vector<Ranked> rank(const Summary& reference,std::span<const Candidate> candidates,
    uint32_t max_candidates=100000,uint64_t max_work=16'000'000,
    bool (*cancelled)(void*) noexcept=nullptr,void* context=nullptr,
    std::pmr::memory_resource* resource=std::pmr::get_default_resource());
}
