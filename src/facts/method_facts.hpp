#pragma once
#include "format/instructions/decoder.hpp"
#include "format/reader.hpp"

namespace dexmeguviz::facts {
inline constexpr uint32_t supported_demands = instructions::strings | instructions::invokes |
    instructions::fields | instructions::numeric | instructions::array_data |
    instructions::switch_targets | instructions::branch_targets | instructions::method_constants | instructions::type_uses | instructions::opcode_list;
enum class FactAvailability { not_requested, no_body, checked, unknown };
struct MethodFacts {
    explicit MethodFacts(std::pmr::memory_resource* resource = std::pmr::get_default_resource())
        : string_uses(resource), invoke_sites(resource), field_uses(resource), numeric_literals(resource), array_elements(resource), switch_cases(resource), branches(resource), method_constants(resource), type_uses(resource) {}
    uint32_t method_index = 0;
    uint32_t code_offset = 0;
    bool has_body = false;
    bool instruction_checked = false;
    uint32_t decoded_code_units = 0;
    uint64_t validation_work = 0;
    // Only a successful collect_method result makes this mask authoritative.
    uint32_t requested_mask = 0;
    // Requires exactly one supported demand bit; malformed inputs throw.
    FactAvailability availability(uint32_t demand) const {
        if (!demand || (demand & (demand - 1)) || (demand & ~supported_demands))
            throw std::invalid_argument("availability requires one supported demand");
        if (!(requested_mask & demand)) return FactAvailability::not_requested;
        if (!has_body) return FactAvailability::no_body;
        return instruction_checked ? FactAvailability::checked : FactAvailability::unknown;
    }
    std::pmr::vector<instructions::StringUse> string_uses;
    std::pmr::vector<instructions::InvokeSite> invoke_sites;
    std::pmr::vector<instructions::FieldUse> field_uses;
    std::pmr::vector<instructions::NumericLiteral> numeric_literals;
    std::pmr::vector<instructions::ArrayDataElement> array_elements;
    std::pmr::vector<instructions::SwitchTarget> switch_cases;
    std::pmr::vector<instructions::BranchTarget> branches;
    std::pmr::vector<instructions::MethodConstant> method_constants;
    std::pmr::vector<instructions::TypeUse> type_uses;
};

// The immutable bytes and Facts must belong to the same logical DEX snapshot.
// method_ordinal indexes Facts.methods, not the method_ref table.
// demand_mask=0 does not decode. Native/abstract definitions report has_body=false.
// Returned rows contain local IDs only; symbol lookup requires the matching Facts.
// Both supplied PMR resources must outlive their respective Facts/MethodFacts objects.
// No data is cached or mutated; callers may collect concurrently from immutable Facts.
MethodFacts collect_method(std::span<const uint8_t> dex, const Facts& metadata,
    uint32_t method_ordinal, uint32_t demand_mask,
    std::pmr::memory_resource* resource = std::pmr::get_default_resource(),
    bool (*cancelled)(void*) noexcept = nullptr, void* cancel_context = nullptr,
    uint64_t max_validation_work = UINT64_MAX);
// A separate request-local output preserves MethodFacts layout. The supplied
// empty vector and resource must match; failed decoding never publishes it.
MethodFacts collect_method_with_instructions(std::span<const uint8_t> dex,const Facts& metadata,
    uint32_t method_ordinal,uint32_t demand_mask,std::pmr::vector<instructions::Instruction>& output,
    std::pmr::memory_resource* resource = std::pmr::get_default_resource(),
    bool (*cancelled)(void*) noexcept = nullptr,void* cancel_context = nullptr,
    uint64_t max_validation_work = UINT64_MAX);
}
