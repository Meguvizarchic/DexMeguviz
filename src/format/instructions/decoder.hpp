#pragma once
#include <cstdint>
#include <memory_resource>
#include <span>
#include <stdexcept>
#include <vector>

namespace dexmeguviz::instructions {
enum class DecodeCode { corrupt, unsupported, cancelled, budget };
struct DecodeError : std::runtime_error {
    DecodeCode code;
    uint64_t dex_offset;
    uint32_t dex_pc;
    DecodeError(DecodeCode value, uint64_t offset, uint32_t pc, const char* message)
        : std::runtime_error(message), code(value), dex_offset(offset), dex_pc(pc) {}
};
struct RefBounds {
    uint32_t strings = 0, types = 0, fields = 0, methods = 0, protos = 0;
    uint32_t call_sites = 0, method_handles = 0;
};
struct DecodeInput {
    std::span<const uint8_t> dex;
    uint32_t code_offset = 0;
    uint32_t dex_version = 35;
    RefBounds refs;
    uint64_t code_end = 0; // Exclusive metadata-checked extent; zero means the supplied span ends here.
    bool experimental_041 = false;
};
enum Demand : uint32_t { strings = 1, invokes = 2, fields = 4, numeric = 8, array_data = 16, switch_targets = 32, branch_targets = 64, method_constants = 128, type_uses = 256, opcode_list = 512 };
struct DecodeOptions {
    uint32_t demand_mask = 0;
    uint32_t max_code_units = 1'048'576;
    uint32_t max_instructions = 1'048'576;
    uint64_t max_payload_elements = 1'048'576;
    uint64_t max_exception_items = 1'048'576;
    uint64_t max_validation_work = UINT64_MAX;
    bool (*cancelled)(void*) noexcept = nullptr;
    void* cancel_context = nullptr;
};
enum class PayloadKind : uint8_t { none = 0, packed_switch = 1, sparse_switch = 2, array_data = 3 };
enum class ReferenceKind : uint8_t { method, call_site, method_and_proto };
struct Instruction { uint32_t pc, width; uint8_t opcode; PayloadKind payload_kind; };
struct StringUse { uint32_t pc, string_index; uint8_t opcode; };
struct InvokeSite { uint32_t pc, index, extra_proto; uint8_t opcode; ReferenceKind reference_kind; };
struct FieldUse { uint32_t pc, field_index; uint8_t opcode; };
struct TypeUse { uint32_t pc, type_index; uint8_t opcode; };
enum class ConstantDomain : uint8_t { method_handle, method_type };
// Local table identity only: this is not an invocation or a resolved target.
struct MethodConstant { uint32_t pc, index, destination; uint8_t opcode; ConstantDomain domain; };
// Literal bit patterns, not computed values or inferred runtime numeric types.
enum class NumericKind : uint8_t { constant, arithmetic_operand };
struct NumericLiteral { uint32_t pc; uint64_t bits; uint8_t opcode, width_bits; NumericKind kind; };
// Referenced payload element bytes, not inferred types or runtime array values.
struct ArrayDataElement { uint32_t pc, payload_pc, element_index; uint64_t bits; uint8_t width_bytes; };
// Signed DEX case key and checked local target, not a reachable CFG edge.
struct SwitchTarget { uint32_t pc, payload_pc, target_pc, case_index; int32_t key; PayloadKind payload_kind; };
// Checked encoded goto/if destination only, not a claim of reachability or a complete CFG edge.
enum class BranchKind : uint8_t { unconditional, conditional };
struct BranchTarget { uint32_t pc, target_pc; uint8_t opcode; BranchKind kind; };
struct DecodeResult {
    explicit DecodeResult(std::pmr::memory_resource* resource = std::pmr::get_default_resource())
        : instructions(resource), string_uses(resource), invoke_sites(resource), field_uses(resource), numeric_literals(resource), array_elements(resource), switch_cases(resource), branches(resource), method_constants(resource), type_uses(resource) {}
    uint32_t code_units = 0;
    uint64_t payload_work = 0;
    uint64_t exception_work = 0;
    uint64_t validation_work = 0;
    std::pmr::vector<Instruction> instructions;
    std::pmr::vector<StringUse> string_uses;
    std::pmr::vector<InvokeSite> invoke_sites;
    std::pmr::vector<FieldUse> field_uses;
    std::pmr::vector<NumericLiteral> numeric_literals;
    std::pmr::vector<ArrayDataElement> array_elements;
    std::pmr::vector<SwitchTarget> switch_cases;
    std::pmr::vector<BranchTarget> branches;
    std::pmr::vector<MethodConstant> method_constants;
    std::pmr::vector<TypeUse> type_uses;
};
// Input table bounds and code_item provenance come from a checked metadata reader.
// Checks widths, local reference/register bounds, payloads, branches and try/handler boundaries.
// Does not validate runtime types, invoke signature word counts, move-result placement,
// exception types, reachable fallthrough, CFG or dataflow semantics.
DecodeResult decode(const DecodeInput& input, const DecodeOptions& options = {},
    std::pmr::memory_resource* resource = std::pmr::get_default_resource());
}
