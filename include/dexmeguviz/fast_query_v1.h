#ifndef DEXMEGUVIZ_FAST_QUERY_V1_H
#define DEXMEGUVIZ_FAST_QUERY_V1_H

#include "dexmeguviz.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Candidate-only DEX reader. The caller explicitly guarantees immutable,
 * structurally valid input and sorted DEX ID tables for the entire call.
 * Untouched portions are not checked; an empty result never proves absence.
 * These handles own their copied plans/results, not the input bytes. */
typedef struct dmg_fast_plans_v1 dmg_fast_plans_v1;
typedef struct dmg_fast_results_v1 dmg_fast_results_v1;
typedef struct {
    const uint8_t* bytes;
    uint64_t size;
    uint32_t capture_calls;
} dmg_fast_rule_v1;
typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint64_t max_dex_bytes;
    uint32_t max_total_rows;
    uint32_t max_total_calls;
    uint64_t max_output_utf16_units;
    uint32_t max_code_units;
    uint32_t max_instructions;
    uint32_t caller_asserts_valid_sorted_dex;
    uint32_t reserved;
} dmg_fast_limits_v1;
typedef struct {
    uint32_t relation; /* 0 = method_defs, 1 = class_defs. */
    uint32_t execution_status;
    uint32_t candidates_count;
    uint32_t unknown_rows;
    uint32_t result_limit;
    uint32_t coverage; /* Always DMG_COVERAGE_PARTIAL in v1. */
    /* Conditional on caller_asserts_valid_sorted_dex, this rule exhausted its
     * selected predicate domain without unknown/error/limit. This is an
     * assertion, not independent validation of input or the complete DEX set. */
    uint32_t caller_asserted_exhaustive;
    uint64_t selected_methods_visited, selected_bodies_decoded, class_defs_visited;
    const char* query_id;
} dmg_fast_rule_info_v1;
typedef struct {
    uint32_t method_ref, access_flags, declaration_offset, code_offset;
    const uint16_t* owner; uint32_t owner_length;
    const uint16_t* name; uint32_t name_length;
    const uint16_t* prototype; uint32_t prototype_length;
    uint32_t call_count;
} dmg_fast_method_v1;
typedef struct {
    uint32_t local_index, type_index, definition_offset, access_flags;
    const uint16_t* descriptor; uint32_t descriptor_length;
} dmg_fast_class_v1;
typedef struct {
    uint32_t pc, target_ref, extra_proto, opcode, reference_kind;
    const uint16_t* owner; uint32_t owner_length;
    const uint16_t* name; uint32_t name_length;
    const uint16_t* prototype; uint32_t prototype_length;
    const uint16_t* extra_prototype; uint32_t extra_prototype_length;
} dmg_fast_call_v1;

/* At most 16 rules and 1 MiB of total JSON are accepted. Supports only
 * explicitly implemented QueryIR shapes; unsupported plans fail
 * compilation rather than silently widening the predicate. Plans are immutable
 * after creation and may be read concurrently. */
dmg_status dmg_fast_compile_v1(const dmg_fast_rule_v1* rules, uint32_t count,
    dmg_fast_plans_v1** out, uint32_t* failure_index, dmg_error* error);
void dmg_fast_plans_release_v1(dmg_fast_plans_v1* plans);
/* All results publish atomically. Bytes must not change while scanning.
 * The decoder limits are per selected method; result limits are per scan.
 * Fast-path allocations use standard C++ allocation, not an Engine account;
 * the bounds above are not a complete process RSS limit. QueryIR max_work is
 * not applied in this selected-only mode. */
dmg_status dmg_fast_scan_v1(const dmg_fast_plans_v1* plans, const uint8_t* dex,
    uint64_t size, const dmg_fast_limits_v1* limits,
    dmg_fast_results_v1** out, uint32_t* failure_index, dmg_error* error);
void dmg_fast_results_release_v1(dmg_fast_results_v1* results);
dmg_status dmg_fast_results_count_v1(const dmg_fast_results_v1* results, uint32_t* out);
dmg_status dmg_fast_rule_info_get_v1(const dmg_fast_results_v1* results, uint32_t rule, dmg_fast_rule_info_v1* out);
dmg_status dmg_fast_method_get_v1(const dmg_fast_results_v1* results, uint32_t rule, uint32_t row, dmg_fast_method_v1* out);
dmg_status dmg_fast_class_get_v1(const dmg_fast_results_v1* results, uint32_t rule, uint32_t row, dmg_fast_class_v1* out);
dmg_status dmg_fast_call_get_v1(const dmg_fast_results_v1* results, uint32_t rule, uint32_t row, uint32_t call, dmg_fast_call_v1* out);

#ifdef __cplusplus
}
#endif
#endif
