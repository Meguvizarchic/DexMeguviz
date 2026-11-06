#pragma once
#include "format/reader.hpp"
#include "format/instructions/decoder.hpp"

namespace dexmeguviz::debug {
// Classification is diagnostic; it does not assert ART validity.
enum class PositionKind { instruction_start, instruction_interior, payload_start, payload_interior, code_end, unknown };
struct Position { uint32_t dex_pc; uint64_t debug_offset; PositionKind kind; };
struct Options {
    uint32_t max_opcodes = 1000000;
    uint32_t max_positions = 1000000;
    uint64_t max_decode_work = 1000000;
    uint32_t max_local_events = 1000000;
    // Explicit diagnostic only; false retains unknown on each local event.
    bool classify_local_boundaries = false;
    uint64_t max_boundary_work = 1000000;
    bool (*cancelled)(void*) noexcept = nullptr;
    void* cancel_context = nullptr;
};
struct Result {
    explicit Result(std::pmr::memory_resource* resource = std::pmr::get_default_resource()) : positions(resource) {}
    bool has_debug_info = false;
    uint64_t decoded_work = 0;
    std::pmr::vector<Position> positions;
};
// bytes and facts must be the same immutable, metadata-checked DEX snapshot.
// Checked decoder errors propagate. End-of-code and payload are reported, never adjudicated.
Result positions(std::span<const uint8_t> bytes, const Facts& facts, uint32_t method_ordinal,
                 const Options& options = {}, std::pmr::memory_resource* resource = std::pmr::get_default_resource());

enum class LocalKind { start, start_extended, end, restart };
struct LocalEvent {
    LocalKind kind;
    uint32_t dex_pc, register_index;
    // Raw uleb128p1 operands: zero means absent; end/restart have all zero.
    uint32_t name_index_p1, type_index_p1, signature_index_p1;
    uint64_t debug_offset;
    PositionKind boundary = PositionKind::unknown;
};
// Requires the same method's complete, ordered, nonoverlapping checked decoder
// spans. A missing covering item or invalid selected item yields unknown; the
// numeric code endpoint is classified without examining spans. No global span
// validation is performed, so arbitrary reordered or overlapping input is invalid.
PositionKind classify_local_pc(uint64_t pc, uint32_t code_units,
                               std::span<const instructions::Instruction> instructions) noexcept;
struct LocalResult {
    explicit LocalResult(std::pmr::memory_resource* resource = std::pmr::get_default_resource()) : events(resource) {}
    bool has_debug_info = false, boundary_classification_requested = false;
    uint64_t decoded_work = 0, boundary_work = 0;
    std::pmr::vector<LocalEvent> events;
};
// Events only; no implied initial locals or lifecycle/type/ART validity judgment.
// bytes and facts must be the same immutable, metadata-checked DEX snapshot.
LocalResult local_events(std::span<const uint8_t> bytes, const Facts& facts, uint32_t method_ordinal,
                         const Options& options = {}, std::pmr::memory_resource* resource = std::pmr::get_default_resource());

// Tracks explicit debug events only. Initial parameter/receiver locals are
// unknown; these observations do not decide verifier or runtime validity.
enum class LocalLiveness { unknown, live, ended };
struct LocalTransition {
    LocalEvent event;
    LocalLiveness before, after;
    bool last_identity_known;
    uint32_t name_index_p1, type_index_p1, signature_index_p1;
    bool end_after_known_end, restart_while_known_live;
};
struct LifecycleResult {
    explicit LifecycleResult(std::pmr::memory_resource* resource = std::pmr::get_default_resource()) : transitions(resource) {}
    bool has_debug_info = false, boundary_classification_requested = false;
    uint64_t decoded_work = 0, boundary_work = 0;
    std::pmr::vector<LocalTransition> transitions;
};
// Applies events in bytecode order. No implicit end at method/code end is added.
LifecycleResult local_lifecycle(std::span<const uint8_t> bytes, const Facts& facts, uint32_t method_ordinal,
                                const Options& options = {}, std::pmr::memory_resource* resource = std::pmr::get_default_resource());
}
