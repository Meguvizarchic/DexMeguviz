#include "debug_positions.hpp"
#include "format/checked_leb128.hpp"
#include <algorithm>
#include <limits>
#include <map>

namespace dexmeguviz::debug {
namespace {
uint32_t word32(std::span<const uint8_t> data, uint64_t pos) {
    if (pos > data.size() || data.size() - pos < 4) throw ReadError(ReadCode::corrupt, pos, "truncated debug offset");
    return uint32_t(data[pos]) | (uint32_t(data[pos + 1]) << 8) | (uint32_t(data[pos + 2]) << 16) | (uint32_t(data[pos + 3]) << 24);
}
uint32_t narrow(size_t n) {
    if (n > UINT32_MAX) throw ReadError(ReadCode::budget, 0, "metadata table exceeds local index width");
    return static_cast<uint32_t>(n);
}
void check_cancel(const Options& options,uint64_t offset,uint32_t pc) {
    if(options.cancelled && options.cancelled(options.cancel_context))
        throw instructions::DecodeError(instructions::DecodeCode::cancelled,offset,pc,"debug diagnostic cancelled");
}
template<class Charge>
PositionKind classify(uint64_t pc,uint32_t units,std::span<const instructions::Instruction> code,Charge&& charge) {
    charge();
    if(pc>units)return PositionKind::unknown;
    if(pc==units)return PositionKind::code_end;
    size_t lo=0,hi=code.size();
    while(lo<hi){charge();const size_t mid=lo+(hi-lo)/2;if(code[mid].pc<=pc)lo=mid+1;else hi=mid;}
    if(lo==0)return PositionKind::unknown;
    const auto& item=code[lo-1];
    if(item.pc>=units||!item.width||item.width>units-item.pc||pc-item.pc>=item.width)return PositionKind::unknown;
    const bool start=item.pc==pc;
    switch(item.payload_kind){
    case instructions::PayloadKind::none:return start?PositionKind::instruction_start:PositionKind::instruction_interior;
    case instructions::PayloadKind::packed_switch:case instructions::PayloadKind::sparse_switch:case instructions::PayloadKind::array_data:
        return start?PositionKind::payload_start:PositionKind::payload_interior;
    default:return PositionKind::unknown;
    }
}
}
PositionKind classify_local_pc(uint64_t pc,uint32_t units,std::span<const instructions::Instruction> code) noexcept {
    return classify(pc,units,code,[]{});
}
Result positions(std::span<const uint8_t> bytes, const Facts& facts, uint32_t ordinal,
                 const Options& options, std::pmr::memory_resource* resource) {
    if (ordinal >= facts.methods.size()) throw std::out_of_range("method ordinal exceeds definition directory");
    check_cancel(options,0,0);
    Result result(resource);
    const auto& method = facts.methods[ordinal];
    if (!method.code_offset) return result;
    const auto offset = word32(bytes, uint64_t(method.code_offset) + 8);
    if (!offset) return result;
    if (offset >= bytes.size()) throw ReadError(ReadCode::corrupt, offset, "debug offset exceeds DEX");
    result.has_debug_info = true;
    instructions::DecodeInput input{bytes, method.code_offset, facts.dex_version,
        {narrow(facts.strings.size()), narrow(facts.types.size()), narrow(facts.field_refs.size()),
         narrow(facts.method_refs.size()), narrow(facts.prototypes.size()), facts.call_site_count, facts.method_handle_count}, method.code_end};
    instructions::DecodeOptions decode_options;
    decode_options.max_validation_work = options.max_decode_work;
    decode_options.cancelled = options.cancelled;
    decode_options.cancel_context = options.cancel_context;
    const auto decoded = instructions::decode(input, decode_options, resource);
    result.decoded_work = decoded.validation_work;
    uint64_t cursor = offset, address = 0;
    auto uleb = [&]() { return detail::read_uleb32(bytes, cursor, bytes.size()); };
    auto sleb = [&]() { return detail::read_sleb32(bytes, cursor, bytes.size()); };
    (void)uleb();
    auto parameters = uleb();
    if (parameters > 65536) throw ReadError(ReadCode::corrupt, cursor, "debug parameter count exceeds format limit");
    while (parameters--) (void)uleb();
    uint32_t used = 0;
    for (;;) {
        check_cancel(options,cursor,static_cast<uint32_t>(address));
        if (used == options.max_opcodes) throw ReadError(ReadCode::budget, cursor, "debug opcode work limit exceeded");
        ++used;
        if (cursor >= bytes.size()) throw ReadError(ReadCode::corrupt, cursor, "truncated debug opcode");
        const auto at = cursor;
        const uint8_t opcode = bytes[cursor++];
        switch (opcode) {
        case 0: return result;
        case 1: address += uleb(); break;
        case 2: (void)sleb(); break;
        case 3: (void)uleb(); (void)uleb(); (void)uleb(); break;
        case 4: (void)uleb(); (void)uleb(); (void)uleb(); (void)uleb(); break;
        case 5: case 6: case 9: (void)uleb(); break;
        case 7: case 8: break;
        default: {
            address += (uint32_t(opcode) - 10) / 15;
            if (address > decoded.code_units) throw ReadError(ReadCode::corrupt, at, "debug position exceeds code instruction count");
            if (result.positions.size() == options.max_positions) throw ReadError(ReadCode::budget, at, "debug position limit exceeded");
            PositionKind kind = PositionKind::code_end;
            if (address < decoded.code_units) {
                const auto after = std::upper_bound(decoded.instructions.begin(), decoded.instructions.end(), address,
                    [](uint64_t value, const instructions::Instruction& instruction) { return value < instruction.pc; });
                if (after == decoded.instructions.begin()) throw ReadError(ReadCode::corrupt, at, "missing decoded instruction");
                const auto& instruction = *std::prev(after);
                const bool start = instruction.pc == address;
                kind = instruction.payload_kind == instructions::PayloadKind::none
                    ? (start ? PositionKind::instruction_start : PositionKind::instruction_interior)
                    : (start ? PositionKind::payload_start : PositionKind::payload_interior);
            }
            result.positions.push_back({static_cast<uint32_t>(address), at, kind});
            break;
        }
        }
        if (address > decoded.code_units) throw ReadError(ReadCode::corrupt, at, "debug address exceeds code instruction count");
    }
}

LocalResult local_events(std::span<const uint8_t> bytes, const Facts& facts, uint32_t ordinal,
                         const Options& options, std::pmr::memory_resource* resource) {
    if (ordinal >= facts.methods.size()) throw std::out_of_range("method ordinal exceeds definition directory");
    check_cancel(options,0,0);
    LocalResult result(resource);
    result.boundary_classification_requested=options.classify_local_boundaries;
    const auto& method = facts.methods[ordinal];
    if (!method.code_offset) return result;
    const auto offset = word32(bytes, uint64_t(method.code_offset) + 8);
    if (!offset) return result;
    if (offset >= bytes.size()) throw ReadError(ReadCode::corrupt, offset, "debug offset exceeds DEX");
    result.has_debug_info = true;
    instructions::DecodeInput input{bytes, method.code_offset, facts.dex_version,
        {narrow(facts.strings.size()), narrow(facts.types.size()), narrow(facts.field_refs.size()),
         narrow(facts.method_refs.size()), narrow(facts.prototypes.size()), facts.call_site_count, facts.method_handle_count}, method.code_end};
    instructions::DecodeOptions decode_options;
    decode_options.max_validation_work = options.max_decode_work;
    decode_options.cancelled = options.cancelled;
    decode_options.cancel_context = options.cancel_context;
    const auto decoded = instructions::decode(input, decode_options, resource);
    result.decoded_work = decoded.validation_work;
    const uint64_t code = method.code_offset;
    if (code > bytes.size() || bytes.size() - code < 2) throw ReadError(ReadCode::corrupt, code, "truncated register count");
    const uint32_t registers = uint32_t(bytes[code]) | (uint32_t(bytes[code + 1]) << 8);
    uint64_t cursor = offset, address = 0;
    auto uleb = [&]() { return detail::read_uleb32(bytes, cursor, bytes.size()); };
    auto sleb = [&]() { return detail::read_sleb32(bytes, cursor, bytes.size()); };
    auto optional_index = [&](size_t count) {
        const auto at = cursor;
        const auto value = uleb();
        if (value && uint64_t(value - 1) >= count) throw ReadError(ReadCode::corrupt, at, "debug local index exceeds table");
        return value;
    };
    (void)uleb();
    auto parameters = uleb();
    if (parameters > 65536) throw ReadError(ReadCode::corrupt, cursor, "debug parameter count exceeds format limit");
    while (parameters--) (void)optional_index(facts.strings.size());
    uint32_t used = 0;
    for (;;) {
        check_cancel(options,cursor,static_cast<uint32_t>(address));
        if (used == options.max_opcodes) throw ReadError(ReadCode::budget, cursor, "debug opcode work limit exceeded");
        ++used;
        if (cursor >= bytes.size()) throw ReadError(ReadCode::corrupt, cursor, "truncated debug opcode");
        const auto at = cursor;
        const uint8_t opcode = bytes[cursor++];
        switch (opcode) {
        case 0: return result;
        case 1: address += uleb(); break;
        case 2: (void)sleb(); break;
        case 3: case 4: case 5: case 6: {
            const auto reg_at = cursor;
            const auto reg = uleb();
            if (reg >= registers) throw ReadError(ReadCode::corrupt, reg_at, "debug register exceeds code register count");
            uint32_t name = 0, type = 0, signature = 0;
            if (opcode == 3 || opcode == 4) {
                name = optional_index(facts.strings.size());
                type = optional_index(facts.types.size());
                if (opcode == 4) signature = optional_index(facts.strings.size());
            }
            if (result.events.size() == options.max_local_events) throw ReadError(ReadCode::budget, at, "debug local event limit exceeded");
            const auto kind = opcode == 3 ? LocalKind::start : opcode == 4 ? LocalKind::start_extended :
                              opcode == 5 ? LocalKind::end : LocalKind::restart;
            PositionKind boundary=PositionKind::unknown;
            if(options.classify_local_boundaries){
                auto charge=[&]{
                    if(result.boundary_work>=options.max_boundary_work)throw ReadError(ReadCode::budget,at,"debug local boundary work limit exceeded");
                    ++result.boundary_work;if((result.boundary_work&63)==1)check_cancel(options,at,static_cast<uint32_t>(address));
                };
                boundary=classify(address,decoded.code_units,decoded.instructions,charge);
            }
            result.events.push_back({kind, static_cast<uint32_t>(address), reg, name, type, signature, at, boundary});
            break;
        }
        case 7: case 8: break;
        case 9: (void)optional_index(facts.strings.size()); break;
        default: address += (uint32_t(opcode) - 10) / 15; break;
        }
        if (address > decoded.code_units) throw ReadError(ReadCode::corrupt, at, "debug address exceeds code instruction count");
    }
}

LifecycleResult local_lifecycle(std::span<const uint8_t> bytes, const Facts& facts, uint32_t ordinal,
                                const Options& options, std::pmr::memory_resource* resource) {
    const auto events = local_events(bytes, facts, ordinal, options, resource);
    LifecycleResult result(resource);
    result.has_debug_info = events.has_debug_info;
    result.boundary_classification_requested = events.boundary_classification_requested;
    result.decoded_work = events.decoded_work;
    result.boundary_work = events.boundary_work;
    struct State {
        LocalLiveness live = LocalLiveness::unknown;
        bool identity_known = false;
        uint32_t name = 0, type = 0, signature = 0;
    };
    std::pmr::map<uint32_t, State> states(resource);
    result.transitions.reserve(events.events.size());
    for (const auto& event : events.events) {
        check_cancel(options,event.debug_offset,event.dex_pc);
        auto& state = states[event.register_index];
        const auto before = state.live;
        const bool end_after_known_end = event.kind == LocalKind::end && before == LocalLiveness::ended;
        const bool restart_while_known_live = event.kind == LocalKind::restart && before == LocalLiveness::live;
        if (event.kind == LocalKind::start || event.kind == LocalKind::start_extended) {
            state.identity_known = true;
            state.name = event.name_index_p1;
            state.type = event.type_index_p1;
            state.signature = event.signature_index_p1;
            state.live = LocalLiveness::live;
        } else if (event.kind == LocalKind::end) {
            state.live = LocalLiveness::ended;
        } else {
            state.live = LocalLiveness::live;
        }
        result.transitions.push_back({event, before, state.live, state.identity_known,
                                      state.name, state.type, state.signature,
                                      end_after_known_end, restart_while_known_live});
    }
    return result;
}
}
