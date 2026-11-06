#include "decoder.hpp"
#include "format/checked_leb128.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <limits>

namespace dexmeguviz::instructions {
namespace {
// Original organization of format facts, cross-checked with AOSP art commit
// 6484611fd45e69db9f33f98bfd6864014b030ecf, dex_instruction_list.h
// (blob bbd7abd8e52b31ac293b416f8527a439ea9b6bab). No upstream implementation copied.
constexpr std::array<uint8_t, 256> widths{
    1,1,2,3,1,2,3,1,2,3,1,1,1,1,1,1,
    1,1,1,2,3,2,2,3,5,2,2,3,2,1,1,2,
    2,1,2,2,3,3,3,1,1,2,3,3,3,2,2,2,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,0,0,
    0,0,0,0,2,2,2,2,2,2,2,2,2,2,2,2,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,3,3,
    3,3,3,0,3,3,3,3,3,0,0,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    2,2,2,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,4,4,3,3,2,2,
};

class Decoder {
public:
    Decoder(const DecodeInput& input, const DecodeOptions& options, std::pmr::memory_resource* resource)
        : input(input), options(options), result(resource), byte_end(input.code_end ? input.code_end : input.dex.size()) {}
    DecodeResult run() {
        if (options.demand_mask & ~(Demand::strings | Demand::invokes | Demand::fields | Demand::numeric | Demand::array_data | Demand::switch_targets | Demand::branch_targets | Demand::method_constants | Demand::type_uses | Demand::opcode_list))
            fail(DecodeCode::unsupported, 0, "unknown required decoder capability");
        if (input.dex_version != 35 && input.dex_version != 37 && input.dex_version != 38 &&
            input.dex_version != 39 && input.dex_version != 40 && !(input.dex_version==41&&input.experimental_041))
            fail(DecodeCode::unsupported, 0, "unsupported DEX instruction version");
        check_cancel(0);
        if(byte_end > input.dex.size() || input.code_offset >= byte_end)
            fail(DecodeCode::corrupt, 0, "invalid checked code_item extent");
        if (input.code_offset % 4) fail(DecodeCode::corrupt, 0, "misaligned code_item");
        byte_range(input.code_offset, 16);
        registers = read16(input.code_offset);
        const auto incoming = read16(uint64_t(input.code_offset) + 2);
        outgoing = read16(uint64_t(input.code_offset) + 4);
        if (incoming > registers) fail(DecodeCode::corrupt, 0, "ins_size exceeds registers_size");
        result.code_units = read32(uint64_t(input.code_offset) + 12);
        if (!result.code_units) fail(DecodeCode::corrupt, 0, "empty instruction stream");
        if (result.code_units > options.max_code_units) fail(DecodeCode::budget, 0, "code unit work limit exceeded");
        if (result.code_units > options.max_validation_work) fail(DecodeCode::budget, 0, "total decoder work limit exceeded");
        result.validation_work = result.code_units;
        start = uint64_t(input.code_offset) + 16;
        byte_range(start, uint64_t(result.code_units) * 2);
        first_pass();
        if (result.instructions.front().payload_kind != PayloadKind::none)
            fail(DecodeCode::corrupt, 0, "method entry cannot be a payload");
        second_pass();
        exception_boundaries();
        check_cancel(result.code_units);
        return std::move(result);
    }
private:
    const DecodeInput& input;
    const DecodeOptions& options;
    DecodeResult result;
    uint64_t start = 0;
    uint64_t byte_end;
    uint16_t registers = 0, outgoing = 0;

    [[noreturn]] void fail(DecodeCode code, uint32_t pc, const char* message) const {
        throw DecodeError(code, uint64_t(input.code_offset) + 16 + uint64_t(pc) * 2, pc, message);
    }
    void check_cancel(uint32_t pc) const {
        if (options.cancelled && options.cancelled(options.cancel_context)) fail(DecodeCode::cancelled, pc, "instruction decoding cancelled");
    }
    void byte_range(uint64_t at, uint64_t size) const {
        if (at > byte_end || size > byte_end - at)
            throw DecodeError(DecodeCode::corrupt, at, 0, "truncated code_item bytes");
    }
    uint16_t read16(uint64_t at) const {
        byte_range(at, 2);
        return static_cast<uint16_t>(uint16_t(input.dex[at]) | (uint16_t(input.dex[at + 1]) << 8));
    }
    uint32_t read32(uint64_t at) const {
        byte_range(at, 4);
        return uint32_t(input.dex[at]) | (uint32_t(input.dex[at + 1]) << 8) |
            (uint32_t(input.dex[at + 2]) << 16) | (uint32_t(input.dex[at + 3]) << 24);
    }
    void code_range(uint32_t pc, uint64_t width) const {
        if (pc > result.code_units || width > uint64_t(result.code_units) - pc)
            fail(DecodeCode::corrupt, pc, "instruction or payload exceeds insns_size");
    }
    uint16_t unit(uint32_t pc) const { code_range(pc, 1); return read16(start + uint64_t(pc) * 2); }
    uint32_t pair(uint32_t pc) const { code_range(pc, 2); return read32(start + uint64_t(pc) * 2); }
    int32_t signed_pair(uint32_t pc) const { return std::bit_cast<int32_t>(pair(pc)); }
    void reg(uint32_t pc, uint32_t index, bool wide = false) const {
        const uint32_t width = wide ? 2 : 1;
        if (index >= registers || width > uint32_t(registers) - index)
            fail(DecodeCode::corrupt, pc, "register operand exceeds registers_size");
    }
    void reference(uint32_t pc, uint32_t index, uint32_t bound) const {
        if (index >= bound) fail(DecodeCode::corrupt, pc, "instruction reference index exceeds its table");
    }
    void payload_work(uint32_t pc, uint64_t count) {
        if (count > options.max_validation_work - result.validation_work)
            fail(DecodeCode::budget, pc, "total decoder work limit exceeded");
        if (count > options.max_payload_elements - result.payload_work)
            fail(DecodeCode::budget, pc, "payload validation work limit exceeded");
        result.payload_work += count;
        result.validation_work += count;
    }
    static bool in(uint8_t value, uint8_t lower, uint8_t upper) { return value >= lower && value <= upper; }
    static bool invoke(uint8_t opcode) { return in(opcode, 0x6e, 0x72) || in(opcode, 0x74, 0x78) || in(opcode, 0xfa, 0xfd); }
    void collect_numeric(uint32_t pc, uint8_t op, uint16_t first) {
        if (!(options.demand_mask & Demand::numeric)) return;
        uint64_t bits = 0;
        uint8_t width = 32;
        auto kind = NumericKind::constant;
        if (op == 0x12) {
            const int32_t nibble = (first >> 12) & 15;
            bits = static_cast<uint32_t>(nibble >= 8 ? nibble - 16 : nibble);
        } else if (op == 0x13) {
            bits = static_cast<uint32_t>(std::bit_cast<int16_t>(unit(pc + 1)));
        } else if (op == 0x14) {
            bits = pair(pc + 1);
        } else if (op == 0x15) {
            bits = uint32_t(unit(pc + 1)) << 16;
        } else if (op == 0x16) {
            width = 64;
            bits = static_cast<uint64_t>(static_cast<int64_t>(std::bit_cast<int16_t>(unit(pc + 1))));
        } else if (op == 0x17) {
            width = 64;
            bits = static_cast<uint64_t>(static_cast<int64_t>(std::bit_cast<int32_t>(pair(pc + 1))));
        } else if (op == 0x18) {
            width = 64;
            bits = uint64_t(pair(pc + 1)) | (uint64_t(pair(pc + 3)) << 32);
        } else if (op == 0x19) {
            width = 64;
            bits = uint64_t(unit(pc + 1)) << 48;
        } else if (in(op, 0xd0, 0xd7)) {
            kind = NumericKind::arithmetic_operand;
            bits = static_cast<uint32_t>(std::bit_cast<int16_t>(unit(pc + 1)));
        } else if (in(op, 0xd8, 0xe2)) {
            kind = NumericKind::arithmetic_operand;
            bits = static_cast<uint32_t>(std::bit_cast<int8_t>(static_cast<uint8_t>(unit(pc + 1) >> 8)));
        } else {
            return;
        }
        result.numeric_literals.push_back({pc, bits, op, width, kind});
    }
    void operands(uint32_t pc, uint8_t op, uint16_t first) {
        const uint32_t a8 = first >> 8, a4 = a8 & 15, b4 = a8 >> 4;
        if (op == 0 || op == 0x0e || op == 0x29 || op == 0x2a || op == 3 || op == 6 || op == 9) {
            if (a8) fail(DecodeCode::corrupt, pc, "reserved instruction operand bits must be zero");
        }
        if (op == 1 || op == 4 || op == 7 || op == 0x21 || in(op, 0x7b, 0x8f) || in(op, 0xb0, 0xcf)) {
            bool aw = op == 4, bw = op == 4;
            if (in(op, 0x7b, 0x8f)) {
                aw = op == 0x7d || op == 0x7e || op == 0x80 || op == 0x81 || op == 0x83 || op == 0x86 || op == 0x88 || op == 0x89 || op == 0x8b;
                bw = op == 0x7d || op == 0x7e || op == 0x80 || in(op, 0x84, 0x86) || in(op, 0x8a, 0x8c);
            }
            if (in(op, 0xb0, 0xcf)) { aw = in(op, 0xbb, 0xc5) || in(op, 0xcb, 0xcf); bw = in(op, 0xbb, 0xc2) || in(op, 0xcb, 0xcf); }
            reg(pc, a4, aw); reg(pc, b4, bw);
        } else if (op == 2 || op == 5 || op == 8) {
            reg(pc, a8, op == 5); reg(pc, unit(pc + 1), op == 5);
        } else if (op == 3 || op == 6 || op == 9) {
            reg(pc, unit(pc + 1), op == 6); reg(pc, unit(pc + 2), op == 6);
        } else if (op == 0x12) {
            reg(pc, a4);
        } else if (op == 0x20 || op == 0x23 || in(op, 0x32, 0x37) || in(op, 0x52, 0x5f) || in(op, 0xd0, 0xd7)) {
            reg(pc, a4, op == 0x53 || op == 0x5a); reg(pc, b4);
        } else if (in(op, 0x2d, 0x31) || in(op, 0x44, 0x51) || in(op, 0x90, 0xaf)) {
            bool aw = op == 0x45 || op == 0x4c;
            bool bw = in(op, 0x2f, 0x31), cw = bw;
            if (in(op, 0x90, 0xaf)) {
                aw = bw = in(op, 0x9b, 0xa5) || in(op, 0xab, 0xaf);
                cw = in(op, 0x9b, 0xa2) || in(op, 0xab, 0xaf);
            }
            reg(pc, a8, aw); reg(pc, unit(pc + 1) & 255, bw); reg(pc, unit(pc + 1) >> 8, cw);
        } else if (in(op, 0xd8, 0xe2)) {
            reg(pc, a8); reg(pc, unit(pc + 1) & 255);
        } else if (op == 0x24 || op == 0x25 || invoke(op)) {
            const bool range = op == 0x25 || in(op, 0x74, 0x78) || op == 0xfb || op == 0xfd;
            const uint32_t count = range ? a8 : b4;
            if (invoke(op) && count > outgoing) fail(DecodeCode::corrupt, pc, "invoke argument words exceed outs_size");
            if (range) {
                const uint32_t first_reg = unit(pc + 2);
                if (first_reg > registers || count > uint32_t(registers) - first_reg)
                    fail(DecodeCode::corrupt, pc, "range registers exceed registers_size");
            } else {
                if (count > 5) fail(DecodeCode::corrupt, pc, "non-range argument count exceeds five");
                const uint16_t packed = unit(pc + 2);
                const std::array<uint32_t, 5> arguments{uint32_t(packed & 15), uint32_t((packed >> 4) & 15), uint32_t((packed >> 8) & 15), uint32_t(packed >> 12), a4};
                for (uint32_t i = 0; i < count; ++i) reg(pc, arguments[i]);
            }
        } else if (op != 0 && op != 0x0e && !in(op, 0x28, 0x2a)) {
            reg(pc, a8, op == 0x0b || op == 0x10 || in(op, 0x16, 0x19) || op == 0x61 || op == 0x68);
        }

        if (op == 0x1a || op == 0x1b) {
            const auto id = op == 0x1a ? uint32_t(unit(pc + 1)) : pair(pc + 1);
            reference(pc, id, input.refs.strings);
            if (options.demand_mask & Demand::strings) result.string_uses.push_back({pc, id, op});
        } else if (op == 0x1c || op == 0x1f || op == 0x20 || op == 0x22 || op == 0x23 || op == 0x24 || op == 0x25) {
            const auto id=unit(pc + 1);reference(pc,id,input.refs.types);
            if(options.demand_mask & Demand::type_uses){
                if(result.validation_work==options.max_validation_work)fail(DecodeCode::budget,pc,"total decoder work limit exceeded");
                ++result.validation_work;result.type_uses.push_back({pc,id,op});
            }
        } else if (in(op, 0x52, 0x6d)) {
            const auto id = unit(pc + 1);
            reference(pc, id, input.refs.fields);
            if (options.demand_mask & Demand::fields) result.field_uses.push_back({pc, id, op});
        } else if (invoke(op)) {
            const auto id = unit(pc + 1);
            const bool custom = op == 0xfc || op == 0xfd, polymorphic = op == 0xfa || op == 0xfb;
            reference(pc, id, custom ? input.refs.call_sites : input.refs.methods);
            const uint32_t proto = polymorphic ? uint32_t(unit(pc + 3)) : std::numeric_limits<uint32_t>::max();
            if (polymorphic) reference(pc, proto, input.refs.protos);
            if (options.demand_mask & Demand::invokes) result.invoke_sites.push_back({pc, id, proto, op,
                custom ? ReferenceKind::call_site : polymorphic ? ReferenceKind::method_and_proto : ReferenceKind::method});
        } else if (op == 0xfe || op == 0xff) {
            const auto id = unit(pc + 1);
            reference(pc, id, op == 0xfe ? input.refs.method_handles : input.refs.protos);
            if (options.demand_mask & Demand::method_constants) {
                if (result.validation_work == options.max_validation_work)
                    fail(DecodeCode::budget, pc, "total decoder work limit exceeded");
                ++result.validation_work;
                result.method_constants.push_back({pc, id, a8, op,
                    op == 0xfe ? ConstantDomain::method_handle : ConstantDomain::method_type});
            }
        }
    }
    uint32_t payload(uint32_t pc, uint16_t first) {
        if (pc & 1) fail(DecodeCode::corrupt, pc, "payload is not four-byte aligned");
        code_range(pc, 2);
        const auto kind = first >> 8;
        if (kind == 1) {
            code_range(pc, 4);
            const auto count = unit(pc + 1);
            payload_work(pc, count);
            const uint64_t width = 4 + uint64_t(count) * 2;
            code_range(pc, width);
            if (count && int64_t(signed_pair(pc + 2)) + count - 1 > std::numeric_limits<int32_t>::max())
                fail(DecodeCode::corrupt, pc, "packed switch keys overflow int32");
            return static_cast<uint32_t>(width);
        }
        if (kind == 2) {
            const auto count = unit(pc + 1);
            payload_work(pc, count);
            const uint64_t width = 2 + uint64_t(count) * 4;
            code_range(pc, width);
            for (uint32_t i = 1; i < count; ++i) {
                if ((i & 1023) == 0) check_cancel(pc);
                if (signed_pair(pc + 2 + (i - 1) * 2) >= signed_pair(pc + 2 + i * 2))
                    fail(DecodeCode::corrupt, pc, "sparse switch keys are not strictly increasing");
            }
            return static_cast<uint32_t>(width);
        }
        if (kind == 3) {
            code_range(pc, 4);
            const auto element_width = unit(pc + 1);
            if (element_width != 1 && element_width != 2 && element_width != 4 && element_width != 8)
                fail(DecodeCode::corrupt, pc, "invalid primitive array payload element width");
            const auto count = pair(pc + 2);
            payload_work(pc, count);
            const uint64_t width = 4 + (uint64_t(count) * element_width + 1) / 2;
            code_range(pc, width);
            return static_cast<uint32_t>(width);
        }
        fail(DecodeCode::corrupt, pc, "unknown payload identifier");
    }
    void first_pass() {
        for (uint32_t pc = 0; pc < result.code_units;) {
            check_cancel(pc);
            if (result.instructions.size() >= options.max_instructions)
                fail(DecodeCode::budget, pc, "instruction count work limit exceeded");
            const auto first = unit(pc);
            const auto op = static_cast<uint8_t>(first);
            uint32_t width = widths[op];
            PayloadKind kind = PayloadKind::none;
            if (op == 0 && first != 0) {
                width = payload(pc, first); kind = static_cast<PayloadKind>(first >> 8);
            } else {
                if (width == 0) fail(DecodeCode::corrupt, pc, "reserved or optimized opcode is not standard DEX");
                if ((op >= 0xfa && input.dex_version < 38) || (op >= 0xfe && input.dex_version < 39))
                    fail(DecodeCode::unsupported, pc, "opcode requires a newer DEX version");
                code_range(pc, width);
                operands(pc, op, first);
                collect_numeric(pc, op, first);
            }
            result.instructions.push_back({pc, width, op, kind});
            pc += width;
        }
    }
    const Instruction& target(uint32_t from, int64_t displacement, PayloadKind expected = PayloadKind::none) const {
        const int64_t destination = int64_t(from) + displacement;
        if (destination < 0 || destination >= result.code_units) fail(DecodeCode::corrupt, from, "branch target is outside code units");
        const auto pc = static_cast<uint32_t>(destination);
        const auto found = std::lower_bound(result.instructions.begin(), result.instructions.end(), pc,
            [](const Instruction& instruction, uint32_t key) { return instruction.pc < key; });
        if (found == result.instructions.end() || found->pc != pc || found->payload_kind != expected)
            fail(DecodeCode::corrupt, from, "branch/payload target does not have the required instruction boundary and kind");
        return *found;
    }
    void second_pass() {
        for (const auto& instruction : result.instructions) {
            const auto pc = instruction.pc;
            const auto op = instruction.opcode;
            check_cancel(pc);
            if (instruction.payload_kind != PayloadKind::none) continue;
            int64_t displacement = 0;
            if (op == 0x28) displacement = std::bit_cast<int8_t>(static_cast<uint8_t>(unit(pc) >> 8));
            else if (op == 0x29 || in(op, 0x32, 0x3d)) displacement = std::bit_cast<int16_t>(unit(pc + 1));
            else if (op == 0x2a) displacement = signed_pair(pc + 1);
            if (in(op, 0x28, 0x2a) || in(op, 0x32, 0x3d)) {
                if (displacement == 0 && op != 0x2a) fail(DecodeCode::corrupt, pc, "zero branch offset is forbidden for this opcode");
                const auto& destination = target(pc, displacement);
                if (options.demand_mask & Demand::branch_targets) {
                    if (result.validation_work == options.max_validation_work)
                        fail(DecodeCode::budget, pc, "total decoder work limit exceeded");
                    ++result.validation_work;
                    result.branches.push_back({pc, destination.pc, op,
                        in(op, 0x28, 0x2a) ? BranchKind::unconditional : BranchKind::conditional});
                }
            } else if (op == 0x26 || op == 0x2b || op == 0x2c) {
                const auto kind = op == 0x26 ? PayloadKind::array_data : op == 0x2b ? PayloadKind::packed_switch : PayloadKind::sparse_switch;
                const auto& table = target(pc, signed_pair(pc + 1), kind);
                if (op == 0x26) {
                    if (options.demand_mask & Demand::array_data) {
                        const auto width = unit(table.pc + 1);
                        const auto count = pair(table.pc + 2);
                        // Charge each reference separately: one payload can be
                        // shared by many fill-array-data instructions.
                        payload_work(pc, count);
                        const uint64_t base = start + (uint64_t(table.pc) + 4) * 2;
                        byte_range(base, uint64_t(count) * width);
                        for (uint32_t i = 0; i < count; ++i) {
                            if ((i & 1023) == 0) check_cancel(pc);
                            uint64_t bits = 0;
                            const auto at = base + uint64_t(i) * width;
                            for (uint32_t j = 0; j < width; ++j)
                                bits |= uint64_t(input.dex[at + j]) << (j * 8);
                            result.array_elements.push_back({pc, table.pc, i, bits, static_cast<uint8_t>(width)});
                        }
                    }
                    continue;
                }
                const auto count = unit(table.pc + 1);
                payload_work(pc, count);
                const uint32_t targets = table.pc + (op == 0x2b ? 4 : 2 + uint32_t(count) * 2);
                for (uint32_t i = 0; i < count; ++i) {
                    if ((i & 1023) == 0) check_cancel(pc);
                    const auto& destination = target(pc, signed_pair(targets + i * 2));
                    if (options.demand_mask & Demand::switch_targets) {
                        const int32_t key = op == 0x2b
                            ? static_cast<int32_t>(int64_t(signed_pair(table.pc + 2)) + i)
                            : signed_pair(table.pc + 2 + i * 2);
                        result.switch_cases.push_back({pc, table.pc, destination.pc, i, key, kind});
                    }
                }
            }
        }
    }
    void exception_charge(uint64_t count) {
        if(count > options.max_validation_work - result.validation_work)
            fail(DecodeCode::budget,0,"total decoder work limit exceeded");
        if(count > options.max_exception_items - result.exception_work)
            fail(DecodeCode::budget, 0, "exception metadata work limit exceeded");
        result.exception_work += count;
        result.validation_work += count;
    }
    void exception_boundaries() {
        const uint16_t tries = read16(uint64_t(input.code_offset) + 6);
        if(!tries) return;
        exception_charge(tries);
        uint64_t tries_start = start + uint64_t(result.code_units) * 2;
        if(result.code_units & 1) {
            if(read16(tries_start) != 0) fail(DecodeCode::corrupt, result.code_units, "nonzero try padding");
            tries_start += 2;
        }
        byte_range(tries_start, uint64_t(tries) * 8);
        const uint64_t handlers = tries_start + uint64_t(tries) * 8;
        uint64_t cursor = handlers;
        std::pmr::vector<uint64_t> offsets(result.instructions.get_allocator().resource());
        try {
            const auto count = detail::read_uleb32(input.dex,cursor,byte_end);
            if(!count) fail(DecodeCode::corrupt,0,"try items require an encoded handler");
            exception_charge(count);offsets.reserve(count);
            for(uint32_t i=0;i<count;++i) {
                check_cancel(0);offsets.push_back(cursor-handlers);
                const auto size = detail::read_sleb32(input.dex,cursor,byte_end);
                const uint64_t pairs = size < 0 ? uint64_t(-int64_t(size)) : uint64_t(size);
                exception_charge(pairs + (size <= 0 ? 1u : 0u));
                for(uint64_t j=0;j<pairs;++j) {
                    if((j&1023)==0)check_cancel(0);
                    const auto type = detail::read_uleb32(input.dex,cursor,byte_end);
                    reference(0,type,input.refs.types);
                    const auto pc = detail::read_uleb32(input.dex,cursor,byte_end);
                    (void)target(0,pc);
                }
                if(size <= 0) {
                    const auto pc = detail::read_uleb32(input.dex,cursor,byte_end);
                    (void)target(0,pc);
                }
            }
        } catch(const ReadError& error) {
            throw DecodeError(DecodeCode::corrupt,error.offset,0,error.what());
        }
        uint64_t previous_end = 0;
        for(uint32_t i=0;i<tries;++i) {
            check_cancel(0);const uint64_t at=tries_start+uint64_t(i)*8;
            const uint32_t begin=read32(at);const uint16_t length=read16(at+4),handler=read16(at+6);
            if(!length || begin < previous_end || begin >= result.code_units || length > result.code_units-begin)
                fail(DecodeCode::corrupt,begin,"invalid or overlapping try range");
            (void)target(0,begin);const uint32_t end=begin+length;
            if(end != result.code_units) {
                const auto found=std::lower_bound(result.instructions.begin(),result.instructions.end(),end,
                    [](const Instruction& instruction,uint32_t pc){return instruction.pc<pc;});
                if(found==result.instructions.end()||found->pc!=end)
                    fail(DecodeCode::corrupt,end,"try end is inside an instruction or payload");
            }
            if(!std::binary_search(offsets.begin(),offsets.end(),handler))
                fail(DecodeCode::corrupt,begin,"try handler offset is not a handler item start");
            previous_end=end;
        }
    }
};
}

DecodeResult decode(const DecodeInput& input, const DecodeOptions& options, std::pmr::memory_resource* resource) {
    return Decoder(input, options, resource).run();
}
}
