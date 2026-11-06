#include "cfg.hpp"
#include "format/checked_leb128.hpp"
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace dexmeguviz::analysis::cfg {
namespace {
using namespace instructions;
[[noreturn]] void fail(const DecodeInput& input, DecodeCode code, uint32_t pc, const char* message) {
    throw DecodeError(code, uint64_t(input.code_offset) + 16 + uint64_t(pc) * 2, pc, message);
}
uint32_t narrow(size_t value) {
    if (value > UINT32_MAX) throw std::length_error("metadata reference table exceeds uint32");
    return static_cast<uint32_t>(value);
}
Terminal terminal(uint8_t op) {
    if (op >= 0x28 && op <= 0x2a) return Terminal::jump;
    if (op >= 0x32 && op <= 0x3d) return Terminal::conditional;
    if (op == 0x2b || op == 0x2c) return Terminal::switch_op;
    if (op >= 0x0e && op <= 0x11) return Terminal::return_op;
    if (op == 0x27) return Terminal::throw_op;
    return Terminal::ordinary;
}
}
Result build_checked(const DecodeInput& input, const Options& options, std::pmr::memory_resource* resource) {
    if (!resource) throw std::invalid_argument("CFG memory resource is null");
    DecodeOptions decode_options;
    decode_options.demand_mask = Demand::branch_targets | Demand::switch_targets;
    decode_options.max_validation_work = options.max_decode_work;
    decode_options.cancelled = options.cancelled;
    decode_options.cancel_context = options.cancel_context;
    auto decoded = decode(input, decode_options, resource);
    // decode() has checked the header, padding, try ranges and handler items.
    const uint64_t at = uint64_t(input.code_offset) + 6;
    const uint16_t tries = uint16_t(input.dex[at]) | (uint16_t(input.dex[at + 1]) << 8);
    if (tries && !options.include_exception_edges)
        fail(input, DecodeCode::unsupported, 0, "CFG exception edges are not implemented");
    Result result(resource); result.has_body = true; result.code_units = decoded.code_units;
    result.decode_work = decoded.validation_work;result.has_exception_regions = tries != 0;
    result.exception_edges_included = options.include_exception_edges && tries != 0;
    auto check_cancel = [&](uint32_t pc) {
        if (options.cancelled && options.cancelled(options.cancel_context)) fail(input, DecodeCode::cancelled, pc, "CFG cancelled");
    };
    auto charge = [&](uint64_t amount, uint32_t pc) {
        if (amount > options.max_graph_work - result.graph_work) fail(input, DecodeCode::budget, pc, "CFG work limit exceeded");
        result.graph_work += amount;
    };
    struct Catch { uint32_t type, target, order; };
    struct Handler { uint64_t offset; uint32_t first, count; };
    struct Try { uint32_t begin, end, handler; };
    std::pmr::vector<Catch> catches(resource);
    std::pmr::vector<Handler> handlers(resource);
    std::pmr::vector<Try> regions(resource);
    if (tries) {
        const uint64_t byte_end = input.code_end ? input.code_end : input.dex.size();
        auto read16 = [&](uint64_t pos) -> uint16_t {
            if (pos > byte_end || byte_end - pos < 2) fail(input, DecodeCode::corrupt, 0, "truncated exception metadata");
            return uint16_t(input.dex[pos]) | (uint16_t(input.dex[pos + 1]) << 8);
        };
        auto read32 = [&](uint64_t pos) -> uint32_t {
            return uint32_t(read16(pos)) | (uint32_t(read16(pos + 2)) << 16);
        };
        const uint64_t start = uint64_t(input.code_offset) + 16 + uint64_t(decoded.code_units) * 2 + ((decoded.code_units & 1u) ? 2u : 0u);
        const uint64_t handler_start = start + uint64_t(tries) * 8;
        uint64_t cursor = handler_start;
        try {
            const auto count = detail::read_uleb32(input.dex, cursor, byte_end);
            charge(uint64_t(count) + tries, 0);
            for (uint32_t i = 0; i < count; ++i) {
                check_cancel(0);
                const uint64_t offset = cursor - handler_start;
                const int32_t n = detail::read_sleb32(input.dex, cursor, byte_end);
                const uint64_t pairs = n < 0 ? uint64_t(-int64_t(n)) : uint64_t(n);
                const uint64_t entries = pairs + (n <= 0 ? 1u : 0u);
                charge(entries, 0);
                if (entries > UINT32_MAX - catches.size()) fail(input, DecodeCode::budget, 0, "too many CFG handler entries");
                const auto first = static_cast<uint32_t>(catches.size());
                for (uint64_t j = 0; j < pairs; ++j) {
                    if ((j & 1023u) == 0) check_cancel(0);
                    const uint32_t type = detail::read_uleb32(input.dex, cursor, byte_end);
                    const uint32_t target = detail::read_uleb32(input.dex, cursor, byte_end);
                    catches.push_back({type, target, static_cast<uint32_t>(j)});
                }
                if (n <= 0) catches.push_back({no_target, detail::read_uleb32(input.dex, cursor, byte_end), static_cast<uint32_t>(pairs)});
                handlers.push_back({offset, first, static_cast<uint32_t>(entries)});
            }
        } catch (const ReadError& error) {
            throw DecodeError(DecodeCode::corrupt, error.offset, 0, error.what());
        }
        for (uint32_t i = 0; i < tries; ++i) {
            check_cancel(0);const uint64_t pos = start + uint64_t(i) * 8;
            const uint32_t begin = read32(pos), end = begin + read16(pos + 4), offset = read16(pos + 6);
            const auto found = std::lower_bound(handlers.begin(), handlers.end(), uint64_t(offset),
                [](const Handler& h, uint64_t value) { return h.offset < value; });
            if (found == handlers.end() || found->offset != offset) fail(input, DecodeCode::corrupt, begin, "missing checked exception handler");
            regions.push_back({begin, end, static_cast<uint32_t>(found - handlers.begin())});
        }
    }
    charge(uint64_t(decoded.code_units) + decoded.instructions.size(), 0);
    std::pmr::vector<uint32_t> index(decoded.code_units, no_target, resource);
    std::pmr::vector<uint8_t> leaders(decoded.instructions.size(), 0, resource);
    std::pmr::vector<uint32_t> leader_block(decoded.instructions.size(), no_target, resource);
    for (uint32_t i = 0; i < decoded.instructions.size(); ++i) {
        const auto& inst = decoded.instructions[i]; index[inst.pc] = i;
        if ((i & 1023u) == 0) check_cancel(inst.pc);
        if (inst.payload_kind == PayloadKind::none && (i == 0 || decoded.instructions[i - 1].payload_kind != PayloadKind::none ||
            terminal(decoded.instructions[i - 1].opcode) != Terminal::ordinary)) leaders[i] = 1;
    }
    auto mark = [&](uint32_t pc) {
        charge(1, pc);
        if (pc >= index.size() || index[pc] == no_target || decoded.instructions[index[pc]].payload_kind != PayloadKind::none)
            fail(input, DecodeCode::corrupt, pc, "CFG target is not an executable boundary");
        leaders[index[pc]] = 1;
    };
    for (const auto& branch : decoded.branches) { check_cancel(branch.pc); mark(branch.target_pc); }
    for (const auto& target : decoded.switch_cases) { check_cancel(target.pc); mark(target.target_pc); }
    for (const auto& region : regions) {
        check_cancel(region.begin);mark(region.begin);
        if (region.end < decoded.code_units && index[region.end] != no_target &&
            decoded.instructions[index[region.end]].payload_kind == PayloadKind::none) mark(region.end);
        const auto& handler = handlers[region.handler];
        for (uint32_t i = 0; i < handler.count; ++i) { check_cancel(region.begin);mark(catches[handler.first + i].target); }
    }
    charge(decoded.instructions.size(), 0);
    for (uint32_t i = 0; i < decoded.instructions.size(); ++i) {
        const auto& inst = decoded.instructions[i];
        if ((i & 1023u) == 0) check_cancel(inst.pc);
        if (inst.payload_kind != PayloadKind::none) continue;
        if (leaders[i]) {
            if (result.blocks.size() >= options.max_blocks) fail(input, DecodeCode::budget, inst.pc, "CFG block limit exceeded");
            leader_block[i] = static_cast<uint32_t>(result.blocks.size());
            result.blocks.push_back({inst.pc, inst.pc + inst.width, inst.pc, 0, 0, terminal(inst.opcode), false});
        } else {
            if (result.blocks.empty()) fail(input, DecodeCode::corrupt, inst.pc, "CFG is missing a block leader");
            auto& block = result.blocks.back();block.end_pc = inst.pc + inst.width;block.last_pc = inst.pc;block.terminal = terminal(inst.opcode);
        }
    }
    auto block_at = [&](uint32_t pc) -> uint32_t {
        if (pc >= index.size() || index[pc] == no_target || leader_block[index[pc]] == no_target)
            fail(input, DecodeCode::corrupt, pc, "CFG edge target is not a block leader");
        return leader_block[index[pc]];
    };
    auto emit = [&](uint32_t from, uint32_t source, uint32_t target, EdgeKind kind,
                    int32_t key = 0, uint32_t case_index = 0, uint32_t payload = no_target,
                    uint32_t catch_type = no_target, uint32_t catch_order = 0) {
        charge(1, source);
        if (result.edges.size() >= options.max_edges) fail(input, DecodeCode::budget, source, "CFG edge limit exceeded");
        const uint32_t destination = target == no_target ? no_target : block_at(target);
        result.edges.push_back({from, destination, source, target, kind, key, case_index, payload, catch_type, catch_order});
    };
    auto fallthrough = [&](uint32_t from, const Instruction& inst, EdgeKind kind) {
        const uint32_t next = inst.pc + inst.width;
        if (next == decoded.code_units) emit(from, inst.pc, no_target, EdgeKind::fallthrough_past_end);
        else if (next > decoded.code_units || index[next] == no_target) fail(input, DecodeCode::corrupt, inst.pc, "CFG fallthrough is not a boundary");
        else if (decoded.instructions[index[next]].payload_kind != PayloadKind::none) emit(from, inst.pc, no_target, EdgeKind::fallthrough_to_payload);
        else emit(from, inst.pc, next, kind);
    };
    size_t branch_index = 0, switch_index = 0, region_index = 0;
    for (uint32_t i = 0; i < result.blocks.size(); ++i) {
        auto& block = result.blocks[i]; const auto& inst = decoded.instructions[index[block.last_pc]];
        check_cancel(inst.pc);charge(1, inst.pc);block.first_edge = static_cast<uint32_t>(result.edges.size());
        if (block.terminal == Terminal::jump || block.terminal == Terminal::conditional) {
            if (branch_index >= decoded.branches.size() || decoded.branches[branch_index].pc != inst.pc)
                fail(input, DecodeCode::corrupt, inst.pc, "missing checked branch fact");
            const auto target = decoded.branches[branch_index++].target_pc;
            emit(i, inst.pc, target, block.terminal == Terminal::jump ? EdgeKind::branch : EdgeKind::conditional_taken);
            if (block.terminal == Terminal::conditional) fallthrough(i, inst, EdgeKind::conditional_fallthrough);
        } else if (block.terminal == Terminal::switch_op) {
            while (switch_index < decoded.switch_cases.size() && decoded.switch_cases[switch_index].pc == inst.pc) {
                const auto& value = decoded.switch_cases[switch_index++];
                emit(i, inst.pc, value.target_pc, EdgeKind::switch_case, value.key, value.case_index, value.payload_pc);
            }
            fallthrough(i, inst, EdgeKind::switch_default);
        } else if (block.terminal == Terminal::ordinary) fallthrough(i, inst, EdgeKind::fallthrough);
        while (region_index < regions.size() && regions[region_index].end <= block.start_pc) ++region_index;
        if (region_index < regions.size() && block.start_pc >= regions[region_index].begin && block.start_pc < regions[region_index].end) {
            const auto& region = regions[region_index];
            if (block.end_pc > region.end) fail(input, DecodeCode::corrupt, block.start_pc, "CFG block crosses try boundary");
            const auto& handler = handlers[region.handler];
            for (uint32_t j = 0; j < handler.count; ++j) {
                check_cancel(block.start_pc);const auto& item = catches[handler.first + j];
                emit(i, block.start_pc, item.target, EdgeKind::exception_handler, 0, 0, no_target, item.type, item.order);
            }
        }
        block.edge_count = static_cast<uint32_t>(result.edges.size()) - block.first_edge;
    }
    if (branch_index != decoded.branches.size() || switch_index != decoded.switch_cases.size())
        fail(input, DecodeCode::corrupt, 0, "unused checked control-flow facts");
    if (result.blocks.empty() || result.blocks[0].start_pc != 0) fail(input, DecodeCode::corrupt, 0, "CFG lacks method entry");
    std::pmr::vector<uint32_t> queue(resource);queue.push_back(0);result.blocks[0].reachable = true;
    result.reachable_flow_complete = true;
    for (size_t q = 0; q < queue.size(); ++q) {
        auto& block = result.blocks[queue[q]];check_cancel(block.start_pc);charge(1, block.start_pc);
        for (uint32_t e = 0; e < block.edge_count; ++e) {
            const auto& edge = result.edges[block.first_edge + e];charge(1, edge.source_pc);
            if (edge.to_block == no_target) { result.reachable_flow_complete = false; continue; }
            if (!result.blocks[edge.to_block].reachable) { result.blocks[edge.to_block].reachable = true;queue.push_back(edge.to_block); }
        }
    }
    return result;
}
Result build(std::span<const uint8_t> dex, const Facts& metadata, uint32_t ordinal,
             const Options& options, std::pmr::memory_resource* resource) {
    if (!resource) throw std::invalid_argument("CFG memory resource is null");
    if (ordinal >= metadata.methods.size()) throw std::out_of_range("method ordinal exceeds definition directory");
    const auto& method = metadata.methods[ordinal];
    if (!method.code_offset) return Result(resource);
    const DecodeInput input{dex, method.code_offset, metadata.dex_version,
        {narrow(metadata.strings.size()), narrow(metadata.types.size()), narrow(metadata.field_refs.size()),
         narrow(metadata.method_refs.size()), narrow(metadata.prototypes.size()), metadata.call_site_count, metadata.method_handle_count}, method.code_end};
    return build_checked(input, options, resource);
}
}
