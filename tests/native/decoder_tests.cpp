#include "format/instructions/decoder.hpp"
#include <algorithm>
#include <array>
#include <iostream>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef _MSC_VER
#include <crtdbg.h>
#endif

using namespace dexmeguviz::instructions;
#define CHECK(condition) do { if (!(condition)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #condition); } while (0)

static void put16(std::vector<uint8_t>& bytes, size_t offset, uint16_t value) {
    bytes.at(offset) = static_cast<uint8_t>(value);
    bytes.at(offset + 1) = static_cast<uint8_t>(value >> 8);
}
static void put32(std::vector<uint8_t>& bytes, size_t offset, uint32_t value) {
    put16(bytes, offset, static_cast<uint16_t>(value)); put16(bytes, offset + 2, static_cast<uint16_t>(value >> 16));
}
static std::vector<uint8_t> code(std::span<const uint16_t> units, uint16_t registers = 16, uint16_t outgoing = 5) {
    std::vector<uint8_t> bytes(32 + units.size() * 2, 0);
    put16(bytes, 16, registers); put16(bytes, 20, outgoing); put32(bytes, 28, static_cast<uint32_t>(units.size()));
    for (size_t i = 0; i < units.size(); ++i) put16(bytes, 32 + i * 2, units[i]);
    return bytes;
}
static DecodeInput input(const std::vector<uint8_t>& bytes, uint32_t version = 40) { return {bytes, 16, version, {70000, 4, 4, 4, 4, 4, 4}}; }
static std::vector<uint8_t> try_code(std::initializer_list<uint16_t> units,uint32_t begin,uint16_t length,
    uint16_t handler,std::initializer_list<uint8_t> handlers) {
    auto bytes=code(units);put16(bytes,22,1);
    if(units.size()&1)bytes.resize(bytes.size()+2,0);
    const size_t at=bytes.size();bytes.resize(at+8,0);
    put32(bytes,at,begin);put16(bytes,at+4,length);put16(bytes,at+6,handler);
    bytes.insert(bytes.end(),handlers.begin(),handlers.end());return bytes;
}
static DecodeResult run(std::initializer_list<uint16_t> units, uint32_t demand = 0, uint16_t registers = 16) {
    const auto bytes = code(units, registers);
    DecodeOptions options; options.demand_mask = demand;
    return decode(input(bytes), options);
}
template<typename Work> static void reject(DecodeCode expected, Work&& work) {
    bool rejected = false;
    try { work(); }
    catch (const DecodeError& error) { CHECK(error.code == expected); rejected = true; }
    CHECK(rejected);
}
static void corrupt(std::initializer_list<uint16_t> units, uint16_t registers = 16) {
    reject(DecodeCode::corrupt, [&] { (void)run(units, 0, registers); });
}
struct Counted final : std::pmr::memory_resource {
    size_t current = 0, peak = 0, limit = std::numeric_limits<size_t>::max();
    void* do_allocate(size_t bytes, size_t alignment) override {
        if (bytes > limit - current) throw std::bad_alloc();
        auto* result = std::pmr::new_delete_resource()->allocate(bytes, alignment);
        current += bytes; peak = std::max(peak, current); return result;
    }
    void do_deallocate(void* pointer, size_t bytes, size_t alignment) override {
        current -= bytes; std::pmr::new_delete_resource()->deallocate(pointer, bytes, alignment);
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override { return this == &other; }
};

int main() {
    try {
#ifdef _MSC_VER
        _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
        _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
        unsigned checks = 0;
        // Independently enumerate the specification's fixed-width instruction families.
        std::array<uint8_t, 256> expected{};
        auto family = [&](uint8_t begin, uint8_t end, uint8_t width) { for (unsigned op = begin; op <= end; ++op) expected[op] = width; };
        family(0x00, 0x12, 1);
        for (const auto op : {0x02, 0x05, 0x08}) expected[op] = 2;
        for (const auto op : {0x03, 0x06, 0x09}) expected[op] = 3;
        family(0x13, 0x23, 2);
        for (const auto op : {0x14, 0x17, 0x1b}) expected[op] = 3;
        expected[0x18] = 5; expected[0x1d] = expected[0x1e] = expected[0x21] = 1;
        family(0x24, 0x26, 3); expected[0x27] = expected[0x28] = 1;
        expected[0x29] = 2; family(0x2a, 0x2c, 3); family(0x2d, 0x3d, 2);
        family(0x44, 0x6d, 2); family(0x6e, 0x72, 3); family(0x74, 0x78, 3);
        family(0x7b, 0x8f, 1); family(0x90, 0xaf, 2); family(0xb0, 0xcf, 1);
        family(0xd0, 0xe2, 2); expected[0xfa] = expected[0xfb] = 4;
        expected[0xfc] = expected[0xfd] = 3; expected[0xfe] = expected[0xff] = 2;
        for (unsigned opcode = 0; opcode < expected.size(); ++opcode) {
            const auto width = expected[opcode];
            if (!width) { corrupt({static_cast<uint16_t>(opcode), 0x000e}); ++checks; continue; }
            if (opcode == 0x26 || opcode == 0x2b || opcode == 0x2c) continue; // Payload cases below.
            std::vector<uint16_t> words(width + 1, 0); words[0] = static_cast<uint16_t>(opcode); words[width] = 0x000e;
            if (opcode == 0x28) words[0] = 0x0128;
            if (opcode == 0x29 || (opcode >= 0x32 && opcode <= 0x3d)) words[1] = width;
            if (opcode == 0x2a) words[1] = width;
            const auto bytes = code(words);
            const auto result = decode(input(bytes));
            CHECK(result.instructions.size() == 2 && result.instructions[0].width == width && result.instructions[1].pc == width);
            CHECK(result.string_uses.empty() && result.invoke_sites.empty() && result.field_uses.empty());
            ++checks;
        }
        auto result = run({0x001a, 3, 0x011b, 0, 1, 0x000e}, Demand::strings);
        CHECK(result.string_uses.size() == 2 && result.string_uses[0].pc == 0 && result.string_uses[0].string_index == 3);
        CHECK(result.string_uses[1].pc == 2 && result.string_uses[1].string_index == 65536 && result.string_uses[1].opcode == 0x1b); ++checks;
        result = run({0x206e, 1, 0x0010, 0x0274, 2, 2, 0x20fa, 3, 0x0010, 1,
                      0x02fb, 2, 2, 3, 0x10fc, 1, 0, 0x01fd, 2, 3, 0x000e}, Demand::invokes);
        CHECK(result.invoke_sites.size() == 6);
        CHECK(result.invoke_sites[0].reference_kind == ReferenceKind::method && result.invoke_sites[0].extra_proto == UINT32_MAX);
        CHECK(result.invoke_sites[2].reference_kind == ReferenceKind::method_and_proto && result.invoke_sites[2].extra_proto == 1);
        CHECK(result.invoke_sites[4].reference_kind == ReferenceKind::call_site && result.invoke_sites[5].index == 2); ++checks;
        result = run({0x1052, 1, 0x0268, 2, 0x000e}, Demand::fields);
        CHECK(result.field_uses.size() == 2 && result.field_uses[0].pc == 0 && result.field_uses[1].pc == 2); ++checks;
        // Switch targets are relative to their referring switch, never to the payload.
        result = run({0x002b, 4, 0, 0x000e, 0x0100, 1, 7, 0, 3, 0});
        CHECK(result.instructions[2].payload_kind == PayloadKind::packed_switch && result.instructions[2].width == 6); ++checks;
        result = run({0x002c, 4, 0, 0x000e, 0x0200, 2, 0xffff, 0xffff, 5, 0, 3, 0, 0, 0});
        CHECK(result.instructions[2].payload_kind == PayloadKind::sparse_switch && result.instructions[2].width == 10); ++checks;
        result = run({0x0026, 4, 0, 0x000e, 0x0300, 1, 3, 0, 0x0201, 3});
        CHECK(result.instructions[2].payload_kind == PayloadKind::array_data && result.instructions[2].width == 6); ++checks;
        for (const auto version : {35u, 37u, 38u, 39u, 40u}) {
            const auto bytes = code(std::array<uint16_t, 1>{0x000e});
            CHECK(decode(input(bytes, version)).instructions.size() == 1); ++checks;
        }
        for (const auto version : {35u, 37u}) {
            const auto bytes = code(std::array<uint16_t, 4>{0x00fc, 0, 0, 0x000e});
            reject(DecodeCode::unsupported, [&] { (void)decode(input(bytes, version)); }); ++checks;
        }
        const auto method_handle = code(std::array<uint16_t, 3>{0x00fe, 0, 0x000e});
        reject(DecodeCode::unsupported, [&] { (void)decode(input(method_handle, 38)); }); ++checks;
        reject(DecodeCode::unsupported, [&] { (void)decode(input(method_handle, 41)); }); ++checks;
        for (const auto words : std::vector<std::vector<uint16_t>>{
            {0x0018, 0, 0}, {0x001b, 0}, {0x002b, 4}, {0x002a, 1, 0, 0x000e},
            {0x0129, 2, 0x000e}, {0x010e}, {0x0028}, {0x0032, 0}, {0x0038, 1, 0x000e},
            {0xff28, 0x000e}, {0x002b, 3, 0, 0x0100, 0, 0, 0},
            {0x002b, 4, 0, 0x000e, 0x0200, 0},
            {0x002b, 4, 0, 0x000e, 0x0100, 1, 0, 0, 5, 0},
            {0x002b, 4, 0, 0x000e, 0x0100, 2, 0xffff, 0x7fff, 3, 0, 3, 0},
            {0x002c, 4, 0, 0x000e, 0x0200, 2, 1, 0, 1, 0, 3, 0, 3, 0},
            {0x0026, 4, 0, 0x000e, 0x0300, 3, 0, 0}, {0x0400},
            {0x0f0b, 0x000e}, {0xf004, 0x000e}, {0x106e, 4, 0, 0x000e},
            {0x60fc, 0, 0, 0x000e}, {0x02fd, 0, 15, 0x000e},
            {0x10fa, 0, 0, 4, 0x000e}, {0x0052, 4, 0x000e}, {0x001c, 4, 0x000e},
            {0x00fc, 4, 0, 0x000e}, {0x00fe, 4, 0x000e}, {0x00ff, 4, 0x000e},
            {0x001b, 0xffff, 1, 0x000e}, {0x002f, 0x000f, 0x000e},
            {0x002b, 4, 0, 0x000e, 0x0100, 1, 0, 0, 4, 0}, {0x0100, 0, 0, 0},
        }) {
            const auto bytes = code(words);
            reject(DecodeCode::corrupt, [&] { (void)decode(input(bytes)); }); ++checks;
        }
        // Long shift count is a single register, while its value/result use pairs.
        CHECK(run({0xf0c3, 0x000e}).instructions.size() == 2); ++checks;
        const auto sample = code(std::array<uint16_t, 6>{0x001a, 3, 0x106e, 1, 0, 0x000e});
        for (size_t n = 0; n < sample.size(); ++n) {
            const std::vector<uint8_t> truncated(sample.begin(), sample.begin() + n);
            reject(DecodeCode::corrupt, [&] { (void)decode(input(truncated)); }); ++checks;
        }
        DecodeOptions limit; limit.max_code_units = 1;
        reject(DecodeCode::budget, [&] { (void)decode(input(sample), limit); }); ++checks;
        limit = {}; limit.max_instructions = 1;
        reject(DecodeCode::budget, [&] { (void)decode(input(sample), limit); }); ++checks;
        const auto payload_bytes = code(std::array<uint16_t, 10>{0x0026, 4, 0, 0x000e, 0x0300, 1, 3, 0, 0x0201, 3});
        limit = {}; limit.max_payload_elements = 2;
        reject(DecodeCode::budget, [&] { (void)decode(input(payload_bytes), limit); }); ++checks;
        const auto shared_payload = code(std::array<uint16_t, 14>{0x002b, 8, 0, 0x002b, 5, 0, 0x000e, 0, 0x0100, 1, 0, 0, 3, 0});
        CHECK(decode(input(shared_payload)).payload_work == 3); ++checks;
        reject(DecodeCode::budget, [&] { (void)decode(input(shared_payload), limit); }); ++checks;
        limit = {}; limit.demand_mask = 256;
        reject(DecodeCode::unsupported, [&] { (void)decode(input(sample), limit); }); ++checks;
        unsigned calls = 0;
        limit = {}; limit.cancel_context = &calls;
        limit.cancelled = [](void* context) noexcept { return ++*static_cast<unsigned*>(context) >= 3; };
        reject(DecodeCode::cancelled, [&] { (void)decode(input(sample), limit); }); CHECK(calls == 3); ++checks;
        Counted resource;
        auto* previous = std::pmr::set_default_resource(std::pmr::null_memory_resource());
        try {
            DecodeOptions all; all.demand_mask = Demand::strings | Demand::invokes | Demand::fields;
            auto parsed = decode(input(sample), all, &resource);
            CHECK(parsed.string_uses.size() == 1 && parsed.invoke_sites.size() == 1);
            CHECK(parsed.instructions.get_allocator().resource() == &resource && resource.current > 0);
        } catch (...) { std::pmr::set_default_resource(previous); throw; }
        std::pmr::set_default_resource(previous);
        CHECK(resource.current == 0); ++checks;
        resource.limit = 1;
        bool allocation_failed = false;
        try { (void)decode(input(sample), {}, &resource); } catch (const std::bad_alloc&) { allocation_failed = true; }
        CHECK(allocation_failed && resource.current == 0); ++checks;
        const auto with_try=try_code({0x0013,7,0x000e},0,2,1,{1,1,0,2});
        CHECK(decode(input(with_try)).exception_work==3);++checks;
        for(const auto& bad:std::vector<std::vector<uint8_t>>{
            try_code({0x0013,7,0x000e},1,2,1,{1,1,0,2}),
            try_code({0x0013,7,0x000e},0,1,1,{1,1,0,2}),
            try_code({0x0013,7,0x000e},0,2,1,{1,1,0,1}),
            try_code({0x0013,7,0x000e},0,2,1,{1,1,0,3}),
            try_code({0x0013,7,0x000e},0,2,2,{1,1,0,2}),
            try_code({0x0013,7,0x000e},0,2,1,{1,1,4,2}),
            try_code({0x0013,7,0x000e},0,2,1,{0}),
            try_code({0x0026,4,0,0x000e,0x0300,1,0,0},0,3,1,{1,0,4})
        }){reject(DecodeCode::corrupt,[&]{(void)decode(input(bad));});++checks;}
        auto bad_padding=with_try;bad_padding[38]=1;
        reject(DecodeCode::corrupt,[&]{(void)decode(input(bad_padding));});++checks;
        auto bounded=input(with_try);bounded.code_end=with_try.size()-1;
        reject(DecodeCode::corrupt,[&]{(void)decode(bounded);});++checks;
        const auto catch_all=try_code({0x0013,7,0x000e},0,3,1,{1,0,2});
        CHECK(decode(input(catch_all)).exception_work==3);++checks;
        const auto typed_and_all=try_code({0x0013,7,0x000e},0,3,1,{1,0x7f,0,2,0});
        CHECK(decode(input(typed_and_all)).exception_work==4);++checks;
        limit={};limit.max_exception_items=2;
        reject(DecodeCode::budget,[&]{(void)decode(input(with_try),limit);});++checks;
        calls=0;limit={};limit.cancel_context=&calls;
        limit.cancelled=[](void* c)noexcept{return ++*static_cast<unsigned*>(c)>=7;};
        reject(DecodeCode::cancelled,[&]{(void)decode(input(with_try),limit);});CHECK(calls==7);++checks;
        std::cout << "PASS decoder: " << checks << " bounded behavior cases; all standard opcode widths; payload/branch/reference/register checks; demand masks, cancellation and PMR\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
