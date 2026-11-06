#include "facts/method_facts.hpp"
#include <array>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <vector>

using namespace dexmeguviz;
using namespace dexmeguviz::instructions;
#define CHECK(x) do { if (!(x)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #x); } while (0)

static void put16(std::vector<uint8_t>& bytes, size_t at, uint16_t value) {
    bytes.at(at) = uint8_t(value); bytes.at(at + 1) = uint8_t(value >> 8);
}
static std::vector<uint8_t> code(const std::vector<uint16_t>& words) {
    std::vector<uint8_t> bytes(32 + words.size() * 2, 0);
    put16(bytes, 16, 2); put16(bytes, 28, uint16_t(words.size()));
    for (size_t i = 0; i < words.size(); ++i) put16(bytes, 32 + 2 * i, words[i]);
    return bytes;
}
static DecodeInput input(const std::vector<uint8_t>& bytes) { return {bytes, 16, 35, {1, 1, 1, 1, 1, 1, 1}}; }
static std::vector<uint8_t> example(uint16_t width, const std::vector<uint64_t>& values, bool shared = false) {
    std::vector<uint16_t> words = shared ? std::vector<uint16_t>{0x0026, 8, 0, 0x0126, 5, 0, 0x000e, 0}
                                         : std::vector<uint16_t>{0x0026, 4, 0, 0x000e};
    words.insert(words.end(), {0x0300, width, static_cast<uint16_t>(values.size()), 0});
    std::vector<uint8_t> raw;
    for (auto value : values) for (uint16_t j = 0; j < width; ++j) raw.push_back(uint8_t(value >> (j * 8)));
    if (raw.size() & 1) raw.push_back(0x99); // padding must not be emitted as an element
    for (size_t i = 0; i < raw.size(); i += 2) words.push_back(uint16_t(raw[i]) | (uint16_t(raw[i + 1]) << 8));
    return code(words);
}
template<class F> static void reject(DecodeCode expected, F action) {
    try { action(); } catch (const DecodeError& error) { CHECK(error.code == expected); return; }
    throw std::runtime_error("expected decode error");
}
struct Counted final : std::pmr::memory_resource {
    size_t live = 0, allocations = 0, fail_at = std::numeric_limits<size_t>::max();
    void* do_allocate(size_t size, size_t alignment) override {
        if (allocations++ == fail_at) throw std::bad_alloc();
        void* p = std::pmr::new_delete_resource()->allocate(size, alignment); live += size; return p;
    }
    void do_deallocate(void* p, size_t size, size_t alignment) override {
        live -= size; std::pmr::new_delete_resource()->deallocate(p, size, alignment);
    }
    bool do_is_equal(const std::pmr::memory_resource& rhs) const noexcept override { return this == &rhs; }
};

int main(int argc, char** argv) {
    try {
        CHECK(argc == 2);
        const std::vector<std::pair<uint16_t, std::vector<uint64_t>>> cases{
            {1, {0, 0x80, 0xff}}, {2, {0, 0x8001}}, {4, {0x12345678, 0xffffffff}},
            {8, {0x123456789abcdef0ULL, 0x8000000000000000ULL}}, {4, {}}};
        DecodeOptions options; options.demand_mask = Demand::array_data;
        for (const auto& [width, values] : cases) {
            const auto bytes = example(width, values);
            const auto result = decode(input(bytes), options);
            CHECK(result.array_elements.size() == values.size());
            for (uint32_t i = 0; i < values.size(); ++i) {
                const auto& item = result.array_elements[i];
                CHECK(item.pc == 0 && item.payload_pc == 4 && item.element_index == i);
                CHECK(item.width_bytes == width && item.bits == values[i]);
            }
            const auto no_request = decode(input(bytes));
            CHECK(no_request.array_elements.empty());
            CHECK(result.payload_work == no_request.payload_work + values.size());
        }
        const auto shared = example(1, {1, 2, 3}, true);
        const auto result = decode(input(shared), options);
        CHECK(result.array_elements.size() == 6 && result.payload_work == 9);
        for (uint32_t i = 0; i < 6; ++i) {
            const auto& item = result.array_elements[i];
            CHECK(item.pc == (i < 3 ? 0u : 3u) && item.payload_pc == 8 && item.element_index == i % 3 && item.bits == i % 3 + 1);
        }
        options.max_payload_elements = 8;
        reject(DecodeCode::budget, [&]{ (void)decode(input(shared), options); });
        options.max_payload_elements = 9;
        CHECK(decode(input(shared), options).array_elements.size() == 6);
        options.max_payload_elements = UINT64_MAX;
        options.max_validation_work = result.validation_work - 1;
        reject(DecodeCode::budget, [&]{ (void)decode(input(shared), options); });
        options.max_validation_work = result.validation_work;
        CHECK(decode(input(shared), options).array_elements.size() == 6);
        options.max_validation_work = UINT64_MAX;
        for (const auto version : {35u, 37u, 38u, 39u, 40u}) {
            auto typed = input(shared); typed.dex_version = version;
            CHECK(decode(typed, options).array_elements.size() == 6);
        }
        auto bad = shared; put16(bad, 34, 9);
        reject(DecodeCode::corrupt, [&]{ (void)decode(input(bad), options); });
        bad = shared; put16(bad, 32 + 2 * 9, 3);
        reject(DecodeCode::corrupt, [&]{ (void)decode(input(bad), options); });
        bad = shared; bad.pop_back();
        reject(DecodeCode::corrupt, [&]{ (void)decode(input(bad), options); });
        // Elements are staged before exception boundaries; failure there must
        // still prevent any result from escaping the decoder.
        bad = shared; put16(bad, 22, 1); bad.insert(bad.end(), 9, 0);
        reject(DecodeCode::corrupt, [&]{ (void)decode(input(bad), options); });
        auto unused = code({0x000e, 0, 0x0300, 1, 2, 0, 0x0201});
        CHECK(decode(input(unused), options).array_elements.empty());
        const auto backward = code({0x0029, 7, 0x0300, 1, 1, 0, 0x00ab, 0x0026, 0xfffb, 0xffff, 0x000e});
        const auto back_result = decode(input(backward), options);
        CHECK(back_result.array_elements.size() == 1 && back_result.array_elements[0].pc == 7 &&
              back_result.array_elements[0].payload_pc == 2 && back_result.array_elements[0].bits == 0xab);
        unsigned calls = 0; options.cancel_context = &calls;
        options.cancelled = [](void* p) noexcept { return ++*static_cast<unsigned*>(p) >= 4; };
        reject(DecodeCode::cancelled, [&]{ (void)decode(input(shared), options); });
        const auto many = example(1, std::vector<uint64_t>(2049, 0x5a));
        calls = 0; Counted cancelled_memory;
        options.cancelled = [](void* p) noexcept { return ++*static_cast<unsigned*>(p) >= 7; };
        reject(DecodeCode::cancelled, [&]{ (void)decode(input(many), options, &cancelled_memory); });
        CHECK(calls == 7 && cancelled_memory.live == 0);
        options.cancelled = nullptr;
        bool failed = false, completed = false;
        for (size_t point = 0; point < 40; ++point) {
            Counted memory; memory.fail_at = point;
            try { auto value = decode(input(shared), options, &memory); CHECK(value.array_elements.size() == 6); completed = true; }
            catch (const std::bad_alloc&) { failed = true; }
            CHECK(memory.live == 0);
        }
        CHECK(failed && completed);
        std::ifstream stream(argv[1], std::ios::binary); CHECK(stream.good());
        const std::vector<uint8_t> dex((std::istreambuf_iterator<char>(stream)), {});
        auto metadata = read_metadata(dex); CHECK(metadata.methods.size() == 1);
        auto collected = facts::collect_method(dex, metadata, 0, Demand::array_data);
        CHECK(collected.instruction_checked && collected.has_body && collected.array_elements.size() == 2);
        CHECK(collected.array_elements[0].pc == 0 && collected.array_elements[0].payload_pc == 4 && collected.array_elements[0].bits == 0x12345678);
        CHECK(collected.array_elements[1].element_index == 1 && collected.array_elements[1].bits == 0x80000001);
        CHECK(collected.numeric_literals.empty());
        auto unchanged = facts::collect_method(dex, metadata, 0, Demand::numeric);
        CHECK(unchanged.array_elements.empty() && unchanged.numeric_literals.empty());
        auto no_demand = facts::collect_method(dex, metadata, 0, 0);
        CHECK(!no_demand.instruction_checked && no_demand.array_elements.empty());
        std::cout << "PASS array data: element bytes, shared references, demand isolation, bounds, budget, cancellation and PMR\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
