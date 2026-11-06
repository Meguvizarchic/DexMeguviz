#include "format/reader.hpp"
#include "format/checked_leb128.hpp"
#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <vector>
#ifdef _MSC_VER
#include <crtdbg.h>
#endif

#define CHECK(condition) do { if (!(condition)) throw std::runtime_error("check failed at line " + std::to_string(__LINE__) + ": " #condition); } while (0)

class CountedResource final : public std::pmr::memory_resource {
public:
    size_t current = 0, peak = 0, allocations = 0;
    size_t limit = std::numeric_limits<size_t>::max();
private:
    void* do_allocate(size_t size, size_t alignment) override {
        if (size > limit - current) throw std::bad_alloc();
        auto* result = std::pmr::new_delete_resource()->allocate(size, alignment);
        current += size;
        peak = std::max(peak, current);
        ++allocations;
        return result;
    }
    void do_deallocate(void* pointer, size_t size, size_t alignment) override {
        current -= size;
        std::pmr::new_delete_resource()->deallocate(pointer, size, alignment);
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override { return this == &other; }
};

std::vector<uint8_t> load(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    CHECK(input.good());
    return {(std::istreambuf_iterator<char>(input)), {}};
}

template<typename Work> void corrupt(Work&& work) {
    bool rejected = false;
    try { work(); }
    catch (const dexmeguviz::ReadError& error) { CHECK(error.code == dexmeguviz::ReadCode::corrupt); rejected = true; }
    CHECK(rejected);
}

int main(int argc, char** argv) {
    try {
#ifdef _MSC_VER
        _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
        _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
        std::cout << std::unitbuf;
        CHECK(argc == 2);
        size_t passed = 0;
        std::cout << "checking bounded SLEB32\n";
        struct SignedVector { std::vector<uint8_t> bytes; int32_t expected; };
        const std::vector<SignedVector> vectors{
            {{0}, 0}, {{0x7f}, -1}, {{0x3f}, 63}, {{0x40}, -64},
            {{0xc0, 0x00}, 64}, {{0xbf, 0x7f}, -65}, {{0x80, 0x01}, 128},
            {{0x80, 0x7f}, -128}, {{0x80, 0x00}, 0}, {{0xff, 0x7f}, -1},
            {{0xff, 0xff, 0xff, 0xff, 0x07}, std::numeric_limits<int32_t>::max()},
            {{0x80, 0x80, 0x80, 0x80, 0x78}, std::numeric_limits<int32_t>::min()},
        };
        for (const auto& test : vectors) {
            uint64_t cursor = 0;
            CHECK(dexmeguviz::detail::read_sleb32(test.bytes, cursor, test.bytes.size()) == test.expected);
            CHECK(cursor == test.bytes.size());
            ++passed;
        }
        for (const auto& bad : std::vector<std::vector<uint8_t>>{
            {}, {0x80}, {0x80, 0x80, 0x80, 0x80, 0x08},
            {0xff, 0xff, 0xff, 0xff, 0x77}, {0x80, 0x80, 0x80, 0x80, 0x80},
        }) {
            corrupt([&] { uint64_t cursor = 0; (void)dexmeguviz::detail::read_sleb32(bad, cursor, bad.size()); });
            ++passed;
        }
        const std::array<uint8_t, 2> bounded{0x80, 0};
        corrupt([&] { uint64_t cursor = 0; (void)dexmeguviz::detail::read_sleb32(bounded, cursor, 1); });
        corrupt([&] { uint64_t cursor = 3; (void)dexmeguviz::detail::read_sleb32(bounded, cursor, 2); });
        corrupt([&] { uint64_t cursor = 0; (void)dexmeguviz::detail::read_sleb32(bounded, cursor, 3); });
        passed += 3;
        const std::filesystem::path directory(argv[1]);
        const auto valid = load(directory / "shared-items.dex");
        std::cout << "checking metadata with default PMR disabled\n";
        CountedResource resource;
        auto* previous = std::pmr::set_default_resource(std::pmr::null_memory_resource());
        try {
            auto facts = dexmeguviz::read_metadata(valid, &resource);
            CHECK(facts.methods.size() == 4);
            CHECK(facts.methods.get_allocator().resource() == &resource);
            uint32_t shared_code = 0;
            unsigned shared_count = 0;
            for (const auto& method : facts.methods) {
                const auto& reference = facts.method_refs[method.method_index];
                CHECK(method.owner.data() == facts.strings[facts.types[reference.owner]].data());
                CHECK(method.name.data() == facts.strings[reference.name].data());
                CHECK(method.prototype.data() == facts.prototypes[reference.type].descriptor.data());
                CHECK(facts.strings[reference.name].get_allocator().resource() == &resource);
                CHECK(method.code_offset != 0);
                if (method.name == u"alpha" || method.name == u"beta" || method.name == u"wide") {
                    if (shared_code == 0) shared_code = method.code_offset;
                    CHECK(shared_code == method.code_offset);
                    ++shared_count;
                }
                if (method.name == u"wide") CHECK(method.prototype == u"(J)V");
                if (method.name == u"gamma") CHECK(method.prototype == u"()V");
            }
            CHECK(shared_count == 3);
            CHECK(resource.current != 0 && resource.allocations > 10);
        } catch (...) { std::pmr::set_default_resource(previous); throw; }
        std::pmr::set_default_resource(previous);
        CHECK(resource.current == 0);
        ++passed;
        std::cout << "checking malformed metadata\n";
        const std::array<const char*, 16> malformed{
            "type-list-interior", "type-list-count-low", "type-list-count-high",
            "code-interior", "code-count-low", "code-count-high", "incoming-mismatch",
            "registers-too-small", "empty-code", "handler-interior", "handler-address-oob",
            "catch-all-address-oob", "try-range-oob", "handlers-count-zero",
            "class-topology", "interface-topology",
        };
        for (const auto* name : malformed) {
            std::cout << "  " << name << '\n';
            const auto bytes = load(directory / (std::string(name) + ".dex"));
            corrupt([&] { (void)dexmeguviz::read_metadata(bytes, &resource); });
            CHECK(resource.current == 0);
            ++passed;
        }
        resource.limit = 128;
        std::cout << "checking bounded PMR failure\n";
        bool exhausted = false;
        try { (void)dexmeguviz::read_metadata(valid, &resource); }
        catch (const std::bad_alloc&) { exhausted = true; }
        CHECK(exhausted && resource.current == 0);
        ++passed;
        std::cout << "PASS reader_extended: " << passed << " checks; PMR peak=" << resource.peak
                  << "; shared metadata/code references and numeric try/catch verified; opcodes/CFG not checked\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
