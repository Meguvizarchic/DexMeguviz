#include "format/reader.hpp"
#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef _MSC_VER
#include <crtdbg.h>
#endif

using namespace dexmeguviz;
#define CHECK(condition) do { if (!(condition)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #condition); } while (0)
struct Counted final : std::pmr::memory_resource {
    size_t current = 0, peak = 0, limit = std::numeric_limits<size_t>::max();
    void* do_allocate(size_t bytes, size_t alignment) override {
        if (bytes > limit - current) throw std::bad_alloc();
        auto* pointer = std::pmr::new_delete_resource()->allocate(bytes, alignment);
        current += bytes; peak = std::max(peak, current); return pointer;
    }
    void do_deallocate(void* pointer, size_t bytes, size_t alignment) override {
        current -= bytes; std::pmr::new_delete_resource()->deallocate(pointer, bytes, alignment);
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override { return this == &other; }
};
static std::vector<uint8_t> load(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary); CHECK(input.good());
    return {(std::istreambuf_iterator<char>(input)), {}};
}
static uint32_t u32(const std::vector<uint8_t>& bytes, uint32_t at) {
    return uint32_t(bytes.at(at)) | (uint32_t(bytes.at(at + 1)) << 8) |
        (uint32_t(bytes.at(at + 2)) << 16) | (uint32_t(bytes.at(at + 3)) << 24);
}

int main(int argc, char** argv) {
    try {
#ifdef _MSC_VER
        _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
        _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
        CHECK(argc == 2); const std::filesystem::path directory(argv[1]);
        const auto bytes = load(directory / "definitions.dex");
        Counted resource;
        auto* previous = std::pmr::set_default_resource(std::pmr::null_memory_resource());
        try {
            const auto facts = read_metadata(bytes, &resource);
            CHECK(facts.class_count == 5 && facts.class_definitions.size() == 5);
            CHECK(facts.field_refs.size() == 4 && facts.field_definitions.size() == 3);
            CHECK(facts.class_definitions.get_allocator().resource() == &resource && facts.field_definitions.get_allocator().resource() == &resource);
            const std::array<uint32_t, 5> expected_types{7, 4, 5, 2, 3};
            const std::array<uint32_t, 5> expected_flags{1, 0x601, 0x601, 1, 0x401};
            const std::array<uint32_t, 5> expected_parents{UINT32_MAX, 7, 7, 7, 2};
            const std::array<uint32_t, 5> expected_data{0, 0, 0, 607, 615};
            for (size_t i = 0; i < facts.class_definitions.size(); ++i) {
                const auto& definition = facts.class_definitions[i];
                CHECK(definition.type_id == expected_types[i] && definition.access_flags == expected_flags[i]);
                CHECK(definition.superclass_type == expected_parents[i] && definition.class_data_offset == expected_data[i]);
                CHECK(definition.definition_offset == 252 + i * 32);
                CHECK(u32(bytes, definition.definition_offset) == definition.type_id);
                CHECK(u32(bytes, definition.definition_offset + 4) == definition.access_flags);
                CHECK(definition.interfaces.get_allocator().resource() == &resource);
                if (i < 3) CHECK(definition.interfaces.empty());
            }
            const auto& base = facts.class_definitions[3];
            const auto& child = facts.class_definitions[4];
            CHECK(base.interfaces.size() == 2 && base.interfaces[0] == 5 && base.interfaces[1] == 4);
            CHECK(child.interfaces.size() == 1 && child.interfaces[0] == 4);
            CHECK(base.annotations_offset == 628 && base.static_values_offset == 625);
            CHECK(child.annotations_offset == 0 && child.static_values_offset == 0);
            CHECK(facts.strings[facts.types[base.type_id]] == u"Lcatalog/Base;");
            CHECK(facts.strings[facts.types[child.superclass_type]] == u"Lcatalog/Base;");
            CHECK(facts.class_definitions[0].superclass_type == UINT32_MAX);
            const std::array<uint32_t, 3> expected_refs{1, 0, 2}, expected_field_flags{9, 1, 1}, expected_offsets{611, 613, 619}, expected_owners{2, 2, 3};
            for (size_t i = 0; i < facts.field_definitions.size(); ++i) {
                const auto& definition = facts.field_definitions[i];
                CHECK(definition.field_ref_index == expected_refs[i] && definition.access_flags == expected_field_flags[i]);
                CHECK(definition.declaration_offset == expected_offsets[i] && definition.owner_type == expected_owners[i]);
                CHECK(bytes.at(definition.declaration_offset) == definition.field_ref_index);
                CHECK(bytes.at(definition.declaration_offset + 1) == definition.access_flags);
                CHECK(facts.field_refs[definition.field_ref_index].owner == definition.owner_type);
            }
            const auto& base_shared = facts.field_refs[facts.field_definitions[0].field_ref_index];
            const auto& child_shared = facts.field_refs[facts.field_definitions[2].field_ref_index];
            CHECK(facts.strings[base_shared.name] == u"shared" && base_shared.name == child_shared.name);
            CHECK(base_shared.owner != child_shared.owner && base_shared.type != child_shared.type);
            CHECK(facts.strings[facts.field_refs[3].name] == u"externalField");
            CHECK(std::none_of(facts.field_definitions.begin(), facts.field_definitions.end(), [](const auto& definition) { return definition.field_ref_index == 3; }));
            CHECK(facts.methods.size() == 1 && facts.methods[0].name == u"abstractMethod");
            CHECK(facts.methods[0].access_flags == 0x401 && facts.methods[0].code_offset == 0 && facts.methods[0].declaration_offset == 621);
        } catch (...) { std::pmr::set_default_resource(previous); throw; }
        std::pmr::set_default_resource(previous);
        CHECK(resource.current == 0);
        for (const auto* name : {"duplicate-class", "duplicate-interface", "wrong-static-group", "wrong-field-owner", "duplicate-field"}) {
            const auto bad = load(directory / (std::string(name) + ".dex"));
            bool rejected = false;
            try { (void)read_metadata(bad, &resource); }
            catch (const ReadError& error) { CHECK(error.code == ReadCode::corrupt); rejected = true; }
            CHECK(rejected && resource.current == 0);
        }
        resource.limit = 512;
        bool limited = false;
        try { (void)read_metadata(bytes, &resource); } catch (const std::bad_alloc&) { limited = true; }
        CHECK(limited && resource.current == 0);
        std::cout << "PASS definition_catalog: five classes, original interface order, three field definitions/four references, raw flags and byte offsets, external reference separation, rejection cases and PMR reclamation\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
