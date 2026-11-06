#include "facts/method_facts.hpp"
#include "source/sha256.hpp"
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

using namespace dexmeguviz;
#define CHECK(x) do { if (!(x)) throw std::runtime_error("use fixture check " + std::to_string(__LINE__) + ": " #x); } while (0)

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

static std::vector<uint8_t> load(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    CHECK(input.good());
    return {(std::istreambuf_iterator<char>(input)), {}};
}

static uint16_t unit(const std::vector<uint8_t>& bytes, uint32_t code_offset, uint32_t pc) {
    const size_t at = size_t(code_offset) + 16 + size_t(pc) * 2;
    CHECK(at < bytes.size() && bytes.size() - at >= 2);
    return uint16_t(bytes[at]) | (uint16_t(bytes[at + 1]) << 8);
}

static uint32_t ordinal(const Facts& facts, std::u16string_view name) {
    for (uint32_t index = 0; index < facts.methods.size(); ++index)
        if (facts.methods[index].name == name) return index;
    throw std::runtime_error("expected fixture method definition absent");
}

struct Fixture { const char* path; const char* sha256; };

int main(int argc, char** argv) {
    try {
        CHECK(argc == 2);
        const std::filesystem::path directory(argv[1]);
        const std::array<Fixture, 4> fixtures{{
            {"two-invokes.dex", "04656bbfe03c8b04e6f77d29b8cae8e7e06f18a038f85300658f8c691435648b"},
            {"field-read-write.dex", "7558a8945c3a87f727de782d885c687539d839e460497f6d2e86c2a7c7f46e8d"},
            {"string-normal-jumbo.dex", "65373dc14bb0b19b3fb4ae8fd236e83befbfee4b69b74e3a8d4a8b7db2637c04"},
            {"valid-then-corrupt.dex", "4e0661d233cfc3eaf32aff66e615a1cacba822e768c3c3b4559f0f0abfc2c2be"},
        }};
        Counted metadata_memory, scratch_memory;
        auto* previous = std::pmr::set_default_resource(std::pmr::null_memory_resource());
        unsigned checks = 0;
        try {
            for (size_t which = 0; which < fixtures.size(); ++which) {
                const auto bytes = load(directory / fixtures[which].path);
                CHECK(sha256<>(bytes) == fixtures[which].sha256);
                {
                    auto metadata = read_metadata(bytes, &metadata_memory);
                    CHECK(metadata.methods.size() == 4 && metadata.method_refs.size() == 5 && metadata.field_refs.size() == 1);
                    CHECK(metadata.strings.size() == 12 && metadata.strings[10] == u"used-string" && metadata.strings[7] == u"only-in-pool");
                    const auto caller = ordinal(metadata, u"uses");
                    CHECK(caller == 2 && metadata.methods[caller].method_index == 3);
                    CHECK(metadata.methods[caller].code_offset == 416 && metadata.methods[caller].code_end > 416);
                    CHECK(metadata.strings[metadata.method_refs[4].name] == u"sink");
                    CHECK(metadata.strings[metadata.types[metadata.method_refs[4].owner]] == u"Ljava/lang/Object;");
                    CHECK(metadata.prototypes[metadata.method_refs[4].type].descriptor == u"()V");
                    CHECK(metadata.strings[metadata.field_refs[0].name] == u"counter");
                    CHECK(metadata.strings[metadata.types[metadata.field_refs[0].type]] == u"I");
                    const auto metadata_baseline = metadata_memory.current;

                    unsigned cancellations = 0;
                    const auto cancelled = [](void* context) noexcept {
                        ++*static_cast<unsigned*>(context); return true;
                    };
                    {
                        const auto not_requested = facts::collect_method(bytes, metadata, caller, 0, &scratch_memory, cancelled, &cancellations);
                        CHECK(not_requested.has_body && !not_requested.instruction_checked && not_requested.decoded_code_units == 0);
                        CHECK(not_requested.string_uses.empty() && not_requested.invoke_sites.empty() && not_requested.field_uses.empty());
                        CHECK(cancellations == 0 && scratch_memory.current == 0);
                    }
                    for (const auto* name : {u"nativeMethod", u"abstractMethod"}) {
                        const auto no_body = facts::collect_method(bytes, metadata, ordinal(metadata, name), 7, &scratch_memory, cancelled, &cancellations);
                        CHECK(!no_body.has_body && !no_body.instruction_checked && no_body.decoded_code_units == 0);
                        CHECK(no_body.string_uses.empty() && no_body.invoke_sites.empty() && no_body.field_uses.empty());
                        CHECK(cancellations == 0 && scratch_memory.current == 0);
                    }
                    {
                        bool cancelled_before = false;
                        try { (void)facts::collect_method(bytes, metadata, caller, 7, &scratch_memory, cancelled, &cancellations); }
                        catch (const instructions::DecodeError& error) {
                            CHECK(error.code == instructions::DecodeCode::cancelled && error.dex_pc == 0);
                            CHECK(error.dex_offset == 432); cancelled_before = true;
                        }
                        CHECK(cancelled_before && cancellations == 1 && scratch_memory.current == 0);
                    }
                    {
                        bool limited = false;
                        try { (void)facts::collect_method(bytes, metadata, caller, 7, &scratch_memory, nullptr, nullptr, 7); }
                        catch (const instructions::DecodeError& error) {
                            CHECK(error.code == instructions::DecodeCode::budget && error.dex_pc == 0); limited = true;
                        }
                        CHECK(limited && scratch_memory.current == 0);
                    }
                    {
                        scratch_memory.limit = 0; bool failed = false;
                        try { (void)facts::collect_method(bytes, metadata, caller, 7, &scratch_memory); }
                        catch (const std::bad_alloc&) { failed = true; }
                        scratch_memory.limit = std::numeric_limits<size_t>::max();
                        CHECK(failed && scratch_memory.current == 0);
                    }

                    const auto code = metadata.methods[caller].code_offset;
                    if (which == 3) {
                        CHECK(unit(bytes, code, 0) == 0x001a && unit(bytes, code, 1) == 10);
                        CHECK(unit(bytes, code, 2) == 0x0071 && unit(bytes, code, 3) == 4);
                        CHECK(unit(bytes, code, 5) == 0x0073);
                        bool returned_complete = false, corrupt = false;
                        try {
                            const auto incomplete = facts::collect_method(bytes, metadata, caller, 7, &scratch_memory);
                            returned_complete = incomplete.instruction_checked;
                        } catch (const instructions::DecodeError& error) {
                            CHECK(error.code == instructions::DecodeCode::corrupt && error.dex_pc == 5);
                            CHECK(error.dex_offset == 442); corrupt = true;
                        }
                        CHECK(corrupt && !returned_complete && scratch_memory.current == 0);
                    } else {
                        {
                            const auto result = facts::collect_method(bytes, metadata, caller, 7, &scratch_memory);
                            CHECK(result.has_body && result.instruction_checked && result.decoded_code_units == 8);
                            CHECK(result.method_index == 3 && result.code_offset == code && result.validation_work >= 8);
                            CHECK(scratch_memory.current > 0);
                            if (which == 0) {
                                CHECK(result.string_uses.empty() && result.field_uses.empty() && result.invoke_sites.size() == 2);
                                for (uint32_t i = 0; i < 2; ++i) {
                                    const auto& call = result.invoke_sites[i];
                                    CHECK(call.pc == i * 3 && call.opcode == 0x71 && call.index == 4);
                                    CHECK(call.reference_kind == instructions::ReferenceKind::method && call.extra_proto == UINT32_MAX);
                                    CHECK(unit(bytes, code, call.pc) == 0x0071 && unit(bytes, code, call.pc + 1) == 4);
                                }
                                CHECK(result.invoke_sites[0].pc != result.invoke_sites[1].pc && result.invoke_sites[0].index == result.invoke_sites[1].index);
                            } else if (which == 1) {
                                CHECK(result.string_uses.empty() && result.invoke_sites.empty() && result.field_uses.size() == 2);
                                CHECK(result.field_uses[0].pc == 0 && result.field_uses[0].opcode == 0x60 && result.field_uses[0].field_index == 0);
                                CHECK(result.field_uses[1].pc == 2 && result.field_uses[1].opcode == 0x67 && result.field_uses[1].field_index == 0);
                                CHECK(unit(bytes, code, 0) == 0x0060 && unit(bytes, code, 1) == 0 && unit(bytes, code, 2) == 0x0067 && unit(bytes, code, 3) == 0);
                            } else {
                                CHECK(result.invoke_sites.empty() && result.field_uses.empty() && result.string_uses.size() == 2);
                                CHECK(result.string_uses[0].pc == 0 && result.string_uses[0].opcode == 0x1a && result.string_uses[0].string_index == 10);
                                CHECK(result.string_uses[1].pc == 2 && result.string_uses[1].opcode == 0x1b && result.string_uses[1].string_index == 10);
                                CHECK(unit(bytes, code, 0) == 0x001a && unit(bytes, code, 1) == 10);
                                CHECK(unit(bytes, code, 2) == 0x001b && unit(bytes, code, 3) == 10 && unit(bytes, code, 4) == 0);
                                CHECK(std::none_of(result.string_uses.begin(), result.string_uses.end(), [](const auto& item) { return item.string_index == 7; }));
                            }
                        }
                        CHECK(scratch_memory.current == 0);
                        {
                            unsigned calls = 0;
                            const auto cancel_after_first_instruction = [](void* context) noexcept {
                                return ++*static_cast<unsigned*>(context) >= 3;
                            };
                            bool cancelled_midway = false, returned_complete = false;
                            try {
                                const auto incomplete = facts::collect_method(bytes, metadata, caller, 7, &scratch_memory, cancel_after_first_instruction, &calls);
                                returned_complete = incomplete.instruction_checked;
                            } catch (const instructions::DecodeError& error) {
                                CHECK(error.code == instructions::DecodeCode::cancelled && error.dex_pc > 0);
                                cancelled_midway = true;
                            }
                            CHECK(cancelled_midway && !returned_complete && calls == 3 && scratch_memory.current == 0);
                        }
                    }
                    CHECK(metadata_memory.current == metadata_baseline && scratch_memory.current == 0);
                }
                CHECK(metadata_memory.current == 0 && scratch_memory.current == 0);
                ++checks;
            }
        } catch (...) { std::pmr::set_default_resource(previous); throw; }
        std::pmr::set_default_resource(previous);
        CHECK(metadata_memory.current == 0 && scratch_memory.current == 0);
        std::cout << "PASS use fixtures: " << checks << " independently authored DEX variants; exact PC/opcode/reference domains, no-body and unrequested facts, corrupt/cancel/budget failures and PMR reclamation\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
