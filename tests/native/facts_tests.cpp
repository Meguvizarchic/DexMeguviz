#include "facts/method_facts.hpp"
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <atomic>
#ifdef _MSC_VER
#include <crtdbg.h>
#endif

using namespace dexmeguviz;
#define CHECK(condition) do { if (!(condition)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #condition); } while (0)
struct Counted final : std::pmr::memory_resource {
    size_t current = 0, peak = 0;
    void* do_allocate(size_t bytes, size_t alignment) override {
        auto* pointer = std::pmr::new_delete_resource()->allocate(bytes, alignment);
        current += bytes; peak = std::max(peak, current); return pointer;
    }
    void do_deallocate(void* pointer, size_t bytes, size_t alignment) override {
        current -= bytes; std::pmr::new_delete_resource()->deallocate(pointer, bytes, alignment);
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override { return this == &other; }
};
static uint32_t ordinal(const Facts& metadata, std::u16string_view name) {
    for (uint32_t i = 0; i < metadata.methods.size(); ++i) if (metadata.methods[i].name == name) return i;
    throw std::runtime_error("expected definition absent");
}
int main(int argc, char** argv) {
    try {
#ifdef _MSC_VER
        _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
        _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
        CHECK(argc == 2);
        std::ifstream input(argv[1], std::ios::binary);
        CHECK(input.good());
        std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)), {});
        std::ifstream domain_input(std::filesystem::path(argv[1]).parent_path() / "invoke-domains-038.dex", std::ios::binary);
        CHECK(domain_input.good());
        std::vector<uint8_t> domain_bytes((std::istreambuf_iterator<char>(domain_input)), {});
        Counted resource;
        auto* previous = std::pmr::set_default_resource(std::pmr::null_memory_resource());
        try {
            auto metadata = read_metadata(bytes, &resource);
            auto moved_metadata=std::move(metadata);
            metadata=std::move(moved_metadata);
            for(const auto& method:metadata.methods){
                const auto& reference=metadata.method_refs[method.method_index];
                CHECK(method.owner.data()==metadata.strings[metadata.types[reference.owner]].data());
                CHECK(method.name.data()==metadata.strings[reference.name].data());
                CHECK(method.prototype.data()==metadata.prototypes[reference.type].descriptor.data());
            }
            { Counted another;Facts incompatible(&another);bool refused=false;
              try{incompatible=std::move(metadata);}catch(const std::invalid_argument&){refused=true;}
              CHECK(refused && !metadata.methods.empty() && another.current==0); }
            CHECK(metadata.methods.size() == 4 && metadata.method_refs.size() == 5 && metadata.field_refs.size() == 1);
            CHECK(metadata.strings.size() == 12 && metadata.types.size() == 4 && metadata.prototypes.size() == 1);
            CHECK(metadata.strings[7] == u"only-in-pool" && metadata.strings[10] == u"used-string");
            CHECK(metadata.call_site_count == 0 && metadata.method_handle_count == 0);
            CHECK(metadata.strings.get_allocator().resource() == &resource && metadata.types.get_allocator().resource() == &resource);
            CHECK(metadata.prototypes.get_allocator().resource() == &resource && metadata.method_refs.get_allocator().resource() == &resource);
            CHECK(metadata.field_refs.get_allocator().resource() == &resource);
            for (const auto& text : metadata.strings) CHECK(text.get_allocator().resource() == &resource);
            CHECK(metadata.prototypes[0].parameters.get_allocator().resource() == &resource);
            CHECK(metadata.prototypes[0].descriptor.get_allocator().resource() == &resource);
            const auto uses = ordinal(metadata, u"uses"), quiet = ordinal(metadata, u"quiet");
            CHECK(metadata.methods[uses].method_index == 3 && metadata.methods[quiet].method_index == 2);
            CHECK(bytes.at(metadata.methods[uses].code_offset + 16) == 0x1a);
            CHECK(bytes.at(metadata.methods[uses].code_offset + 20) == 0x71);
            CHECK(bytes.at(metadata.methods[uses].code_offset + 26) == 0x60);
            CHECK(bytes.at(metadata.methods[quiet].code_offset + 16) == 0x0e);
            { facts::MethodFacts inconsistent(&resource); inconsistent.has_body=true;
              inconsistent.requested_mask=instructions::strings;
              CHECK(inconsistent.availability(instructions::strings)==facts::FactAvailability::unknown); }

            const auto retained_metadata = resource.current;
            {
                auto result = facts::collect_method(bytes, metadata, uses, instructions::strings | instructions::invokes | instructions::fields, &resource);
                CHECK(result.has_body && result.instruction_checked && result.decoded_code_units == 8);
                CHECK(result.availability(instructions::strings) == facts::FactAvailability::checked);
                CHECK(result.availability(instructions::numeric) == facts::FactAvailability::not_requested);
                CHECK(result.method_index == 3 && result.code_offset == metadata.methods[uses].code_offset);
                CHECK(result.string_uses.size() == 1 && result.string_uses[0].pc == 0 && result.string_uses[0].string_index == 10);
                CHECK(result.invoke_sites.size() == 1 && result.invoke_sites[0].pc == 2 && result.invoke_sites[0].index == 4);
                CHECK(result.invoke_sites[0].reference_kind == instructions::ReferenceKind::method && result.invoke_sites[0].extra_proto == UINT32_MAX);
                CHECK(result.field_uses.size() == 1 && result.field_uses[0].pc == 5 && result.field_uses[0].field_index == 0);
                const auto& invoked = metadata.method_refs[result.invoke_sites[0].index];
                CHECK(metadata.strings[metadata.types[invoked.owner]] == u"Ljava/lang/Object;");
                CHECK(metadata.strings[invoked.name] == u"sink" && metadata.prototypes[invoked.type].descriptor == u"()V");
                CHECK(std::none_of(metadata.methods.begin(), metadata.methods.end(), [&](const Method& method) { return method.method_index == result.invoke_sites[0].index; }));
                const auto& field = metadata.field_refs[result.field_uses[0].field_index];
                CHECK(metadata.strings[field.name] == u"counter" && metadata.strings[metadata.types[field.type]] == u"I");
                CHECK(result.string_uses.get_allocator().resource() == &resource && resource.current > retained_metadata);
            }
            CHECK(resource.current == retained_metadata);
            {
                const auto result = facts::collect_method(bytes, metadata, quiet, instructions::strings | instructions::invokes | instructions::fields, &resource);
                CHECK(result.has_body && result.instruction_checked && result.decoded_code_units == 1);
                CHECK(result.string_uses.empty() && result.invoke_sites.empty() && result.field_uses.empty());
                CHECK(result.availability(instructions::strings) == facts::FactAvailability::checked);
                CHECK(result.availability(instructions::numeric) == facts::FactAvailability::not_requested);
            }
            for (const auto name : {u"nativeMethod", u"abstractMethod"}) {
                const auto result = facts::collect_method(bytes, metadata, ordinal(metadata, name), instructions::strings, &resource);
                CHECK(!result.has_body && !result.instruction_checked && result.decoded_code_units == 0 && result.string_uses.empty());
                CHECK(result.availability(instructions::strings) == facts::FactAvailability::no_body);
                CHECK(result.availability(instructions::invokes) == facts::FactAvailability::not_requested);
                const auto branch = facts::collect_method(bytes, metadata, ordinal(metadata, name), instructions::branch_targets, &resource);
                CHECK(!branch.has_body && !branch.instruction_checked && branch.branches.empty());
            }
            {
                const auto result = facts::collect_method(bytes, metadata, uses, instructions::strings, &resource);
                CHECK(result.string_uses.size() == 1 && result.invoke_sites.empty() && result.field_uses.empty());
                CHECK(result.availability(instructions::strings) == facts::FactAvailability::checked);
                CHECK(result.availability(instructions::invokes) == facts::FactAvailability::not_requested);
                bool invalid=false;
                for (auto bad : {0u, 256u, uint32_t(instructions::strings | instructions::invokes)}) {
                    try { (void)result.availability(bad); } catch (const std::invalid_argument&) { invalid=true; }
                    CHECK(invalid); invalid=false;
                }
                CHECK(std::none_of(result.string_uses.begin(), result.string_uses.end(), [](const auto& use) { return use.string_index == 7; }));
            }
            for (const uint32_t bit : {uint32_t(instructions::strings), uint32_t(instructions::invokes),
                    uint32_t(instructions::fields), uint32_t(instructions::numeric), uint32_t(instructions::array_data),
                    uint32_t(instructions::switch_targets), uint32_t(instructions::branch_targets)}) {
                const auto result=facts::collect_method(bytes, metadata, uses, bit, &resource);
                CHECK(result.availability(bit)==facts::FactAvailability::checked);
                const auto other=bit==instructions::strings ? uint32_t(instructions::invokes) : uint32_t(instructions::strings);
                CHECK(result.availability(other)==facts::FactAvailability::not_requested);
                const auto empty=facts::collect_method(bytes, metadata, ordinal(metadata,u"nativeMethod"),bit,&resource);
                CHECK(empty.availability(bit)==facts::FactAvailability::no_body);
                CHECK(empty.availability(other)==facts::FactAvailability::not_requested);
            }
            unsigned cancellation_calls = 0;
            const auto cancel = [](void* context) noexcept { ++*static_cast<unsigned*>(context); return true; };
            {
                const auto result = facts::collect_method(bytes, metadata, uses, 0, &resource, cancel, &cancellation_calls);
                CHECK(result.has_body && !result.instruction_checked && !result.decoded_code_units && cancellation_calls == 0);
                CHECK(result.availability(instructions::strings) == facts::FactAvailability::not_requested);
            }
            bool cancelled = false;
            try { (void)facts::collect_method(bytes, metadata, uses, instructions::strings, &resource, cancel, &cancellation_calls); }
            catch (const instructions::DecodeError& error) { CHECK(error.code == instructions::DecodeCode::cancelled); cancelled = true; }
            CHECK(cancelled && cancellation_calls == 1 && resource.current == retained_metadata);
            bool unsupported = false;
            try { (void)facts::collect_method(bytes, metadata, ordinal(metadata, u"nativeMethod"), 256, &resource); }
            catch (const instructions::DecodeError& error) { CHECK(error.code == instructions::DecodeCode::unsupported); unsupported = true; }
            CHECK(unsupported && resource.current == retained_metadata);
            bool bad_ordinal = false;
            try { (void)facts::collect_method(bytes, metadata, 999, 0, &resource); }
            catch (const std::out_of_range&) { bad_ordinal = true; }
            CHECK(bad_ordinal);
            auto bad_bytes = bytes;
            bad_bytes[metadata.methods[uses].code_offset + 16] = 0x3e;
            auto bad_metadata = read_metadata(bad_bytes, &resource);
            const auto skipped = facts::collect_method(bad_bytes, bad_metadata, ordinal(bad_metadata, u"uses"), 0, &resource);
            CHECK(skipped.has_body && !skipped.instruction_checked);
            bool corrupt = false;
            try { (void)facts::collect_method(bad_bytes, bad_metadata, ordinal(bad_metadata, u"uses"), instructions::strings, &resource); }
            catch (const instructions::DecodeError& error) { CHECK(error.code == instructions::DecodeCode::corrupt); corrupt = true; }
            CHECK(corrupt);
            const auto domain_metadata = read_metadata(domain_bytes, &resource);
            CHECK(domain_metadata.call_site_count == 1 && domain_metadata.method_handle_count == 1);
            const auto domains = facts::collect_method(domain_bytes, domain_metadata, ordinal(domain_metadata, u"uses"), instructions::invokes, &resource);
            CHECK(domains.invoke_sites.size() == 2 && domains.string_uses.empty() && domains.field_uses.empty());
            CHECK(domains.invoke_sites[0].pc == 0 && domains.invoke_sites[0].index == 4 && domains.invoke_sites[0].extra_proto == 0 &&
                domains.invoke_sites[0].reference_kind == instructions::ReferenceKind::method_and_proto);
            CHECK(domains.invoke_sites[1].pc == 4 && domains.invoke_sites[1].index == 0 && domains.invoke_sites[1].extra_proto == UINT32_MAX &&
                domains.invoke_sites[1].reference_kind == instructions::ReferenceKind::call_site);
        } catch (...) { std::pmr::set_default_resource(previous); throw; }
        std::pmr::set_default_resource(previous);
        CHECK(resource.current == 0);
        auto metadata = read_metadata(bytes);
        std::atomic<unsigned> successful{0};
        auto work = [&] {
            try {
                // Concurrent callers use separate result allocators; immutable metadata is shared.
                std::pmr::unsynchronized_pool_resource local;
                const auto result = facts::collect_method(bytes, metadata, ordinal(metadata, u"uses"), instructions::strings, &local);
                if (result.string_uses.size() == 1 && result.string_uses[0].pc == 0) ++successful;
            } catch (...) {}
        };
        std::thread one(work), two(work); one.join(); two.join();
        CHECK(successful == 2);
        std::cout << "PASS method_facts: original DEX -> retained metadata -> checked method uses, independent PC/index golden, no-body/demand/cancel/error scopes, external references, PMR release and concurrent read-only collection\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
