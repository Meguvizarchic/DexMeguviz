#include "facts/use_relations/use_scan.hpp"
#include "source/sha256.hpp"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <vector>

using namespace dexmeguviz;
using namespace dexmeguviz::facts;
#define CHECK(x) do { if (!(x)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #x); } while (0)

struct Counted final : std::pmr::memory_resource {
    size_t live = 0, allocations = 0;
    void* do_allocate(size_t bytes, size_t alignment) override {
        void* p = std::pmr::new_delete_resource()->allocate(bytes, alignment);
        live += bytes; ++allocations; return p;
    }
    void do_deallocate(void* p, size_t bytes, size_t alignment) override {
        CHECK(live >= bytes); live -= bytes;
        std::pmr::new_delete_resource()->deallocate(p, bytes, alignment);
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override { return this == &other; }
};

struct Trace {
    std::vector<UseRecord> records;
    std::vector<UseScanProgress> completed;
};

static UseScanHooks hooks(Trace& trace) {
    return {
        [](void*) noexcept { return UINT64_MAX; },
        [](void* context, std::span<const UseRecord> rows, const UseScanProgress& progress) {
            auto& trace = *static_cast<Trace*>(context);
            CHECK(progress.visited_methods == trace.completed.size() + 1);
            CHECK(progress.attempted_methods == progress.visited_methods);
            for (const auto& row : rows) CHECK(row.key.caller_ordinal + 1 == progress.visited_methods);
            trace.records.insert(trace.records.end(), rows.begin(), rows.end());
            trace.completed.push_back(progress);
        },
        &trace,
    };
}

static bool same(const UseRecord& a, const UseRecord& b) {
    return a.key == b.key && a.caller_method_ref == b.caller_method_ref && a.code_offset == b.code_offset &&
           a.target_index == b.target_index && a.extra_proto == b.extra_proto && a.opcode == b.opcode &&
           a.target_domain == b.target_domain;
}

int main(int argc, char** argv) {
    try {
        CHECK(argc == 2);
        const auto path = std::filesystem::path(argv[1]) / "generated/use_relations/two-invokes.dex";
        std::ifstream file(path, std::ios::binary); CHECK(file.good());
        const std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)), {});
        CHECK(sha256<>(bytes) == "04656bbfe03c8b04e6f77d29b8cae8e7e06f18a038f85300658f8c691435648b");
        Counted owner, scratch;
        {
            const auto metadata = read_metadata(bytes, &owner);
            const auto owner_before = owner.live;
            CHECK(metadata.methods.size() == 4);
            for (const auto kind : {UseKind::string_use, UseKind::invoke_site, UseKind::field_use}) {
                Trace trace;
                UseScanProgress traced{}, plain{};
                {
                    const auto a = collect_uses(bytes, metadata, 7, kind, traced, &scratch, {}, {}, hooks(trace));
                    const auto b = collect_uses(bytes, metadata, 7, kind, plain, &scratch);
                    CHECK(trace.completed.size() == 4 && traced.total_methods == 4 && traced.attempted_methods == 4);
                    CHECK(traced.visited_methods == 4 && traced.decoded_methods == 2 && traced.no_body_methods == 2);
                    CHECK(traced.emitted_events == a.rows.size() && a.rows.size() == trace.records.size());
                    CHECK(a.rows.size() == b.rows.size() && traced.work_units == plain.work_units);
                    CHECK(traced.validation_work == plain.validation_work && traced.code_units == plain.code_units);
                    for (size_t i = 0; i < a.rows.size(); ++i) {
                        CHECK(same(a.rows[i], trace.records[i]) && same(a.rows[i], b.rows[i]));
                        CHECK(a.rows[i].key.source_index == 7 && a.rows[i].key.kind == kind);
                    }
                    if (kind == UseKind::invoke_site) {
                        CHECK(a.rows.size() == 2 && a.rows[0].key.caller_ordinal == 2 && a.rows[1].key.caller_ordinal == 2);
                        CHECK(a.rows[0].key.dex_pc == 0 && a.rows[1].key.dex_pc == 3);
                        CHECK(a.rows[0].target_index == 4 && a.rows[1].target_index == 4);
                    } else CHECK(a.rows.empty());
                }
                CHECK(owner.live == owner_before && scratch.live == 0);
                // A second scan repeats the forward method callbacks; no cache reuse is inferred.
                Trace again; UseScanProgress repeated{};
                {
                    const auto result = collect_uses(bytes, metadata, 7, kind, repeated, &scratch, {}, {}, hooks(again));
                    CHECK(again.completed.size() == 4 && repeated.work_units == traced.work_units);
                    CHECK(result.rows.size() == trace.records.size());
                    for (size_t i = 0; i < result.rows.size(); ++i) CHECK(same(result.rows[i], trace.records[i]));
                }
                CHECK(owner.live == owner_before && scratch.live == 0);
            }
        }
        CHECK(owner.live == 0 && scratch.live == 0 && scratch.allocations > 0);
        std::cout << "PASS forward scan trace: callbacks, stable occurrences, repeated scans, work and PMR reclamation\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
