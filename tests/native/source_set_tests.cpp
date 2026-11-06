#include "dexmeguviz/dexmeguviz.h"
#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef _MSC_VER
#include <crtdbg.h>
#endif

#define CHECK(condition) do { if (!(condition)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #condition); } while (0)
using Engine = std::unique_ptr<dmg_engine, decltype(&dmg_engine_release)>;
using Snapshot = std::unique_ptr<dmg_snapshot, decltype(&dmg_snapshot_release)>;
using Result = std::unique_ptr<dmg_result, decltype(&dmg_result_release)>;
using Query = std::unique_ptr<dmg_query, decltype(&dmg_query_release)>;
using Job = std::unique_ptr<dmg_job, decltype(&dmg_job_release)>;
using Batch = std::unique_ptr<dmg_batch, decltype(&dmg_batch_release)>;

static std::vector<uint8_t> load(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary); CHECK(input.good());
    return {(std::istreambuf_iterator<char>(input)), {}};
}
static dmg_engine_stats stats(dmg_engine* engine) {
    dmg_engine_stats out{}; CHECK(dmg_engine_get_stats(engine, &out) == DMG_OK); return out;
}
static dmg_source_spec spec(const std::vector<uint8_t>& bytes, const char* slot, uint32_t format = DMG_INPUT_RAW_DEX, uint32_t allow_empty = 0) {
    return {sizeof(dmg_source_spec), DMG_ABI_VERSION, format, allow_empty, bytes.data(), bytes.size(), slot, "source", nullptr};
}
static dmg_source_set_options options(uint32_t complete = 1) {
    return {sizeof(dmg_source_set_options), DMG_ABI_VERSION, "source-set-test", complete, 32, 8u << 20};
}
static Snapshot open(dmg_engine* engine, const dmg_source_spec* sources, uint32_t count, uint32_t complete = 1) {
    const auto o = options(complete); dmg_snapshot* raw = nullptr; dmg_error error{};
    CHECK(dmg_snapshot_open_sources(engine, sources, count, &o, &raw, &error) == DMG_OK);
    return Snapshot(raw, &dmg_snapshot_release);
}
static dmg_method_query query_options(bool match = true, uint32_t intent = DMG_UNIQUE) {
    static const uint16_t second[]{'s','e','c','o','n','d'};
    static const uint16_t absent[]{'n','o','p','e'};
    dmg_method_query q{}; q.struct_size = sizeof(q); q.abi_version = DMG_ABI_VERSION;
    q.intent = intent; q.max_results = 100; q.name_enabled = 1;
    q.name = match ? second : absent; q.name_length = match ? 6 : 4;
    return q;
}
static Result query(dmg_snapshot* snapshot, bool match = true, uint32_t intent = DMG_UNIQUE) {
    const auto q = query_options(match, intent); dmg_result* raw = nullptr; dmg_error error{};
    CHECK(dmg_query_methods(snapshot, &q, &raw, &error) == DMG_OK);
    return Result(raw, &dmg_result_release);
}
static dmg_result_info outcome(const Result& result) {
    dmg_result_info info{}; CHECK(dmg_result_get_info(result.get(), &info) == DMG_OK); return info;
}
static dmg_snapshot_overview overview(dmg_snapshot* snapshot) {
    dmg_snapshot_overview info{}; CHECK(dmg_snapshot_get_overview(snapshot, &info) == DMG_OK); return info;
}

int main(int argc, char** argv) {
    try {
#ifdef _MSC_VER
        _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
        _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
        CHECK(argc == 2); const std::filesystem::path root(argv[1]);
        const auto raw = load(root / "generated/minimal.dex");
        const auto stored = load(root / "generated/archive/stored.apk");
        const auto deflated = load(root / "generated/archive/deflated.apk");
        const auto multidex = load(root / "generated/archive/multidex.apk");
        const auto empty = load(root / "generated/archive/empty.zip");
        const auto resource_only = load(root / "generated/archive/zero-entry.zip");
        const auto crc_bad = load(root / "generated/archive/crc-mismatch.apk");
        dmg_engine_options engine_options{sizeof(engine_options), DMG_ABI_VERSION, 16u << 20, 8u << 20, 8u << 20, 2, 0};
        dmg_engine* raw_engine = nullptr; dmg_error error{};
        CHECK(dmg_engine_create(&engine_options, &raw_engine, &error) == DMG_OK);
        Engine engine(raw_engine, &dmg_engine_release);
        const auto baseline = stats(engine.get()).owned_bytes;
        std::array<dmg_source_spec, 2> sources{spec(raw, "base"), spec(raw, "split")};
        auto snapshot = open(engine.get(), sources.data(), 2);
        auto summary = overview(snapshot.get());
        CHECK(summary.input_count == 2 && summary.source_count == 2 && summary.scope_complete == 1 && summary.method_def_count == 4);
        const std::string first_snapshot = summary.snapshot_id;
        dmg_source_info first{}, second{};
        CHECK(dmg_snapshot_get_source_info(snapshot.get(), 0, &first) == DMG_OK);
        CHECK(dmg_snapshot_get_source_info(snapshot.get(), 1, &second) == DMG_OK);
        const std::string base_occurrence = first.dex.occurrence_id, split_occurrence = second.dex.occurrence_id;
        CHECK(base_occurrence != split_occurrence && std::string(first.dex.content_id) == second.dex.content_id);
        CHECK(std::string(first.logical_dex_id) == second.logical_dex_id);
        {
            auto input = raw;
            auto checked = spec(input, "checked", DMG_INPUT_AUTO);
            checked.expected_sha256 = "dd0e9527dda007481637b6b43393a8239635e85fa006b452092dcc064c3e456f";
            auto copied = open(engine.get(), &checked, 1);
            dmg_input_info input_info{}; dmg_source_info source_info{};
            CHECK(dmg_snapshot_get_input_info(copied.get(), 0, &input_info) == DMG_OK);
            CHECK(dmg_snapshot_get_source_info(copied.get(), 0, &source_info) == DMG_OK);
            CHECK(input_info.expected_digest_verified && source_info.expected_digest_verified);
            CHECK(std::string(input_info.source_sha256) == checked.expected_sha256);
            CHECK(std::string(source_info.dex.source_sha256) == checked.expected_sha256);
            input[0] ^= 0xff;
            const uint8_t* bytes = nullptr; uint64_t size = 0;
            CHECK(dmg_snapshot_get_source_bytes_v1(copied.get(), 0, raw.size(), &bytes, &size) == DMG_OK);
            CHECK(size == raw.size() && std::equal(bytes, bytes + size, raw.begin()));
        }
        dmg_snapshot_info unsupported{};
        CHECK(dmg_snapshot_get_info(snapshot.get(), &unsupported) == DMG_UNSUPPORTED);
        auto result = query(snapshot.get());
        auto info = outcome(result);
        CHECK(info.candidates_count == 2 && info.decision == DMG_PROVEN_FALSE && info.reason == DMG_AMBIGUOUS);
        CHECK(dmg_result_get_origin(result.get(), 0, &first) == DMG_OK && first.source_index == 0);
        CHECK(dmg_result_get_origin(result.get(), 1, &second) == DMG_OK && second.source_index == 1);
        CHECK(std::string(first.dex.occurrence_id) != second.dex.occurrence_id);
        CHECK(dmg_result_get_source(result.get(), &unsupported) == DMG_UNSUPPORTED);
        snapshot.reset();
        CHECK(dmg_result_get_source_info(result.get(), 1, &second) == DMG_OK && split_occurrence == second.dex.occurrence_id);
        CHECK(stats(engine.get()).source_bytes > 0 && stats(engine.get()).fact_bytes > 0);
        result.reset(); CHECK(stats(engine.get()).owned_bytes == baseline);

        std::swap(sources[0], sources[1]);
        snapshot = open(engine.get(), sources.data(), 2);
        CHECK(first_snapshot != overview(snapshot.get()).snapshot_id);
        CHECK(dmg_snapshot_get_source_info(snapshot.get(), 0, &first) == DMG_OK && split_occurrence == first.dex.occurrence_id);
        CHECK(dmg_snapshot_get_source_info(snapshot.get(), 1, &second) == DMG_OK && base_occurrence == second.dex.occurrence_id);
        snapshot.reset(); std::swap(sources[0], sources[1]);
        snapshot = open(engine.get(), sources.data(), 2);
        CHECK(first_snapshot == overview(snapshot.get()).snapshot_id);
        snapshot.reset(); CHECK(stats(engine.get()).owned_bytes == baseline);

        const auto full = options(); dmg_snapshot* rejected = nullptr;
        sources[1].slot_key = "base";
        CHECK(dmg_snapshot_open_sources(engine.get(), sources.data(), 2, &full, &rejected, &error) == DMG_INVALID_ARGUMENT && rejected == nullptr);
        CHECK(stats(engine.get()).owned_bytes == baseline); sources[1].slot_key = "split";
        for (const uint32_t source_count : {1u, 2u}) {
            snapshot = open(engine.get(), sources.data(), source_count, 0);
            if (source_count == 2) CHECK(first_snapshot != overview(snapshot.get()).snapshot_id);
            result = query(snapshot.get(), true);
            info = outcome(result);
            CHECK(info.coverage == DMG_COVERAGE_PARTIAL && info.execution_status == DMG_OK);
            CHECK(info.decision == (source_count == 1 ? DMG_UNDETERMINED : DMG_PROVEN_FALSE));
            CHECK(info.reason == (source_count == 1 ? DMG_SOURCE_SCOPE_INCOMPLETE : DMG_AMBIGUOUS));
            result.reset(); result = query(snapshot.get(), false); info = outcome(result);
            CHECK(info.candidates_count == 0 && info.coverage == DMG_COVERAGE_PARTIAL && info.decision == DMG_UNDETERMINED && info.reason == DMG_SOURCE_SCOPE_INCOMPLETE);
            result.reset(); snapshot.reset(); CHECK(stats(engine.get()).owned_bytes == baseline);
        }

        auto empty_spec = spec(empty, "resources", DMG_INPUT_APK);
        CHECK(dmg_snapshot_open_sources(engine.get(), &empty_spec, 1, &full, &rejected, &error) == DMG_CORRUPT_INPUT && rejected == nullptr);
        CHECK(stats(engine.get()).owned_bytes == baseline);
        empty_spec.allow_no_dex = 1; snapshot = open(engine.get(), &empty_spec, 1);
        summary = overview(snapshot.get()); CHECK(summary.input_count == 1 && summary.source_count == 0 && summary.method_def_count == 0);
        const std::string empty_snapshot = summary.snapshot_id;
        result = query(snapshot.get()); info = outcome(result);
        CHECK(info.coverage == DMG_COVERAGE_COMPLETE && info.decision == DMG_PROVEN_FALSE && info.reason == DMG_NO_MATCH);
        CHECK(dmg_snapshot_get_info(snapshot.get(), &unsupported) == DMG_UNSUPPORTED);
        result.reset(); snapshot.reset();
        const auto resource_spec = spec(resource_only, "resources", DMG_INPUT_APK, 1);
        snapshot = open(engine.get(), &resource_spec, 1);
        CHECK(overview(snapshot.get()).source_count == 0 && empty_snapshot != overview(snapshot.get()).snapshot_id);
        snapshot.reset(); CHECK(stats(engine.get()).owned_bytes == baseline);

        std::string stored_snapshot, stored_occurrence;
        for (const auto* archive_bytes : {&stored, &deflated, &multidex}) {
            const auto archive_spec = spec(*archive_bytes, "apk", DMG_INPUT_AUTO);
            snapshot = open(engine.get(), &archive_spec, 1);
            const uint32_t count = archive_bytes == &multidex ? 2 : 1;
            CHECK(overview(snapshot.get()).source_count == count);
            for (uint32_t i = 0; i < count; ++i) {
                CHECK(dmg_snapshot_get_source_info(snapshot.get(), i, &first) == DMG_OK);
                CHECK(first.crc_verified && first.header_consistency_verified && std::string(first.slot_key) == "apk");
                CHECK(std::string(first.archive_entry_name) == (i ? "classes2.dex" : "classes.dex"));
            }
            if (archive_bytes == &stored) {
                stored_snapshot = overview(snapshot.get()).snapshot_id;
                stored_occurrence = first.dex.occurrence_id;
            } else if (archive_bytes == &deflated) {
                CHECK(stored_snapshot != overview(snapshot.get()).snapshot_id && stored_occurrence == first.dex.occurrence_id);
            }
            snapshot.reset(); CHECK(stats(engine.get()).owned_bytes == baseline);
        }
        // An attacker-controlled raw slot must not collide with a former encoded APK slot.
        const std::array<dmg_source_spec, 2> collision{spec(stored, "apk", DMG_INPUT_APK), spec(raw, "archive-slot:v1:3:apk11:classes.dex")};
        snapshot = open(engine.get(), collision.data(), 2);
        CHECK(dmg_snapshot_get_source_info(snapshot.get(), 0, &first) == DMG_OK && dmg_snapshot_get_source_info(snapshot.get(), 1, &second) == DMG_OK);
        CHECK(std::string(first.dex.content_id) == second.dex.content_id && std::string(first.dex.occurrence_id) != second.dex.occurrence_id);
        snapshot.reset(); CHECK(stats(engine.get()).owned_bytes == baseline);

        auto damaged = raw; damaged[0] = 0;
        sources[1] = spec(damaged, "bad");
        CHECK(dmg_snapshot_open_sources(engine.get(), sources.data(), 2, &full, &rejected, &error) == DMG_CORRUPT_INPUT && rejected == nullptr);
        CHECK(stats(engine.get()).owned_bytes == baseline);
        sources[1] = spec(crc_bad, "bad", DMG_INPUT_APK);
        CHECK(dmg_snapshot_open_sources(engine.get(), sources.data(), 2, &full, &rejected, &error) == DMG_CORRUPT_INPUT && rejected == nullptr);
        CHECK(stats(engine.get()).owned_bytes == baseline);
        sources[1] = spec(raw, "split"); sources[1].expected_sha256 = "incorrect";
        CHECK(dmg_snapshot_open_sources(engine.get(), sources.data(), 2, &full, &rejected, &error) == DMG_SOURCE_MISMATCH && rejected == nullptr);
        CHECK(stats(engine.get()).owned_bytes == baseline); sources[1].expected_sha256 = nullptr;
        auto limited = full; limited.max_sources = 1;
        CHECK(dmg_snapshot_open_sources(engine.get(), sources.data(), 2, &limited, &rejected, &error) == DMG_BUDGET_EXCEEDED && rejected == nullptr);
        CHECK(stats(engine.get()).owned_bytes == baseline);
        limited = full; limited.max_total_dex_bytes = raw.size();
        CHECK(dmg_snapshot_open_sources(engine.get(), sources.data(), 2, &limited, &rejected, &error) == DMG_BUDGET_EXCEEDED && rejected == nullptr);
        CHECK(stats(engine.get()).owned_bytes == baseline);

        snapshot = open(engine.get(), sources.data(), 2);
        const auto q = query_options(true, DMG_ENUMERATE); dmg_query* raw_query = nullptr;
        CHECK(dmg_query_compile_methods(engine.get(), &q, &raw_query, &error) == DMG_OK);
        Query compiled(raw_query, &dmg_query_release);
        const dmg_job_options job_options{sizeof(job_options), DMG_ABI_VERSION, 1, 1, 0}; dmg_job* raw_job = nullptr;
        CHECK(dmg_job_start(snapshot.get(), compiled.get(), &job_options, &raw_job, &error) == DMG_OK);
        Job job(raw_job, &dmg_job_release); snapshot.reset(); compiled.reset();
        Batch retained(nullptr, &dmg_batch_release); unsigned rows = 0;
        for (unsigned attempts = 0; attempts < 100; ++attempts) {
            dmg_batch* batch = nullptr;
            const auto state = dmg_job_next(job.get(), 100, &batch, &error);
            if (state == DMG_NOT_READY) continue;
            if (state == DMG_END_OF_STREAM) break;
            CHECK(state == DMG_OK && batch != nullptr);
            Batch item(batch, &dmg_batch_release);
            CHECK(dmg_result_get_origin(item.get(), 0, &first) == DMG_OK && first.source_index == rows);
            ++rows; if (!retained) retained = std::move(item);
        }
        dmg_job_status final{}; CHECK(rows == 2 && dmg_job_wait(job.get(), 2000, &final) == DMG_OK && final.terminal && final.outcome.coverage == DMG_COVERAGE_COMPLETE);
        job.reset();
        CHECK(dmg_result_get_source_info(retained.get(), 1, &second) == DMG_OK && std::string(second.slot_key) == "split");
        CHECK(dmg_batch_get_source(retained.get(), &unsupported) == DMG_UNSUPPORTED);
        CHECK(stats(engine.get()).source_bytes > 0 && stats(engine.get()).fact_bytes > 0 && stats(engine.get()).active_jobs == 0);
        retained.reset(); CHECK(stats(engine.get()).owned_bytes == baseline);
        std::cout << "PASS source_set: duplicate-byte occurrences, ordered snapshot identity, slot-domain collision regression, incomplete cardinality, APK/resource-only intake, atomic rollback and Dataset-preserving Result/Batch accounting\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
