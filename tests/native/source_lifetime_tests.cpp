#include "dexmeguviz/dexmeguviz.h"
#include <algorithm>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef _WIN32
#include <io.h>
#include <crtdbg.h>
#else
#include <unistd.h>
#endif

#define CHECK(condition) do { if (!(condition)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #condition); } while (0)
using Engine = std::unique_ptr<dmg_engine, decltype(&dmg_engine_release)>;
using Snapshot = std::unique_ptr<dmg_snapshot, decltype(&dmg_snapshot_release)>;
using Result = std::unique_ptr<dmg_result, decltype(&dmg_result_release)>;

static dmg_engine_stats stats(dmg_engine* engine) {
    dmg_engine_stats result{};
    CHECK(dmg_engine_get_stats(engine, &result) == DMG_OK);
    CHECK(result.owned_bytes == result.source_bytes + result.fact_bytes + result.scratch_bytes +
        result.query_bytes + result.result_bytes + result.control_bytes);
    return result;
}
static Engine engine(uint64_t owned, uint64_t borrowed) {
    dmg_engine_options options{sizeof(options), DMG_ABI_VERSION, owned, borrowed, 1u << 20, 2, 0};
    dmg_engine* raw = nullptr;
    dmg_error error{};
    CHECK(dmg_engine_create(&options, &raw, &error) == DMG_OK);
    return Engine(raw, &dmg_engine_release);
}
static Result query(dmg_snapshot* snapshot) {
    dmg_method_query options{};
    options.struct_size = sizeof(options); options.abi_version = DMG_ABI_VERSION;
    options.max_results = 100; options.intent = DMG_ENUMERATE;
    dmg_result* raw = nullptr;
    dmg_error error{};
    CHECK(dmg_query_methods(snapshot, &options, &raw, &error) == DMG_OK);
    return Result(raw, &dmg_result_release);
}
struct LeaseCounts {
    unsigned retained = 0, released = 0, references = 1;
    static void retain(void* context) { auto& self = *static_cast<LeaseCounts*>(context); ++self.retained; ++self.references; }
    static void release(void* context) { auto& self = *static_cast<LeaseCounts*>(context); ++self.released; --self.references; }
    dmg_buffer_lease options() { return {sizeof(dmg_buffer_lease), DMG_ABI_VERSION, this, &retain, &release, 1, 0}; }
};
static int descriptor(std::FILE* file) {
#ifdef _WIN32
    return _fileno(file);
#else
    return fileno(file);
#endif
}
static int64_t position(int fd) {
#ifdef _WIN32
    return _lseeki64(fd, 0, SEEK_CUR);
#else
    return lseek(fd, 0, SEEK_CUR);
#endif
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
        std::vector<uint8_t> original((std::istreambuf_iterator<char>(input)), {});
        CHECK(!original.empty());
        auto e = engine(8u << 20, 8u << 20);
        const auto baseline = stats(e.get()).owned_bytes;
        const dmg_open_options options{sizeof(dmg_open_options), DMG_ABI_VERSION, 0, "source-test", "slot", nullptr};
        dmg_error error{};
        dmg_snapshot* raw = nullptr;
        auto copied = original;
        CHECK(dmg_snapshot_open_copy_in(e.get(), copied.data(), copied.size(), &options, &raw, &error) == DMG_OK);
        Snapshot snapshot(raw, &dmg_snapshot_release);
        dmg_snapshot_info source{};
        CHECK(dmg_snapshot_get_info(snapshot.get(), &source) == DMG_OK);
        const std::string digest = source.source_sha256;
        const auto methods = source.method_def_count;
        CHECK(methods > 0);
        std::fill(copied.begin(), copied.end(), 0);
        auto open_stats = stats(e.get());
        CHECK(open_stats.source_bytes >= original.size() && open_stats.fact_bytes > 0);
        CHECK(open_stats.borrowed_bytes == 0 && open_stats.scratch_bytes == 0);
        auto result = query(snapshot.get());
        dmg_result_info outcome{};
        CHECK(dmg_result_get_info(result.get(), &outcome) == DMG_OK);
        CHECK(outcome.candidates_count == methods && outcome.coverage == DMG_COVERAGE_COMPLETE);
        CHECK(dmg_result_get_source(result.get(), &source) == DMG_OK && digest == source.source_sha256);
        snapshot.reset();
        CHECK(stats(e.get()).source_bytes >= original.size() && stats(e.get()).result_bytes > 0);
        dmg_method_row row{};
        CHECK(dmg_result_get_method(result.get(), 0, &row) == DMG_OK && row.name_length > 0);
        result.reset();
        CHECK(stats(e.get()).owned_bytes == baseline);

        auto mismatch = options;
        mismatch.expected_sha256 = "not-the-owned-digest";
        CHECK(dmg_snapshot_open_copy_in(e.get(), original.data(), original.size(), &mismatch, &raw, &error) == DMG_SOURCE_MISMATCH);
        CHECK(raw == nullptr && stats(e.get()).owned_bytes == baseline);
        auto expected = options;
        expected.expected_sha256 = digest.c_str();
        CHECK(dmg_snapshot_open_copy_in(e.get(), original.data(), original.size(), &expected, &raw, &error) == DMG_OK);
        dmg_snapshot_release(raw);
        CHECK(stats(e.get()).owned_bytes == baseline);
        auto invalid = original;
        invalid[0] = 0;
        CHECK(dmg_snapshot_open_copy_in(e.get(), invalid.data(), invalid.size(), &options, &raw, &error) == DMG_CORRUPT_INPUT);
        CHECK(raw == nullptr && stats(e.get()).owned_bytes == baseline);

        LeaseCounts counts;
        const auto lease = counts.options();
        CHECK(dmg_snapshot_open_borrowed(e.get(), original.data(), original.size(), &lease, &options, &raw, &error) == DMG_OK);
        snapshot.reset(raw);
        CHECK(counts.retained == 1 && counts.released == 0 && counts.references == 2);
        CHECK(stats(e.get()).borrowed_bytes == original.size());
        LeaseCounts::release(&counts); // The caller drops its own lease; the SDK still owns one.
        result = query(snapshot.get());
        snapshot.reset();
        CHECK(counts.references == 1 && counts.released == 1 && stats(e.get()).borrowed_bytes == original.size());
        CHECK(dmg_result_get_method(result.get(), 0, &row) == DMG_OK);
        result.reset();
        CHECK(counts.references == 0 && counts.released == 2);
        CHECK(stats(e.get()).borrowed_bytes == 0 && stats(e.get()).owned_bytes == baseline);

        for (bool corrupt : {false, true}) {
            LeaseCounts failed;
            const auto failed_lease = failed.options();
            const auto& bytes = corrupt ? invalid : original;
            const auto status = dmg_snapshot_open_borrowed(e.get(), bytes.data(), bytes.size(), &failed_lease,
                corrupt ? &options : &mismatch, &raw, &error);
            CHECK(status == (corrupt ? DMG_CORRUPT_INPUT : DMG_SOURCE_MISMATCH));
            CHECK(raw == nullptr && failed.retained == 1 && failed.released == 1 && failed.references == 1);
            CHECK(stats(e.get()).borrowed_bytes == 0 && stats(e.get()).owned_bytes == baseline);
        }
        LeaseCounts rejected;
        auto rejected_lease = rejected.options();
        rejected_lease.immutable = 0;
        CHECK(dmg_snapshot_open_borrowed(e.get(), original.data(), original.size(), &rejected_lease, &options, &raw, &error) == DMG_INVALID_ARGUMENT);
        CHECK(rejected.retained == 0 && rejected.released == 0 && raw == nullptr);
        auto borrowed_limited = engine(8u << 20, original.size() - 1);
        const auto borrowed_baseline = stats(borrowed_limited.get()).owned_bytes;
        rejected_lease.immutable = 1;
        CHECK(dmg_snapshot_open_borrowed(borrowed_limited.get(), original.data(), original.size(), &rejected_lease, &options, &raw, &error) == DMG_BUDGET_EXCEEDED);
        CHECK(raw == nullptr && rejected.retained == 0 && rejected.released == 0);
        CHECK(stats(borrowed_limited.get()).owned_bytes == borrowed_baseline && stats(borrowed_limited.get()).borrowed_bytes == 0);
        auto owned_limited = engine(256, 8u << 20);
        const auto owned_baseline = stats(owned_limited.get()).owned_bytes;
        CHECK(dmg_snapshot_open_copy_in(owned_limited.get(), original.data(), original.size(), &options, &raw, &error) == DMG_BUDGET_EXCEEDED);
        CHECK(raw == nullptr && stats(owned_limited.get()).owned_bytes == owned_baseline);

        std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::tmpfile(), &std::fclose);
        CHECK(file != nullptr);
        const std::vector<uint8_t> prefix(23, 0x5a);
        CHECK(std::fwrite(prefix.data(), 1, prefix.size(), file.get()) == prefix.size());
        CHECK(std::fwrite(original.data(), 1, original.size(), file.get()) == original.size());
        CHECK(std::fflush(file.get()) == 0 && std::fseek(file.get(), 7, SEEK_SET) == 0);
        const int fd = descriptor(file.get());
        const auto original_position = position(fd);
        CHECK(original_position == 7);
        CHECK(dmg_snapshot_open_fd(e.get(), fd, prefix.size(), original.size(), &expected, &raw, &error) == DMG_OK);
        CHECK(position(fd) == original_position);
        snapshot.reset(raw);
        file.reset();
        CHECK(dmg_snapshot_get_info(snapshot.get(), &source) == DMG_OK && digest == source.source_sha256);
        result = query(snapshot.get());
        snapshot.reset();
        CHECK(dmg_result_get_info(result.get(), &outcome) == DMG_OK && outcome.candidates_count == methods);
        result.reset();
        CHECK(stats(e.get()).owned_bytes == baseline);
        CHECK(dmg_snapshot_open_fd(e.get(), -1, 0, original.size(), &options, &raw, &error) == DMG_INVALID_ARGUMENT && raw == nullptr);

        CHECK(dmg_engine_shutdown(e.get(), 0) == DMG_OK);
        CHECK(dmg_snapshot_open_copy_in(e.get(), original.data(), original.size(), &options, &raw, &error) == DMG_CLOSED && raw == nullptr);
        CHECK(stats(e.get()).admission_closed == 1 && stats(e.get()).owned_bytes == baseline);
        std::cout << "PASS source_lifetime: owned copy, caller mutation, expected digest, retained results, borrowed callback balance, failure unwind, FD range/position/close, Engine budget reclamation\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
