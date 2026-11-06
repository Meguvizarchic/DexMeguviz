#include "dexmeguviz/dexmeguviz.h"
#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#ifdef _MSC_VER
#include <crtdbg.h>
#endif

#define CHECK(condition) do { if (!(condition)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #condition); } while (0)
using Engine = std::unique_ptr<dmg_engine, decltype(&dmg_engine_release)>;
using Snapshot = std::unique_ptr<dmg_snapshot, decltype(&dmg_snapshot_release)>;
using Query = std::unique_ptr<dmg_query, decltype(&dmg_query_release)>;
using Job = std::unique_ptr<dmg_job, decltype(&dmg_job_release)>;
using Batch = std::unique_ptr<dmg_batch, decltype(&dmg_batch_release)>;

static dmg_engine_stats stats(dmg_engine* engine) {
    dmg_engine_stats result{};
    CHECK(dmg_engine_get_stats(engine, &result) == DMG_OK);
    return result;
}
static Job start(dmg_snapshot* snapshot, dmg_query* query, uint64_t deadline = 0) {
    dmg_job_options options{sizeof(options), DMG_ABI_VERSION, 1, 1, deadline};
    dmg_job* raw = nullptr;
    dmg_error error{};
    CHECK(dmg_job_start(snapshot, query, &options, &raw, &error) == DMG_OK);
    return Job(raw, &dmg_job_release);
}
static dmg_job_status status(dmg_job* job) {
    dmg_job_status result{};
    CHECK(dmg_job_get_status(job, &result) == DMG_OK);
    return result;
}
static void await_full_queue(dmg_job* job) {
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (true) {
        const auto current = status(job);
        CHECK(!current.terminal);
        if (current.outcome.candidates_count >= 1) return;
        CHECK(std::chrono::steady_clock::now() < end);
        std::this_thread::yield();
    }
}
struct Drained { uint32_t rows = 0; Batch retained{nullptr, &dmg_batch_release}; };
static Drained drain(dmg_job* job, bool keep_first = false) {
    Drained result;
    for (unsigned attempts = 0; attempts < 100; ++attempts) {
        dmg_batch* raw = nullptr;
        dmg_error error{};
        const auto next = dmg_job_next(job, 100, &raw, &error);
        if (next == DMG_NOT_READY) { CHECK(raw == nullptr); continue; }
        if (next == DMG_END_OF_STREAM) { CHECK(raw == nullptr); return result; }
        CHECK(next == DMG_OK && raw != nullptr);
        Batch batch(raw, &dmg_batch_release);
        dmg_result_info info{};
        CHECK(dmg_batch_get_info(batch.get(), &info) == DMG_OK);
        CHECK(info.candidates_count == 1 && info.coverage == DMG_COVERAGE_PARTIAL);
        dmg_method_row row{};
        CHECK(dmg_batch_get_method(batch.get(), 0, &row) == DMG_OK && row.name_length > 0);
        ++result.rows;
        if (keep_first && !result.retained) result.retained = std::move(batch);
    }
    throw std::runtime_error("job did not reach EOF within the bounded drain");
}
static void assert_terminal(dmg_job* job, dmg_status expected) {
    dmg_job_status final{};
    CHECK(dmg_job_wait(job, 2000, &final) == DMG_OK);
    CHECK(final.terminal == 1 && final.outcome.execution_status == expected);
    const auto before = final;
    dmg_job_cancel(job);
    CHECK(dmg_job_get_status(job, &final) == DMG_OK);
    CHECK(final.lifecycle == before.lifecycle && final.outcome.execution_status == before.outcome.execution_status &&
        final.outcome.decision == before.outcome.decision && final.outcome.candidates_count == before.outcome.candidates_count);
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
        dmg_engine_options engine_options{sizeof(engine_options), DMG_ABI_VERSION, 8u << 20, 8u << 20, 1u << 20, 1, 0};
        dmg_engine* raw_engine = nullptr;
        dmg_error error{};
        CHECK(dmg_engine_create(&engine_options, &raw_engine, &error) == DMG_OK);
        Engine engine(raw_engine, &dmg_engine_release);
        const auto baseline = stats(engine.get()).owned_bytes;
        const dmg_open_options open_options{sizeof(open_options), DMG_ABI_VERSION, 0, "job-test", "slot", nullptr};
        dmg_snapshot* raw_snapshot = nullptr;
        CHECK(dmg_snapshot_open_copy_in(engine.get(), bytes.data(), bytes.size(), &open_options, &raw_snapshot, &error) == DMG_OK);
        Snapshot snapshot(raw_snapshot, &dmg_snapshot_release);
        dmg_snapshot_info source{};
        CHECK(dmg_snapshot_get_info(snapshot.get(), &source) == DMG_OK && source.method_def_count >= 2);
        const auto expected_rows = source.method_def_count;
        dmg_method_query query_options{};
        query_options.struct_size = sizeof(query_options); query_options.abi_version = DMG_ABI_VERSION;
        query_options.intent = DMG_ENUMERATE; query_options.max_results = 100;
        dmg_query* raw_query = nullptr;
        CHECK(dmg_query_compile_methods(engine.get(), &query_options, &raw_query, &error) == DMG_OK);
        Query query(raw_query, &dmg_query_release);
        const auto prepared = stats(engine.get()).owned_bytes;

        dmg_engine* other_raw = nullptr;
        CHECK(dmg_engine_create(&engine_options, &other_raw, &error) == DMG_OK);
        Engine other(other_raw, &dmg_engine_release);
        dmg_query* foreign_raw = nullptr;
        CHECK(dmg_query_compile_methods(other.get(), &query_options, &foreign_raw, &error) == DMG_OK);
        Query foreign(foreign_raw, &dmg_query_release);
        dmg_job* foreign_job = nullptr;
        CHECK(dmg_job_start(snapshot.get(), foreign.get(), nullptr, &foreign_job, &error) == DMG_INVALID_ARGUMENT && foreign_job == nullptr);
        foreign.reset(); other.reset();
        CHECK(stats(engine.get()).owned_bytes == prepared);

        auto job = start(snapshot.get(), query.get());
        await_full_queue(job.get());
        dmg_job_status waiting{};
        CHECK(dmg_job_wait(job.get(), 5, &waiting) == DMG_NOT_READY);
        CHECK(!waiting.terminal && waiting.outcome.execution_status == DMG_OK);
        CHECK(stats(engine.get()).active_jobs == 1);
        dmg_job* rejected = nullptr;
        CHECK(dmg_job_start(snapshot.get(), query.get(), nullptr, &rejected, &error) == DMG_BUDGET_EXCEEDED && rejected == nullptr);
        auto first = drain(job.get(), true);
        CHECK(first.rows == expected_rows);
        assert_terminal(job.get(), DMG_OK);
        CHECK(status(job.get()).outcome.coverage == DMG_COVERAGE_COMPLETE);
        job.reset();
        CHECK(stats(engine.get()).active_jobs == 0 && stats(engine.get()).result_bytes > 0);
        first.retained.reset();
        CHECK(stats(engine.get()).owned_bytes == prepared);

        job = start(snapshot.get(), query.get());
        await_full_queue(job.get());
        dmg_job_cancel(job.get());
        assert_terminal(job.get(), DMG_CANCELLED);
        CHECK(status(job.get()).outcome.coverage == DMG_COVERAGE_PARTIAL);
        CHECK(drain(job.get()).rows == 1);
        job.reset();
        CHECK(stats(engine.get()).owned_bytes == prepared && stats(engine.get()).active_jobs == 0);

        job = start(snapshot.get(), query.get(), 30);
        assert_terminal(job.get(), DMG_DEADLINE_EXCEEDED);
        CHECK(status(job.get()).outcome.coverage == DMG_COVERAGE_PARTIAL);
        CHECK(drain(job.get()).rows <= 1);
        job.reset();
        CHECK(stats(engine.get()).owned_bytes == prepared);

        // Final release cancels a producer blocked by its one-batch queue.
        job = start(snapshot.get(), query.get());
        await_full_queue(job.get());
        job.reset();
        CHECK(stats(engine.get()).owned_bytes == prepared && stats(engine.get()).active_jobs == 0);

        // Closing the snapshot rejects new work while an accepted Job keeps its source alive.
        job = start(snapshot.get(), query.get());
        await_full_queue(job.get());
        dmg_snapshot_close(snapshot.get());
        CHECK(dmg_job_start(snapshot.get(), query.get(), nullptr, &rejected, &error) == DMG_CLOSED && rejected == nullptr);
        snapshot.reset();
        query.reset();
        auto retained = drain(job.get(), true);
        CHECK(retained.rows == expected_rows);
        assert_terminal(job.get(), DMG_OK);
        job.reset();
        CHECK(stats(engine.get()).source_bytes > 0 && stats(engine.get()).fact_bytes > 0 && stats(engine.get()).result_bytes > 0);
        CHECK(dmg_batch_get_source(retained.retained.get(), &source) == DMG_OK && source.method_def_count == expected_rows);
        dmg_batch_retain(retained.retained.get());
        dmg_batch_release(retained.retained.get());
        retained.retained.reset();
        CHECK(stats(engine.get()).owned_bytes == baseline && stats(engine.get()).active_jobs == 0);

        CHECK(dmg_snapshot_open_copy_in(engine.get(), bytes.data(), bytes.size(), &open_options, &raw_snapshot, &error) == DMG_OK);
        snapshot.reset(raw_snapshot);
        CHECK(dmg_query_compile_methods(engine.get(), &query_options, &raw_query, &error) == DMG_OK);
        query.reset(raw_query);
        job = start(snapshot.get(), query.get());
        await_full_queue(job.get());
        CHECK(dmg_engine_shutdown(engine.get(), 1) == DMG_OK);
        assert_terminal(job.get(), DMG_CANCELLED);
        CHECK(dmg_job_start(snapshot.get(), query.get(), nullptr, &rejected, &error) == DMG_CLOSED && rejected == nullptr);
        dmg_query* closed_query = nullptr;
        CHECK(dmg_query_compile_methods(engine.get(), &query_options, &closed_query, &error) == DMG_CLOSED && closed_query == nullptr);
        job.reset(); snapshot.reset(); query.reset();
        CHECK(stats(engine.get()).owned_bytes == baseline && stats(engine.get()).active_jobs == 0 && stats(engine.get()).admission_closed == 1);
        std::cout << "PASS job: reusable query, bounded producer queue, timeout without cancel, deadline/cancel/EOF, stable terminal state, retained Batch ownership/accounting, snapshot/Engine shutdown and weak-slot reclamation\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
