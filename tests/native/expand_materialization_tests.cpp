#include "c_api/runtime.hpp"
#include <array>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

#ifndef DMG_TEST_ALLOC_FAILURES
#error expand_materialization_tests requires DMG_TEST_ALLOC_FAILURES in every target source
#endif

using namespace dexmeguviz;
using namespace dexmeguviz::runtime;
#define CHECK(x) do { if (!(x)) throw std::runtime_error("expand materialization " + std::to_string(__LINE__) + ": " #x); } while (0)

namespace {
constexpr uint64_t owned_limit = 32u << 20;
struct Gate {
    std::mutex mutex;
    std::condition_variable changed;
    std::array<bool, 3> entered{}, released{};
    void stop(uint32_t stage) {
        std::unique_lock lock(mutex);
        entered.at(stage) = true;
        changed.notify_all();
        changed.wait(lock, [&] { return released.at(stage); });
    }
    void wait(uint32_t stage) {
        std::unique_lock lock(mutex);
        CHECK(changed.wait_for(lock, std::chrono::seconds(30), [&] { return entered.at(stage); }));
    }
    void open(uint32_t stage) {
        std::lock_guard lock(mutex);
        released.at(stage) = true;
        changed.notify_all();
    }
    void open_all() {
        std::lock_guard lock(mutex);
        released.fill(true);
        changed.notify_all();
    }
};
// Runs are sequential; hooks are cleared only after joining their worker.
std::atomic<Gate*> current_gate{nullptr};
void commit_gate(uint32_t stage) { current_gate.load(std::memory_order_acquire)->stop(stage); }
void terminal_gate() noexcept { current_gate.load(std::memory_order_acquire)->stop(2); }

std::vector<uint8_t> load(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    CHECK(input.good());
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
dmg_engine_stats stats(dmg_engine* engine) {
    dmg_engine_stats value{};
    CHECK(dmg_engine_get_stats(engine, &value) == DMG_OK);
    return value;
}
void same_resources(const dmg_engine_stats& actual, const dmg_engine_stats& before) {
    // Peak usage is deliberately not a live-allocation invariant.
    CHECK(actual.owned_bytes == before.owned_bytes);
    CHECK(actual.source_bytes == before.source_bytes && actual.fact_bytes == before.fact_bytes);
    CHECK(actual.scratch_bytes == before.scratch_bytes && actual.query_bytes == before.query_bytes);
    CHECK(actual.result_bytes == before.result_bytes && actual.control_bytes == before.control_bytes);
    CHECK(actual.borrowed_bytes == before.borrowed_bytes);
}
struct Shape {
    const char* name;
    uint32_t sources, rows, frontiers;
    bool endpoints, limited;
};
std::string query_text(const Shape& shape, const std::string& budget = "") {
    return std::string(R"({"schema_version":1,"relation":{"op":"bounded_expand","input":{"op":"label","label":"seed","input":{"op":"scan","relation":"method_defs","where":{"name":"a"}}},"min_depth":2,"max_depth":2,"output":")")
        + (shape.endpoints ? "endpoints" : "paths") + "\"" + budget + "}"
        + (shape.limited ? ",\"max_results\":1" : "") + "}";
}
struct Context {
    dmg_engine* engine = nullptr;
    dmg_snapshot* snapshot = nullptr;
    dmg_query* query = nullptr;
    ~Context() {
        dmg_query_release(query);
        dmg_snapshot_release(snapshot);
        dmg_engine_release(engine);
    }
    void open(const std::filesystem::path& root, const Shape& shape, const std::string& budget = "") {
        dmg_error error{};
        dmg_engine_options options{sizeof(options), DMG_ABI_VERSION, owned_limit, owned_limit, 1u << 20, 4, 0};
        CHECK(dmg_engine_create(&options, &engine, &error) == DMG_OK);
        const char* names[]{"amb-a.dex", "amb-b1.dex", "amb-b2.dex", "amb-c1.dex", "amb-c2.dex"};
        const char* slots[]{"a", "b1", "b2", "c1", "c2"};
        std::vector<std::vector<uint8_t>> bytes;
        std::vector<dmg_source_spec> sources;
        bytes.reserve(shape.sources);
        sources.reserve(shape.sources);
        // Four sources omit C2: successful C1 paths coexist with B2 frontiers.
        // One source omits every definition targeted by A: frontier-only output.
        for (uint32_t i = 0; i < shape.sources; ++i) {
            bytes.push_back(load(root / names[i]));
            dmg_source_spec source{};
            source.struct_size = sizeof(source); source.abi_version = DMG_ABI_VERSION;
            source.format = DMG_INPUT_RAW_DEX; source.data = bytes.back().data(); source.size = bytes.back().size();
            source.slot_key = slots[i]; source.role = "code";
            sources.push_back(source);
        }
        dmg_source_set_options source_options{sizeof(source_options), DMG_ABI_VERSION, "expand-materialization", 1, 16, 1u << 20};
        CHECK(dmg_snapshot_open_sources(engine, sources.data(), shape.sources, &source_options, &snapshot, &error) == DMG_OK);
        const auto text = query_text(shape, budget);
        CHECK(dmg_query_compile_json(engine, reinterpret_cast<const uint8_t*>(text.data()), text.size(), &query, &error) == DMG_OK);
    }
};
struct Run {
    Gate gate;
    dmg_job* job = nullptr;
    dmg_batch* batch = nullptr;
    dmg_engine* engine = nullptr;
    dmg_engine_stats before_start{}, before_execution{};
    void* held = nullptr;
    size_t held_bytes = 0;
    ~Run() {
        release_budget();
        gate.open_all(); // Also unblocks every failure/assertion-unwind path.
        dmg_batch_release(batch);
        dmg_job_release(job);
        test_expand_commit_hook.store(nullptr, std::memory_order_release);
        test_expand_after_terminal_hook.store(nullptr, std::memory_order_release);
        test_expand_fail_materialization_after.store(-1, std::memory_order_release);
        current_gate.store(nullptr, std::memory_order_release);
    }
    void start(Context& context, int64_t fail_after) {
        engine = context.engine;
        before_start = stats(engine);
        CHECK(before_start.active_jobs == 0 && before_start.result_bytes == 0 && before_start.scratch_bytes == 0);
        current_gate.store(&gate, std::memory_order_release);
        test_expand_commit_hook.store(&commit_gate, std::memory_order_release);
        test_expand_after_terminal_hook.store(&terminal_gate, std::memory_order_release);
        test_expand_fail_materialization_after.store(fail_after, std::memory_order_release);
        dmg_error error{};
        dmg_job_options options{sizeof(options), DMG_ABI_VERSION, 1, 1, 0};
        CHECK(dmg_job_start(context.snapshot, context.query, &options, &job, &error) == DMG_OK);
        gate.wait(0);
        // Baseline AFTER JobState/handle/queue/profile construction, but BEFORE
        // evaluation or pending result allocations. The worker cannot advance.
        before_execution = stats(engine);
        CHECK(before_execution.active_jobs == 1 && before_execution.scratch_bytes == 0 && before_execution.result_bytes == 0);
        no_visible_batch();
    }
    void no_visible_batch() {
        dmg_error error{};
        CHECK(dmg_job_next(job, 0, &batch, &error) == DMG_NOT_READY && batch == nullptr);
        dmg_expand_job_status value{};
        CHECK(dmg_job_get_expand_status(job, &value, sizeof(value)) == DMG_OK && !value.terminal);
        CHECK(value.info.outcome.candidates_count == 0 && value.info.total_candidates == 0 && value.info.frontier_count == 0);
        dmg_expand_frontier frontier{};
        CHECK(dmg_job_get_expand_frontier(job, 0, &frontier, sizeof(frontier)) == DMG_NOT_READY);
    }
    void exhaust_budget() {
        held_bytes = static_cast<size_t>(owned_limit - before_execution.owned_bytes);
        CHECK(held_bytes > 0);
        held = engine->owner->control_resource.allocate(held_bytes, alignof(std::max_align_t));
    }
    void release_budget() {
        if (held) {
            engine->owner->control_resource.deallocate(held, held_bytes, alignof(std::max_align_t));
            held = nullptr;
        }
    }
    dmg_expand_job_status terminal() {
        gate.open(1);
        gate.wait(2);
        dmg_expand_job_status value{};
        CHECK(dmg_job_wait_expand(job, 0, &value, sizeof(value)) == DMG_OK && value.terminal);
        CHECK(stats(engine).active_jobs == 0);
        return value;
    }
    void failed(const dmg_expand_job_status& value, dmg_status expected) {
        CHECK(value.lifecycle == (expected == DMG_CANCELLED ? DMG_JOB_CANCELLED : DMG_JOB_FAILED));
        CHECK(value.info.outcome.execution_status == expected && value.info.outcome.reason != DMG_RESULT_LIMIT);
        CHECK(value.info.outcome.candidates_count == 0 && value.info.total_candidates == 0 && value.info.frontier_count == 0);
        dmg_error error{};
        CHECK(dmg_job_next(job, 0, &batch, &error) == DMG_END_OF_STREAM && batch == nullptr);
        dmg_expand_frontier frontier{};
        CHECK(dmg_job_get_expand_frontier(job, 0, &frontier, sizeof(frontier)) == DMG_INVALID_ARGUMENT);
        // Worker is STILL blocked at its terminal hook: this detects pending
        // result/progress graphs accidentally retained until worker return.
        same_resources(stats(engine), before_execution);
    }
    void finish() {
        gate.open(2);
        dmg_job_release(job); job = nullptr;
        same_resources(stats(engine), before_start);
        CHECK(stats(engine).active_jobs == 0);
    }
};

void validate_success(Run& run, const Shape& shape, const dmg_expand_job_status& value) {
    const auto& outcome = value.info.outcome;
    CHECK(value.lifecycle == DMG_JOB_COMPLETED);
    CHECK(outcome.execution_status == (shape.limited ? DMG_BUDGET_EXCEEDED : DMG_OK));
    CHECK((outcome.reason == DMG_RESULT_LIMIT) == shape.limited);
    CHECK(outcome.coverage == (shape.limited ? DMG_COVERAGE_PARTIAL : DMG_COVERAGE_COMPLETE));
    CHECK(outcome.candidates_count == shape.rows && value.info.total_candidates == shape.rows);
    CHECK(value.info.frontier_count == shape.frontiers);
    if (shape.limited) CHECK(value.info.graph.identity_count > shape.rows);
    CHECK(stats(run.engine).scratch_bytes == run.before_execution.scratch_bytes);
    // Cancellation AFTER commit (while the worker is still alive) cannot
    // mutate a successful or truncated terminal result, nor discard its data.
    dmg_job_cancel(run.job);
    dmg_expand_job_status cancelled{};
    CHECK(dmg_job_get_expand_status(run.job, &cancelled, sizeof(cancelled)) == DMG_OK);
    CHECK(cancelled.terminal == value.terminal && cancelled.lifecycle == value.lifecycle);
    CHECK(cancelled.info.outcome.execution_status == outcome.execution_status && cancelled.info.outcome.reason == outcome.reason);
    CHECK(cancelled.info.outcome.coverage == outcome.coverage && cancelled.info.outcome.decision == outcome.decision);
    CHECK(cancelled.info.outcome.candidates_count == shape.rows && cancelled.info.total_candidates == shape.rows && cancelled.info.frontier_count == shape.frontiers);
    uint32_t frontier_pcs = 0;
    for (uint32_t i = 0; i < shape.frontiers; ++i) {
        dmg_expand_frontier frontier{};
        CHECK(dmg_job_get_expand_frontier(run.job, i, &frontier, sizeof(frontier)) == DMG_OK);
        CHECK(frontier.reason == DMG_EXPAND_UNRESOLVED && frontier.has_target_symbol && frontier.seed.source_index == 0);
        CHECK(frontier.seed_binding_count == 1 && frontier.seed_witness_count > 0);
        CHECK(frontier.target_method_ref == 1 && frontier.target_symbol.prototype_length == 3);
        CHECK(frontier.depth == (shape.sources == 1 ? 0u : 1u) && frontier.prefix_count == frontier.depth);
        dmg_expand_binding binding{};
        CHECK(dmg_job_get_expand_frontier_binding(run.job, i, 0, &binding, sizeof(binding)) == DMG_OK);
        CHECK(std::string(binding.label) == "seed");
        dmg_relation_witness_v2 witness{};
        CHECK(dmg_job_get_expand_frontier_witness(run.job, i, DMG_EXPAND_SEED_WITNESS, 0, &witness, sizeof(witness)) == DMG_OK);
        uint32_t pc = frontier.dex_pc;
        if (shape.sources == 4) {
            CHECK(frontier.caller.source_index == 2 && frontier.dex_pc == 0);
            dmg_expand_hop hop{};
            CHECK(dmg_job_get_expand_frontier_hop(run.job, i, 0, &hop, sizeof(hop)) == DMG_OK);
            CHECK(hop.caller.source_index == 0 && hop.resolved.source_index == 2 && hop.candidate_count == 2);
            pc = hop.dex_pc;
        } else CHECK(frontier.caller.source_index == 0);
        CHECK(pc == 0 || pc == 3);
        const auto bit = 1u << (pc / 3);
        CHECK(!(frontier_pcs & bit)); frontier_pcs |= bit;
    }
    CHECK(frontier_pcs == (shape.frontiers ? 3u : 0u));
    std::array<uint32_t, 4> seen{};
    dmg_error error{};
    uint32_t rows = 0;
    for (;;) {
        const auto status = dmg_job_next(run.job, 0, &run.batch, &error);
        if (status == DMG_END_OF_STREAM) { CHECK(run.batch == nullptr); break; }
        CHECK(status == DMG_OK && run.batch);
        dmg_expand_info info{};
        CHECK(dmg_result_get_expand_info(run.batch, &info, sizeof(info)) == DMG_OK);
        CHECK(info.outcome.candidates_count == 1 && info.total_candidates == shape.rows && info.frontier_count == shape.frontiers);
        CHECK(info.outcome.execution_status == outcome.execution_status && info.outcome.reason == outcome.reason);
        uint32_t paths = 0;
        CHECK(dmg_result_get_expand_path_count(run.batch, 0, &paths) == DMG_OK && paths == (shape.endpoints ? 2u : 1u));
        for (uint32_t p = 0; p < paths; ++p) {
            dmg_expand_path_info path{};
            CHECK(dmg_result_get_expand_path(run.batch, 0, p, &path, sizeof(path)) == DMG_OK);
            CHECK(path.hop_count == 2 && path.seed.source_index == 0 && path.seed_binding_count == 1 && path.seed_witness_count > 0);
            dmg_expand_binding binding{};
            CHECK(dmg_result_get_expand_path_binding(run.batch, 0, p, 0, &binding, sizeof(binding)) == DMG_OK && std::string(binding.label) == "seed");
            dmg_expand_hop first{}, second{};
            CHECK(dmg_result_get_expand_path_hop(run.batch, 0, p, 0, &first, sizeof(first)) == DMG_OK);
            CHECK(dmg_result_get_expand_path_hop(run.batch, 0, p, 1, &second, sizeof(second)) == DMG_OK);
            CHECK(first.caller.source_index == 0 && (first.resolved.source_index == 1 || first.resolved.source_index == 2));
            CHECK((first.dex_pc == 0 || first.dex_pc == 3) && first.candidate_count == 2 && first.resolution_complete);
            CHECK(second.caller.source_index == first.resolved.source_index && second.resolved.source_index == first.resolved.source_index + 2);
            CHECK(second.dex_pc == 0 && second.candidate_count == 1 && second.resolution_complete);
            CHECK(first.target_method_ref == 1 && second.target_method_ref == 1 && path.endpoint.source_index == second.resolved.source_index);
            CHECK(first.target_symbol.prototype_length == 3 && second.target_symbol.prototype_length == 3);
            ++seen[first.resolved.source_index - 1 + 2 * (first.dex_pc / 3)];
        }
        dmg_batch_release(run.batch); run.batch = nullptr;
        ++rows;
    }
    CHECK(rows == shape.rows);
    std::array<uint32_t, 4> expected{};
    if (shape.rows) {
        expected[0] = 1;
        if (!shape.limited || shape.endpoints) expected[2] = 1;
        if (shape.sources == 5 && !shape.limited) expected[1] = expected[3] = 1;
    }
    CHECK(seen == expected);
}

void sweep(const std::filesystem::path& root, const Shape& shape) {
    Context context; context.open(root, shape);
    bool succeeded = false, late_pending_seen = false;
    // The ceiling is a failing watchdog, never permission to skip a suffix.
    for (int64_t fail_after = 0; fail_after < 8192; ++fail_after) {
        Run run; run.start(context, fail_after);
        run.gate.open(0); run.gate.wait(1);
        run.no_visible_batch();
        const auto pending = stats(context.engine);
        const auto value = run.terminal();
        if (value.lifecycle == DMG_JOB_COMPLETED) {
            CHECK(fail_after > 1 && late_pending_seen);
            validate_success(run, shape, value);
            run.finish(); succeeded = true;
            std::cout << "PASS " << shape.name << ": NOMEM at every allocation [0," << fail_after - 1 << "], first success " << fail_after << '\n';
            break;
        }
        if (fail_after > 0 && pending.result_bytes > run.before_execution.result_bytes) late_pending_seen = true;
        run.failed(value, DMG_OUT_OF_MEMORY);
        // Reduction already saw more identities than max_results: this is a
        // materialization OOM AFTER traversal, not an early traversal failure.
        if (shape.limited) CHECK(value.info.graph.identity_count > shape.rows);
        run.finish();
    }
    CHECK(succeeded);
}
void sync_sweep(const std::filesystem::path& root, const Shape& shape) {
    Context context; context.open(root, shape);
    const auto before = stats(context.engine);
    bool succeeded = false;
    for (int64_t fail_after = 0; fail_after < 8192; ++fail_after) {
        dmg_result* result = reinterpret_cast<dmg_result*>(uintptr_t(1));
        dmg_error error{};
        test_fail_allocation_after(fail_after);
        const auto status = dmg_query_execute(context.snapshot, context.query, &result, &error);
        test_fail_allocation_after(-1);
        if (status == DMG_OK) {
            CHECK(fail_after > 5 && result != nullptr);
            dmg_expand_info info{};
            CHECK(dmg_result_get_expand_info(result, &info, sizeof(info)) == DMG_OK);
            CHECK(info.outcome.execution_status == (shape.limited ? DMG_BUDGET_EXCEEDED : DMG_OK));
            CHECK((info.outcome.reason == DMG_RESULT_LIMIT) == shape.limited);
            CHECK(info.outcome.candidates_count == shape.rows && info.total_candidates == shape.rows);
            CHECK(info.frontier_count == shape.frontiers);
            if (shape.limited) CHECK(info.graph.identity_count > shape.rows);
            dmg_result_release(result);
            same_resources(stats(context.engine), before);
            succeeded = true;
            break;
        }
        CHECK(status == DMG_OUT_OF_MEMORY && result == nullptr);
        same_resources(stats(context.engine), before);
    }
    CHECK(succeeded);
}
void interrupt_before_commit(const std::filesystem::path& root, const Shape& shape, bool deadline) {
    Context context; context.open(root, shape);
    Run run; run.start(context, -1);
    run.gate.open(0); run.gate.wait(1);
    run.no_visible_batch();
    CHECK(stats(context.engine).result_bytes > run.before_execution.result_bytes);
    if (deadline) {
        // The worker is stopped outside Control::check. Gate release gives a
        // happens-before edge for this test-only clock injection; no sleep,
        // short timeout or scheduling race is used to manufacture expiration.
        run.job->state->control.deadline = std::chrono::steady_clock::time_point::min();
    } else dmg_job_cancel(run.job);
    const auto value = run.terminal();
    run.failed(value, deadline ? DMG_DEADLINE_EXCEEDED : DMG_CANCELLED);
    CHECK(value.info.graph.identity_count > shape.rows);
    run.finish();
}
void budget_failure(const std::filesystem::path& root, const Shape& shape, const std::string& budget, bool exhaust) {
    Context context; context.open(root, shape, budget);
    Run run; run.start(context, -1);
    if (exhaust) run.exhaust_budget();
    run.gate.open(0); run.gate.wait(1);
    run.release_budget();
    run.no_visible_batch();
    const auto value = run.terminal();
    run.failed(value, DMG_BUDGET_EXCEEDED);
    run.finish();
}
} // namespace

int main(int argc, char** argv) {
    try {
        CHECK(argc == 2);
        const std::filesystem::path root(argv[1]);
        const Shape shapes[]{
            {"paths", 5, 4, 0, false, false},
            {"endpoints", 5, 2, 0, true, false},
            {"paths-result-limit", 5, 1, 0, false, true},
            {"endpoints-result-limit", 5, 1, 0, true, true},
            {"paths-with-frontiers", 4, 2, 2, false, false},
            {"endpoints-with-frontiers", 4, 1, 2, true, false},
            {"paths-frontiers-result-limit", 4, 1, 2, false, true},
            {"paths-frontier-only", 1, 0, 2, false, false},
            {"endpoints-frontier-only", 1, 0, 2, true, false}
        };
        for (const auto& shape : shapes) {
            sweep(root, shape);
            sync_sweep(root, shape);
            if (shape.limited) {
                interrupt_before_commit(root, shape, false);
                interrupt_before_commit(root, shape, true);
            }
        }
        for (const auto* budget : {",\"max_edges\":1", ",\"max_paths\":1", ",\"max_visited\":1"})
            budget_failure(root, shapes[2], budget, false);
        budget_failure(root, shapes[2], "", true);
        std::cout << "PASS expand atomic materialization: late OOM, ResultLimit precedence, commit cancellation/deadline, budgets and live-worker cleanup\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
