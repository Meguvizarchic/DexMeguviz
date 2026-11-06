#pragma once
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

struct dmg_snapshot;

namespace dexmeguviz::desktop_sql {
namespace detail { struct CursorQuota; }
struct SqlValue {
    enum class Kind { null, integer, text, blob } kind = Kind::null;
    int64_t integer = 0;
    std::string text; // UTF-8 TEXT, or exact uninterpreted bytes for blob.
    bool operator==(const SqlValue&) const = default;
};
using SqlRows = std::vector<std::vector<SqlValue>>;
// Synchronous borrowed inputs: callers keep TEXT bytes stable until the call
// returns; SQLite copies them while binding. Only the tagged member is used.
struct SqlParameter {
    enum class Kind { null, integer, text, blob } kind = Kind::null;
    int64_t integer = 0;
    std::string_view text; // UTF-8 TEXT, or exact uninterpreted bytes for blob.
};
// This is only the caller-declared source scope. A successful SQL statement
// does not prove global absence, uniqueness, or stability under new sources.
enum class SqlScopeCoverage { partial_source_scope, declared_complete_source_scope };
struct SqlScopedResult {
    SqlRows rows;
    std::string snapshot_id;
    SqlScopeCoverage source_scope = SqlScopeCoverage::partial_source_scope;
    uint32_t input_count = 0;
    uint32_t source_count = 0;
};
// Provisional rows are borrowed only during on_row. The consumer must discard
// every row from an attempt whose terminal execution_status is not SQLITE_OK.
struct SqlProvisionalScope {
    std::string snapshot_id;
    SqlScopeCoverage source_scope = SqlScopeCoverage::partial_source_scope;
    uint32_t input_count = 0, source_count = 0;
};
struct SqlProvisionalSink {
    void* context = nullptr;
    // Return zero to continue; nonzero aborts the attempt. Must not throw or
    // reenter the same session. The row and scope references are not retained.
    int (*on_row)(void*, uint64_t, const SqlProvisionalScope&, const std::vector<SqlValue>&) noexcept = nullptr;
};
struct SqlProvisionalOutcome {
    SqlProvisionalScope scope;
    uint64_t rows_emitted = 0;
    int execution_status = 0;
    bool terminal = false;
};
// Optional per-statement observations. Timings use a monotonic clock and are
// wall elapsed microseconds, not CPU, memory or whole-session accounting.
struct SqlQueryProfile {
    uint64_t sequence = 0, elapsed_us = 0, prepare_us = 0, first_step_us = 0;
    uint64_t progress_callbacks = 0, rows_staged = 0, rows_committed = 0;
    int execution_status = 0, first_step_status = 0;
    bool prepare_attempted = false, prepared = false, first_step_observed = false;
};
// Opt-in single prepared-statement cache observations. A hit reuses a handle;
// SQLite may still automatically reprepare it for schema or bound values.
struct SqlStatementReuseStats {
    uint64_t prepare_attempts = 0, cache_hits = 0, automatic_reprepares = 0;
    uint64_t retained_statement_bytes = 0;
    bool cached = false;
};
// Private SQLite singleton budget, independent of Engine and host SQLite.
// Configuration is one-shot before the first private connection; zero disables
// no existing cap and is rejected. It cannot be reset during the process.
struct SqliteHeapStats {
    uint64_t limit_bytes = 0;
    uint64_t used_bytes = 0;
    uint64_t lifetime_peak_bytes = 0;
    bool configured = false;
    bool started = false;
};
struct SqlCursorQuotaStats {
    uint32_t max_live_cursors = 0, live_cursors = 0;
    uint64_t max_retained_bytes = 0, retained_bytes = 0;
};
int configure_private_sqlite_heap(uint64_t limit_bytes) noexcept;
int private_sqlite_heap_stats(SqliteHeapStats& out) noexcept;
struct SqlSessionProbe;
class SqlCommittedCursor;
struct SqlSiteLimits {
    uint64_t max_work = 100'000'000;
    uint32_t max_records = 100'000;
    // Optional cumulative limits shared by all site scans in one statement.
    // Zero disables the corresponding cumulative limit.
    uint64_t max_statement_work = 0;
    uint64_t max_statement_records = 0;
};
// Experimental metadata identity filtering; off unless explicitly requested.
struct SqlPlanningOptions {
    bool metadata_identity_equality = false;
    // All-at-once IN is independently opt-in and requires identity equality.
    bool metadata_identity_in = false;
};
// Called synchronously on the query thread. The callback must not throw or
// reenter the session, and its context must remain valid until query returns.
struct SqlCancel {
    bool (*requested)(void*) noexcept = nullptr;
    void* context = nullptr;
};

// Internal prototype; every session creates its own connection with its
// compiled SQLite. No SQLite connection or statement pointer is accepted or
// exposed. All methods, including destruction, require single-threaded use.
class SqlSession final {
public:
    static int open(const dmg_snapshot* snapshot, std::unique_ptr<SqlSession>& out) noexcept;
    static int open(const dmg_snapshot* snapshot, std::unique_ptr<SqlSession>& out,
                    SqlSiteLimits site_limits) noexcept;
    // Explicit opt-in to range-labelled results; permits incomplete source scope.
    // Old query() is unavailable on sessions created by open_scoped().
    static int open_scoped(const dmg_snapshot* snapshot, std::unique_ptr<SqlSession>& out,
                           SqlSiteLimits site_limits = {}) noexcept;
    static int open_planned(const dmg_snapshot* snapshot, std::unique_ptr<SqlSession>& out,
                            SqlSiteLimits site_limits, SqlPlanningOptions planning) noexcept;
    static int open_scoped_planned(const dmg_snapshot* snapshot, std::unique_ptr<SqlSession>& out,
                                   SqlSiteLimits site_limits, SqlPlanningOptions planning) noexcept;
    int query_scoped(std::string_view sql, std::optional<std::string_view> parameter,
                     uint64_t max_rows, uint64_t max_bytes, SqlScopedResult& out,
                     uint64_t max_progress_intervals = 10000, SqlCancel cancel = {}) noexcept;
    // Positional bindings use SQLite indices 1..N, including ?NNN gaps.
    int query_scoped_bound(std::string_view sql, std::span<const SqlParameter> parameters,
                           uint64_t max_rows, uint64_t max_bytes, SqlScopedResult& out,
                           uint64_t max_progress_intervals = 10000, SqlCancel cancel = {}) noexcept;
    // Explicit opt-in: synchronous borrowed row callbacks are provisional until
    // this call returns and terminal.execution_status is SQLITE_OK.
    int query_provisional_scoped_bound(std::string_view sql, std::span<const SqlParameter> parameters,
                                      uint64_t max_rows, uint64_t max_bytes, SqlProvisionalSink sink,
                                      SqlProvisionalOutcome& terminal,
                                      uint64_t max_progress_intervals = 10000, SqlCancel cancel = {}) noexcept;
    // Internal strict cursor: no page is available until the statement has
    // completed and finalized. The caller supplies a bounded in-memory spool.
    int query_cursor_scoped(std::string_view sql, std::optional<std::string_view> parameter,
                            uint64_t max_rows, uint64_t max_bytes, uint64_t lifetime_ms,
                            std::unique_ptr<SqlCommittedCursor>& out,
                            uint64_t max_progress_intervals = 10000, SqlCancel cancel = {}) noexcept;
    int query_cursor_scoped_bound(std::string_view sql, std::span<const SqlParameter> parameters,
                                  uint64_t max_rows, uint64_t max_bytes, uint64_t lifetime_ms,
                                  std::unique_ptr<SqlCommittedCursor>& out,
                                  uint64_t max_progress_intervals = 10000, SqlCancel cancel = {}) noexcept;
    // Optional, one-shot before the first valid cursor attempt. Limits cover
    // retained committed rows only, not SQLite, temporary queries or pages.
    int configure_cursor_quota(uint32_t max_live_cursors, uint64_t max_retained_bytes) noexcept;
    // SQLITE_NOTFOUND leaves out unchanged when no quota is configured.
    int cursor_quota_stats(SqlCursorQuotaStats& out) const noexcept;
    int query(std::string_view sql, std::optional<std::string_view> parameter,
              uint64_t max_rows, uint64_t max_bytes, SqlRows& out,
              uint64_t max_progress_intervals = 10000) noexcept;
    int query(std::string_view sql, std::optional<std::string_view> parameter,
              uint64_t max_rows, uint64_t max_bytes, SqlRows& out,
              uint64_t max_progress_intervals, SqlCancel cancel) noexcept;
    // Disabled by default. Toggling invalidates the previous observation.
    int enable_profiling(bool enabled) noexcept;
    // SQLITE_NOTFOUND leaves out unchanged when no profiled attempt exists.
    int last_query_profile(SqlQueryProfile& out) const noexcept;
    // Explicit single-slot reuse, one-shot per scoped session. max_statement_bytes
    // bounds SQLite's approximate retained statement memory, not transient RSS.
    int enable_statement_reuse(uint64_t max_statement_bytes) noexcept;
    int statement_reuse_stats(SqlStatementReuseStats& out) const noexcept;
    // Discard the retained statement while keeping the scoped session usable.
    // Counters and opt-in configuration remain; no secure memory erasure is promised.
    int clear_statement_reuse_cache() noexcept;
    // A distinct opt-in path: results publish only after DONE, reset and clear.
    int query_scoped_reused_bound(std::string_view sql, std::span<const SqlParameter> parameters,
                                 uint64_t max_rows, uint64_t max_bytes, SqlScopedResult& out,
                                 uint64_t max_progress_intervals = 10000, SqlCancel cancel = {}) noexcept;
    // No close_v2; BUSY leaves the connection and Dataset owned by the session.
    int close() noexcept;
    ~SqlSession();
    SqlSession(const SqlSession&) = delete;
    SqlSession& operator=(const SqlSession&) = delete;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::shared_ptr<detail::CursorQuota> cursor_quota_;
    bool cursor_attempted_ = false;
    explicit SqlSession(std::unique_ptr<Impl> impl) noexcept;
    static int open_impl(const dmg_snapshot* snapshot, std::unique_ptr<SqlSession>& out,
                         SqlSiteLimits site_limits, bool scoped, SqlPlanningOptions planning) noexcept;
    int query_impl(std::string_view sql, std::optional<std::string_view> parameter,
                   uint64_t max_rows, uint64_t max_bytes, SqlRows& out,
                   uint64_t max_progress_intervals, SqlCancel cancel) noexcept;
    int query_bound_impl(std::string_view sql, std::span<const SqlParameter> parameters,
                         uint64_t max_rows, uint64_t max_bytes, SqlRows& out,
                         uint64_t max_progress_intervals, SqlCancel cancel,
                         const SqlProvisionalSink* sink = nullptr, const SqlProvisionalScope* scope = nullptr,
                         uint64_t* emitted = nullptr, bool reuse = false) noexcept;
    int query_bound_execute(std::string_view sql, std::span<const SqlParameter> parameters,
                            uint64_t max_rows, uint64_t max_bytes, SqlRows& out,
                            uint64_t max_progress_intervals, SqlCancel cancel, SqlQueryProfile* profile,
                            const SqlProvisionalSink* sink, const SqlProvisionalScope* scope,
                            uint64_t* emitted, bool reuse) noexcept;
    friend struct SqlSessionProbe;
};
}


