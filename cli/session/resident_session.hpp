#pragma once
#include "method_tables.hpp"
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

namespace dexmeguviz::desktop_sql {
// Internal desktop prototype. All methods and destruction must run on the
// same thread; callbacks must not reenter this object or its SqlSession.
struct ResidentLimits {
    uint32_t max_outstanding = 0;
    uint64_t max_input_bytes = 0;
    uint64_t max_reserved_result_bytes = 0;
    uint64_t max_statement_bytes = 0;
};
struct ResidentStats {
    uint32_t queued = 0, terminal = 0;
    uint64_t input_bytes = 0, reserved_result_bytes = 0;
    uint64_t accepted = 0, completed = 0, cancelled = 0;
    uint64_t open_us = 0, close_us = 0;
    bool closed = false;
};
struct ResidentFinal {
    uint64_t id = 0;
    int execution_status = 0;
    bool has_profile = false;
    SqlQueryProfile profile{};
    SqlStatementReuseStats reuse{};
    SqlScopedResult result{}; // populated only for SQLITE_OK
};
class ResidentSession final {
public:
    // Requires an empty output owner; otherwise leaves the existing session intact.
    static int open(const dmg_snapshot* snapshot, ResidentLimits limits,
                    std::unique_ptr<ResidentSession>& out) noexcept;
    static int open(const dmg_snapshot* snapshot, ResidentLimits limits,
                    std::unique_ptr<ResidentSession>& out, SqlPlanningOptions planning) noexcept;
    // Deep-copies SQL and TEXT arguments. The result byte budget is reserved
    // until acknowledge; rejection leaves id unchanged and creates no job.
    int submit(std::string_view sql, std::span<const SqlParameter> parameters,
               uint64_t max_rows, uint64_t max_bytes, uint64_t max_progress_intervals,
               uint64_t& id) noexcept;
    // Queued cancellation creates a retained terminal SQLITE_INTERRUPT record.
    int cancel_queued(uint64_t id) noexcept;
    // Processes the oldest queued job synchronously. Return SQLITE_OK means a
    // terminal was recorded; inspect that terminal for query status.
    int run_next(SqlCancel cancel = {}) noexcept;
    // Only terminal records are readable. The pointer is borrowed until the
    // corresponding acknowledge or this session's destruction.
    int final(uint64_t id, const ResidentFinal*& out) const noexcept;
    int acknowledge(uint64_t id) noexcept;
    int stats(ResidentStats& out) const noexcept;
    // Refuses to close with any queued or unacknowledged terminal job.
    int close() noexcept;
    ~ResidentSession();
    ResidentSession(const ResidentSession&) = delete;
    ResidentSession& operator=(const ResidentSession&) = delete;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    explicit ResidentSession(std::unique_ptr<Impl>) noexcept;
};
}
