#pragma once
#include "../method_tables.hpp"
#include <chrono>
#include <cstddef>

namespace dexmeguviz::desktop_sql {
// Each delivered page is already committed, never a provisional statement row.
struct SqlCommittedPage {
    SqlScopedResult result;
    uint64_t first_row = 0;
    bool final_page = false;
};
struct SqlCursorProbe;
class SqlCommittedCursor final {
public:
    // Page count and logical bytes are independently bounded. SQLITE_DONE is
    // returned only after a final page; SQLITE_ABORT means expiration.
    int next(uint32_t max_page_rows, uint64_t max_page_bytes, SqlCommittedPage& out,
             SqlCancel cancel = {}) noexcept;
    void close() noexcept;
    ~SqlCommittedCursor();
    SqlCommittedCursor(const SqlCommittedCursor&) = delete;
    SqlCommittedCursor& operator=(const SqlCommittedCursor&) = delete;
private:
    using Clock = std::chrono::steady_clock;
    SqlCommittedCursor(SqlScopedResult&& result, Clock::time_point deadline) noexcept;
    SqlScopedResult committed_;
    Clock::time_point deadline_;
    std::shared_ptr<detail::CursorQuota> quota_;
    uint64_t quota_bytes_ = 0;
    size_t position_ = 0;
    bool done_ = false;
    bool closed_ = false;
    friend class SqlSession;
    friend struct SqlCursorProbe;
};
}
