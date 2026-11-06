#include "cursor.hpp"
#include "cursor_quota.hpp"
#include "sqlite3.h"
#include <algorithm>
#include <limits>
#include <new>
#include <utility>

namespace dexmeguviz::desktop_sql {
namespace {
constexpr uint64_t max_result_bytes = 8u << 20;
constexpr uint64_t max_lifetime_ms = 600000;
struct QuotaReservation {
    explicit QuotaReservation(std::shared_ptr<detail::CursorQuota> value) noexcept : quota(std::move(value)) {}
    ~QuotaReservation(){if(held)quota->release(bytes);}
    bool acquire_slot() noexcept {if(!quota)return true;held=quota->acquire_slot();return held;}
    bool acquire_bytes(uint64_t amount) noexcept {if(!quota)return true;if(!quota->acquire_bytes(amount))return false;bytes=amount;return true;}
    void disarm() noexcept {held=false;}
    std::shared_ptr<detail::CursorQuota> quota;
    uint64_t bytes=0;
    bool held=false;
};
#ifdef DMG_SQLITE_PROTO_TESTING
thread_local int64_t fail_page_after = -1;
thread_local bool fail_cursor_create = false;
void page_allocation_point() {
    if (fail_page_after == 0) throw std::bad_alloc();
    if (fail_page_after > 0) --fail_page_after;
}
#endif
}
SqlCommittedCursor::SqlCommittedCursor(SqlScopedResult&& value, Clock::time_point deadline) noexcept
    : committed_(std::move(value)), deadline_(deadline) {}
SqlCommittedCursor::~SqlCommittedCursor() { close(); }
void SqlCommittedCursor::close() noexcept {
    if (closed_) return;
    closed_ = true;
    committed_ = SqlScopedResult{};
    if(quota_){quota_->release(quota_bytes_);quota_.reset();quota_bytes_=0;}
}
int SqlSession::query_cursor_scoped(std::string_view sql, std::optional<std::string_view> parameter,
                                    uint64_t max_rows, uint64_t max_bytes, uint64_t lifetime_ms,
                                    std::unique_ptr<SqlCommittedCursor>& out,
                                    uint64_t max_progress_intervals, SqlCancel cancel) noexcept {
    const SqlParameter single{SqlParameter::Kind::text, 0, parameter.value_or(std::string_view{})};
    return query_cursor_scoped_bound(sql, parameter ? std::span<const SqlParameter>(&single, 1) : std::span<const SqlParameter>{},
                                     max_rows, max_bytes, lifetime_ms, out, max_progress_intervals, cancel);
}
int SqlSession::query_cursor_scoped_bound(std::string_view sql, std::span<const SqlParameter> parameters,
                                          uint64_t max_rows, uint64_t max_bytes, uint64_t lifetime_ms,
                                          std::unique_ptr<SqlCommittedCursor>& out,
                                          uint64_t max_progress_intervals, SqlCancel cancel) noexcept {
    if (out || !lifetime_ms || lifetime_ms > max_lifetime_ms) return SQLITE_MISUSE;
    try {
        cursor_attempted_=true;
        QuotaReservation reservation(cursor_quota_);
        if(!reservation.acquire_slot())return SQLITE_BUSY;
        SqlScopedResult result;
        const int rc = query_scoped_bound(sql, parameters, max_rows, max_bytes, result, max_progress_intervals, cancel);
        if (rc != SQLITE_OK) return rc;
        const auto now = SqlCommittedCursor::Clock::now();
        const auto lifetime = std::chrono::milliseconds(lifetime_ms);
        if (now > SqlCommittedCursor::Clock::time_point::max() - lifetime) return SQLITE_TOOBIG;
        const auto deadline = now + lifetime;
        uint64_t retained=0;
        if(cursor_quota_){
            for(const auto& row:result.rows){
                if(cancel.requested&&cancel.requested(cancel.context))return SQLITE_INTERRUPT;
                const uint64_t base=8+uint64_t(row.size())*16;
                if(base>std::numeric_limits<uint64_t>::max()-retained)return SQLITE_TOOBIG;
                retained+=base;
                for(const auto& value:row)if((value.kind==SqlValue::Kind::text || value.kind == SqlValue::Kind::blob)){
                    if(value.text.size()>std::numeric_limits<uint64_t>::max()-retained)return SQLITE_TOOBIG;
                    retained+=static_cast<uint64_t>(value.text.size());
                }
            }
            if(!reservation.acquire_bytes(retained))return SQLITE_TOOBIG;
            if(SqlCommittedCursor::Clock::now()>=deadline)return SQLITE_ABORT;
        }
#ifdef DMG_SQLITE_PROTO_TESTING
        if(fail_cursor_create)throw std::bad_alloc();
#endif
        auto pending = std::unique_ptr<SqlCommittedCursor>(new SqlCommittedCursor(std::move(result), deadline));
        if (cancel.requested && cancel.requested(cancel.context)) return SQLITE_INTERRUPT;
        if(cursor_quota_&&SqlCommittedCursor::Clock::now()>=deadline)return SQLITE_ABORT;
        pending->quota_=cursor_quota_;pending->quota_bytes_=retained;reservation.disarm();
        out.swap(pending);
        return SQLITE_OK;
    } catch (const std::bad_alloc&) { return SQLITE_NOMEM; }
    catch (...) { return SQLITE_ERROR; }
}
int SqlCommittedCursor::next(uint32_t max_page_rows, uint64_t max_page_bytes,
                             SqlCommittedPage& out, SqlCancel cancel) noexcept {
    if (closed_ || !max_page_rows || max_page_rows > 4096 || !max_page_bytes || max_page_bytes > max_result_bytes) return SQLITE_MISUSE;
    if (Clock::now() >= deadline_) { close(); return SQLITE_ABORT; }
    if (done_) return SQLITE_DONE;
    if (cancel.requested && cancel.requested(cancel.context)) return SQLITE_INTERRUPT;
    try {
        SqlCommittedPage pending;
        pending.result.snapshot_id = committed_.snapshot_id;
        pending.result.source_scope = committed_.source_scope;
        pending.result.input_count = committed_.input_count;
        pending.result.source_count = committed_.source_count;
        pending.first_row = position_;
        uint64_t used = 0;
        size_t end = position_;
        while (end < committed_.rows.size() && end - position_ < max_page_rows) {
            if (cancel.requested && cancel.requested(cancel.context)) return SQLITE_INTERRUPT;
            const auto& row = committed_.rows[end];
            uint64_t bytes = 8 + uint64_t(row.size()) * 16;
            for (const auto& value : row) {
                if ((value.kind == SqlValue::Kind::text || value.kind == SqlValue::Kind::blob)) {
                    if (value.text.size() > std::numeric_limits<uint64_t>::max() - bytes) return SQLITE_TOOBIG;
                    bytes += static_cast<uint64_t>(value.text.size());
                }
            }
            if (bytes > max_page_bytes - used) {
                if (end == position_) return SQLITE_TOOBIG;
                break;
            }
#ifdef DMG_SQLITE_PROTO_TESTING
            page_allocation_point();
#endif
            pending.result.rows.push_back(row);
            used += bytes;
            ++end;
        }
        pending.final_page = end == committed_.rows.size();
        if (cancel.requested && cancel.requested(cancel.context)) return SQLITE_INTERRUPT;
        if (Clock::now() >= deadline_) { close(); return SQLITE_ABORT; }
        // All potentially throwing copies are finished. The following swaps
        // and scalar stores are non-throwing, so failure never advances a page.
        out.result.rows.swap(pending.result.rows);
        out.result.snapshot_id.swap(pending.result.snapshot_id);
        out.result.source_scope = pending.result.source_scope;
        out.result.input_count = pending.result.input_count;
        out.result.source_count = pending.result.source_count;
        out.first_row = pending.first_row;
        out.final_page = pending.final_page;
        position_ = end;
        done_ = pending.final_page;
        return SQLITE_OK;
    } catch (const std::bad_alloc&) { return SQLITE_NOMEM; }
    catch (...) { return SQLITE_ERROR; }
}
#ifdef DMG_SQLITE_PROTO_TESTING
struct SqlCursorProbe {
    static void fail_after(int64_t value) noexcept { fail_page_after = value; }
    static void expire(SqlCommittedCursor& cursor) noexcept { cursor.deadline_ = SqlCommittedCursor::Clock::time_point::min(); }
};
void test_cursor_fail_after(int64_t value) noexcept { SqlCursorProbe::fail_after(value); }
void test_cursor_expire(SqlCommittedCursor& cursor) noexcept { SqlCursorProbe::expire(cursor); }
void test_cursor_create_fail(bool value) noexcept { fail_cursor_create=value; }
#endif
}
