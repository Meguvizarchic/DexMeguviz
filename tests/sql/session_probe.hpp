#pragma once
#include "method_tables.hpp"

namespace dexmeguviz::desktop_sql {
// Test-only access never exposes a SQLite connection or statement pointer.
struct SqlSessionProbe {
    static int configure_private_log(void (*callback)(void*,int,const char*) noexcept, void* context) noexcept;
    static int emit_private_log(SqlSession& session) noexcept;
    static bool private_default_vfs_is(const char* name) noexcept;
    static void observe_close_return(SqlSession& session, bool* result) noexcept;
    static int hold_statement(SqlSession& session) noexcept;
    static int release_statement(SqlSession& session) noexcept;
    // True only while the native site collector invokes its cancel callback.
    static bool in_site_cancel_callback() noexcept;
    // Test-only synthetic allocation failure before the UTF-8 buffer reserve.
    static void fail_utf8_after(int64_t count) noexcept;
    // Synthetic failure immediately before row-copy storage allocation.
    static void fail_row_copy_after(int64_t count) noexcept;
    static uint64_t utf8_conversions() noexcept;
    static uint64_t utf8_allocations() noexcept;
    // Counts integer source-index xFilter probes in this test thread only.
    static void reset_identity_filter_metrics() noexcept;
    static uint64_t identity_filter_count() noexcept;
    static uint64_t identity_rowid_filter_count() noexcept;
    static uint32_t identity_filter_source_mask() noexcept;
    static uint64_t identity_in_filter_count() noexcept;
    static uint64_t identity_in_fallback_count() noexcept;
    static bool in_identity_in_callback() noexcept;
    static void fail_scratch_after(int64_t count) noexcept;
    // Per-thread observation only; does not synthesize or alter SQLite results.
    static void reset_bind_observation() noexcept;
    static uint32_t bind_success_count() noexcept;
    static int bind_failure_index() noexcept;
    static int bind_failure_code() noexcept;
};
}
