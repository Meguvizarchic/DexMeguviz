#pragma once
#include "resident_session.hpp"
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

namespace dexmeguviz::desktop_sql {
// Internal desktop experiment. Concurrent methods are supported; destruction
// requires exclusive ownership. The only SQL session lives on one worker.
struct BackgroundStats {
    uint32_t queued=0, running=0, terminal=0;
    uint64_t input_bytes=0, reserved_result_bytes=0;
    uint64_t accepted=0, completed=0, interrupted=0;
    bool stopping=false, closed=false;
};
class BackgroundSession final {
public:
    static int open(const dmg_snapshot* snapshot, ResidentLimits limits,
                    std::unique_ptr<BackgroundSession>& out) noexcept;
    static int open(const dmg_snapshot* snapshot, ResidentLimits limits,
                    std::unique_ptr<BackgroundSession>& out, SqlPlanningOptions planning) noexcept;
    int submit(std::string_view sql, std::span<const SqlParameter> parameters,
               uint64_t max_rows, uint64_t max_bytes, uint64_t max_progress_intervals,
               uint64_t& id) noexcept;
    int cancel(uint64_t id) noexcept;
    // Copies a retained terminal; BUSY/NOTFOUND/failure leave out unchanged.
    int final(uint64_t id, ResidentFinal& out) noexcept;
    int acknowledge(uint64_t id) noexcept;
    int stats(BackgroundStats& out) noexcept;
    // Stops admission; optional cancellation applies to queued and running jobs.
    int shutdown(bool request_cancel) noexcept;
    // Requires shutdown and acknowledgement of every terminal; BUSY otherwise.
    // On success joins the worker; concurrent close calls are rejected.
    int close() noexcept;
    ~BackgroundSession();
    BackgroundSession(const BackgroundSession&)=delete;
    BackgroundSession& operator=(const BackgroundSession&)=delete;
private:
    struct Impl;
    explicit BackgroundSession(std::unique_ptr<Impl>) noexcept;
    std::unique_ptr<Impl> impl_;
};
}
