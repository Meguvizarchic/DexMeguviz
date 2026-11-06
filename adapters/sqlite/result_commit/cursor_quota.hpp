#pragma once
#include <atomic>
#include <cstdint>

namespace dexmeguviz::desktop_sql::detail {
// Shared only by one session and the cursors it creates. A cursor can outlive
// the session; atomic counters keep releases of distinct cursors independent.
struct CursorQuota {
    CursorQuota(uint32_t count,uint64_t bytes) noexcept : max_cursors(count),max_bytes(bytes) {}
    const uint32_t max_cursors;
    const uint64_t max_bytes;
    std::atomic<uint32_t> live{0};
    std::atomic<uint64_t> bytes{0};
    bool acquire_slot() noexcept {
        auto current=live.load(std::memory_order_relaxed);
        while(current<max_cursors)if(live.compare_exchange_weak(current,current+1,std::memory_order_relaxed))return true;
        return false;
    }
    bool acquire_bytes(uint64_t amount) noexcept {
        auto current=bytes.load(std::memory_order_relaxed);
        for(;;){
            if(current>max_bytes||amount>max_bytes-current)return false;
            if(bytes.compare_exchange_weak(current,current+amount,std::memory_order_relaxed))return true;
        }
    }
    void release(uint64_t amount) noexcept {
        bytes.fetch_sub(amount,std::memory_order_relaxed);
        live.fetch_sub(1,std::memory_order_relaxed);
    }
};
}
