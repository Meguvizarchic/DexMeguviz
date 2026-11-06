#pragma once
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <memory_resource>
#include <new>

namespace dexmeguviz {
#ifdef DMG_TEST_ALLOC_FAILURES
inline thread_local int64_t test_allocations_left=-1;
inline void test_fail_allocation_after(int64_t count)noexcept{test_allocations_left=count;}
#endif
enum class MemoryKind : uint32_t { source, facts, scratch, query, result, control, count };
struct BudgetExceeded final : std::bad_alloc {
    char detail[256]="engine owned allocation budget exceeded";
    BudgetExceeded()noexcept=default;
    BudgetExceeded(const char* kind,uint64_t requested,uint64_t used,uint64_t source,uint64_t facts)noexcept{
        std::snprintf(detail,sizeof(detail),"engine budget exceeded: kind=%s requested=%llu owned=%llu source=%llu facts=%llu",
            kind,static_cast<unsigned long long>(requested),static_cast<unsigned long long>(used),static_cast<unsigned long long>(source),static_cast<unsigned long long>(facts));
    }
    const char* what() const noexcept override { return detail; }
};
class Account {
public:
    explicit Account(uint64_t limit,uint64_t borrowed_limit) : limit_(limit),borrowed_limit_(borrowed_limit) {}
    void reserve(uint64_t bytes,MemoryKind kind) {
        uint64_t current=total_.load(std::memory_order_relaxed);
        do { if(bytes>limit_-current) {
            constexpr const char* names[]={"source","facts","scratch","query","result","control"};
            throw BudgetExceeded(names[static_cast<size_t>(kind)],bytes,current,category(MemoryKind::source),category(MemoryKind::facts));
        } }
        while(!total_.compare_exchange_weak(current,current+bytes,std::memory_order_acq_rel));
        categories_[static_cast<size_t>(kind)].fetch_add(bytes,std::memory_order_relaxed);
        uint64_t peak=peak_.load(std::memory_order_relaxed);
        while(peak<current+bytes&&!peak_.compare_exchange_weak(peak,current+bytes,std::memory_order_relaxed)){}
    }
    void release(uint64_t bytes,MemoryKind kind) noexcept {
        categories_[static_cast<size_t>(kind)].fetch_sub(bytes,std::memory_order_relaxed);
        total_.fetch_sub(bytes,std::memory_order_release);
    }
    void reserve_borrowed(uint64_t bytes) {
        uint64_t current=borrowed_.load(std::memory_order_relaxed);
        do { if(bytes>borrowed_limit_-current) throw BudgetExceeded(); }
        while(!borrowed_.compare_exchange_weak(current,current+bytes,std::memory_order_acq_rel));
    }
    void release_borrowed(uint64_t bytes) noexcept { borrowed_.fetch_sub(bytes,std::memory_order_release); }
    uint64_t total() const noexcept { return total_.load(std::memory_order_acquire); }
    uint64_t peak() const noexcept { return peak_.load(std::memory_order_acquire); }
    uint64_t borrowed() const noexcept { return borrowed_.load(std::memory_order_acquire); }
    uint64_t category(MemoryKind kind) const noexcept { return categories_[static_cast<size_t>(kind)].load(std::memory_order_acquire); }
private:
    uint64_t limit_,borrowed_limit_;
    std::atomic<uint64_t> total_{0},peak_{0},borrowed_{0};
    std::array<std::atomic<uint64_t>,static_cast<size_t>(MemoryKind::count)> categories_{};
};
class AccountResource final : public std::pmr::memory_resource {
public:
    AccountResource(Account& account,MemoryKind kind):account_(account),kind_(kind){}
private:
    Account& account_;MemoryKind kind_;
    void* do_allocate(size_t bytes,size_t alignment) override {
        account_.reserve(bytes,kind_);
        try {
#ifdef DMG_TEST_ALLOC_FAILURES
            if(test_allocations_left>=0&&test_allocations_left--==0)throw std::bad_alloc();
#endif
            return std::pmr::new_delete_resource()->allocate(bytes,alignment);
        }
        catch(...) { account_.release(bytes,kind_);throw; }
    }
    void do_deallocate(void* p,size_t bytes,size_t alignment) override {
        std::pmr::new_delete_resource()->deallocate(p,bytes,alignment);
        account_.release(bytes,kind_);
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override { return this==&other; }
};
// Account object lifetime is held by the containing Source/Query/Result/Job.
class Charge {
public:
    Charge(Account& account,uint64_t bytes,MemoryKind kind):account_(&account),bytes_(bytes),kind_(kind){account_->reserve(bytes_,kind_);}
    Charge(const Charge&)=delete;Charge& operator=(const Charge&)=delete;
    ~Charge(){account_->release(bytes_,kind_);}
private:
    Account* account_;uint64_t bytes_;MemoryKind kind_;
};
}
