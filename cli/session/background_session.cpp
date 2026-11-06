#include "background_session.hpp"
#include "dexmeguviz/dexmeguviz.h"
#include "sqlite3.h"
#include <atomic>
#include <condition_variable>
#include <chrono>
#include <limits>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace dexmeguviz::desktop_sql {
namespace {
enum class State { empty, queued, running, terminal };
struct OwnedParameter { SqlParameter::Kind kind; int64_t integer; std::string text; };
struct Slot {
    State state=State::empty;
    uint64_t id=0, input_bytes=0, reservation=0, max_rows=0, max_bytes=0, max_progress=0;
    std::string sql;
    std::vector<OwnedParameter> params;
    std::atomic<bool> cancelled{false};
    ResidentFinal final;
};
static_assert(std::is_nothrow_move_assignable_v<ResidentFinal>);
void increment(uint64_t& value) noexcept { if(value!=UINT64_MAX)++value; }
#ifdef DMG_SQLITE_PROTO_TESTING
std::atomic<int> fault_point{0};
std::atomic<int> callback_checks{0};
std::atomic<int> destroyed_on_owner{0}, destroyed_wrong_thread{0};
std::mutex gate_mutex;
std::condition_variable gate_cv;
bool gate_paused=false, gate_entered=false;
bool finish_paused=false, finish_entered=false;
void test_finish_gate() {
    std::unique_lock lock(gate_mutex);
    if(finish_paused){finish_entered=true;gate_cv.notify_all();gate_cv.wait(lock,[]{return !finish_paused;});}
}
void test_gate() {
    std::unique_lock lock(gate_mutex);
    if(gate_paused){gate_entered=true;gate_cv.notify_all();gate_cv.wait(lock,[]{return !gate_paused;});}
}
void fault(int point) { int value=point;if(fault_point.compare_exchange_strong(value,0))throw std::bad_alloc(); }
#endif
}
struct BackgroundSession::Impl {
    ResidentLimits limits{};
    SqlPlanningOptions planning{};
    std::unique_ptr<Slot[]> slots;
    std::unique_ptr<SqlSession> session;
    std::mutex mutex;
    std::condition_variable cv;
    std::thread worker;
    BackgroundStats stats{};
    uint64_t next_id=1;
    bool ready=false, close_requested=false, close_finished=false, force_close=false, closing=false;
    int open_rc=SQLITE_ERROR, close_rc=SQLITE_ERROR;
#ifdef DMG_SQLITE_PROTO_TESTING
    std::thread::id owner;
#endif
    void dispose_session() noexcept {
        if(!session)return;
#ifdef DMG_SQLITE_PROTO_TESTING
        if(std::this_thread::get_id()==owner)++destroyed_on_owner;else ++destroyed_wrong_thread;
#endif
        session.reset();
    }
    Slot* find(uint64_t id) noexcept {
        for(uint32_t i=0;i<limits.max_outstanding;++i)if(slots[i].state!=State::empty && slots[i].id==id)return &slots[i];
        return nullptr;
    }
    void free_input(Slot& slot) noexcept {
        stats.input_bytes-=slot.input_bytes;slot.input_bytes=0;
        std::string{}.swap(slot.sql);std::vector<OwnedParameter>{}.swap(slot.params);
    }
    void finish(Slot& slot,int rc) noexcept {
        free_input(slot);
        if(rc!=SQLITE_OK)slot.final.result=SqlScopedResult{};
        slot.final.execution_status=rc;slot.state=State::terminal;
        ++stats.terminal;increment(stats.completed);if(rc==SQLITE_INTERRUPT)increment(stats.interrupted);
    }
    static bool cancel_callback(void* context) noexcept {
#ifdef DMG_SQLITE_PROTO_TESTING
        ++callback_checks;
#endif
        return static_cast<Slot*>(context)->cancelled.load(std::memory_order_acquire);
    }
    void run(const dmg_snapshot* snapshot) noexcept {
#ifdef DMG_SQLITE_PROTO_TESTING
        owner=std::this_thread::get_id();
#endif
        int rc=planning.metadata_identity_equality?SqlSession::open_scoped_planned(snapshot,session,{},planning):SqlSession::open_scoped(snapshot,session);
        dmg_snapshot_release(const_cast<dmg_snapshot*>(snapshot));
        if(rc==SQLITE_OK)rc=session->enable_profiling(true);
        if(rc==SQLITE_OK)rc=session->enable_statement_reuse(limits.max_statement_bytes);
        if(rc!=SQLITE_OK)dispose_session();
        {
            std::lock_guard lock(mutex);open_rc=rc;ready=true;cv.notify_all();
        }
        if(rc!=SQLITE_OK)return;
        for(;;) {
            Slot* slot=nullptr;
            {
                std::unique_lock lock(mutex);
                cv.wait(lock,[&]{return stats.queued || close_requested;});
                if(close_requested && !stats.queued) {
                    const bool force=force_close;lock.unlock();
#ifdef DMG_SQLITE_PROTO_TESTING
                    int point=4;const int result=fault_point.compare_exchange_strong(point,0)?SQLITE_BUSY:session->close();
#else
                    const int result=session->close();
#endif
                    if(result==SQLITE_OK || force)dispose_session();
                    lock.lock();
                    close_rc=result;close_finished=true;close_requested=false;cv.notify_all();
                    if(result==SQLITE_OK || force)return;
                    continue;
                }
                for(uint32_t i=0;i<limits.max_outstanding;++i) {
                    auto& candidate=slots[i];
                    if(candidate.state==State::queued && (!slot || candidate.id<slot->id))slot=&candidate;
                }
                if(!slot)continue;
                slot->state=State::running;--stats.queued;++stats.running;
            }
#ifdef DMG_SQLITE_PROTO_TESTING
            test_gate();
#endif
            rc=SQLITE_ERROR;
            try {
#ifdef DMG_SQLITE_PROTO_TESTING
                fault(3);
#endif
                std::vector<SqlParameter> params;params.reserve(slot->params.size());
                for(const auto& p:slot->params)params.push_back({p.kind,p.integer,p.text});
                (void)session->enable_profiling(false);(void)session->enable_profiling(true);
                rc=session->query_scoped_reused_bound(slot->sql,params,slot->max_rows,slot->max_bytes,
                                                     slot->final.result,slot->max_progress,{cancel_callback,slot});
                slot->final.has_profile=session->last_query_profile(slot->final.profile)==SQLITE_OK;
                (void)session->statement_reuse_stats(slot->final.reuse);
            } catch(const std::bad_alloc&) {rc=SQLITE_NOMEM;} catch(...) {rc=SQLITE_ERROR;}
#ifdef DMG_SQLITE_PROTO_TESTING
            test_finish_gate();
#endif
            {
                std::lock_guard lock(mutex);
                // Cancellation that wins this lock over successful publication
                // invalidates the result. Earlier query errors retain priority.
                if(rc==SQLITE_OK && slot->cancelled.load(std::memory_order_acquire))rc=SQLITE_INTERRUPT;
                --stats.running;finish(*slot,rc);cv.notify_all();
            }
        }
    }
};
BackgroundSession::BackgroundSession(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
int BackgroundSession::open(const dmg_snapshot* snapshot,ResidentLimits limits,std::unique_ptr<BackgroundSession>& out) noexcept { return open(snapshot,limits,out,{}); }
int BackgroundSession::open(const dmg_snapshot* snapshot,ResidentLimits limits,std::unique_ptr<BackgroundSession>& out,SqlPlanningOptions planning) noexcept {
    if(out || !snapshot || (planning.metadata_identity_in&&!planning.metadata_identity_equality) || !limits.max_outstanding || limits.max_outstanding>1024 ||
       !limits.max_input_bytes || limits.max_input_bytes>(uint64_t(1)<<30) ||
       !limits.max_reserved_result_bytes || limits.max_reserved_result_bytes>(uint64_t(1)<<30) ||
       !limits.max_statement_bytes || limits.max_statement_bytes>(16u<<20))return SQLITE_MISUSE;
    try {
        auto impl=std::make_unique<Impl>();impl->limits=limits;impl->planning=planning;impl->slots=std::make_unique<Slot[]>(limits.max_outstanding);
        auto candidate=std::unique_ptr<BackgroundSession>(new BackgroundSession(std::move(impl)));
        auto* state=candidate->impl_.get();dmg_snapshot_retain(const_cast<dmg_snapshot*>(snapshot));
        try { state->worker=std::thread([state,snapshot]{state->run(snapshot);}); }
        catch(...) { dmg_snapshot_release(const_cast<dmg_snapshot*>(snapshot)); throw; }
        std::unique_lock lock(state->mutex);state->cv.wait(lock,[&]{return state->ready;});
        const int rc=state->open_rc;lock.unlock();
        if(rc!=SQLITE_OK){state->worker.join();return rc;}
        out=std::move(candidate);return SQLITE_OK;
    } catch(const std::bad_alloc&) {return SQLITE_NOMEM;} catch(...) {return SQLITE_ERROR;}
}
int BackgroundSession::submit(std::string_view sql,std::span<const SqlParameter> params,uint64_t max_rows,
                              uint64_t max_bytes,uint64_t max_progress,uint64_t& id) noexcept {
    if(!impl_||sql.empty()||sql.size()>65536||sql.find('\0')!=std::string_view::npos||params.size()>256||
       !max_rows||max_rows>100000||!max_bytes||max_bytes>(8u<<20)||!max_progress||max_progress>1000000)return SQLITE_MISUSE;
    uint64_t text=0,charge=static_cast<uint64_t>(sql.size())+static_cast<uint64_t>(params.size())*32;
    for(const auto& p:params){
        if((p.kind==SqlParameter::Kind::text || p.kind == SqlParameter::Kind::blob)){if(p.text.size()>max_bytes-text)return SQLITE_TOOBIG;text+=static_cast<uint64_t>(p.text.size());}
        else if(p.kind!=SqlParameter::Kind::null && p.kind!=SqlParameter::Kind::integer)return SQLITE_MISUSE;
    }
    if(text>UINT64_MAX-charge)return SQLITE_TOOBIG;charge+=text;
    try {
        std::lock_guard lock(impl_->mutex);auto& v=*impl_;
        if(v.stats.stopping||v.stats.closed)return SQLITE_MISUSE;
        if(charge>v.limits.max_input_bytes-v.stats.input_bytes || max_bytes>v.limits.max_reserved_result_bytes-v.stats.reserved_result_bytes || !v.next_id)return SQLITE_FULL;
        Slot* target=nullptr;for(uint32_t i=0;i<v.limits.max_outstanding;++i)if(v.slots[i].state==State::empty){target=&v.slots[i];break;}
        if(!target)return SQLITE_FULL;
#ifdef DMG_SQLITE_PROTO_TESTING
        fault(1);
#endif
        std::string owned_sql(sql);std::vector<OwnedParameter> owned;owned.reserve(params.size());
        for(const auto& p:params)owned.push_back({p.kind,p.integer,(p.kind==SqlParameter::Kind::text || p.kind == SqlParameter::Kind::blob)?std::string(p.text):std::string{}});
        target->sql.swap(owned_sql);target->params.swap(owned);target->id=v.next_id;
        target->input_bytes=charge;target->reservation=max_bytes;target->max_rows=max_rows;target->max_bytes=max_bytes;target->max_progress=max_progress;
        target->cancelled.store(false,std::memory_order_release);target->final.id=v.next_id;target->state=State::queued;
        v.stats.input_bytes+=charge;v.stats.reserved_result_bytes+=max_bytes;++v.stats.queued;increment(v.stats.accepted);id=v.next_id++;v.cv.notify_all();return SQLITE_OK;
    } catch(const std::bad_alloc&) {return SQLITE_NOMEM;} catch(...) {return SQLITE_ERROR;}
}
int BackgroundSession::cancel(uint64_t id) noexcept {
    try {std::lock_guard lock(impl_->mutex);auto& v=*impl_;if(v.stats.closed)return SQLITE_MISUSE;
        auto* s=v.find(id);if(!s)return SQLITE_NOTFOUND;
        if(s->state==State::queued){--v.stats.queued;v.finish(*s,SQLITE_INTERRUPT);v.cv.notify_all();return SQLITE_OK;}
        if(s->state==State::running){s->cancelled.store(true,std::memory_order_release);return SQLITE_OK;}
        return SQLITE_MISUSE;
    } catch(...) {return SQLITE_ERROR;}
}
int BackgroundSession::final(uint64_t id,ResidentFinal& out) noexcept {
    try {std::lock_guard lock(impl_->mutex);auto& v=*impl_;if(v.stats.closed)return SQLITE_MISUSE;
        auto* s=v.find(id);if(!s)return SQLITE_NOTFOUND;if(s->state!=State::terminal)return SQLITE_BUSY;
#ifdef DMG_SQLITE_PROTO_TESTING
        fault(2);
#endif
        ResidentFinal copy=s->final;out=std::move(copy);return SQLITE_OK;
    } catch(const std::bad_alloc&) {return SQLITE_NOMEM;}catch(...) {return SQLITE_ERROR;}
}
int BackgroundSession::acknowledge(uint64_t id) noexcept {
    try {std::lock_guard lock(impl_->mutex);auto& v=*impl_;if(v.stats.closed)return SQLITE_MISUSE;
        auto* s=v.find(id);if(!s)return SQLITE_NOTFOUND;if(s->state!=State::terminal)return SQLITE_BUSY;
        v.stats.reserved_result_bytes-=s->reservation;--v.stats.terminal;s->final=ResidentFinal{};s->id=0;s->reservation=0;s->state=State::empty;return SQLITE_OK;
    } catch(...) {return SQLITE_ERROR;}
}
int BackgroundSession::stats(BackgroundStats& out) noexcept {
    try {std::lock_guard lock(impl_->mutex);out=impl_->stats;return SQLITE_OK;}catch(...) {return SQLITE_ERROR;}
}
int BackgroundSession::shutdown(bool request_cancel) noexcept {
    try {std::lock_guard lock(impl_->mutex);auto& v=*impl_;if(v.stats.closed)return SQLITE_MISUSE;v.stats.stopping=true;
        if(request_cancel)for(uint32_t i=0;i<v.limits.max_outstanding;++i){auto& s=v.slots[i];
            if(s.state==State::queued){--v.stats.queued;v.finish(s,SQLITE_INTERRUPT);}
            else if(s.state==State::running)s.cancelled.store(true,std::memory_order_release);
        }
        v.cv.notify_all();return SQLITE_OK;
    } catch(...) {return SQLITE_ERROR;}
}
int BackgroundSession::close() noexcept {
    try {std::unique_lock lock(impl_->mutex);auto& v=*impl_;
        if(v.stats.closed)return SQLITE_OK;if(v.closing || !v.stats.stopping || v.stats.queued || v.stats.running || v.stats.terminal)return SQLITE_BUSY;
        v.closing=true;v.close_finished=false;v.close_requested=true;v.cv.notify_all();v.cv.wait(lock,[&]{return v.close_finished;});
        const int rc=v.close_rc;if(rc!=SQLITE_OK){v.closing=false;return rc;}
        lock.unlock();v.worker.join();lock.lock();v.stats.closed=true;v.closing=false;return SQLITE_OK;
    } catch(...) {return SQLITE_ERROR;}
}
BackgroundSession::~BackgroundSession() {
    if(!impl_ || !impl_->worker.joinable())return;
    // Destruction explicitly abandons unacknowledged results; callers that
    // require delivery must shutdown, read, acknowledge and close first.
    (void)shutdown(true);
    {std::lock_guard lock(impl_->mutex);impl_->force_close=true;impl_->close_requested=true;impl_->cv.notify_all();}
    impl_->worker.join();
}
#ifdef DMG_SQLITE_PROTO_TESTING
void test_background_fail_next(int point) noexcept {fault_point.store(point);}
void test_background_pause(bool value) {std::lock_guard lock(gate_mutex);gate_paused=value;if(value)gate_entered=false;gate_cv.notify_all();}
bool test_background_wait_paused() {std::unique_lock lock(gate_mutex);return gate_cv.wait_for(lock,std::chrono::seconds(5),[]{return gate_entered;});}
void test_background_finish_pause(bool value) {std::lock_guard lock(gate_mutex);finish_paused=value;if(value)finish_entered=false;gate_cv.notify_all();}
bool test_background_wait_finish() {std::unique_lock lock(gate_mutex);return gate_cv.wait_for(lock,std::chrono::seconds(5),[]{return finish_entered;});}
void test_background_reset_checks() noexcept {callback_checks.store(0);}
int test_background_checks() noexcept {return callback_checks.load();}
int test_background_destroyed_on_owner() noexcept {return destroyed_on_owner.load();}
int test_background_destroyed_wrong_thread() noexcept {return destroyed_wrong_thread.load();}
#endif
}
