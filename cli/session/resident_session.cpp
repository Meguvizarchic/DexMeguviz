#include "resident_session.hpp"
#include "sqlite3.h"
#include <chrono>
#include <limits>
#include <new>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace dexmeguviz::desktop_sql {
namespace {
using Clock = std::chrono::steady_clock;
uint64_t elapsed_us(Clock::time_point start) noexcept {
    const auto n=std::chrono::duration_cast<std::chrono::microseconds>(Clock::now()-start).count();
    return n>0 ? static_cast<uint64_t>(n) : 0;
}
void increment(uint64_t& n) noexcept { if(n!=UINT64_MAX) ++n; }
struct OwnedParameter { SqlParameter::Kind kind=SqlParameter::Kind::null; int64_t integer=0; std::string text; };
enum class State { empty, queued, running, terminal };
struct Slot {
    State state=State::empty;
    uint64_t id=0, input_bytes=0, result_reservation=0, max_rows=0, max_bytes=0, max_progress=0;
    std::string sql;
    std::vector<OwnedParameter> parameters;
    ResidentFinal final;
};
static_assert(std::is_nothrow_move_assignable_v<Slot>);
}
struct ResidentSession::Impl {
    std::unique_ptr<SqlSession> session;
    ResidentLimits limits;
    ResidentStats stats;
    std::vector<Slot> slots;
    uint64_t next_id=1;
    Slot* find(uint64_t id) noexcept {
        for(auto& s:slots) if(s.state!=State::empty && s.id==id) return &s;
        return nullptr;
    }
    const Slot* find(uint64_t id) const noexcept {
        for(const auto& s:slots) if(s.state!=State::empty && s.id==id) return &s;
        return nullptr;
    }
    void release_input(Slot& slot) noexcept {
        stats.input_bytes-=slot.input_bytes;slot.input_bytes=0;
        std::string{}.swap(slot.sql);
        std::vector<OwnedParameter>{}.swap(slot.parameters);
    }
    void terminal(Slot& slot,int rc) noexcept {
        release_input(slot);slot.final.execution_status=rc;slot.state=State::terminal;
        ++stats.terminal;increment(stats.completed);if(rc==SQLITE_INTERRUPT)increment(stats.cancelled);
    }
};
ResidentSession::ResidentSession(std::unique_ptr<Impl> p) noexcept : impl_(std::move(p)) {}
ResidentSession::~ResidentSession() = default;
int ResidentSession::open(const dmg_snapshot* snapshot,ResidentLimits limits,
                          std::unique_ptr<ResidentSession>& out) noexcept { return open(snapshot,limits,out,{}); }
int ResidentSession::open(const dmg_snapshot* snapshot,ResidentLimits limits,
                          std::unique_ptr<ResidentSession>& out,SqlPlanningOptions planning) noexcept {
    if(out || !snapshot || (planning.metadata_identity_in&&!planning.metadata_identity_equality) || !limits.max_outstanding || limits.max_outstanding>1024 ||
       !limits.max_input_bytes || limits.max_input_bytes>(uint64_t(1)<<30) ||
       !limits.max_reserved_result_bytes || limits.max_reserved_result_bytes>(uint64_t(1)<<30) ||
       !limits.max_statement_bytes || limits.max_statement_bytes>(16u<<20)) return SQLITE_MISUSE;
    const auto start=Clock::now();
    try {
        auto p=std::make_unique<Impl>();p->limits=limits;p->slots.resize(limits.max_outstanding);
        int rc=planning.metadata_identity_equality?SqlSession::open_scoped_planned(snapshot,p->session,{},planning):SqlSession::open_scoped(snapshot,p->session);if(rc!=SQLITE_OK)return rc;
        rc=p->session->enable_profiling(true);if(rc!=SQLITE_OK)return rc;
        rc=p->session->enable_statement_reuse(limits.max_statement_bytes);if(rc!=SQLITE_OK)return rc;
        p->stats.open_us=elapsed_us(start);
        auto candidate=std::unique_ptr<ResidentSession>(new ResidentSession(std::move(p)));
        out=std::move(candidate);return SQLITE_OK;
    } catch(const std::bad_alloc&) {return SQLITE_NOMEM;} catch(...) {return SQLITE_ERROR;}
}
int ResidentSession::submit(std::string_view sql,std::span<const SqlParameter> params,
                            uint64_t max_rows,uint64_t max_bytes,uint64_t max_progress,uint64_t& id) noexcept {
    if(!impl_||impl_->stats.closed||!impl_->session||sql.empty()||sql.size()>65536||
       sql.find('\0')!=std::string_view::npos||params.size()>256||!max_rows||max_rows>100000||
       !max_bytes||max_bytes>(8u<<20)||!max_progress||max_progress>1000000) return SQLITE_MISUSE;
    uint64_t text_bytes=0;
    uint64_t charge=static_cast<uint64_t>(sql.size())+static_cast<uint64_t>(params.size())*32;
    for(const auto& value:params){
        if((value.kind==SqlParameter::Kind::text || value.kind == SqlParameter::Kind::blob)){
            if(value.text.size()>max_bytes-text_bytes)return SQLITE_TOOBIG;
            text_bytes+=static_cast<uint64_t>(value.text.size());
        } else if(value.kind!=SqlParameter::Kind::null && value.kind!=SqlParameter::Kind::integer) return SQLITE_MISUSE;
    }
    if(text_bytes>UINT64_MAX-charge)return SQLITE_TOOBIG;charge+=text_bytes;
    if(charge>impl_->limits.max_input_bytes-impl_->stats.input_bytes ||
       max_bytes>impl_->limits.max_reserved_result_bytes-impl_->stats.reserved_result_bytes || !impl_->next_id) return SQLITE_FULL;
    Slot* target=nullptr;for(auto& slot:impl_->slots) if(slot.state==State::empty){target=&slot;break;}
    if(!target)return SQLITE_FULL;
    try {
        Slot pending;pending.state=State::queued;pending.id=impl_->next_id;pending.input_bytes=charge;
        pending.result_reservation=max_bytes;pending.max_rows=max_rows;pending.max_bytes=max_bytes;pending.max_progress=max_progress;
        pending.sql.assign(sql);pending.parameters.reserve(params.size());
        for(const auto& value:params){
            OwnedParameter own;own.kind=value.kind;own.integer=value.integer;
            if((value.kind==SqlParameter::Kind::text || value.kind == SqlParameter::Kind::blob) && !value.text.empty())own.text.assign(value.text);
            pending.parameters.push_back(std::move(own));
        }
        pending.final.id=pending.id;
        *target=std::move(pending);impl_->stats.input_bytes+=charge;impl_->stats.reserved_result_bytes+=max_bytes;
        ++impl_->stats.queued;increment(impl_->stats.accepted);id=impl_->next_id++;return SQLITE_OK;
    } catch(const std::bad_alloc&) {return SQLITE_NOMEM;} catch(...) {return SQLITE_ERROR;}
}
int ResidentSession::cancel_queued(uint64_t id) noexcept {
    if(!impl_||impl_->stats.closed)return SQLITE_MISUSE;
    auto* slot=impl_->find(id);if(!slot)return SQLITE_NOTFOUND;
    if(slot->state!=State::queued)return SQLITE_MISUSE;
    --impl_->stats.queued;impl_->terminal(*slot,SQLITE_INTERRUPT);return SQLITE_OK;
}
int ResidentSession::run_next(SqlCancel cancel) noexcept {
    if(!impl_||impl_->stats.closed||!impl_->session)return SQLITE_MISUSE;
    Slot* slot=nullptr;
    for(auto& s:impl_->slots)if(s.state==State::queued && (!slot || s.id<slot->id))slot=&s;
    if(!slot)return SQLITE_NOTFOUND;
    slot->state=State::running;--impl_->stats.queued;
    int rc=SQLITE_ERROR;
    try {
        std::vector<SqlParameter> params;params.reserve(slot->parameters.size());
        for(const auto& value:slot->parameters)params.push_back({value.kind,value.integer,value.text});
        (void)impl_->session->enable_profiling(false);(void)impl_->session->enable_profiling(true);
        rc=impl_->session->query_scoped_reused_bound(slot->sql,params,slot->max_rows,slot->max_bytes,
                                                      slot->final.result,slot->max_progress,cancel);
        slot->final.has_profile=impl_->session->last_query_profile(slot->final.profile)==SQLITE_OK;
        (void)impl_->session->statement_reuse_stats(slot->final.reuse);
    } catch(const std::bad_alloc&) {rc=SQLITE_NOMEM;} catch(...) {rc=SQLITE_ERROR;}
    impl_->terminal(*slot,rc);return SQLITE_OK;
}
int ResidentSession::final(uint64_t id,const ResidentFinal*& out) const noexcept {
    if(!impl_||impl_->stats.closed)return SQLITE_MISUSE;
    const auto* slot=impl_->find(id);if(!slot)return SQLITE_NOTFOUND;
    if(slot->state!=State::terminal)return SQLITE_BUSY;
    out=&slot->final;return SQLITE_OK;
}
int ResidentSession::acknowledge(uint64_t id) noexcept {
    if(!impl_||impl_->stats.closed)return SQLITE_MISUSE;
    auto* slot=impl_->find(id);if(!slot)return SQLITE_NOTFOUND;
    if(slot->state!=State::terminal)return SQLITE_BUSY;
    impl_->stats.reserved_result_bytes-=slot->result_reservation;--impl_->stats.terminal;*slot=Slot{};return SQLITE_OK;
}
int ResidentSession::stats(ResidentStats& out) const noexcept {
    if(!impl_)return SQLITE_MISUSE;out=impl_->stats;return SQLITE_OK;
}
int ResidentSession::close() noexcept {
    if(!impl_)return SQLITE_OK;if(impl_->stats.closed)return SQLITE_OK;
    if(impl_->stats.queued||impl_->stats.terminal)return SQLITE_BUSY;
    const auto start=Clock::now();const int rc=impl_->session->close();
    impl_->stats.close_us=elapsed_us(start);if(rc!=SQLITE_OK)return rc;
    impl_->stats.closed=true;return SQLITE_OK;
}
}
