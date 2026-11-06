#include "method_tables.hpp"
#include "result_commit/cursor.hpp"
#include "dexmeguviz/dexmeguviz.h"
#include "sqlite3.h"
#include "../session_probe.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>
using namespace dexmeguviz::desktop_sql;
namespace dexmeguviz::desktop_sql { void test_cursor_fail_after(int64_t) noexcept; void test_cursor_expire(SqlCommittedCursor&) noexcept; void test_cursor_create_fail(bool) noexcept; }
#define CHECK(x) do { if (!(x)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #x); } while (false)
static std::vector<uint8_t> load(const std::filesystem::path& p) {
    std::ifstream in(p,std::ios::binary); CHECK(in.good()); return {std::istreambuf_iterator<char>(in),{}};
}
static bool same(const SqlCommittedPage& a,const SqlCommittedPage& b) {
    return a.result.rows==b.result.rows && a.result.snapshot_id==b.result.snapshot_id &&
        a.result.source_scope==b.result.source_scope && a.result.input_count==b.result.input_count &&
        a.result.source_count==b.result.source_count && a.first_row==b.first_row && a.final_page==b.final_page;
}
struct CancelAfter {
    int checks=0, stop=0;
    static bool requested(void* context) noexcept { auto& c=*static_cast<CancelAfter*>(context);return ++c.checks>=c.stop; }
};
struct CancelInsideSiteScan {
    int checks=0;
    static bool requested(void* context) noexcept {
        if (!SqlSessionProbe::in_site_cancel_callback()) return false;
        return ++static_cast<CancelInsideSiteScan*>(context)->checks == 6;
    }
};
static bool delayed_not_cancelled(void*) noexcept {
    std::this_thread::sleep_for(std::chrono::milliseconds(15));return false;
}
struct DelayAt {
    int checks=0, at=0;
    static bool requested(void* context) noexcept {auto& c=*static_cast<DelayAt*>(context);if(++c.checks==c.at)std::this_thread::sleep_for(std::chrono::milliseconds(30));return false;}
};
static SqlRows ordinary(sqlite3* db,const char* sql) {
    sqlite3_stmt* stmt=nullptr;CHECK(sqlite3_prepare_v2(db,sql,-1,&stmt,nullptr)==SQLITE_OK);
    struct Guard { sqlite3_stmt* p; ~Guard(){if(p)sqlite3_finalize(p);} } guard{stmt};
    SqlRows rows;int rc;
    while((rc=sqlite3_step(stmt))==SQLITE_ROW) {
        std::vector<SqlValue> row;
        for(int i=0;i<sqlite3_column_count(stmt);++i) {
            SqlValue v;const int t=sqlite3_column_type(stmt,i);
            if(t==SQLITE_INTEGER){v.kind=SqlValue::Kind::integer;v.integer=sqlite3_column_int64(stmt,i);}
            else if(t==SQLITE_TEXT){v.kind=SqlValue::Kind::text;const char* p=reinterpret_cast<const char*>(sqlite3_column_text(stmt,i));CHECK(p);v.text.assign(p,sqlite3_column_bytes(stmt,i));}
            else CHECK(t==SQLITE_NULL);
            row.push_back(std::move(v));
        }
        rows.push_back(std::move(row));
    }
    CHECK(rc==SQLITE_DONE);return rows;
}
int main(int argc,char** argv){try {
    CHECK(argc==2);const auto dex=load(argv[1]);
    dmg_engine* engine=nullptr;dmg_error error{};CHECK(dmg_engine_create(nullptr,&engine,&error)==DMG_OK);
    struct EngineGuard { dmg_engine* p;~EngineGuard(){if(p)dmg_engine_release(p);} } eg{engine};
    dmg_source_spec inputs[]{
        {sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,dex.data(),dex.size(),"one","raw",nullptr},
        {sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,dex.data(),dex.size(),"two","raw",nullptr}};
    dmg_source_set_options opts{sizeof(dmg_source_set_options),DMG_ABI_VERSION,"cursor41",0,8,8u<<20};
    dmg_snapshot *one=nullptr,*two=nullptr;CHECK(dmg_snapshot_open_sources(engine,inputs,1,&opts,&one,&error)==DMG_OK);
    opts.scope_complete=1;CHECK(dmg_snapshot_open_sources(engine,inputs,2,&opts,&two,&error)==DMG_OK);
    struct Guard { dmg_snapshot* p;~Guard(){if(p)dmg_snapshot_release(p);} } g1{one},g2{two};
    dmg_snapshot_overview overview{};CHECK(dmg_snapshot_get_overview(one,&overview)==DMG_OK);const std::string first_id=overview.snapshot_id;
    std::unique_ptr<SqlSession> a,b;CHECK(SqlSession::open_scoped(one,a)==SQLITE_OK);CHECK(SqlSession::open_scoped(two,b)==SQLITE_OK);
    const char* sql="SELECT source_index,ordinal,name FROM dmg_method_defs ORDER BY source_index,ordinal";
    SqlScopedResult direct;CHECK(a->query_scoped(sql,std::nullopt,100,1u<<20,direct)==SQLITE_OK && direct.rows.size()>2);
    std::unique_ptr<SqlCommittedCursor> cursor;CHECK(a->query_cursor_scoped(sql,std::nullopt,100,1u<<20,60000,cursor)==SQLITE_OK && cursor);
    auto* const original_cursor=cursor.get();
    CHECK(a->query_cursor_scoped("SELECT 1",std::nullopt,10,1024,60000,cursor)==SQLITE_MISUSE && cursor.get()==original_cursor);
    SqlCommittedPage page;page.first_row=123;page.result.snapshot_id="unchanged";page.result.rows={{{SqlValue::Kind::integer,999,{}}}};const auto saved=page;
    CHECK(cursor->next(0,1024,page)==SQLITE_MISUSE && same(page,saved));
    CHECK(cursor->next(1,1,page)==SQLITE_TOOBIG && same(page,saved));
    CancelAfter cancelling{0,3};CHECK(cursor->next(2,1u<<20,page,{CancelAfter::requested,&cancelling})==SQLITE_INTERRUPT && same(page,saved) && cancelling.checks==3);
    test_cursor_fail_after(1);CHECK(cursor->next(2,1u<<20,page)==SQLITE_NOMEM && same(page,saved));test_cursor_fail_after(-1);
    SqlRows joined;uint64_t offset=0;bool final=false;
    while(!final){CHECK(cursor->next(2,1u<<20,page)==SQLITE_OK && page.first_row==offset);
        CHECK(page.result.snapshot_id==first_id && page.result.source_scope==SqlScopeCoverage::partial_source_scope && page.result.input_count==1 && page.result.source_count==1);
        offset+=page.result.rows.size();joined.insert(joined.end(),page.result.rows.begin(),page.result.rows.end());final=page.final_page;}
    CHECK(joined==direct.rows && cursor->next(2,1u<<20,page)==SQLITE_DONE);
    // Bounded strict spool is independent of later session and snapshot lifetime.
    std::unique_ptr<SqlCommittedCursor> held;CHECK(a->query_cursor_scoped(sql,std::nullopt,100,1u<<20,60000,held)==SQLITE_OK);
    CHECK(a->close()==SQLITE_OK);dmg_snapshot_release(one);g1.p=nullptr;
    CHECK(held->next(1,1u<<20,page)==SQLITE_OK && page.result.snapshot_id==first_id);
    held->close();CHECK(held->next(1,1u<<20,page)==SQLITE_MISUSE);
    // Two snapshots and plans are bound to separate materializations: no token can mix them.
    std::unique_ptr<SqlCommittedCursor> other;CHECK(b->query_cursor_scoped("SELECT source_index FROM dmg_method_defs ORDER BY source_index",std::nullopt,100,1u<<20,60000,other)==SQLITE_OK);
    CHECK(other->next(1,1u<<20,page)==SQLITE_OK && page.result.snapshot_id!=first_id && page.result.source_count==2 && page.result.source_scope==SqlScopeCoverage::declared_complete_source_scope);
    // Compare a committed paged query with independent ordinary SQLite execution.
    sqlite3* ordinary_db=nullptr;CHECK(sqlite3_open(":memory:",&ordinary_db)==SQLITE_OK);
    struct DbGuard { sqlite3* p;~DbGuard(){if(p)sqlite3_close(p);} } db{ordinary_db};
    const char* constants="SELECT 1 AS x UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4";
    const auto expected=ordinary(ordinary_db,constants);std::unique_ptr<SqlCommittedCursor> constants_cursor;
    CHECK(b->query_cursor_scoped(constants,std::nullopt,8,1024,60000,constants_cursor)==SQLITE_OK);
    const auto previous_page=page;CHECK(constants_cursor->next(2,23,page)==SQLITE_TOOBIG && same(page,previous_page));
    CHECK(constants_cursor->next(2,24,page)==SQLITE_OK && page.result.rows.size()==1 && page.first_row==0);
    joined=page.result.rows;final=page.final_page;while(!final){CHECK(constants_cursor->next(2,24,page)==SQLITE_OK);joined.insert(joined.end(),page.result.rows.begin(),page.result.rows.end());final=page.final_page;}CHECK(joined==expected);
    std::unique_ptr<SqlCommittedCursor> empty;CHECK(b->query_cursor_scoped("SELECT 1 WHERE 0",std::nullopt,5,1024,60000,empty)==SQLITE_OK);
    CHECK(empty->next(1,1024,page)==SQLITE_OK && page.final_page && page.result.rows.empty() && page.first_row==0);
    CHECK(empty->next(1,1024,page)==SQLITE_DONE);
    // No cursor is published for a late unsupported value or row budget failure.
    std::unique_ptr<SqlCommittedCursor> failed;
    CHECK(b->query_cursor_scoped("SELECT 1 UNION ALL SELECT zeroblob(2)",std::nullopt,5,1024,60000,failed)==SQLITE_MISMATCH && !failed);
    CHECK(b->query_cursor_scoped("SELECT 1 UNION ALL SELECT 2",std::nullopt,1,1024,60000,failed)==SQLITE_TOOBIG && !failed);
    CHECK(b->query_cursor_scoped("SELECT 1",std::nullopt,1,1024,0,failed)==SQLITE_MISUSE && !failed);
    CancelAfter late{0,3};CHECK(b->query_cursor_scoped("SELECT 1 UNION ALL SELECT 2",std::nullopt,5,1024,60000,failed,10000,{CancelAfter::requested,&late})==SQLITE_INTERRUPT && !failed && late.checks==3);
    for(const char* aggregate : {"SELECT count(*) FROM dmg_string_uses","SELECT NOT EXISTS(SELECT 1 FROM dmg_invoke_sites WHERE dex_pc=-1)"}) {
        SqlSessionProbe::fail_scratch_after(0);const int rc=b->query_cursor_scoped(aggregate,std::nullopt,100,1u<<20,60000,failed);
        SqlSessionProbe::fail_scratch_after(-1);CHECK(rc==SQLITE_NOMEM && !failed);
        CancelAfter early{0,1};CHECK(b->query_cursor_scoped(aggregate,std::nullopt,100,1u<<20,60000,failed,10000,{CancelAfter::requested,&early})==SQLITE_INTERRUPT && !failed);
        CHECK(b->query_cursor_scoped(aggregate,std::nullopt,100,1u<<20,60000,failed)==SQLITE_OK && failed);
        CHECK(failed->next(1,1u<<20,page)==SQLITE_OK && page.final_page);failed.reset();
    }
    // Stop from inside native use collection, after multiple scan checkpoints.
    // The fixture contains one string use and one invoke per occurrence.
    const std::pair<const char*,const char*> scan_queries[] = {
        {"SELECT count(*) FROM dmg_string_uses", "SELECT 2"},
        {"SELECT NOT EXISTS(SELECT 1 FROM dmg_invoke_sites WHERE dex_pc=-1)", "SELECT 1"},
        {"SELECT NOT EXISTS(SELECT 1 FROM dmg_invoke_sites WHERE dex_pc=2)", "SELECT 0"}
    };
    CHECK(b->enable_profiling(true)==SQLITE_OK);
    for (const auto& [statement,oracle_sql] : scan_queries) {
        SqlScopedResult strict_saved;strict_saved.snapshot_id="preserved";strict_saved.input_count=77;
        strict_saved.rows={{{SqlValue::Kind::integer,999,{}}}};const auto prior=strict_saved;
        CancelInsideSiteScan scan;
        CHECK(b->query_scoped(statement,std::nullopt,100,1u<<20,strict_saved,10000,{CancelInsideSiteScan::requested,&scan})==SQLITE_INTERRUPT);
        CHECK(scan.checks==6 && strict_saved.rows==prior.rows && strict_saved.snapshot_id==prior.snapshot_id &&
              strict_saved.source_scope==prior.source_scope && strict_saved.input_count==prior.input_count && strict_saved.source_count==prior.source_count);
        scan={};const std::string compound=std::string("SELECT 1 UNION ALL ")+statement;
        CHECK(b->query_scoped(compound,std::nullopt,100,1u<<20,strict_saved,10000,{CancelInsideSiteScan::requested,&scan})==SQLITE_INTERRUPT && scan.checks==6);
        CHECK(strict_saved.rows==prior.rows && strict_saved.snapshot_id==prior.snapshot_id && strict_saved.input_count==prior.input_count);
        SqlQueryProfile scan_profile;CHECK(b->last_query_profile(scan_profile)==SQLITE_OK && scan_profile.execution_status==SQLITE_INTERRUPT && scan_profile.rows_staged==1 && scan_profile.rows_committed==0);
        SqlSessionProbe::fail_scratch_after(0);
        const int strict_fault=b->query_scoped(compound,std::nullopt,100,1u<<20,strict_saved);
        SqlSessionProbe::fail_scratch_after(-1);
        CHECK(strict_fault==SQLITE_NOMEM && strict_saved.rows==prior.rows && strict_saved.snapshot_id==prior.snapshot_id);
        CHECK(b->last_query_profile(scan_profile)==SQLITE_OK && scan_profile.execution_status==SQLITE_NOMEM && scan_profile.rows_staged==1 && scan_profile.rows_committed==0);
        scan={};std::unique_ptr<SqlCommittedCursor> no_cursor;
        CHECK(b->query_cursor_scoped(statement,std::nullopt,100,1u<<20,60000,no_cursor,10000,{CancelInsideSiteScan::requested,&scan})==SQLITE_INTERRUPT && !no_cursor && scan.checks==6);
        SqlSessionProbe::fail_scratch_after(0);
        const int failed_rc=b->query_cursor_scoped(statement,std::nullopt,100,1u<<20,60000,no_cursor);
        SqlSessionProbe::fail_scratch_after(-1);
        CHECK(failed_rc==SQLITE_NOMEM && !no_cursor);
        CHECK(b->query_cursor_scoped(statement,std::nullopt,100,1u<<20,60000,no_cursor)==SQLITE_OK && no_cursor);
        CHECK(no_cursor->next(4,1024,page)==SQLITE_OK && page.final_page && page.result.rows==ordinary(ordinary_db,oracle_sql));
        CHECK(page.result.source_scope==SqlScopeCoverage::declared_complete_source_scope && page.result.input_count==2 && page.result.source_count==2);
    }
    std::unique_ptr<SqlCommittedCursor> expired;CHECK(b->query_cursor_scoped("SELECT 1",std::nullopt,2,1024,1,expired)==SQLITE_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(15));const auto before_expired=page;
    CHECK(expired->next(1,1024,page)==SQLITE_ABORT && same(page,before_expired));
    CHECK(expired->next(1,1024,page)==SQLITE_MISUSE);
    std::unique_ptr<SqlCommittedCursor> expires_during;CHECK(b->query_cursor_scoped("SELECT 1",std::nullopt,2,1024,5,expires_during)==SQLITE_OK);
    CHECK(expires_during->next(1,1024,page,{delayed_not_cancelled,nullptr})==SQLITE_ABORT && same(page,before_expired));
    std::unique_ptr<SqlCommittedCursor> completed_then_expired;CHECK(b->query_cursor_scoped("SELECT 1",std::nullopt,2,1024,60000,completed_then_expired)==SQLITE_OK);
    CHECK(completed_then_expired->next(1,1024,page)==SQLITE_OK && page.final_page && page.first_row==0);
    const auto terminal_page=page;test_cursor_expire(*completed_then_expired);
    CHECK(completed_then_expired->next(1,1024,page)==SQLITE_ABORT && same(page,terminal_page));
    CHECK(completed_then_expired->next(1,1024,page)==SQLITE_MISUSE && same(page,terminal_page));
    // Optional aggregate quota accounts all simultaneously retained cursors
    // from one session; failed queries/reservations must release their slot.
    std::unique_ptr<SqlSession> quota;CHECK(SqlSession::open_scoped(two,quota)==SQLITE_OK);
    SqlCursorQuotaStats stats{9,9,9,9};CHECK(quota->cursor_quota_stats(stats)==SQLITE_NOTFOUND&&stats.live_cursors==9);
    CHECK(quota->configure_cursor_quota(0,72)==SQLITE_MISUSE&&quota->configure_cursor_quota(2,0)==SQLITE_MISUSE);
    CHECK(quota->configure_cursor_quota(2,72)==SQLITE_OK&&quota->configure_cursor_quota(2,72)==SQLITE_MISUSE);
    CHECK(quota->cursor_quota_stats(stats)==SQLITE_OK&&stats.live_cursors==0&&stats.retained_bytes==0);
    std::unique_ptr<SqlCommittedCursor> quota_interrupted;CancelInsideSiteScan quota_scan;
    CHECK(quota->query_cursor_scoped("SELECT count(*) FROM dmg_string_uses",std::nullopt,8,1024,60000,quota_interrupted,10000,{CancelInsideSiteScan::requested,&quota_scan})==SQLITE_INTERRUPT && !quota_interrupted && quota_scan.checks==6);
    CHECK(quota->cursor_quota_stats(stats)==SQLITE_OK && stats.live_cursors==0 && stats.retained_bytes==0);
    std::unique_ptr<SqlCommittedCursor> qa,qb,qc;
    CHECK(quota->query_cursor_scoped("SELECT 1 UNION ALL SELECT 2",std::nullopt,8,1024,60000,qa)==SQLITE_OK);
    CHECK(quota->cursor_quota_stats(stats)==SQLITE_OK&&stats.live_cursors==1&&stats.retained_bytes==48);
    CHECK(quota->query_cursor_scoped("SELECT 3",std::nullopt,8,1024,60000,qb)==SQLITE_OK);
    CHECK(quota->cursor_quota_stats(stats)==SQLITE_OK&&stats.live_cursors==2&&stats.retained_bytes==72);
    CHECK(quota->query_cursor_scoped("SELECT 4",std::nullopt,8,1024,60000,qc)==SQLITE_BUSY&&!qc);
    CHECK(quota->cursor_quota_stats(stats)==SQLITE_OK&&stats.live_cursors==2&&stats.retained_bytes==72);
    qa->close();qa->close();CHECK(quota->cursor_quota_stats(stats)==SQLITE_OK&&stats.live_cursors==1&&stats.retained_bytes==24);
    CHECK(quota->query_cursor_scoped("SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3",std::nullopt,8,1024,60000,qc)==SQLITE_TOOBIG&&!qc);
    CHECK(quota->cursor_quota_stats(stats)==SQLITE_OK&&stats.live_cursors==1&&stats.retained_bytes==24);
    CHECK(qb->next(1,1024,page)==SQLITE_OK&&page.final_page);
    CHECK(quota->cursor_quota_stats(stats)==SQLITE_OK&&stats.live_cursors==1&&stats.retained_bytes==24);
    qb.reset();CHECK(quota->cursor_quota_stats(stats)==SQLITE_OK&&stats.live_cursors==0&&stats.retained_bytes==0);
    CHECK(quota->query_cursor_scoped("SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3",std::nullopt,8,1024,60000,qc)==SQLITE_OK);
    CHECK(quota->cursor_quota_stats(stats)==SQLITE_OK&&stats.live_cursors==1&&stats.retained_bytes==72);
    const auto expected_quota=ordinary(ordinary_db,"SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3");
    CHECK(qc->next(3,1024,page)==SQLITE_OK&&page.final_page&&page.result.rows==expected_quota);
    test_cursor_expire(*qc);CHECK(qc->next(1,1024,page)==SQLITE_ABORT);
    CHECK(quota->cursor_quota_stats(stats)==SQLITE_OK&&stats.live_cursors==0&&stats.retained_bytes==0);
    std::unique_ptr<SqlCommittedCursor> failed_quota;
    CHECK(quota->query_cursor_scoped("SELECT zeroblob(2)",std::nullopt,8,1024,60000,failed_quota)==SQLITE_MISMATCH&&!failed_quota);
    CHECK(quota->cursor_quota_stats(stats)==SQLITE_OK&&stats.live_cursors==0&&stats.retained_bytes==0);
    CancelAfter early_quota{0,1};CHECK(quota->query_cursor_scoped("SELECT 1",std::nullopt,8,1024,60000,failed_quota,10000,{CancelAfter::requested,&early_quota})==SQLITE_INTERRUPT&&!failed_quota);
    CHECK(quota->cursor_quota_stats(stats)==SQLITE_OK&&stats.live_cursors==0&&stats.retained_bytes==0);
    CancelAfter measured_quota{0,4};CHECK(quota->query_cursor_scoped("SELECT 1",std::nullopt,8,1024,60000,failed_quota,10000,{CancelAfter::requested,&measured_quota})==SQLITE_INTERRUPT&&!failed_quota&&measured_quota.checks==4);
    CHECK(quota->cursor_quota_stats(stats)==SQLITE_OK&&stats.live_cursors==0&&stats.retained_bytes==0);
    test_cursor_create_fail(true);CHECK(quota->query_cursor_scoped("SELECT 1",std::nullopt,8,1024,60000,failed_quota)==SQLITE_NOMEM&&!failed_quota);test_cursor_create_fail(false);
    CHECK(quota->cursor_quota_stats(stats)==SQLITE_OK&&stats.live_cursors==0&&stats.retained_bytes==0);
    DelayAt deadline_quota{0,4};CHECK(quota->query_cursor_scoped("SELECT 1",std::nullopt,8,1024,10,failed_quota,10000,{DelayAt::requested,&deadline_quota})==SQLITE_ABORT&&!failed_quota&&deadline_quota.checks==4);
    CHECK(quota->cursor_quota_stats(stats)==SQLITE_OK&&stats.live_cursors==0&&stats.retained_bytes==0);
    CHECK(quota->query_cursor_scoped("SELECT 1",std::nullopt,8,1024,60000,failed_quota)==SQLITE_OK&&failed_quota);
    CHECK(quota->close()==SQLITE_OK);CHECK(failed_quota->next(1,1024,page)==SQLITE_OK&&page.final_page);failed_quota.reset();
    // Two actual DEX occurrences are compared with an independently populated
    // ordinary SQLite table; logical-byte accounting uses the returned text.
    std::unique_ptr<SqlSession> dex_quota;CHECK(SqlSession::open_scoped(two,dex_quota)==SQLITE_OK);
    CHECK(dex_quota->configure_cursor_quota(1,2048)==SQLITE_OK);
    const char* expected_dex_sql="WITH x(s,o,n) AS (VALUES(0,0,'nativeMethod'),(0,1,'quiet'),(0,2,'uses'),(0,3,'abstractMethod'),(1,0,'nativeMethod'),(1,1,'quiet'),(1,2,'uses'),(1,3,'abstractMethod')) SELECT s,o,n FROM x ORDER BY s,o";
    const auto ordinary_dex=ordinary(ordinary_db,expected_dex_sql);uint64_t expected_bytes=0;
    for(const auto& row:ordinary_dex){expected_bytes+=8+row.size()*16;for(const auto& value:row)if(value.kind==SqlValue::Kind::text)expected_bytes+=value.text.size();}
    std::unique_ptr<SqlCommittedCursor> dex_cursor;CHECK(dex_quota->query_cursor_scoped(sql,std::nullopt,100,2048,60000,dex_cursor)==SQLITE_OK);
    CHECK(dex_quota->cursor_quota_stats(stats)==SQLITE_OK&&stats.live_cursors==1&&stats.retained_bytes==expected_bytes);
    CHECK(dex_cursor->next(16,2048,page)==SQLITE_OK&&page.final_page&&page.result.rows==ordinary_dex&&page.result.source_count==2);
    dex_cursor.reset();CHECK(dex_quota->cursor_quota_stats(stats)==SQLITE_OK&&stats.live_cursors==0&&stats.retained_bytes==0);CHECK(dex_quota->close()==SQLITE_OK);
    std::unique_ptr<SqlSession> late_quota;CHECK(SqlSession::open_scoped(two,late_quota)==SQLITE_OK);
    CHECK(late_quota->query_cursor_scoped("SELECT zeroblob(2)",std::nullopt,8,1024,60000,failed_quota)==SQLITE_MISMATCH);
    CHECK(late_quota->configure_cursor_quota(1,1024)==SQLITE_MISUSE);CHECK(late_quota->close()==SQLITE_OK);
    CHECK(b->close()==SQLITE_OK);
    std::cout<<"PASS committed SQL cursor, strict failures, scoped identity and bounded pages\n";return 0;
} catch(const std::exception& e){test_cursor_create_fail(false);test_cursor_fail_after(-1);SqlSessionProbe::fail_scratch_after(-1);std::cerr<<e.what()<<'\n';return 1;} }
