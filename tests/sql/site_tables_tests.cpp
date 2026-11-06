#include "method_tables.hpp"
#include "session_probe.hpp"
#include "dexmeguviz/dexmeguviz.h"
#include "execution/budget/account.hpp"
#include "sqlite3.h"
#include <filesystem>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace dexmeguviz::desktop_sql;
#define CHECK(x) do { if (!(x)) throw std::runtime_error("check failed at line " + std::to_string(__LINE__) + ": " #x); } while (0)

static std::vector<uint8_t> load(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary); CHECK(in.good());
    return {(std::istreambuf_iterator<char>(in)), {}};
}
struct Engine {
    dmg_engine* value = nullptr;
    Engine() { dmg_error error{}; CHECK(dmg_engine_create(nullptr, &value, &error) == DMG_OK); }
    ~Engine() { if (value) dmg_engine_release(value); }
};
struct Snapshot { dmg_snapshot* value = nullptr; ~Snapshot() { if (value) dmg_snapshot_release(value); } };
static dmg_source_spec source(const std::vector<uint8_t>& bytes, const char* slot,
                              uint32_t format = DMG_INPUT_RAW_DEX, uint32_t empty = 0) {
    return {sizeof(dmg_source_spec), DMG_ABI_VERSION, format, empty, bytes.data(), bytes.size(), slot, "sql-sites", nullptr};
}
static void open_sources(dmg_engine* engine, const std::vector<dmg_source_spec>& sources, Snapshot& snapshot) {
    const dmg_source_set_options options{sizeof(dmg_source_set_options), DMG_ABI_VERSION, "sql-sites", 1, 32, 8u << 20};
    dmg_error error{};
    CHECK(dmg_snapshot_open_sources(engine, sources.data(), static_cast<uint32_t>(sources.size()), &options, &snapshot.value, &error) == DMG_OK);
}
static uint64_t owned(dmg_engine* engine) {
    dmg_engine_stats stats{}; CHECK(dmg_engine_get_stats(engine, &stats) == DMG_OK); return stats.owned_bytes;
}
struct Database {
    sqlite3* db = nullptr;
    Database() { CHECK(sqlite3_open(":memory:", &db) == SQLITE_OK); }
    ~Database() { if (db) sqlite3_close(db); }
};
static void exec(sqlite3* db, const char* sql) {
    char* error = nullptr; const int rc = sqlite3_exec(db, sql, nullptr, nullptr, &error);
    if (rc != SQLITE_OK) { std::string text = error ? error : sqlite3_errmsg(db); sqlite3_free(error); throw std::runtime_error(text); }
}
static SqlRows ordinary(sqlite3* db, const std::string& sql) {
    sqlite3_stmt* raw = nullptr; CHECK(sqlite3_prepare_v2(db, sql.c_str(), -1, &raw, nullptr) == SQLITE_OK);
    struct Finalize { sqlite3_stmt* value; ~Finalize(){ sqlite3_finalize(value); } } statement{raw};
    SqlRows rows; int rc;
    while ((rc = sqlite3_step(raw)) == SQLITE_ROW) {
        std::vector<SqlValue> row;
        for (int i=0; i<sqlite3_column_count(raw); ++i) {
            SqlValue value{}; const auto type=sqlite3_column_type(raw,i);
            if (type==SQLITE_INTEGER) { value.kind=SqlValue::Kind::integer; value.integer=sqlite3_column_int64(raw,i); }
            else if (type==SQLITE_TEXT) { value.kind=SqlValue::Kind::text; const auto* text=sqlite3_column_text(raw,i); CHECK(text); value.text.assign(reinterpret_cast<const char*>(text),static_cast<size_t>(sqlite3_column_bytes(raw,i))); }
            else CHECK(type==SQLITE_NULL);
            row.push_back(std::move(value));
        }
        rows.push_back(std::move(row));
    }
    CHECK(rc==SQLITE_DONE); return rows;
}
static SqlRows actual(SqlSession& session, const std::string& sql) {
    SqlRows rows; const auto rc=session.query(sql,std::nullopt,1000,1u<<20,rows);
    if (rc!=SQLITE_OK) throw std::runtime_error("session query failed " + std::to_string(rc) + ": " + sql);
    return rows;
}
static void replace(std::string& text, const std::string& from, const std::string& to) {
    for (size_t pos=0; (pos=text.find(from,pos))!=std::string::npos; pos+=to.size()) text.replace(pos,from.size(),to);
}
static void compare(SqlSession& session, sqlite3* db, std::string query) {
    auto control=query;
    replace(query,"$STR","dmg_string_uses"); replace(query,"$INV","dmg_invoke_sites"); replace(query,"$FIELD","dmg_field_uses");
    replace(control,"$STR","str_copy"); replace(control,"$INV","inv_copy"); replace(control,"$FIELD","field_copy");
    CHECK(actual(session,query)==ordinary(db,control));
}
static void create_oracle(sqlite3* db) {
    const char* schema="(source_index INTEGER,caller_ordinal INTEGER,caller_reference_index INTEGER,code_offset INTEGER,dex_pc INTEGER,opcode INTEGER,target_domain INTEGER,target_index INTEGER,extra_proto INTEGER)";
    for (const char* name : {"str_copy","inv_copy","field_copy"}) exec(db,(std::string("CREATE TABLE ")+name+schema).c_str());
    // Fixed fixture expectations come from the authored DEX words, not the native scanner.
    exec(db,"INSERT INTO str_copy(rowid,source_index,caller_ordinal,caller_reference_index,code_offset,dex_pc,opcode,target_domain,target_index,extra_proto) VALUES "
            "(1,0,2,3,416,0,26,0,10,NULL),(2,1,2,3,416,0,26,0,10,NULL),"
            "(3,4,2,3,416,0,26,0,10,NULL),(4,4,2,3,416,2,27,0,10,NULL)");
    exec(db,"INSERT INTO inv_copy(rowid,source_index,caller_ordinal,caller_reference_index,code_offset,dex_pc,opcode,target_domain,target_index,extra_proto) VALUES "
            "(1,0,2,3,416,2,113,2,4,NULL),(2,1,2,3,416,2,113,2,4,NULL),"
            "(3,2,2,3,416,0,113,2,4,NULL),(4,2,2,3,416,3,113,2,4,NULL),"
            "(5,5,2,3,416,0,250,3,4,0),(6,5,2,3,416,4,252,4,0,NULL)");
    exec(db,"INSERT INTO field_copy(rowid,source_index,caller_ordinal,caller_reference_index,code_offset,dex_pc,opcode,target_domain,target_index,extra_proto) VALUES "
            "(1,0,2,3,416,5,96,1,0,NULL),(2,1,2,3,416,5,96,1,0,NULL),"
            "(3,3,2,3,416,0,96,1,0,NULL),(4,3,2,3,416,2,103,1,0,NULL)");
}
struct CancelAfter {
    int checks=0;
    static bool requested(void* context) noexcept { return ++static_cast<CancelAfter*>(context)->checks>=8; }
};
struct ConcurrentCancel {
    std::atomic<bool> entered{false},cancelled{false},stop{false};
    int scan_checks=0;
    static bool requested(void* context) noexcept {
        auto& state=*static_cast<ConcurrentCancel*>(context);
        if (SqlSessionProbe::in_site_cancel_callback() && ++state.scan_checks==6) {
            state.entered.store(true,std::memory_order_release);
            while (!state.cancelled.load(std::memory_order_acquire) && !state.stop.load(std::memory_order_acquire)) std::this_thread::yield();
        }
        return state.cancelled.load(std::memory_order_acquire);
    }
};
int main(int argc,char** argv) {
    try {
        CHECK(argc==2); const std::filesystem::path fixtures=argv[1];
        auto normal=load(fixtures/"method_facts/method-uses.dex");
        auto inv=load(fixtures/"use_relations/two-invokes.dex");
        auto field=load(fixtures/"use_relations/field-read-write.dex");
        auto str=load(fixtures/"use_relations/string-normal-jumbo.dex");
        auto domains=load(fixtures/"method_facts/invoke-domains-038.dex");
        auto corrupt=load(fixtures/"use_relations/valid-then-corrupt.dex");
        auto resource=load(fixtures/"multisource/resource-only.apk");
        Engine engine;const auto baseline=owned(engine.value);
        Snapshot snap;open_sources(engine.value,{source(normal,"one"),source(normal,"duplicate"),source(inv,"invoke"),source(field,"field"),source(str,"string"),source(domains,"domains")},snap);
        std::unique_ptr<SqlSession> session; CHECK(SqlSession::open(snap.value,session)==SQLITE_OK);
        dmg_snapshot_release(snap.value);snap.value=nullptr;
        Database db; create_oracle(db.db);
        const std::vector<std::string> queries{
            "SELECT rowid,* FROM $STR ORDER BY source_index,caller_ordinal,dex_pc",
            "SELECT rowid,* FROM $INV ORDER BY source_index,caller_ordinal,dex_pc",
            "SELECT rowid,* FROM $FIELD ORDER BY source_index,caller_ordinal,dex_pc",
            "SELECT source_index,dex_pc FROM $INV WHERE target_index IN (4,4,NULL) ORDER BY source_index,dex_pc",
            "SELECT source_index,dex_pc FROM $INV WHERE extra_proto IS NULL ORDER BY source_index,dex_pc",
            "SELECT source_index,dex_pc FROM $INV WHERE target_index NOT IN (NULL,4) ORDER BY source_index,dex_pc",
            "SELECT a.source_index,a.dex_pc,b.dex_pc FROM $INV a JOIN $INV b ON a.source_index=b.source_index AND a.target_index=b.target_index ORDER BY a.source_index,a.dex_pc,b.dex_pc",
            "SELECT source_index,dex_pc FROM $STR ORDER BY source_index DESC,dex_pc DESC LIMIT 2 OFFSET 1",
            "SELECT count(*),sum(extra_proto IS NULL) FROM $INV",
            "SELECT EXISTS(SELECT 1 FROM $FIELD WHERE opcode=103),NOT EXISTS(SELECT 1 FROM $STR WHERE target_index=7)"
        };
        for (const auto& query:queries) compare(*session,db.db,query);
        const auto settled=owned(engine.value);for(int i=0;i<5;++i)CHECK(actual(*session,"SELECT count(*) FROM dmg_invoke_sites")[0][0].integer==6);
        CHECK(owned(engine.value)==settled);
        SqlRows interrupted{{SqlValue{SqlValue::Kind::text,0,"preserved"}}}; const auto saved=interrupted;
        for (const auto& sql : {"SELECT count(*) FROM dmg_string_uses",
                                "SELECT NOT EXISTS(SELECT 1 FROM dmg_invoke_sites)",
                                "SELECT * FROM dmg_field_uses LIMIT 1"}) {
            CancelAfter cancellation;
            CHECK(session->query(sql,std::nullopt,100,1u<<20,interrupted,10000,{&CancelAfter::requested,&cancellation})==SQLITE_INTERRUPT && interrupted==saved);
            CHECK(cancellation.checks==8);
        }
        ConcurrentCancel concurrent;
        std::thread signal([&] {
            const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(10);
            while (!concurrent.entered.load(std::memory_order_acquire) && !concurrent.stop.load(std::memory_order_acquire) && std::chrono::steady_clock::now()<deadline) std::this_thread::yield();
            if (concurrent.entered.load(std::memory_order_acquire)) concurrent.cancelled.store(true,std::memory_order_release);
            else concurrent.stop.store(true,std::memory_order_release);
        });
        const auto concurrent_rc=session->query("SELECT count(*) FROM dmg_string_uses",std::nullopt,100,1u<<20,interrupted,10000,{&ConcurrentCancel::requested,&concurrent});
        concurrent.stop.store(true,std::memory_order_release); signal.join();
        CHECK(concurrent.entered.load() && concurrent.scan_checks==6 && concurrent_rc==SQLITE_INTERRUPT && interrupted==saved);
        // Exercise real PMR scratch allocation failure inside each native scan.
        for (const auto& sql : {"SELECT count(*) FROM dmg_string_uses",
                                "SELECT NOT EXISTS(SELECT 1 FROM dmg_invoke_sites)",
                                "SELECT * FROM dmg_field_uses LIMIT 1"}) {
            dexmeguviz::test_fail_allocation_after(0);
            const auto rc=session->query(sql,std::nullopt,100,1u<<20,interrupted);
            dexmeguviz::test_fail_allocation_after(-1);
            CHECK(rc==SQLITE_NOMEM && interrupted==saved);
        }
        CHECK(actual(*session,"SELECT count(*) FROM dmg_invoke_sites")[0][0].integer==6);
        CHECK(owned(engine.value)==settled);
        CHECK(session->close()==SQLITE_OK);session.reset();CHECK(owned(engine.value)==baseline);

        Snapshot bad;open_sources(engine.value,{source(normal,"good"),source(corrupt,"bad")},bad);
        std::unique_ptr<SqlSession> failed;CHECK(SqlSession::open(bad.value,failed)==SQLITE_OK);
        SqlRows output{{SqlValue{SqlValue::Kind::text,0,"preserved"}}};const auto original=output;
        for (const auto* table : {"dmg_string_uses","dmg_invoke_sites","dmg_field_uses"}) {
            for (const auto& query : {std::string("SELECT count(*) FROM ")+table,
                                      std::string("SELECT NOT EXISTS(SELECT 1 FROM ")+table+")",
                                      std::string("SELECT * FROM ")+table+" LIMIT 1"}) {
                CHECK(failed->query(query,std::nullopt,100,1u<<20,output)==SQLITE_CORRUPT && output==original);
            }
        }
        CHECK(failed->close()==SQLITE_OK);failed.reset();dmg_snapshot_release(bad.value);bad.value=nullptr;CHECK(owned(engine.value)==baseline);

        Snapshot budget;open_sources(engine.value,{source(normal,"normal"),source(inv,"two")},budget);
        std::unique_ptr<SqlSession> tiny;CHECK(SqlSession::open(budget.value,tiny,{100'000'000,2})==SQLITE_OK);
        CHECK(tiny->query("SELECT count(*) FROM dmg_invoke_sites",std::nullopt,100,1u<<20,output)==SQLITE_TOOBIG && output==original);
        CHECK(tiny->close()==SQLITE_OK);tiny.reset();
        CHECK(SqlSession::open(budget.value,tiny,{1,100})==SQLITE_OK);
        CHECK(tiny->query("SELECT * FROM dmg_string_uses LIMIT 1",std::nullopt,100,1u<<20,output)==SQLITE_TOOBIG && output==original);
        CHECK(tiny->close()==SQLITE_OK);tiny.reset();
        CHECK(SqlSession::open(budget.value,tiny,{0,100})==SQLITE_MISUSE && !tiny);
        // Two input rows force two complete scans of the inner site table.
        const std::string repeated="SELECT count(*) FROM dmg_inputs CROSS JOIN dmg_string_uses";
        const std::string mixed="SELECT count(*) FROM dmg_string_uses CROSS JOIN dmg_invoke_sites";
        CHECK(SqlSession::open(budget.value,tiny,{100'000'000,100'000,0,1})==SQLITE_OK);
        CHECK(tiny->query(repeated,std::nullopt,100,1u<<20,output)==SQLITE_TOOBIG && output==original);
        CHECK(tiny->query("SELECT NOT EXISTS(SELECT 1 FROM dmg_inputs CROSS JOIN dmg_string_uses WHERE dex_pc=-1)",std::nullopt,100,1u<<20,output)==SQLITE_TOOBIG && output==original);
        CHECK(actual(*tiny,"SELECT count(*) FROM dmg_string_uses")[0][0].integer==1);
        CHECK(actual(*tiny,"SELECT count(*) FROM dmg_string_uses WHERE 0")[0][0].integer==0);
        CHECK(tiny->close()==SQLITE_OK);tiny.reset();
        CHECK(SqlSession::open(budget.value,tiny,{100'000'000,100'000,100'000,2})==SQLITE_OK);
        CHECK(actual(*tiny,repeated)==ordinary(db.db,"SELECT count(*) FROM (SELECT 0 UNION ALL SELECT 1) CROSS JOIN str_copy WHERE source_index=0"));
        CHECK(tiny->query(mixed,std::nullopt,100,1u<<20,output)==SQLITE_TOOBIG && output==original);
        CancelAfter budget_cancel;
        CHECK(tiny->query(repeated,std::nullopt,100,1u<<20,output,10000,{&CancelAfter::requested,&budget_cancel})==SQLITE_INTERRUPT && output==original);
        CHECK(budget_cancel.checks==8);
        CHECK(actual(*tiny,repeated)[0][0].integer==2);
        dexmeguviz::test_fail_allocation_after(0);
        const auto budget_alloc_rc=tiny->query(repeated,std::nullopt,100,1u<<20,output);
        dexmeguviz::test_fail_allocation_after(-1);
        CHECK(budget_alloc_rc==SQLITE_NOMEM && output==original);
        CHECK(actual(*tiny,repeated)[0][0].integer==2);
        CHECK(tiny->close()==SQLITE_OK);tiny.reset();
        CHECK(SqlSession::open(budget.value,tiny,{100'000'000,100'000,0,4})==SQLITE_OK);
        CHECK(actual(*tiny,mixed)==ordinary(db.db,"SELECT count(*) FROM str_copy a CROSS JOIN inv_copy b WHERE a.source_index=0 AND b.source_index IN (0,2)"));
        CHECK(tiny->close()==SQLITE_OK);tiny.reset();
        // Determine the actual minimum work for this fixed single-scan input,
        // then check its exact cumulative boundary with two forced scans.
        uint64_t low=1,high=100000;
        while (low<high) {
            const uint64_t mid=low+(high-low)/2;
            CHECK(SqlSession::open(budget.value,tiny,{100'000'000,100'000,mid,0})==SQLITE_OK);
            SqlRows probe=original;
            const int rc=tiny->query("SELECT count(*) FROM dmg_string_uses",std::nullopt,100,1u<<20,probe);
            CHECK(rc==SQLITE_OK || (rc==SQLITE_TOOBIG && probe==original));
            if (rc==SQLITE_OK) high=mid; else low=mid+1;
            CHECK(tiny->close()==SQLITE_OK);tiny.reset();
        }
        CHECK(low>1 && low<100000);
        CHECK(SqlSession::open(budget.value,tiny,{100'000'000,100'000,2*low-1,0})==SQLITE_OK);
        CHECK(tiny->query(repeated,std::nullopt,100,1u<<20,output)==SQLITE_TOOBIG && output==original);
        CHECK(actual(*tiny,"SELECT count(*) FROM dmg_string_uses")[0][0].integer==1);
        CHECK(tiny->close()==SQLITE_OK);tiny.reset();
        CHECK(SqlSession::open(budget.value,tiny,{100'000'000,100'000,2*low,0})==SQLITE_OK);
        CHECK(actual(*tiny,repeated)[0][0].integer==2);
        CHECK(tiny->close()==SQLITE_OK);tiny.reset();
        CHECK(SqlSession::open(budget.value,tiny,{100'000'000,100'000,100'000'001,0})==SQLITE_MISUSE && !tiny);
        CHECK(SqlSession::open_scoped(budget.value,tiny,{100'000'000,100'000,0,1})==SQLITE_OK);
        SqlScopedResult scoped;scoped.snapshot_id="preserved";scoped.rows=original;
        CHECK(tiny->query_scoped(repeated,std::nullopt,100,1u<<20,scoped)==SQLITE_TOOBIG && scoped.snapshot_id=="preserved" && scoped.rows==original);
        CHECK(tiny->query_scoped("SELECT count(*) FROM dmg_string_uses",std::nullopt,100,1u<<20,scoped)==SQLITE_OK && scoped.rows[0][0].integer==1);
        CHECK(tiny->close()==SQLITE_OK);tiny.reset();
        dmg_snapshot_release(budget.value);budget.value=nullptr;CHECK(owned(engine.value)==baseline);

        Snapshot empty;open_sources(engine.value,{source(resource,"resource",DMG_INPUT_APK,1)},empty);
        std::unique_ptr<SqlSession> empty_session;CHECK(SqlSession::open(empty.value,empty_session)==SQLITE_OK);
        CHECK(actual(*empty_session,"SELECT count(*) FROM dmg_string_uses")[0][0].integer==0);
        CHECK(actual(*empty_session,"SELECT count(*) FROM dmg_invoke_sites")[0][0].integer==0);
        CHECK(actual(*empty_session,"SELECT count(*) FROM dmg_field_uses")[0][0].integer==0);
        CHECK(empty_session->close()==SQLITE_OK);empty_session.reset();dmg_snapshot_release(empty.value);empty.value=nullptr;
        CHECK(owned(engine.value)==baseline);
        std::cout<<"PASS "<<queries.size()<<" site materialized comparisons, corruption and budget atomicity\n";return 0;
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n';return 1; }
}
