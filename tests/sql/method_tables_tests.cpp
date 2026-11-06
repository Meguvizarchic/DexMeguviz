#include "method_tables.hpp"
#include "session_probe.hpp"
#include "dexmeguviz/dexmeguviz.h"
#include "sqlite3.h"

#include <filesystem>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace dexmeguviz::desktop_sql;
#define CHECK(x) do { if (!(x)) throw std::runtime_error("check failed at line " + std::to_string(__LINE__) + ": " #x); } while (0)

static sqlite3_vfs* original_vfs = nullptr;
static int refused_temp_opens = 0;
static int tracking_open(sqlite3_vfs*, const char* name, sqlite3_file* file, int flags, int* output) {
    constexpr int temp_flags = SQLITE_OPEN_TEMP_DB | SQLITE_OPEN_TEMP_JOURNAL |
                               SQLITE_OPEN_TRANSIENT_DB | SQLITE_OPEN_SUBJOURNAL |
                               SQLITE_OPEN_DELETEONCLOSE;
    if (!name || (flags & temp_flags)) { ++refused_temp_opens; return SQLITE_CANTOPEN; }
    return original_vfs->xOpen(original_vfs, name, file, flags, output);
}

struct Database {
    sqlite3* db = nullptr;
    Database() { CHECK(sqlite3_open(":memory:", &db) == SQLITE_OK); }
    ~Database() { if (db) sqlite3_close(db); }
};
struct Statement {
    sqlite3_stmt* stmt = nullptr;
    Statement(sqlite3* db, const std::string& sql) {
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
            throw std::runtime_error("prepare failed: " + sql + ": " + sqlite3_errmsg(db));
    }
    ~Statement() { sqlite3_finalize(stmt); }
};
static void exec(sqlite3* db, const char* sql) {
    char* error = nullptr;
    const auto rc = sqlite3_exec(db, sql, nullptr, nullptr, &error);
    if (rc != SQLITE_OK) {
        std::string message = error ? error : sqlite3_errmsg(db);
        sqlite3_free(error);
        throw std::runtime_error(message + ": " + sql);
    }
}
static std::vector<uint8_t> load(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary); CHECK(in.good());
    return {(std::istreambuf_iterator<char>(in)), {}};
}
struct Engine {
    dmg_engine* value = nullptr;
    Engine() { dmg_error error{}; CHECK(dmg_engine_create(nullptr, &value, &error) == DMG_OK); }
    ~Engine() { if (value) dmg_engine_release(value); }
};
struct Snapshot {
    dmg_snapshot* value = nullptr;
    ~Snapshot() { if (value) dmg_snapshot_release(value); }
};
struct LeaseCounts {
    uint32_t retained = 0, released = 0;
    bool* close_returned = nullptr;
    bool released_after_close = false;
    static void retain(void* p) { ++static_cast<LeaseCounts*>(p)->retained; }
    static void release(void* p) {
        auto& self = *static_cast<LeaseCounts*>(p);
        ++self.released;
        self.released_after_close = self.close_returned && *self.close_returned;
    }
};
static dmg_source_spec source(const std::vector<uint8_t>& bytes, const char* slot,
                              uint32_t format = DMG_INPUT_RAW_DEX, uint32_t allow_empty = 0) {
    return {sizeof(dmg_source_spec), DMG_ABI_VERSION, format, allow_empty, bytes.data(), bytes.size(), slot, "source", nullptr};
}
static void open_sources(dmg_engine* engine, const std::vector<dmg_source_spec>& sources,
                         uint32_t complete, Snapshot& snapshot) {
    const dmg_source_set_options options{sizeof(dmg_source_set_options), DMG_ABI_VERSION, "sql-prototype", complete, 32, 8u << 20};
    dmg_error error{};
    CHECK(dmg_snapshot_open_sources(engine, sources.data(), static_cast<uint32_t>(sources.size()), &options, &snapshot.value, &error) == DMG_OK);
}
static uint64_t owned(dmg_engine* engine) {
    dmg_engine_stats stats{}; CHECK(dmg_engine_get_stats(engine, &stats) == DMG_OK); return stats.owned_bytes;
}
using Result = std::vector<std::vector<std::string>>;
static Result query(sqlite3* db, const std::string& sql, const char* parameter = nullptr) {
    Statement statement(db, sql);
    if (parameter) CHECK(sqlite3_bind_text(statement.stmt, 1, parameter, -1, SQLITE_TRANSIENT) == SQLITE_OK);
    Result result;
    int rc;
    while ((rc = sqlite3_step(statement.stmt)) == SQLITE_ROW) {
        std::vector<std::string> row;
        for (int i = 0; i < sqlite3_column_count(statement.stmt); ++i) {
            const auto type = sqlite3_column_type(statement.stmt, i);
            if (type == SQLITE_NULL) row.emplace_back("N");
            else if (type == SQLITE_INTEGER) row.push_back("I" + std::to_string(sqlite3_column_int64(statement.stmt, i)));
            else if (type == SQLITE_TEXT) {
                const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(statement.stmt, i));
                const auto length = sqlite3_column_bytes(statement.stmt, i);
                CHECK(text != nullptr);
                row.push_back("T" + std::string(text, static_cast<size_t>(length)));
            } else throw std::runtime_error("unexpected result type");
        }
        result.push_back(std::move(row));
    }
    if (rc != SQLITE_DONE) throw std::runtime_error("step failed: " + sql + ": " + sqlite3_errmsg(db));
    return result;
}
static void materialize(sqlite3* db) {
    exec(db, "CREATE TABLE ref_copy(source_index INTEGER, ordinal INTEGER, reference_index INTEGER, definition_ordinal INTEGER, owner TEXT, name TEXT, prototype TEXT, access_flags INTEGER, declaration_offset INTEGER, code_offset INTEGER)");
    exec(db, "CREATE TABLE def_copy(source_index INTEGER, ordinal INTEGER, reference_index INTEGER, definition_ordinal INTEGER, owner TEXT, name TEXT, prototype TEXT, access_flags INTEGER, declaration_offset INTEGER, code_offset INTEGER)");
    // Authored from the pinned generator model, not native reader output.
    for (int source : {0, 1}) {
        const auto id = std::to_string(source);
        const auto row = [source](int ordinal) { return std::to_string(int64_t(source) * 4294967296LL + ordinal); };
        exec(db, ("INSERT INTO ref_copy(rowid,source_index,ordinal,reference_index,definition_ordinal,owner,name,prototype,access_flags,declaration_offset,code_offset) VALUES (" + row(0) + "," + id + ",0,0,NULL,'Ljava/lang/Object;','external','()V',NULL,NULL,NULL),"
                  "(" + row(1) + "," + id + ",1,1,1,'Lsample/Example;','locate','()V',1025,330,NULL),"
                  "(" + row(2) + "," + id + ",2,2,0,'Lsample/Example;','second','()V',265,326,NULL)").c_str());
        exec(db, ("INSERT INTO def_copy(rowid,source_index,ordinal,reference_index,definition_ordinal,owner,name,prototype,access_flags,declaration_offset,code_offset) VALUES (" + row(0) + "," + id + ",0,2,0,'Lsample/Example;','second','()V',265,326,NULL),"
                  "(" + row(1) + "," + id + ",1,1,1,'Lsample/Example;','locate','()V',1025,330,NULL)").c_str());
    }
    exec(db, "INSERT INTO ref_copy(rowid,source_index,ordinal,reference_index,definition_ordinal,owner,name,prototype,access_flags,declaration_offset,code_offset) VALUES (8589934592,2,0,0,0,'Lq03/Subject;','quiet','()V',9,456,NULL),(8589934593,2,1,1,1,'Lq03/Subject;','uses','()V',9,460,NULL)");
    exec(db, "INSERT INTO def_copy(rowid,source_index,ordinal,reference_index,definition_ordinal,owner,name,prototype,access_flags,declaration_offset,code_offset) VALUES (8589934592,2,0,0,0,'Lq03/Subject;','quiet','()V',9,456,408),(8589934593,2,1,1,1,'Lq03/Subject;','uses','()V',9,460,428)");
    exec(db, "CREATE TABLE filters(value TEXT); INSERT INTO filters VALUES ('locate'),('locate'),(NULL),('uses')");
}
static Result session_query(SqlSession& session, const std::string& sql, const char* parameter = nullptr) {
    SqlRows rows;
    const auto input = parameter ? std::optional<std::string_view>(parameter) : std::nullopt;
    const int rc = session.query(sql, input, 1000, 1u << 20, rows);
    if (rc != SQLITE_OK) throw std::runtime_error("session query failed " + std::to_string(rc) + ": " + sql);
    Result result;
    for (const auto& row : rows) {
        std::vector<std::string> values;
        for (const auto& value : row) {
            if (value.kind == SqlValue::Kind::null) values.emplace_back("N");
            else if (value.kind == SqlValue::Kind::integer) values.push_back("I" + std::to_string(value.integer));
            else values.push_back("T" + value.text);
        }
        result.push_back(std::move(values));
    }
    return result;
}
static void equivalent(SqlSession& session, sqlite3* db, const std::string& templ, const char* parameter = nullptr) {
    auto virtual_sql = templ, material_sql = templ;
    auto substitute = [](std::string& sql, const std::string& old, const std::string& replacement) {
        for (size_t p = 0; (p = sql.find(old, p)) != std::string::npos; p += replacement.size()) sql.replace(p, old.size(), replacement);
    };
    substitute(virtual_sql, "$REF", "dmg_method_refs"); substitute(virtual_sql, "$DEF", "dmg_method_defs");
    substitute(material_sql, "$REF", "ref_copy"); substitute(material_sql, "$DEF", "def_copy");
    const auto a = session_query(session, virtual_sql, parameter), b = query(db, material_sql, parameter);
    if (a != b) throw std::runtime_error("virtual/materialized mismatch: " + templ);
}
int main(int argc, char** argv) {
    try {
        CHECK(argc == 5);
        struct LogProbe { int sentinel_hits = 0; } log;
        LogProbe private_log;
        CHECK(SqlSessionProbe::configure_private_log(
            +[](void* context, int code, const char* message) noexcept {
                if (code == 12345 && message && std::strcmp(message, "dmg-test-sentinel") == 0)
                    ++static_cast<LogProbe*>(context)->sentinel_hits;
            }, &private_log) == SQLITE_OK);
        CHECK(sqlite3_config(SQLITE_CONFIG_LOG,
            +[](void* context, int code, const char* message) noexcept {
                if (code == 12345 && message && std::strcmp(message, "dmg-test-sentinel") == 0)
                    ++static_cast<LogProbe*>(context)->sentinel_hits;
            }, &log) == SQLITE_OK);
        CHECK(std::string(sqlite3_libversion()) == "3.54.1");
        CHECK(sqlite3_compileoption_used("TEMP_STORE=3") != 0);
        original_vfs = sqlite3_vfs_find(nullptr);
        CHECK(original_vfs != nullptr);
        sqlite3_vfs tracking = *original_vfs;
        tracking.zName = "dmg-test-no-temp";
        tracking.xOpen = tracking_open;
        tracking.pNext = nullptr;
        CHECK(sqlite3_vfs_register(&tracking, 1) == SQLITE_OK);
        struct VfsGuard {
            sqlite3_vfs* value;
            ~VfsGuard() { sqlite3_vfs_unregister(value); }
        } vfs_guard{&tracking};
        CHECK(tracking_open(&tracking, nullptr, nullptr, SQLITE_OPEN_TEMP_DB, nullptr) == SQLITE_CANTOPEN);
        CHECK(refused_temp_opens == 1);
        refused_temp_opens = 0;
        auto a = load(argv[1]); auto b = load(argv[2]); auto resource_apk = load(argv[3]); auto fields = load(argv[4]);
        Engine engine;
        const auto baseline = owned(engine.value);
        Snapshot input;
        open_sources(engine.value, {source(a, "base"), source(a, "split"), source(b, "other")}, 1, input);
        dmg_snapshot_overview overview{};
        CHECK(dmg_snapshot_get_overview(input.value, &overview) == DMG_OK && overview.scope_complete == 1 && overview.source_count == 3);
        dmg_source_info first{}, second{};
        CHECK(dmg_snapshot_get_source_info(input.value, 0, &first) == DMG_OK && dmg_snapshot_get_source_info(input.value, 1, &second) == DMG_OK);
        CHECK(std::string(first.dex.content_id) == second.dex.content_id && std::string(first.dex.occurrence_id) != second.dex.occurrence_id);
        std::unique_ptr<SqlSession> session;
        CHECK(SqlSession::open(input.value, session) == SQLITE_OK);
        std::unique_ptr<SqlSession> planned;
        CHECK(SqlSession::open_planned(input.value, planned, {}, {true}) == SQLITE_OK);
        std::unique_ptr<SqlSession> in_planned, invalid_planning, scoped_rowid;
        CHECK(SqlSession::open_scoped_planned(input.value, scoped_rowid, {}, {true,true}) == SQLITE_OK);
        CHECK(SqlSession::open_planned(input.value, invalid_planning, {}, {false, true}) == SQLITE_MISUSE && !invalid_planning);
        CHECK(SqlSession::open_planned(input.value, in_planned, {}, {true, true}) == SQLITE_OK);
        CHECK(SqlSessionProbe::emit_private_log(*session) == SQLITE_OK && private_log.sentinel_hits == 1);
        // Existing SQL modules retain the immutable Engine-owned Dataset after the Snapshot closes.
        dmg_snapshot_close(input.value);
        std::unique_ptr<SqlSession> closed_snapshot;
        CHECK(SqlSession::open(input.value, closed_snapshot) == SQLITE_MISUSE && !closed_snapshot);
        dmg_snapshot_release(input.value); input.value = nullptr;
        CHECK(owned(engine.value) > baseline);
        Database oracle;
        exec(oracle.db, "SELECT sqlite_log(12345,'dmg-test-sentinel')");
        CHECK(log.sentinel_hits == 1);
        materialize(oracle.db);
        const std::vector<std::string> statements{
            "SELECT * FROM $REF ORDER BY source_index,ordinal",
            "SELECT * FROM $DEF ORDER BY source_index,ordinal",
            "SELECT rowid,source_index,ordinal FROM $REF ORDER BY source_index,ordinal",
            "SELECT source_index,name FROM $REF WHERE name IN ('locate','locate',NULL) ORDER BY source_index,name",
            "SELECT source_index,name FROM $REF WHERE name IN (SELECT name FROM $DEF WHERE name IN ('locate','uses') UNION ALL SELECT NULL) ORDER BY source_index,name",
            "SELECT source_index,name FROM $REF WHERE name LIKE 'loc%' ORDER BY source_index,name",
            "SELECT source_index,name FROM $REF WHERE access_flags IS NULL ORDER BY source_index,name",
            "SELECT source_index,name FROM $REF WHERE name NOT IN (NULL,'locate') ORDER BY source_index,name",
            "SELECT r.source_index,r.name,d.ordinal FROM $REF r LEFT JOIN $DEF d ON r.source_index=d.source_index AND r.reference_index=d.reference_index ORDER BY r.source_index,r.ordinal",
            "SELECT a.source_index,b.source_index,a.name FROM $REF a JOIN $REF b ON a.name=b.name ORDER BY a.source_index,b.source_index,a.name",
            "SELECT source_index,name FROM $REF WHERE owner LIKE 'L%' ORDER BY name DESC,source_index DESC LIMIT 3 OFFSET 1",
            "SELECT name FROM $REF WHERE source_index=0 UNION ALL SELECT name FROM $REF WHERE source_index=1 ORDER BY name",
            "SELECT count(*),count(DISTINCT name),sum(access_flags IS NULL) FROM $REF",
            "SELECT EXISTS(SELECT 1 FROM $REF WHERE name='external'),NOT EXISTS(SELECT 1 FROM $DEF WHERE name='external')",
            "SELECT source_index,name FROM $REF WHERE name=?1 ORDER BY source_index"
        };
        for (size_t i = 0; i < statements.size(); ++i) equivalent(*session, oracle.db, statements[i], i + 1 == statements.size() ? "locate" : nullptr);
        for (size_t i = 0; i < statements.size(); ++i) equivalent(*planned, oracle.db, statements[i], i + 1 == statements.size() ? "locate" : nullptr);
        for (size_t i = 0; i < statements.size(); ++i) equivalent(*in_planned, oracle.db, statements[i], i + 1 == statements.size() ? "locate" : nullptr);
        // The ordinary tables above are authored from the fixture model. Keep
        // ordering deterministic and compare bag multiplicity without deduping.
        const std::vector<std::string> acceptance_queries{
            "SELECT source_index,ordinal FROM $REF WHERE source_index IN () ORDER BY 1,2",
            "SELECT source_index,ordinal FROM $REF WHERE source_index IN (SELECT ordinal FROM $DEF WHERE ordinal<0) ORDER BY 1,2",
            "SELECT source_index,ordinal FROM $REF WHERE source_index IN (SELECT source_index FROM $DEF WHERE ordinal=0 UNION ALL SELECT NULL UNION ALL SELECT 0) ORDER BY 1,2",
            "SELECT a.source_index,a.ordinal,b.ordinal FROM $REF a CROSS JOIN $DEF b ON a.source_index=b.source_index WHERE b.ordinal=0 ORDER BY 1,2,3",
            "SELECT a.source_index,a.ordinal,b.source_index,b.ordinal FROM $REF a JOIN $REF b ON a.name=b.name WHERE a.source_index IN (0,1) ORDER BY 1,2,3,4",
            "SELECT source_index,ordinal,name FROM $REF WHERE source_index=0 UNION ALL SELECT source_index,ordinal,name FROM $REF WHERE source_index IN (0,1) ORDER BY 1,2,3",
            "SELECT r.source_index,r.ordinal,d.ordinal FROM $REF r LEFT JOIN $DEF d ON r.source_index=d.source_index AND r.reference_index=d.reference_index WHERE d.ordinal IS NULL ORDER BY 1,2",
            "SELECT r.source_index,r.ordinal,d.ordinal FROM $REF r LEFT JOIN $DEF d ON r.source_index=d.source_index AND r.reference_index=d.reference_index WHERE d.ordinal=0 ORDER BY 1,2",
            "SELECT source_index,ordinal,access_flags FROM $REF ORDER BY access_flags ASC,name DESC,source_index DESC,ordinal ASC LIMIT 5 OFFSET 1",
            "SELECT source_index,ordinal,access_flags FROM $REF ORDER BY access_flags DESC,name ASC,source_index ASC,ordinal DESC LIMIT 5 OFFSET 1",
            "SELECT DISTINCT r.name FROM $REF r JOIN $DEF d ON r.source_index=d.source_index WHERE r.ordinal IN (0,1,2) AND d.ordinal=0 ORDER BY r.name DESC LIMIT 2 OFFSET 1",
            "SELECT source_index,ordinal,owner FROM $REF WHERE owner='Lsample/Example;' ORDER BY 1,2",
            "SELECT source_index,ordinal,owner FROM $REF WHERE source_index=0 AND ordinal=1 AND owner='Lsample/Example;' ORDER BY 1,2"
        };
        for (const auto& sql : acceptance_queries) {
            equivalent(*session, oracle.db, sql); equivalent(*planned, oracle.db, sql); equivalent(*in_planned, oracle.db, sql);
        }
        CHECK(query(oracle.db,"SELECT count(*) FROM ref_copy WHERE owner='Lsample/Example;'")[0][0]=="I4");
        CHECK(query(oracle.db,"SELECT count(*) FROM ref_copy a JOIN ref_copy b ON a.name=b.name")[0][0]=="I14");
        CHECK(query(oracle.db,"SELECT count(*) FROM ref_copy r LEFT JOIN def_copy d ON r.source_index=d.source_index AND r.reference_index=d.reference_index WHERE d.ordinal IS NULL")[0][0]=="I2");
        // CROSS JOIN fixes loop order: a cannot use b's not-yet-available key.
        const auto join_plan=session_query(*planned,"EXPLAIN QUERY PLAN SELECT a.source_index,a.ordinal,b.ordinal FROM dmg_method_refs a CROSS JOIN dmg_method_defs b ON a.source_index=b.source_index WHERE b.ordinal=0 ORDER BY 1,2,3");
        bool first_unconstrained=false, second_keyed=false;
        for (const auto& row : join_plan) if (row.size()>3) {
            if (row[3].find("SCAN a VIRTUAL TABLE INDEX 0:")!=std::string::npos) first_unconstrained=true;
            if (row[3].find("SCAN b VIRTUAL TABLE INDEX 3:")!=std::string::npos) second_keyed=true;
        }
        CHECK(first_unconstrained && second_keyed);
        // ID-only projection never converts text; SELECT * really reads it.
        SqlSessionProbe::fail_utf8_after(0);
        equivalent(*planned,oracle.db,"SELECT rowid,ordinal FROM $REF WHERE source_index=0 AND ordinal=1");
        CHECK(SqlSessionProbe::utf8_allocations()==0 && SqlSessionProbe::utf8_conversions()==0);
        SqlSessionProbe::fail_utf8_after(-1);
        equivalent(*planned,oracle.db,"SELECT * FROM $REF WHERE source_index=0 AND ordinal=1");
        CHECK(SqlSessionProbe::utf8_conversions()>0);
        SqlSessionProbe::fail_utf8_after(-1);
        // Rowid is a source/ordinal composite. SQLite retains every residual;
        // numeric/text/NULL/IN behavior is compared to an independent table.
        for (const char* predicate : {"rowid=0", "rowid=1", "rowid=4294967296", "rowid=8589934593",
             "rowid=12884901888", "rowid=4294967295", "rowid=9223372036854775807", "rowid=-1",
             "rowid=0.5", "rowid=1.0", "rowid='1'", "rowid='1.0'", "rowid='1e0'", "rowid='9223372036854775808'", "rowid=9223372036854775808", "rowid=-9223372036854775809", "rowid='not a number'", "rowid=X'31'", "rowid=NULL",
             "rowid IN (0,0,4294967296,NULL)", "rowid IN (SELECT rowid FROM $DEF UNION ALL SELECT NULL)",
             "rowid=0 AND source_index=1", "rowid=0 AND ordinal=1", "rowid=0 AND rowid=1", "rowid=?1"}) {
            const std::string sql=std::string("SELECT rowid,source_index,ordinal,name FROM $REF WHERE ")+predicate+" ORDER BY rowid";
            const char* parameter=std::strstr(predicate,"?1")?"1":nullptr;
            equivalent(*session,oracle.db,sql,parameter);equivalent(*planned,oracle.db,sql,parameter);equivalent(*in_planned,oracle.db,sql,parameter);
        }
        for (const char* sql : {
             "SELECT a.rowid,b.rowid FROM $REF a LEFT JOIN $DEF b ON b.rowid=a.rowid ORDER BY 1,2",
             "SELECT a.rowid,b.rowid FROM $DEF b CROSS JOIN $REF a WHERE a.rowid=b.rowid ORDER BY 1,2",
             "SELECT DISTINCT a.name FROM $REF a JOIN $DEF b ON b.rowid=a.rowid WHERE a.rowid IN (0,1,4294967296,NULL) ORDER BY 1 LIMIT 2 OFFSET 1"}) {
            equivalent(*planned,oracle.db,sql);equivalent(*in_planned,oracle.db,sql);
        }
        SqlSessionProbe::reset_identity_filter_metrics();
        equivalent(*planned,oracle.db,"SELECT rowid,name FROM $REF WHERE rowid=4294967296");
        CHECK(SqlSessionProbe::identity_rowid_filter_count()>=1);
        SqlSessionProbe::reset_identity_filter_metrics();
        equivalent(*session,oracle.db,"SELECT rowid,name FROM $REF WHERE rowid=4294967296");
        CHECK(SqlSessionProbe::identity_rowid_filter_count()==0);
        for (const char* table : {"dmg_method_refs", "dmg_method_defs", "dmg_field_refs", "dmg_field_defs",
                                  "dmg_type_refs", "dmg_class_defs", "dmg_string_values"}) {
            for (const char* predicate : {"rowid=0", "rowid=4294967296", "rowid=-1", "rowid=1.0", "rowid='1'", "rowid=NULL", "rowid IN (0,0,4294967296,NULL)"}) {
                const std::string sql=std::string("SELECT rowid,source_index,ordinal FROM ")+table+" WHERE "+predicate+" ORDER BY rowid";
                CHECK(session_query(*planned,sql)==session_query(*session,sql));CHECK(session_query(*in_planned,sql)==session_query(*session,sql));
            }
        }
        const SqlParameter boundRowid{SqlParameter::Kind::integer,4294967296LL,{}};
        SqlScopedResult boundResult;
        SqlSessionProbe::reset_identity_filter_metrics();
        CHECK(scoped_rowid->query_scoped_bound("SELECT rowid,source_index,ordinal FROM dmg_method_refs WHERE rowid=?1",std::span(&boundRowid,1),10,1024,boundResult)==SQLITE_OK);
        CHECK(boundResult.rows.size()==1 && boundResult.rows[0].size()==3 && boundResult.rows[0][0].integer==4294967296LL &&
              boundResult.rows[0][1].integer==1 && boundResult.rows[0][2].integer==0 && SqlSessionProbe::identity_rowid_filter_count()>=1);
        const SqlParameter boundNull{SqlParameter::Kind::null,0,{}};
        CHECK(scoped_rowid->query_scoped_bound("SELECT rowid FROM dmg_method_refs WHERE rowid=?1",std::span(&boundNull,1),10,1024,boundResult)==SQLITE_OK && boundResult.rows.empty());
        CHECK(scoped_rowid->close()==SQLITE_OK);
        // Use more than 32 IN constraints so SQLite sends rowid values one at
        // a time, then check that repeated cursor probes match the SQL oracle.
        std::string rowidMany=" WHERE ";
        for(int i=1;i<=33;++i)rowidMany+="reference_index>=-"+std::to_string(i)+" AND ";
        rowidMany+="rowid IN (0,4294967296,4294967296,NULL) ORDER BY rowid";
        SqlSessionProbe::reset_identity_filter_metrics();
        equivalent(*planned,oracle.db,"SELECT rowid,source_index,ordinal FROM $REF"+rowidMany);
        CHECK(SqlSessionProbe::identity_rowid_filter_count()>=2);
        SqlRows rowidSaved{{SqlValue{SqlValue::Kind::text,0,"preserved"}}};const auto rowidBefore=rowidSaved;
        SqlCancel cancelled{+[](void*) noexcept{return true;},nullptr};
        CHECK(planned->query("SELECT name FROM dmg_method_refs WHERE rowid=0",std::nullopt,10,1024,rowidSaved,10000,cancelled)==SQLITE_INTERRUPT && rowidSaved==rowidBefore);
        CHECK(planned->query("SELECT name FROM dmg_method_refs WHERE rowid=0",std::nullopt,10,16,rowidSaved)==SQLITE_TOOBIG && rowidSaved==rowidBefore);
        // Test actual all-at-once source and ordinal paths against independent
        // ordinary SQLite tables.  IN is a set predicate even when its RHS
        // contains duplicates; joining still retains each source occurrence.
        for (const char* predicate : {
                "source_index IN (0,1,1,NULL)", "ordinal IN (0,0,1,NULL)",
                "source_index IN (0,2,NULL) AND ordinal IN (0,1,1,NULL)",
                "source_index IN (NULL,-1,9223372036854775807)",
                "ordinal IN (NULL,-1,4294967295)",
                "source_index IN (0,'1',1.0,NULL)", "ordinal IN (0,'1',1.0,NULL)",
                "source_index IN (SELECT source_index FROM $DEF UNION ALL SELECT NULL)",
                "source_index IN (?1,0,NULL)"}) {
            const std::string sql=std::string("SELECT rowid,source_index,ordinal FROM $REF WHERE ")+predicate+" ORDER BY source_index,ordinal";
            SqlSessionProbe::reset_identity_filter_metrics();
            equivalent(*in_planned,oracle.db,sql,std::strstr(predicate,"?1") ? "1" : nullptr);
            CHECK(SqlSessionProbe::identity_in_filter_count() >= 1);
        }
        equivalent(*in_planned,oracle.db,"SELECT a.source_index,a.ordinal,b.ordinal FROM $REF a JOIN $DEF b ON a.source_index=b.source_index WHERE a.source_index IN (0,1,1,NULL) AND b.ordinal IN (0,1,1,NULL) ORDER BY 1,2,3");
        SqlSessionProbe::reset_identity_filter_metrics();
        equivalent(*in_planned,oracle.db,"SELECT rowid,source_index,ordinal FROM $REF WHERE source_index IN (0,1) AND ordinal IN (0,1) ORDER BY 1");
        CHECK(SqlSessionProbe::identity_in_filter_count() == 2);
        SqlSessionProbe::reset_identity_filter_metrics();
        equivalent(*in_planned,oracle.db,"SELECT rowid,source_index,ordinal FROM $REF WHERE source_index IN (0,X'31') ORDER BY 1");
        CHECK(SqlSessionProbe::identity_in_filter_count() >= 1 && SqlSessionProbe::identity_in_fallback_count() >= 1);
        // Exceed the 4096-element bound with distinct values and require a
        // fallback scan, without assuming an RSS or SQLite prepare bound.
        std::string large_in="SELECT count(*) FROM $REF WHERE source_index IN (";
        for (int i=0;i<4100;++i) { if (i) large_in+=','; large_in+=std::to_string(i); }
        large_in+=')';
        SqlSessionProbe::reset_identity_filter_metrics();
        equivalent(*in_planned,oracle.db,large_in);
        CHECK(SqlSessionProbe::identity_in_filter_count() >= 1 && SqlSessionProbe::identity_in_fallback_count() >= 1);
        SqlRows in_failure{{SqlValue{SqlValue::Kind::text,0,"preserved"}}};
        const auto in_saved=in_failure;
        SqlSessionProbe::reset_identity_filter_metrics();
        SqlSessionProbe::fail_scratch_after(0);
        const int in_rc=in_planned->query("SELECT count(*) FROM dmg_method_refs WHERE source_index IN (0,1)",std::nullopt,10,1024,in_failure);
        SqlSessionProbe::fail_scratch_after(-1);
        CHECK(in_rc==SQLITE_NOMEM && in_failure==in_saved && SqlSessionProbe::identity_in_filter_count() >= 1);
        bool reached_in_cancel=false;
        SqlCancel in_cancel{+[](void* context) noexcept {
            if (!SqlSessionProbe::in_identity_in_callback()) return false;
            *static_cast<bool*>(context)=true; return true;
        }, &reached_in_cancel};
        CHECK(in_planned->query("SELECT count(*) FROM dmg_method_refs WHERE source_index IN (0,1)",std::nullopt,10,1024,in_failure,10000,in_cancel)==SQLITE_INTERRUPT && in_failure==in_saved && reached_in_cancel);
        equivalent(*in_planned,oracle.db,"SELECT count(*) FROM $REF WHERE source_index IN (0,1)");
        // Compare opt-in and original behavior across every metadata table.
        // Each query retains SQLite's residual check, including IN and TEXT.
        for (const char* table : {"dmg_method_refs", "dmg_method_defs", "dmg_field_refs", "dmg_field_defs",
                                  "dmg_type_refs", "dmg_class_defs", "dmg_string_values"}) {
            for (const char* predicate : {"source_index=0", "source_index=1 AND ordinal=0",
                 "source_index=9223372036854775807", "source_index=-1", "ordinal=-1", "ordinal=4294967295",
                 "ordinal=0", "source_index=1.0", "source_index=0.5", "source_index='1'",
                 "source_index='not a number'", "source_index=X'31'", "source_index=NULL",
                 "source_index IN (0,1,1,NULL)", "ordinal IN (0,0,1,NULL)",
                 "source_index=?1", "source_index=1 AND source_index=2"}) {
                const std::string sql = std::string("SELECT rowid,source_index,ordinal FROM ") + table + " WHERE " + predicate + " ORDER BY source_index,ordinal";
                const char* parameter = std::strstr(predicate, "?1") ? "1" : nullptr;
                CHECK(session_query(*planned, sql, parameter) == session_query(*session, sql, parameter));
                CHECK(session_query(*in_planned, sql, parameter) == session_query(*session, sql, parameter));
            }
        }
        for (const char* predicate : {"source_index=0", "source_index=1 AND ordinal=0", "ordinal=2",
             "source_index=9223372036854775807", "source_index=-1", "source_index=1.0", "source_index='1'",
             "source_index IN (0,1,1,NULL)", "source_index=NULL", "source_index=?1"}) {
            const std::string sql = std::string("SELECT rowid,source_index,ordinal FROM $REF WHERE ") + predicate + " ORDER BY source_index,ordinal";
            equivalent(*planned, oracle.db, sql, std::strstr(predicate, "?1") ? "1" : nullptr);
        }
        const auto fast_plan = session_query(*planned, "EXPLAIN QUERY PLAN SELECT ordinal FROM dmg_method_refs WHERE source_index=1 AND ordinal=2");
        const auto old_plan = session_query(*session, "EXPLAIN QUERY PLAN SELECT ordinal FROM dmg_method_refs WHERE source_index=1 AND ordinal=2");
        bool fast_index = false, old_index = false;
        for (const auto& row : fast_plan) if (row.size() > 3 && row[3].find("INDEX 3:") != std::string::npos) fast_index = true;
        for (const auto& row : old_plan) if (row.size() > 3 && row[3].find("INDEX 0:") != std::string::npos) old_index = true;
        CHECK(fast_index && old_index);
        // SQLite 3.54.1 tracks only the first 32 all-at-once IN constraints.
        // Place this IN after >32 other constraints: it becomes one-at-a-time
        // equality probes. Verify the actual xFilter calls and source values,
        // not just the displayed plan, against the independent ordinary table.
        std::string many = " WHERE ";
        for (int i = 1; i <= 33; ++i) many += "reference_index>=-" + std::to_string(i) + " AND ";
        many += "source_index IN (0,1,1,NULL) ORDER BY source_index,ordinal";
        const auto in_actual = "SELECT rowid,source_index,ordinal FROM dmg_method_refs" + many;
        const auto in_expected = "SELECT rowid,source_index,ordinal FROM ref_copy" + many;
        const auto in_plan = session_query(*planned, "EXPLAIN QUERY PLAN " + in_actual);
        bool in_index = false;
        for (const auto& row : in_plan) if (row.size() > 3 && row[3].find("INDEX 1:") != std::string::npos) in_index = true;
        CHECK(in_index);
        SqlSessionProbe::reset_identity_filter_metrics();
        CHECK(session_query(*planned, in_actual) == query(oracle.db, in_expected));
        CHECK(SqlSessionProbe::identity_filter_count() >= 2 && (SqlSessionProbe::identity_filter_source_mask() & 3u) == 3u);
        CHECK(in_planned->close() == SQLITE_OK);
        CHECK(planned->close() == SQLITE_OK);
        CHECK(session_query(*session, "SELECT count(*) FROM dmg_method_refs")[0][0] == "I8");
        CHECK(session_query(*session, "SELECT count(*) FROM dmg_method_defs")[0][0] == "I6");
        CHECK(session_query(*session, "SELECT count(*) FROM dmg_method_refs WHERE access_flags IS NULL")[0][0] == "I2");
        const auto plan = session_query(*session, "EXPLAIN QUERY PLAN SELECT name FROM dmg_method_refs ORDER BY name DESC");
        bool sorter = false;
        for (const auto& row : plan) if (row.size() > 3 && row[3].find("USE TEMP B-TREE") != std::string::npos) sorter = true;
        CHECK(sorter);
        SqlRows prior{{SqlValue{SqlValue::Kind::text, 0, "preserved"}}};
        const auto saved = prior;
        const auto denied_log = session->query("SELECT sqlite_log(12345,'dmg-test-sentinel')", std::nullopt, 10, 1024, prior);
        CHECK((denied_log == SQLITE_AUTH || denied_log == SQLITE_ERROR) && prior == saved);
        CHECK(log.sentinel_hits == 1 && private_log.sentinel_hits == 1);
        CHECK(session->query("SELECT * FROM dmg_method_refs", std::nullopt, 1, 1u << 20, prior) == SQLITE_TOOBIG && prior == saved);
        CHECK(session->query("SELECT * FROM dmg_method_refs", std::nullopt, 100, 1, prior) == SQLITE_TOOBIG && prior == saved);
        CHECK(session->query("DELETE FROM dmg_method_refs", std::nullopt, 10, 1024, prior) != SQLITE_OK && prior == saved);
        CHECK(session->query("SELECT 1; SELECT 2", std::nullopt, 10, 1024, prior) != SQLITE_OK && prior == saved);
        CHECK(session->query("SELECT 1.5", std::nullopt, 10, 1024, prior) == SQLITE_MISMATCH && prior == saved);
        CHECK(session->query("SELECT ?1", std::nullopt, 10, 1024, prior) == SQLITE_RANGE && prior == saved);
        CHECK(session_query(*session, "SELECT 'a' LIKE 'A'")[0][0] == "I1");
        CHECK(session->query("PRAGMA case_sensitive_like=ON", std::nullopt, 10, 1024, prior) == SQLITE_AUTH && prior == saved);
        CHECK(session_query(*session, "SELECT 'a' LIKE 'A'")[0][0] == "I1");
        CHECK(session->query("EXPLAIN PRAGMA case_sensitive_like=ON", std::nullopt, 10, 1024, prior) == SQLITE_AUTH && prior == saved);
        CHECK(session_query(*session, "SELECT 'a' LIKE 'A'")[0][0] == "I1");
        CHECK(session->query("ATTACH DATABASE ':memory:' AS other", std::nullopt, 10, 1024, prior) == SQLITE_AUTH && prior == saved);
        CHECK(session->query("BEGIN", std::nullopt, 10, 1024, prior) == SQLITE_AUTH && prior == saved);
        const std::string oversized_parameter(1025, 'x');
        CHECK(session->query("SELECT ?1", oversized_parameter, 10, 1024, prior) == SQLITE_TOOBIG && prior == saved);
        CHECK(session->query("SELECT zeroblob(100000)", std::nullopt, 10, 1024, prior) == SQLITE_TOOBIG && prior == saved);
        const std::string expensive = "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000) SELECT count(*) FROM n";
        CHECK(session->query(expensive, std::nullopt, 10, 1024, prior, 1) == SQLITE_INTERRUPT && prior == saved);
        CHECK(session->query("SELECT 1", std::nullopt, 10, 1024, prior, 0) == SQLITE_MISUSE && prior == saved);
        CHECK(session_query(*session, "SELECT count(*) FROM dmg_method_refs")[0][0] == "I8");
        SqlRows sorted_rows;
        const std::string sort_sql = "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000) SELECT x FROM n ORDER BY x DESC";
        CHECK(session->query(sort_sql, std::nullopt, 20000, 1u << 20, sorted_rows) == SQLITE_OK);
        CHECK(sorted_rows.size() == 10000 && refused_temp_opens == 0);
        Snapshot incomplete;
        open_sources(engine.value, {source(a, "base")}, 0, incomplete);
        std::unique_ptr<SqlSession> invalid;
        CHECK(SqlSession::open(incomplete.value, invalid) == SQLITE_MISUSE && !invalid);
        dmg_snapshot_release(incomplete.value); incomplete.value = nullptr;
        CHECK(SqlSession::open(nullptr, invalid) == SQLITE_MISUSE);
        Snapshot empty_data;
        open_sources(engine.value, {source(resource_apk, "resources", DMG_INPUT_APK, 1)}, 1, empty_data);
        CHECK(dmg_snapshot_get_overview(empty_data.value, &overview) == DMG_OK && overview.source_count == 0);
        std::unique_ptr<SqlSession> empty;
        CHECK(SqlSession::open(empty_data.value, empty) == SQLITE_OK);
        CHECK(session_query(*empty, "SELECT count(*) FROM dmg_method_refs")[0][0] == "I0");
        dmg_snapshot_release(empty_data.value); empty_data.value = nullptr;
        CHECK(empty->close() == SQLITE_OK); empty.reset();
        CHECK(session->close() == SQLITE_OK);
        CHECK(session->query("SELECT 1", std::nullopt, 10, 1024, prior) == SQLITE_MISUSE && prior == saved);
        session.reset();
        CHECK(owned(engine.value) == baseline);
        {
            Engine borrowed_engine;
            LeaseCounts counts;
            const dmg_buffer_lease lease{sizeof(dmg_buffer_lease), DMG_ABI_VERSION, &counts, &LeaseCounts::retain, &LeaseCounts::release, 1, 0};
            const dmg_open_options options{sizeof(dmg_open_options), DMG_ABI_VERSION, 0, "sql-prototype", "borrow", nullptr};
            dmg_error error{}; Snapshot borrowed;
            CHECK(dmg_snapshot_open_borrowed(borrowed_engine.value, a.data(), a.size(), &lease, &options, &borrowed.value, &error) == DMG_OK);
            CHECK(counts.retained == 1 && counts.released == 0);
            CHECK(dmg_snapshot_get_overview(borrowed.value, &overview) == DMG_OK && overview.scope_complete == 1 && overview.source_count == 1);
            std::unique_ptr<SqlSession> borrowed_session;
            CHECK(SqlSession::open(borrowed.value, borrowed_session) == SQLITE_OK);
            dmg_snapshot_release(borrowed.value); borrowed.value = nullptr;
            CHECK(counts.released == 0 && session_query(*borrowed_session, "SELECT count(*) FROM dmg_method_refs")[0][0] == "I3");
            CHECK(session_query(*borrowed_session, "SELECT NOT EXISTS(SELECT 1 FROM dmg_method_defs WHERE name='uses')")[0][0] == "I1");
            bool close_returned = false;
            counts.close_returned = &close_returned;
            SqlSessionProbe::observe_close_return(*borrowed_session, &close_returned);
            CHECK(SqlSessionProbe::hold_statement(*borrowed_session) == SQLITE_OK);
            CHECK(borrowed_session->close() == SQLITE_BUSY && !close_returned && counts.released == 0);
            CHECK(SqlSessionProbe::release_statement(*borrowed_session) == SQLITE_OK);
            CHECK(borrowed_session->close() == SQLITE_OK && close_returned && counts.released == 1 && counts.released_after_close);
            borrowed_session.reset();
        }
        {
            Snapshot field_data;
            open_sources(engine.value, {source(fields, "base"), source(fields, "split")}, 1, field_data);
            std::unique_ptr<SqlSession> field_session;
            CHECK(SqlSession::open(field_data.value, field_session) == SQLITE_OK);
            std::unique_ptr<SqlSession> field_planned;
            CHECK(SqlSession::open_planned(field_data.value, field_planned, {}, {true}) == SQLITE_OK);
            dmg_snapshot_release(field_data.value); field_data.value = nullptr;
            Database field_oracle;
            exec(field_oracle.db, "CREATE TABLE field_ref_copy(source_index INTEGER,ordinal INTEGER,reference_index INTEGER,definition_ordinal INTEGER,owner TEXT,name TEXT,type_descriptor TEXT,access_flags INTEGER,declaration_offset INTEGER)");
            exec(field_oracle.db, "CREATE TABLE field_def_copy(source_index INTEGER,ordinal INTEGER,reference_index INTEGER,definition_ordinal INTEGER,owner TEXT,name TEXT,type_descriptor TEXT,access_flags INTEGER,declaration_offset INTEGER)");
            for (int source_index : {0, 1}) {
                const auto id = std::to_string(source_index);
                const auto row = [source_index](int ordinal) { return std::to_string(int64_t(source_index) * 4294967296LL + ordinal); };
                exec(field_oracle.db, ("INSERT INTO field_ref_copy(rowid,source_index,ordinal,reference_index,definition_ordinal,owner,name,type_descriptor,access_flags,declaration_offset) VALUES "
                    "("+row(0)+","+id+",0,0,1,'Lcatalog/Base;','instanceField','I',1,613),"
                    "("+row(1)+","+id+",1,1,0,'Lcatalog/Base;','shared','J',9,611),"
                    "("+row(2)+","+id+",2,2,2,'Lcatalog/Child;','shared','I',1,619),"
                    "("+row(3)+","+id+",3,3,NULL,'Lexternal/External;','externalField','I',NULL,NULL)").c_str());
                exec(field_oracle.db, ("INSERT INTO field_def_copy(rowid,source_index,ordinal,reference_index,definition_ordinal,owner,name,type_descriptor,access_flags,declaration_offset) VALUES "
                    "("+row(0)+","+id+",0,1,0,'Lcatalog/Base;','shared','J',9,611),"
                    "("+row(1)+","+id+",1,0,1,'Lcatalog/Base;','instanceField','I',1,613),"
                    "("+row(2)+","+id+",2,2,2,'Lcatalog/Child;','shared','I',1,619)").c_str());
            }
            const std::vector<std::string> field_statements{
                "SELECT rowid,* FROM $FREF ORDER BY source_index,ordinal",
                "SELECT rowid,* FROM $FDEF ORDER BY source_index,ordinal",
                "SELECT source_index,name FROM $FREF WHERE name IN ('shared','shared',NULL) ORDER BY source_index,ordinal",
                "SELECT source_index,name FROM $FREF WHERE name NOT IN (NULL,'shared') ORDER BY source_index,ordinal",
                "SELECT r.source_index,r.name,d.ordinal FROM $FREF r LEFT JOIN $FDEF d ON r.source_index=d.source_index AND r.reference_index=d.reference_index ORDER BY r.source_index,r.ordinal",
                "SELECT source_index,name FROM $FREF ORDER BY name DESC,source_index DESC LIMIT 3 OFFSET 1",
                "SELECT count(*),count(DISTINCT name),sum(access_flags IS NULL) FROM $FREF",
                "SELECT EXISTS(SELECT 1 FROM $FREF WHERE name='externalField'),NOT EXISTS(SELECT 1 FROM $FDEF WHERE name='externalField')",
                "SELECT source_index,name FROM $FREF WHERE name=?1 ORDER BY source_index,ordinal"
            };
            auto replace_all = [](std::string& text, const std::string& from, const std::string& to) {
                for (size_t pos = 0; (pos = text.find(from, pos)) != std::string::npos; pos += to.size()) text.replace(pos, from.size(), to);
            };
            for (const auto& statement : field_statements) {
                auto actual = statement, expected = statement;
                replace_all(actual, "$FREF", "dmg_field_refs"); replace_all(actual, "$FDEF", "dmg_field_defs");
                replace_all(expected, "$FREF", "field_ref_copy"); replace_all(expected, "$FDEF", "field_def_copy");
                const auto parameter = statement.find("?1") != std::string::npos ? "shared" : nullptr;
                CHECK(session_query(*field_session, actual, parameter) == query(field_oracle.db, expected, parameter));
                CHECK(session_query(*field_planned, actual, parameter) == query(field_oracle.db, expected, parameter));
            }
            exec(field_oracle.db, "CREATE TABLE type_ref_copy(source_index INTEGER,ordinal INTEGER,reference_index INTEGER,definition_ordinal INTEGER,descriptor TEXT,access_flags INTEGER,definition_offset INTEGER,superclass_descriptor TEXT)");
            exec(field_oracle.db, "CREATE TABLE class_def_copy(source_index INTEGER,ordinal INTEGER,reference_index INTEGER,definition_ordinal INTEGER,descriptor TEXT,access_flags INTEGER,definition_offset INTEGER,superclass_descriptor TEXT)");
            // Independent expected rows from definition_catalog's authored model:
            // each tuple is type_id, class ordinal/NULL, descriptor, flags/NULL,
            // class_def offset/NULL, superclass descriptor/NULL.
            const char* type_rows[] = {
                "0,NULL,'I',NULL,NULL,NULL", "1,NULL,'J',NULL,NULL,NULL",
                "2,3,'Lcatalog/Base;',1,348,'Ljava/lang/Object;'",
                "3,4,'Lcatalog/Child;',1025,380,'Lcatalog/Base;'",
                "4,1,'Lcatalog/InterfaceA;',1537,284,'Ljava/lang/Object;'",
                "5,2,'Lcatalog/InterfaceB;',1537,316,'Ljava/lang/Object;'",
                "6,NULL,'Lexternal/External;',NULL,NULL,NULL",
                "7,0,'Ljava/lang/Object;',1,252,NULL", "8,NULL,'V',NULL,NULL,NULL"
            };
            const char* class_rows[] = {
                "7,0,'Ljava/lang/Object;',1,252,NULL",
                "4,1,'Lcatalog/InterfaceA;',1537,284,'Ljava/lang/Object;'",
                "5,2,'Lcatalog/InterfaceB;',1537,316,'Ljava/lang/Object;'",
                "2,3,'Lcatalog/Base;',1,348,'Ljava/lang/Object;'",
                "3,4,'Lcatalog/Child;',1025,380,'Lcatalog/Base;'"
            };
            for (int source_index : {0, 1}) {
                for (int ordinal = 0; ordinal < 9; ++ordinal) {
                    const auto prefix = std::to_string(int64_t(source_index) * 4294967296LL + ordinal) + "," +
                                        std::to_string(source_index) + "," + std::to_string(ordinal) + ",";
                    exec(field_oracle.db, ("INSERT INTO type_ref_copy(rowid,source_index,ordinal,reference_index,definition_ordinal,descriptor,access_flags,definition_offset,superclass_descriptor) VALUES (" + prefix + type_rows[ordinal] + ")").c_str());
                }
                for (int ordinal = 0; ordinal < 5; ++ordinal) {
                    const auto prefix = std::to_string(int64_t(source_index) * 4294967296LL + ordinal) + "," +
                                        std::to_string(source_index) + "," + std::to_string(ordinal) + ",";
                    exec(field_oracle.db, ("INSERT INTO class_def_copy(rowid,source_index,ordinal,reference_index,definition_ordinal,descriptor,access_flags,definition_offset,superclass_descriptor) VALUES (" + prefix + class_rows[ordinal] + ")").c_str());
                }
            }
            const std::vector<std::string> type_statements{
                "SELECT rowid,* FROM $TREF ORDER BY source_index,ordinal",
                "SELECT rowid,* FROM $CDEF ORDER BY source_index,ordinal",
                "SELECT source_index,ordinal,descriptor FROM $TREF WHERE descriptor='Lcatalog/Base;' ORDER BY source_index,ordinal",
                "SELECT source_index,ordinal,descriptor FROM $TREF WHERE source_index=1 AND ordinal=2 AND descriptor='Lcatalog/Base;' ORDER BY source_index,ordinal",
                "SELECT source_index,descriptor FROM $TREF WHERE definition_ordinal IS NULL ORDER BY source_index,ordinal",
                "SELECT source_index,descriptor FROM $TREF WHERE descriptor IN ('Lcatalog/Base;','Lcatalog/Base;',NULL) ORDER BY source_index,ordinal",
                "SELECT source_index,descriptor FROM $TREF WHERE descriptor NOT IN (NULL,'Lcatalog/Base;') ORDER BY source_index,ordinal",
                "SELECT t.source_index,t.descriptor,c.ordinal FROM $TREF t LEFT JOIN $CDEF c ON t.source_index=c.source_index AND t.reference_index=c.reference_index ORDER BY t.source_index,t.ordinal",
                "SELECT source_index,descriptor FROM $CDEF ORDER BY descriptor DESC,source_index DESC LIMIT 3 OFFSET 1",
                "SELECT count(*),count(DISTINCT descriptor),sum(definition_ordinal IS NULL),sum(superclass_descriptor IS NULL) FROM $TREF",
                "SELECT EXISTS(SELECT 1 FROM $TREF WHERE descriptor='Lexternal/External;'),NOT EXISTS(SELECT 1 FROM $CDEF WHERE descriptor='Lexternal/External;')",
                "SELECT source_index,descriptor FROM $TREF WHERE descriptor=?1 ORDER BY source_index,ordinal"
            };
            for (const auto& statement : type_statements) {
                auto actual = statement, expected = statement;
                replace_all(actual, "$TREF", "dmg_type_refs"); replace_all(actual, "$CDEF", "dmg_class_defs");
                replace_all(expected, "$TREF", "type_ref_copy"); replace_all(expected, "$CDEF", "class_def_copy");
                const auto parameter = statement.find("?1") != std::string::npos ? "Lcatalog/Base;" : nullptr;
                CHECK(session_query(*field_session, actual, parameter) == query(field_oracle.db, expected, parameter));
                CHECK(session_query(*field_planned, actual, parameter) == query(field_oracle.db, expected, parameter));
            }
            CHECK(query(field_oracle.db,"SELECT count(*) FROM type_ref_copy WHERE descriptor='Lcatalog/Base;'")[0][0]=="I2");
            CHECK(query(field_oracle.db,"SELECT count(*) FROM type_ref_copy WHERE source_index=1 AND ordinal=2 AND descriptor='Lcatalog/Base;'")[0][0]=="I1");
            for (const auto& pair : {std::pair{"dmg_field_refs", "field_ref_copy"}, std::pair{"dmg_field_defs", "field_def_copy"},
                                     std::pair{"dmg_type_refs", "type_ref_copy"}, std::pair{"dmg_class_defs", "class_def_copy"}}) {
                for (const char* predicate : {"source_index=1 AND ordinal=1", "ordinal=0", "source_index=1.0",
                                              "source_index IN (0,1,1,NULL)", "source_index=?1"}) {
                    const auto suffix = std::string(" WHERE ") + predicate + " ORDER BY source_index,ordinal";
                    const auto actual = std::string("SELECT rowid,source_index,ordinal FROM ") + pair.first + suffix;
                    const auto expected = std::string("SELECT rowid,source_index,ordinal FROM ") + pair.second + suffix;
                    const char* parameter = std::strstr(predicate, "?1") ? "1" : nullptr;
                    CHECK(session_query(*field_planned, actual, parameter) == query(field_oracle.db, expected, parameter));
                }
            }
            SqlRows output{{SqlValue{SqlValue::Kind::text, 0, "preserved"}}};
            const auto original = output;
            CHECK(field_session->query("SELECT * FROM dmg_field_refs", std::nullopt, 1, 1u << 20, output) == SQLITE_TOOBIG && output == original);
            CHECK(field_session->query("SELECT * FROM dmg_type_refs", std::nullopt, 1, 1u << 20, output) == SQLITE_TOOBIG && output == original);
            CHECK(field_session->close() == SQLITE_OK); field_session.reset();
            CHECK(field_planned->close() == SQLITE_OK); field_planned.reset();
            CHECK(owned(engine.value) == baseline);
        }
        {
            Snapshot combined;
            open_sources(engine.value, {source(a, "base"), source(b, "other")}, 1, combined);
            std::unique_ptr<SqlSession> combined_session;
            CHECK(SqlSession::open(combined.value, combined_session) == SQLITE_OK);
            CHECK(session_query(*combined_session, "SELECT NOT EXISTS(SELECT 1 FROM dmg_method_defs WHERE name='uses')")[0][0] == "I0");
            dmg_snapshot_release(combined.value); combined.value = nullptr;
            CHECK(combined_session->close() == SQLITE_OK); combined_session.reset();
            CHECK(owned(engine.value) == baseline);
        }
        {
            // The first DEX references Object without defining it; the second
            // defines Object. Local properties must not leak across sources.
            Snapshot cross_source;
            open_sources(engine.value, {source(a, "base"), source(fields, "other")}, 1, cross_source);
            std::unique_ptr<SqlSession> cross_session;
            CHECK(SqlSession::open(cross_source.value, cross_session) == SQLITE_OK);
            dmg_snapshot_release(cross_source.value); cross_source.value = nullptr;
            const Result expected{{"I0", "N", "N", "N"}, {"I1", "I0", "I1", "N"}};
            CHECK(session_query(*cross_session, "SELECT source_index,definition_ordinal,access_flags,superclass_descriptor FROM dmg_type_refs WHERE descriptor='Ljava/lang/Object;' ORDER BY source_index") == expected);
            CHECK(cross_session->close() == SQLITE_OK); cross_session.reset();
            CHECK(owned(engine.value) == baseline);
        }
        Snapshot shutdown_input;
        open_sources(engine.value, {source(a, "base")}, 1, shutdown_input);
        CHECK(dmg_engine_shutdown(engine.value, 0) == DMG_OK);
        std::unique_ptr<SqlSession> shutdown_session;
        CHECK(SqlSession::open(shutdown_input.value, shutdown_session) == SQLITE_MISUSE && !shutdown_session);
        std::cout << "PASS " << statements.size() << " SQLite materialized comparisons; duplicate occurrences and missing refs preserved\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
