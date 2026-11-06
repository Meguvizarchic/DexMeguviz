#include "method_tables.hpp"
#include "session_probe.hpp"
#include "dexmeguviz/dexmeguviz.h"
#include "sqlite3.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace dexmeguviz::desktop_sql;
#define CHECK(x) do { if (!(x)) throw std::runtime_error("check failed at line " + std::to_string(__LINE__) + ": " #x); } while (0)
using Result = std::vector<std::vector<std::string>>;
static Result ordinary(sqlite3* db, const std::string& sql, const std::string* parameter) {
    sqlite3_stmt* raw = nullptr;
    CHECK(sqlite3_prepare_v2(db, sql.c_str(), -1, &raw, nullptr) == SQLITE_OK);
    struct Guard { sqlite3_stmt* s; ~Guard() { sqlite3_finalize(s); } } guard{raw};
    if (parameter) CHECK(sqlite3_bind_text(raw, 1, parameter->data(), static_cast<int>(parameter->size()), SQLITE_TRANSIENT) == SQLITE_OK);
    Result rows;
    int rc;
    while ((rc = sqlite3_step(raw)) == SQLITE_ROW) {
        std::vector<std::string> row;
        for (int i = 0; i < sqlite3_column_count(raw); ++i) {
            const int type = sqlite3_column_type(raw, i);
            if (type == SQLITE_NULL) row.emplace_back("N");
            else if (type == SQLITE_INTEGER) row.push_back("I" + std::to_string(sqlite3_column_int64(raw, i)));
            else { CHECK(type == SQLITE_TEXT); const auto* p = reinterpret_cast<const char*>(sqlite3_column_text(raw, i));
                   const auto n = sqlite3_column_bytes(raw, i); CHECK(p); row.push_back("T" + std::string(p, static_cast<size_t>(n))); }
        }
        rows.push_back(std::move(row));
    }
    CHECK(rc == SQLITE_DONE);
    return rows;
}
static Result virtual_rows(SqlSession& session, const std::string& sql, const std::string* parameter) {
    SqlRows raw;
    auto arg = parameter ? std::optional<std::string_view>(*parameter) : std::nullopt;
    CHECK(session.query(sql, arg, 1000, 1u << 20, raw) == SQLITE_OK);
    Result rows;
    for (const auto& r : raw) { std::vector<std::string> row;
        for (const auto& v : r) {
            if (v.kind == SqlValue::Kind::null) row.emplace_back("N");
            else if (v.kind == SqlValue::Kind::integer) row.push_back("I" + std::to_string(v.integer));
            else row.push_back("T" + v.text);
        } rows.push_back(std::move(row));
    } return rows;
}
int main(int argc, char** argv) {
    try {
        CHECK(argc == 8); std::ifstream in(std::filesystem::path(argv[1]), std::ios::binary); CHECK(in.good());
        const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(in), {}};
        dmg_engine* engine = nullptr; dmg_error err{}; CHECK(dmg_engine_create(nullptr, &engine, &err) == DMG_OK);
        struct EngineGuard { dmg_engine* p; ~EngineGuard() { dmg_engine_release(p); } } eg{engine};
        dmg_source_spec spec[]{
            {sizeof(dmg_source_spec), DMG_ABI_VERSION, DMG_INPUT_RAW_DEX, 0, bytes.data(), bytes.size(), "one", "one", nullptr},
            {sizeof(dmg_source_spec), DMG_ABI_VERSION, DMG_INPUT_RAW_DEX, 0, bytes.data(), bytes.size(), "two", "two", nullptr}};
        dmg_source_set_options opts{sizeof(dmg_source_set_options), DMG_ABI_VERSION, "strings", 1, 32, 8u << 20};
        dmg_snapshot* snapshot = nullptr; CHECK(dmg_snapshot_open_sources(engine, spec, 2, &opts, &snapshot, &err) == DMG_OK);
        struct SnapGuard { dmg_snapshot* p; ~SnapGuard() { dmg_snapshot_release(p); } } sg{snapshot};
        std::unique_ptr<SqlSession> session; CHECK(SqlSession::open(snapshot, session) == SQLITE_OK);
        std::unique_ptr<SqlSession> planned, in_planned;
        CHECK(SqlSession::open_planned(snapshot, planned, {}, {true}) == SQLITE_OK);
        CHECK(SqlSession::open_planned(snapshot, in_planned, {}, {true, true}) == SQLITE_OK);
        sqlite3* db = nullptr; CHECK(sqlite3_open(":memory:", &db) == SQLITE_OK);
        struct DbGuard { sqlite3* p; ~DbGuard() { sqlite3_close(p); } } dg{db};
        CHECK(sqlite3_exec(db, "CREATE TABLE ordinary(source_index INTEGER,ordinal INTEGER,value TEXT)", nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_stmt* insert = nullptr; CHECK(sqlite3_prepare_v2(db, "INSERT INTO ordinary(rowid,source_index,ordinal,value) VALUES(?1,?2,?3,?4)", -1, &insert, nullptr) == SQLITE_OK);
        const std::string nul = std::string("\xe9\x9b\xaa\xf0\x9f\x98\x80", 7) + std::string("\0tail", 5);
        const std::vector<std::string> expected{"", "Ljava/lang/Object;", "Lsample/Example;", "V", "external", "locate", "second", nul};
        for (int source = 0; source < 2; ++source) for (int i = 0; i < 8; ++i) {
            CHECK(sqlite3_bind_int64(insert, 1, (sqlite3_int64(source) << 32) | i) == SQLITE_OK);
            CHECK(sqlite3_bind_int(insert, 2, source) == SQLITE_OK); CHECK(sqlite3_bind_int(insert, 3, i) == SQLITE_OK);
            CHECK(sqlite3_bind_text(insert, 4, expected[i].data(), static_cast<int>(expected[i].size()), SQLITE_TRANSIENT) == SQLITE_OK);
            CHECK(sqlite3_step(insert) == SQLITE_DONE); CHECK(sqlite3_reset(insert) == SQLITE_OK); CHECK(sqlite3_clear_bindings(insert) == SQLITE_OK);
        } CHECK(sqlite3_finalize(insert) == SQLITE_OK);
        const std::vector<std::string> queries{
            "SELECT rowid,source_index,ordinal,value FROM $TABLE ORDER BY source_index,ordinal",
            "SELECT source_index,ordinal,value FROM $TABLE WHERE value=?1 ORDER BY source_index,ordinal",
            "SELECT value FROM $TABLE WHERE value IN ('locate','locate',NULL) ORDER BY value",
            "SELECT value FROM $TABLE WHERE value NOT IN (NULL,'locate') ORDER BY value",
            "SELECT a.source_index,b.source_index,a.ordinal FROM $TABLE a JOIN $TABLE b ON a.value=b.value ORDER BY a.source_index,b.source_index,a.ordinal,b.ordinal",
            "SELECT source_index,ordinal,value FROM $TABLE WHERE value LIKE 'Lsample!/%' ESCAPE '!' ORDER BY 1,2",
            "SELECT source_index,ordinal,value FROM $TABLE WHERE value LIKE '雪%' ORDER BY 1,2",
            "SELECT source_index,ordinal,value FROM $TABLE WHERE value LIKE '雪_' ORDER BY 1,2",
            "SELECT source_index,ordinal,value FROM $TABLE WHERE value='LOCATE' COLLATE NOCASE ORDER BY 1,2",
            "SELECT source_index,ordinal,value FROM $TABLE WHERE value='LOCATE' COLLATE BINARY ORDER BY 1,2",
            "SELECT source_index,ordinal,value FROM $TABLE WHERE ordinal IN (7,7,NULL) ORDER BY 1,2",
            "SELECT source_index,ordinal,value FROM $TABLE ORDER BY value COLLATE NOCASE ASC,value COLLATE BINARY DESC,source_index DESC,ordinal DESC LIMIT 7 OFFSET 1",
            "SELECT value FROM $TABLE ORDER BY value DESC LIMIT 5 OFFSET 1",
            "SELECT count(*),count(DISTINCT value),sum(value='') FROM $TABLE",
            "SELECT EXISTS(SELECT 1 FROM $TABLE WHERE value=''),NOT EXISTS(SELECT 1 FROM $TABLE WHERE value IS NULL)"};
        for (const auto& q : queries) {
            auto a=q,b=q; const std::string token="$TABLE";
            for (size_t pos=0;(pos=a.find(token,pos))!=std::string::npos;) { a.replace(pos,token.size(),"dmg_string_values"); pos+=17; }
            for (size_t pos=0;(pos=b.find(token,pos))!=std::string::npos;) { b.replace(pos,token.size(),"ordinary"); pos+=8; }
            const auto* parameter = q.find("?1") != std::string::npos ? &nul : nullptr;
            const auto oracle_rows=ordinary(db,b,parameter);
            CHECK(virtual_rows(*session,a,parameter) == oracle_rows);
            CHECK(virtual_rows(*planned,a,parameter) == oracle_rows);
            CHECK(virtual_rows(*in_planned,a,parameter) == oracle_rows);
        }
        CHECK(ordinary(db,"SELECT source_index,ordinal,value FROM ordinary WHERE value LIKE '雪%' ORDER BY 1,2",nullptr).size()==2);
        CHECK(ordinary(db,"SELECT source_index,ordinal,value FROM ordinary WHERE value LIKE '雪_' ORDER BY 1,2",nullptr).size()==2);
        CHECK(ordinary(db,"SELECT source_index,ordinal,value FROM ordinary WHERE value='LOCATE' COLLATE NOCASE ORDER BY 1,2",nullptr).size()==2);
        CHECK(ordinary(db,"SELECT source_index,ordinal,value FROM ordinary WHERE value LIKE 'Lsample!/%' ESCAPE '!' ORDER BY 1,2",nullptr).size()==2);
        CHECK(planned->close()==SQLITE_OK && in_planned->close()==SQLITE_OK);
        const auto exact = virtual_rows(*session,"SELECT source_index,ordinal,value FROM dmg_string_values WHERE value=?1 ORDER BY source_index",&nul);
        CHECK(exact.size()==2 && exact[0][1]=="I7" && exact[0][2]=="T"+nul);
        const auto empty = virtual_rows(*session,"SELECT source_index,ordinal,value FROM dmg_string_values WHERE value='' ORDER BY source_index",nullptr);
        CHECK(empty.size()==2 && empty[0][1]=="I0" && empty[0][2]=="T");
        const auto plan = virtual_rows(*session,"EXPLAIN QUERY PLAN SELECT value FROM dmg_string_values ORDER BY value DESC",nullptr);
        bool sorted = false; for (const auto& row : plan) if (row.size()>3 && row[3].find("USE TEMP B-TREE")!=std::string::npos) sorted=true;
        CHECK(sorted);
        SqlRows unchanged{{SqlValue{SqlValue::Kind::text,0,"unchanged"}}}; const auto saved=unchanged;
        SqlSessionProbe::fail_utf8_after(2);
        CHECK(session->query("SELECT value FROM dmg_string_values",std::nullopt,100,1u<<20,unchanged)==SQLITE_NOMEM);
        CHECK(SqlSessionProbe::utf8_conversions()==2 && unchanged==saved);
        SqlSessionProbe::fail_utf8_after(-1);
        CHECK(virtual_rows(*session,"SELECT count(*) FROM dmg_string_values",nullptr)[0][0]=="I16");
        CHECK(session->close()==SQLITE_OK);
        for (int which=0;which<3;++which) {
            std::ifstream input(std::filesystem::path(argv[which+2]),std::ios::binary); CHECK(input.good());
            const std::vector<uint8_t> fixture{std::istreambuf_iterator<char>(input),{}};
            dmg_source_spec bom_source{sizeof(dmg_source_spec), DMG_ABI_VERSION, DMG_INPUT_RAW_DEX, 0,
                                       fixture.data(),fixture.size(),"bom","bom",nullptr};
            dmg_snapshot* bom_snapshot=nullptr; CHECK(dmg_snapshot_open_sources(engine,&bom_source,1,&opts,&bom_snapshot,&err)==DMG_OK);
            SnapGuard bom_guard{bom_snapshot}; std::unique_ptr<SqlSession> bom_session;
            CHECK(SqlSession::open(bom_snapshot,bom_session)==SQLITE_OK);
            const std::string value=which==2 ? std::string("tail\0",5) : std::string(which==0?"\xef\xbb\xbf":"\xef\xbf\xbe",3)+"leading";
            sqlite3_stmt* add=nullptr; CHECK(sqlite3_prepare_v2(db,"INSERT INTO ordinary VALUES(0,0,?1)",-1,&add,nullptr)==SQLITE_OK);
            CHECK(sqlite3_bind_text(add,1,value.data(),static_cast<int>(value.size()),SQLITE_TRANSIENT)==SQLITE_OK);
            CHECK(sqlite3_step(add)==SQLITE_DONE); CHECK(sqlite3_finalize(add)==SQLITE_OK);
            const auto actual=virtual_rows(*bom_session,"SELECT value FROM dmg_string_values WHERE value=?1",&value);
            const auto expected_bom=ordinary(db,"SELECT value FROM ordinary WHERE value=?1",&value);
            CHECK(expected_bom.size()==1 && expected_bom[0][0]=="T"+value);
            CHECK(actual==expected_bom);
            CHECK(bom_session->close()==SQLITE_OK);
        }
        for (int which=5;which<7;++which) {
            std::ifstream input(std::filesystem::path(argv[which]),std::ios::binary); CHECK(input.good());
            const std::vector<uint8_t> fixture{std::istreambuf_iterator<char>(input),{}};
            dmg_source_spec invalid_source{sizeof(dmg_source_spec), DMG_ABI_VERSION, DMG_INPUT_RAW_DEX, 0,
                                           fixture.data(),fixture.size(),"invalid","invalid",nullptr};
            dmg_snapshot* invalid_snapshot=nullptr; CHECK(dmg_snapshot_open_sources(engine,&invalid_source,1,&opts,&invalid_snapshot,&err)==DMG_OK);
            SnapGuard invalid_guard{invalid_snapshot}; std::unique_ptr<SqlSession> invalid_session;
            CHECK(SqlSession::open(invalid_snapshot,invalid_session)==SQLITE_OK);
            SqlRows prior{{SqlValue{SqlValue::Kind::text,0,"unchanged"}}}; const auto saved=prior;
            CHECK(invalid_session->query("SELECT value FROM dmg_string_values ORDER BY ordinal",std::nullopt,100,1u<<20,prior)==SQLITE_MISMATCH);
            CHECK(prior==saved);
            CHECK(invalid_session->close()==SQLITE_OK);
        }
        {
            std::ifstream input(std::filesystem::path(argv[7]),std::ios::binary); CHECK(input.good());
            const std::vector<uint8_t> fixture{std::istreambuf_iterator<char>(input),{}};
            dmg_source_spec long_source{sizeof(dmg_source_spec), DMG_ABI_VERSION, DMG_INPUT_RAW_DEX, 0,
                                        fixture.data(),fixture.size(),"long","long",nullptr};
            dmg_snapshot* long_snapshot=nullptr; CHECK(dmg_snapshot_open_sources(engine,&long_source,1,&opts,&long_snapshot,&err)==DMG_OK);
            SnapGuard long_guard{long_snapshot}; std::unique_ptr<SqlSession> long_session;
            CHECK(SqlSession::open(long_snapshot,long_session)==SQLITE_OK);
            SqlRows prior{{SqlValue{SqlValue::Kind::text,0,"unchanged"}}}; const auto saved_long=prior;
            SqlSessionProbe::fail_utf8_after(-1);
            CHECK(long_session->query("SELECT value FROM dmg_string_values WHERE ordinal=6",std::nullopt,100,1024,prior)==SQLITE_TOOBIG);
            CHECK(SqlSessionProbe::utf8_allocations()==0 && prior==saved_long);
            CHECK(long_session->close()==SQLITE_OK);
        }
        std::cout << "PASS string_values: two occurrences, empty/NUL/Unicode, ordinary SQLite equivalence\n"; return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
