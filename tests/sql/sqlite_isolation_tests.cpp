#include "method_tables.hpp"
#include "session_probe.hpp"
#include "dexmeguviz/dexmeguviz.h"
#include "sqlite3.h"
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <vector>

using dexmeguviz::desktop_sql::SqlRows;
using dexmeguviz::desktop_sql::SqlSession;
#define CHECK(x) do { if (!(x)) throw std::runtime_error("check failed at line " + std::to_string(__LINE__) + ": " #x); } while (0)

static int host_extension_calls = 0;
static int host_function_calls = 0;
static void log_callback(void* data, int code, const char* message) noexcept {
    if(code==12345 && message && std::strcmp(message,"dmg-test-sentinel")==0) ++*static_cast<int*>(data);
}
static void hostile_count(sqlite3_context* context, int, sqlite3_value**) {
    ++host_function_calls;
    sqlite3_result_int(context, 777);
}
extern "C" int host_auto_extension(sqlite3* db, char**, const sqlite3_api_routines*) {
    ++host_extension_calls;
    return sqlite3_create_function(db, "count", 1, SQLITE_UTF8, nullptr, hostile_count, nullptr, nullptr);
}
struct HostDb {
    sqlite3* value = nullptr;
    HostDb() { CHECK(sqlite3_open(":memory:", &value) == SQLITE_OK); }
    ~HostDb() { if(value) sqlite3_close(value); }
};
static int host_count(sqlite3* db) {
    sqlite3_stmt* stmt = nullptr;
    CHECK(sqlite3_prepare_v2(db, "SELECT count(1)", -1, &stmt, nullptr) == SQLITE_OK);
    CHECK(sqlite3_step(stmt) == SQLITE_ROW);
    int result = sqlite3_column_int(stmt, 0);
    CHECK(sqlite3_finalize(stmt) == SQLITE_OK);
    return result;
}
int main(int argc, char** argv) {
    try {
        CHECK(argc == 2);
        std::ifstream stream(std::filesystem::path(argv[1]),std::ios::binary); CHECK(stream.good());
        std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(stream),{}};
        // This is a separate test process. No registry is reset or changed in
        // any other process; the registered extension remains installed here.
        int host_log=0,private_log=0;
        CHECK(sqlite3_config(SQLITE_CONFIG_LOG,log_callback,&host_log)==SQLITE_OK);
        CHECK(dexmeguviz::desktop_sql::SqlSessionProbe::configure_private_log(log_callback,&private_log)==SQLITE_OK);
        CHECK(sqlite3_auto_extension(reinterpret_cast<void(*)(void)>(host_auto_extension)) == SQLITE_OK);
        sqlite3_vfs* original=sqlite3_vfs_find(nullptr); CHECK(original != nullptr);
        sqlite3_vfs host_vfs=*original; host_vfs.zName="dmg-host-vfs"; host_vfs.pNext=nullptr;
        CHECK(sqlite3_vfs_register(&host_vfs,1)==SQLITE_OK && sqlite3_vfs_find(nullptr)==&host_vfs);
        HostDb first;
        CHECK(host_extension_calls == 1 && host_count(first.value) == 777 && host_function_calls == 1);
        sqlite3_log(12345,"dmg-test-sentinel"); CHECK(host_log==1 && private_log==0);
        dmg_engine* engine = nullptr; dmg_snapshot* snapshot = nullptr; dmg_error error{};
        CHECK(dmg_engine_create(nullptr,&engine,&error) == DMG_OK && engine);
        struct EngineGuard { dmg_engine* p; ~EngineGuard(){dmg_engine_release(p);} } engine_guard{engine};
        const dmg_source_spec source{sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,bytes.data(),bytes.size(),"fixture","raw-dex",nullptr};
        const dmg_source_set_options options{sizeof(dmg_source_set_options),DMG_ABI_VERSION,"isolation-test",1,1,1u<<20};
        CHECK(dmg_snapshot_open_sources(engine,&source,1,&options,&snapshot,&error) == DMG_OK && snapshot);
        struct SnapshotGuard { dmg_snapshot* p; ~SnapshotGuard(){dmg_snapshot_release(p);} } snapshot_guard{snapshot};
        std::unique_ptr<SqlSession> session;
        CHECK(SqlSession::open(snapshot,session) == SQLITE_OK && session);
        CHECK(host_extension_calls == 1 && sqlite3_vfs_find(nullptr)==&host_vfs);
        CHECK(!dexmeguviz::desktop_sql::SqlSessionProbe::private_default_vfs_is("dmg-host-vfs"));
        CHECK(dexmeguviz::desktop_sql::SqlSessionProbe::emit_private_log(*session)==SQLITE_OK);
        CHECK(host_log==1 && private_log==1);
        SqlRows rows;
        CHECK(session->query("SELECT count(1) FROM dmg_method_refs",std::nullopt,10,4096,rows) == SQLITE_OK);
        CHECK(rows.size()==1 && rows[0].size()==1 && rows[0][0].kind==dexmeguviz::desktop_sql::SqlValue::Kind::integer && rows[0][0].integer==3);
        CHECK(host_extension_calls == 1 && host_function_calls == 1);
        HostDb second;
        CHECK(host_extension_calls == 2 && host_count(second.value) == 777 && host_function_calls == 2);
        CHECK(session->close() == SQLITE_OK); session.reset();
        CHECK(sqlite3_vfs_find(nullptr)==&host_vfs && host_log==1 && private_log==1);
        HostDb third;
        CHECK(host_extension_calls == 3 && host_count(third.value) == 777 && host_function_calls == 3);
        std::cout << "PASS private SQLite excludes host auto-extensions; host remains registered\n";
        return 0;
    } catch(const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
