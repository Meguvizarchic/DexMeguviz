#include "method_tables.hpp"
#include "result_commit/cursor.hpp"
#include "session_probe.hpp"
#include "dexmeguviz/dexmeguviz.h"
#include "sqlite3.h"
#include <barrier>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>
using namespace dexmeguviz::desktop_sql;
#define CHECK(x) do { if (!(x)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #x); } while(false)
struct HostDb { sqlite3* db=nullptr; ~HostDb(){if(db)sqlite3_close(db);} };
struct EngineGuard { dmg_engine* p=nullptr; ~EngineGuard(){if(p)dmg_engine_release(p);} };
struct SnapshotGuard { dmg_snapshot* p=nullptr; ~SnapshotGuard(){if(p)dmg_snapshot_release(p);} };
static std::vector<uint8_t> load(const std::filesystem::path& p){std::ifstream in(p,std::ios::binary);CHECK(in.good());return {std::istreambuf_iterator<char>(in),{}};}
static bool same(const SqlScopedResult& a,const SqlScopedResult& b){return a.rows==b.rows&&a.snapshot_id==b.snapshot_id&&a.source_scope==b.source_scope&&a.input_count==b.input_count&&a.source_count==b.source_count;}
static void host_large_value(sqlite3* db,uint64_t limit){
    sqlite3_stmt* statement=nullptr;
    CHECK(sqlite3_prepare_v2(db,"SELECT hex(zeroblob(800000))",-1,&statement,nullptr)==SQLITE_OK);
    CHECK(sqlite3_step(statement)==SQLITE_ROW);CHECK(sqlite3_column_bytes(statement,0)==1600000);
    CHECK(static_cast<uint64_t>(sqlite3_memory_used())>limit);CHECK(sqlite3_finalize(statement)==SQLITE_OK);
}
int main(int argc,char** argv){try{
    CHECK(argc==3);const std::string_view scenario(argv[1]);auto bytes=load(std::filesystem::path(argv[2]));
    CHECK(sqlite3_hard_heap_limit64(-1)==0);HostDb host;CHECK(sqlite3_open(":memory:",&host.db)==SQLITE_OK);
    SqliteHeapStats initial{};CHECK(private_sqlite_heap_stats(initial)==SQLITE_OK);
    CHECK(!initial.configured&&!initial.started&&initial.limit_bytes==0);
    CHECK(configure_private_sqlite_heap(0)==SQLITE_MISUSE);
    CHECK(configure_private_sqlite_heap(std::numeric_limits<uint64_t>::max())==SQLITE_MISUSE);
    EngineGuard engine;SnapshotGuard snapshot;dmg_error error{};
    CHECK(dmg_engine_create(nullptr,&engine.p,&error)==DMG_OK);
    const dmg_source_spec source{sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,bytes.data(),bytes.size(),"budget","raw",nullptr};
    const dmg_source_set_options opts{sizeof(dmg_source_set_options),DMG_ABI_VERSION,"heap-test",0,1,1u<<20};
    CHECK(dmg_snapshot_open_sources(engine.p,&source,1,&opts,&snapshot.p,&error)==DMG_OK);
    if(scenario=="bind-oom"){
        const uint64_t limit=1u<<20;CHECK(configure_private_sqlite_heap(limit)==SQLITE_OK);
        std::unique_ptr<SqlSession> session;CHECK(SqlSession::open_scoped(snapshot.p,session)==SQLITE_OK&&session);
        SqlScopedResult result;CHECK(session->query_scoped("SELECT 42",std::nullopt,10,1024,result)==SQLITE_OK);const auto saved=result;
        CHECK(session->enable_profiling(true)==SQLITE_OK);SqlQueryProfile profile;
        const std::string huge(static_cast<size_t>(limit),'x');
        const std::vector<SqlParameter> args{{SqlParameter::Kind::integer,7,{}},{SqlParameter::Kind::text,0,huge}};
        SqlSessionProbe::reset_bind_observation();
        const int rc=session->query_scoped_bound("SELECT ?1,?2",args,10,2u<<20,result);
        CHECK(rc==SQLITE_NOMEM&&same(result,saved));
        CHECK(SqlSessionProbe::bind_success_count()==1&&SqlSessionProbe::bind_failure_index()==2&&SqlSessionProbe::bind_failure_code()==SQLITE_NOMEM);
        CHECK(session->last_query_profile(profile)==SQLITE_OK&&profile.sequence==1&&profile.execution_status==SQLITE_NOMEM&&
              profile.prepare_attempted&&profile.prepared&&!profile.first_step_observed&&profile.rows_staged==0&&profile.rows_committed==0);
        std::unique_ptr<SqlCommittedCursor> cursor;SqlSessionProbe::reset_bind_observation();
        CHECK(session->query_cursor_scoped_bound("SELECT ?1,?2",args,10,2u<<20,60000,cursor)==SQLITE_NOMEM&&!cursor);
        CHECK(SqlSessionProbe::bind_success_count()==1&&SqlSessionProbe::bind_failure_index()==2&&SqlSessionProbe::bind_failure_code()==SQLITE_NOMEM);
        CHECK(session->last_query_profile(profile)==SQLITE_OK&&profile.sequence==2&&profile.execution_status==SQLITE_NOMEM&&
              profile.prepared&&!profile.first_step_observed&&profile.rows_staged==0&&profile.rows_committed==0);
        const std::vector<SqlParameter> recovery{{SqlParameter::Kind::integer,7,{}},{SqlParameter::Kind::text,0,"ok"}};
        SqlSessionProbe::reset_bind_observation();CHECK(session->query_scoped_bound("SELECT ?1,?2",recovery,10,1024,result)==SQLITE_OK);
        CHECK(SqlSessionProbe::bind_success_count()==2&&SqlSessionProbe::bind_failure_index()==0&&result.rows.size()==1&&result.rows[0].size()==2&&result.rows[0][0].integer==7&&result.rows[0][1].text=="ok");
        CHECK(session->last_query_profile(profile)==SQLITE_OK&&profile.sequence==3&&profile.execution_status==SQLITE_OK&&
              profile.prepared&&profile.first_step_observed&&profile.first_step_status==SQLITE_ROW&&profile.rows_staged==1&&profile.rows_committed==1);
        CHECK(session->query_cursor_scoped_bound("SELECT ?1,?2",recovery,10,1024,60000,cursor)==SQLITE_OK&&cursor);
        CHECK(session->last_query_profile(profile)==SQLITE_OK&&profile.sequence==4&&profile.execution_status==SQLITE_OK&&profile.rows_committed==1);
        SqlCommittedPage page;CHECK(cursor->next(1,1024,page)==SQLITE_OK&&page.final_page&&page.result.rows==result.rows);
        SqliteHeapStats current{};CHECK(private_sqlite_heap_stats(current)==SQLITE_OK&&current.used_bytes<=limit);
        CHECK(session->close()==SQLITE_OK);
    } else if(scenario=="bounded"){
        const uint64_t limit=1u<<20;CHECK(configure_private_sqlite_heap(limit)==SQLITE_OK);
        CHECK(configure_private_sqlite_heap(limit)==SQLITE_MISUSE);
        CHECK(sqlite3_hard_heap_limit64(-1)==0);host_large_value(host.db,limit);
        std::unique_ptr<SqlSession> session;CHECK(SqlSession::open_scoped(snapshot.p,session)==SQLITE_OK&&session);
        SqliteHeapStats opened{};CHECK(private_sqlite_heap_stats(opened)==SQLITE_OK);
        CHECK(opened.configured&&opened.started&&opened.limit_bytes==limit&&opened.used_bytes<=limit&&opened.lifetime_peak_bytes>=opened.used_bytes);
        SqlScopedResult result;CHECK(session->query_scoped("SELECT count(*) FROM dmg_method_refs",std::nullopt,10,4096,result)==SQLITE_OK);
        CHECK(result.source_scope==SqlScopeCoverage::partial_source_scope&&result.rows.size()==1);
        const auto saved=result;
        const auto rc=session->query_scoped("WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r WHERE n<100000) SELECT n FROM r ORDER BY n DESC",std::nullopt,100000,8u<<20,result,1000000);
        CHECK(rc==SQLITE_NOMEM&&same(result,saved));
        SqliteHeapStats failed{};CHECK(private_sqlite_heap_stats(failed)==SQLITE_OK);CHECK(failed.used_bytes<=limit&&failed.limit_bytes==limit);
        CHECK(session->query_scoped("SELECT count(*) FROM dmg_method_refs",std::nullopt,10,4096,result)==SQLITE_OK);
        CHECK(session->close()==SQLITE_OK);session.reset();
        SqliteHeapStats closed{};CHECK(private_sqlite_heap_stats(closed)==SQLITE_OK);
        CHECK(closed.used_bytes<=limit&&closed.configured&&closed.started&&closed.limit_bytes==limit);
        CHECK(sqlite3_hard_heap_limit64(-1)==0);host_large_value(host.db,limit);
    } else if(scenario=="late"){
        std::unique_ptr<SqlSession> session;CHECK(SqlSession::open_scoped(snapshot.p,session)==SQLITE_OK);
        CHECK(configure_private_sqlite_heap(1u<<20)==SQLITE_MISUSE);
        SqliteHeapStats current{};CHECK(private_sqlite_heap_stats(current)==SQLITE_OK);
        CHECK(current.started&&!current.configured&&current.limit_bytes==0);CHECK(session->close()==SQLITE_OK);
    } else if(scenario=="race-config"){
        std::barrier gate(3);int first=-1,second=-1;
        std::thread a([&]{gate.arrive_and_wait();first=configure_private_sqlite_heap(2u<<20);});
        std::thread b([&]{gate.arrive_and_wait();second=configure_private_sqlite_heap(3u<<20);});
        gate.arrive_and_wait();a.join();b.join();CHECK((first==SQLITE_OK&&second==SQLITE_MISUSE)||(first==SQLITE_MISUSE&&second==SQLITE_OK));
        SqliteHeapStats current{};CHECK(private_sqlite_heap_stats(current)==SQLITE_OK);
        CHECK(current.configured&&!current.started&&current.limit_bytes==(first==SQLITE_OK?(2u<<20):(3u<<20)));
        std::unique_ptr<SqlSession> session;CHECK(SqlSession::open_scoped(snapshot.p,session)==SQLITE_OK);CHECK(session->close()==SQLITE_OK);
    } else if(scenario=="race-open"){
        std::barrier gate(3);int configure=-1,opened=-1;std::unique_ptr<SqlSession> session;
        std::thread a([&]{gate.arrive_and_wait();configure=configure_private_sqlite_heap(2u<<20);});
        std::thread b([&]{gate.arrive_and_wait();opened=SqlSession::open_scoped(snapshot.p,session);});
        gate.arrive_and_wait();a.join();b.join();CHECK(opened==SQLITE_OK&&session);CHECK(configure==SQLITE_OK||configure==SQLITE_MISUSE);
        SqliteHeapStats current{};CHECK(private_sqlite_heap_stats(current)==SQLITE_OK&&current.started);
        CHECK((configure==SQLITE_OK&&current.configured&&current.limit_bytes==(2u<<20))||(configure==SQLITE_MISUSE&&!current.configured&&current.limit_bytes==0));
        CHECK(session->close()==SQLITE_OK);
    } else throw std::runtime_error("unknown scenario");
    CHECK(sqlite3_hard_heap_limit64(-1)==0);
    std::cout<<"PASS private SQLite heap budget "<<scenario<<"\n";return 0;
}catch(const std::exception& ex){std::cerr<<ex.what()<<'\n';return 1;}}
