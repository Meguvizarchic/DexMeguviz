#include "method_tables.hpp"
#include "dexmeguviz/dexmeguviz.h"
#include "sqlite3.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <vector>
using namespace dexmeguviz::desktop_sql;
#define CHECK(x) do { if (!(x)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #x); } while (false)
static std::vector<uint8_t> load(const std::filesystem::path& p) {
    std::ifstream in(p,std::ios::binary); CHECK(in.good()); return {std::istreambuf_iterator<char>(in),{}};
}
static bool cancel_now(void*) noexcept { return true; }
static bool same(const SqlScopedResult& a,const SqlScopedResult& b) {
    return a.rows==b.rows && a.snapshot_id==b.snapshot_id && a.source_scope==b.source_scope && a.input_count==b.input_count && a.source_count==b.source_count;
}
int main(int argc,char** argv){try {
    CHECK(argc==2);const auto dex=load(std::filesystem::path(argv[1]));dmg_engine* engine=nullptr;dmg_error error{};dmg_snapshot* snapshot=nullptr;
    CHECK(dmg_engine_create(nullptr,&engine,&error)==DMG_OK);
    struct EngineGuard {dmg_engine* p;~EngineGuard(){if(p)dmg_engine_release(p);}} eg{engine};
    dmg_source_spec spec{sizeof(spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,dex.data(),dex.size(),"profile","raw",nullptr};
    dmg_source_set_options options{sizeof(options),DMG_ABI_VERSION,"profile44",0,8,1u<<20};
    CHECK(dmg_snapshot_open_sources(engine,&spec,1,&options,&snapshot,&error)==DMG_OK);
    struct SnapshotGuard {dmg_snapshot* p;~SnapshotGuard(){if(p)dmg_snapshot_release(p);}} sg{snapshot};
    std::unique_ptr<SqlSession> session;CHECK(SqlSession::open_scoped(snapshot,session)==SQLITE_OK);
    SqlQueryProfile profile;profile.sequence=999;
    CHECK(session->last_query_profile(profile)==SQLITE_NOTFOUND&&profile.sequence==999);
    SqlScopedResult plain;CHECK(session->query_scoped("SELECT ordinal FROM dmg_method_defs ORDER BY ordinal",std::nullopt,100,1u<<20,plain)==SQLITE_OK);
    CHECK(session->last_query_profile(profile)==SQLITE_NOTFOUND&&profile.sequence==999);
    CHECK(session->enable_profiling(true)==SQLITE_OK);
    CHECK(session->last_query_profile(profile)==SQLITE_NOTFOUND&&profile.sequence==999);
    SqlScopedResult result;
    CHECK(session->query_scoped("SELECT ordinal FROM dmg_method_defs ORDER BY ordinal",std::nullopt,100,1u<<20,result)==SQLITE_OK&&same(result,plain));
    CHECK(session->last_query_profile(profile)==SQLITE_OK&&profile.sequence==1&&profile.execution_status==SQLITE_OK&&profile.prepare_attempted&&profile.prepared&&profile.first_step_observed);
    CHECK(profile.first_step_status==(result.rows.empty()?SQLITE_DONE:SQLITE_ROW)&&profile.rows_staged==result.rows.size()&&profile.rows_committed==result.rows.size());
    CHECK(profile.prepare_us<=profile.elapsed_us&&profile.first_step_us<=profile.elapsed_us);
    CHECK(session->query_scoped("SELECT ordinal FROM dmg_method_defs ORDER BY ordinal",std::nullopt,100,1u<<20,result)==SQLITE_OK&&same(result,plain));
    CHECK(session->last_query_profile(profile)==SQLITE_OK&&profile.sequence==2&&profile.rows_committed==result.rows.size());
    const auto saved=result;
    CHECK(session->query_scoped("SELECT missing_column FROM dmg_method_defs",std::nullopt,100,1u<<20,result)!=SQLITE_OK&&same(result,saved));
    CHECK(session->last_query_profile(profile)==SQLITE_OK&&profile.sequence==3&&profile.execution_status!=SQLITE_OK&&profile.prepare_attempted&&!profile.prepared&&!profile.first_step_observed&&profile.rows_committed==0);
    CHECK(session->query_scoped("SELECT 1",std::nullopt,100,1u<<20,result,10000,{cancel_now,nullptr})==SQLITE_INTERRUPT&&same(result,saved));
    CHECK(session->last_query_profile(profile)==SQLITE_OK&&profile.sequence==4&&profile.execution_status==SQLITE_INTERRUPT&&!profile.prepare_attempted&&!profile.first_step_observed&&profile.rows_committed==0);
    CHECK(session->query_scoped("SELECT 1 UNION ALL SELECT 2",std::nullopt,1,1u<<20,result)==SQLITE_TOOBIG&&same(result,saved));
    CHECK(session->last_query_profile(profile)==SQLITE_OK&&profile.sequence==5&&profile.execution_status==SQLITE_TOOBIG&&profile.first_step_status==SQLITE_ROW&&profile.rows_staged==1&&profile.rows_committed==0);
    CHECK(session->query_scoped("SELECT 1 WHERE 0",std::nullopt,100,1u<<20,result)==SQLITE_OK&&result.rows.empty());
    CHECK(session->last_query_profile(profile)==SQLITE_OK&&profile.sequence==6&&profile.first_step_status==SQLITE_DONE&&profile.rows_committed==0);
    CHECK(session->query_scoped("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<10000) SELECT count(*) FROM n",std::nullopt,100,1u<<20,result,1)==SQLITE_INTERRUPT);
    CHECK(session->last_query_profile(profile)==SQLITE_OK&&profile.sequence==7&&profile.execution_status==SQLITE_INTERRUPT&&profile.progress_callbacks>=2&&profile.rows_committed==0);
    CHECK(session->enable_profiling(false)==SQLITE_OK);profile.sequence=999;
    CHECK(session->last_query_profile(profile)==SQLITE_NOTFOUND&&profile.sequence==999);
    CHECK(session->enable_profiling(true)==SQLITE_OK&&session->last_query_profile(profile)==SQLITE_NOTFOUND);
    CHECK(session->query_scoped("SELECT 1",std::nullopt,100,1u<<20,result)==SQLITE_OK);
    CHECK(session->last_query_profile(profile)==SQLITE_OK&&profile.sequence==8);
    CHECK(session->close()==SQLITE_OK);profile.sequence=999;
    CHECK(session->last_query_profile(profile)==SQLITE_MISUSE&&profile.sequence==999&&session->enable_profiling(true)==SQLITE_MISUSE);
    std::cout<<"PASS SQL opt-in query phase observations and commit boundaries\n";return 0;
}catch(const std::exception& ex){std::cerr<<ex.what()<<'\n';return 1;}}
