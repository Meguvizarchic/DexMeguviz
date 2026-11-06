#include "method_tables.hpp"
#include "session_probe.hpp"
#include "dexmeguviz/dexmeguviz.h"
#include "sqlite3.h"
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <vector>
using namespace dexmeguviz::desktop_sql;
#define CHECK(x) do{if(!(x))throw std::runtime_error("line "+std::to_string(__LINE__)+": " #x);}while(false)
static std::vector<uint8_t> load(const std::filesystem::path& p){std::ifstream in(p,std::ios::binary);CHECK(in.good());return {std::istreambuf_iterator<char>(in),{}};}
static bool cancelled(void*) noexcept{return true;}
struct CancelOnSecond { int calls=0; };
static bool cancel_on_second(void* context) noexcept { return ++static_cast<CancelOnSecond*>(context)->calls >= 2; }
static bool same(const SqlScopedResult& a,const SqlScopedResult& b){return a.rows==b.rows&&a.snapshot_id==b.snapshot_id&&a.source_scope==b.source_scope&&a.input_count==b.input_count&&a.source_count==b.source_count;}
static void compare_materialized(const SqlScopedResult& actual,int64_t ordinal){
 sqlite3* db=nullptr;sqlite3_stmt* stmt=nullptr;CHECK(sqlite3_open(":memory:",&db)==SQLITE_OK);
 CHECK(sqlite3_exec(db,"CREATE TABLE mirror(ordinal INTEGER,name TEXT); INSERT INTO mirror VALUES(0,'second'),(1,'locate');",nullptr,nullptr,nullptr)==SQLITE_OK);
 CHECK(sqlite3_prepare_v2(db,"SELECT ordinal,name FROM mirror WHERE ordinal=?1 ORDER BY ordinal",-1,&stmt,nullptr)==SQLITE_OK);
 CHECK(sqlite3_bind_int64(stmt,1,ordinal)==SQLITE_OK);size_t index=0;int rc;
 while((rc=sqlite3_step(stmt))==SQLITE_ROW){
  CHECK(index<actual.rows.size()&&actual.rows[index].size()==2);
  CHECK(actual.rows[index][0].kind==SqlValue::Kind::integer&&actual.rows[index][0].integer==sqlite3_column_int64(stmt,0));
  const auto* text=reinterpret_cast<const char*>(sqlite3_column_text(stmt,1));const auto bytes=sqlite3_column_bytes(stmt,1);CHECK(text&&bytes>=0);
  if(actual.rows[index][1].kind!=SqlValue::Kind::text||actual.rows[index][1].text!=std::string(text,static_cast<size_t>(bytes)))
   throw std::runtime_error("fixture name mismatch ordinal="+std::to_string(ordinal)+" actual="+actual.rows[index][1].text+" expected="+std::string(text,static_cast<size_t>(bytes)));
  ++index;
 }
 CHECK(rc==SQLITE_DONE&&index==actual.rows.size());CHECK(sqlite3_finalize(stmt)==SQLITE_OK&&sqlite3_close(db)==SQLITE_OK);
}
int main(int argc,char** argv){try{
 CHECK(argc==2);const auto dex=load(argv[1]);dmg_error error{};dmg_engine* engine=nullptr;dmg_snapshot* snapshot=nullptr;
 CHECK(dmg_engine_create(nullptr,&engine,&error)==DMG_OK);
 struct EngineGuard{dmg_engine* p;~EngineGuard(){if(p)dmg_engine_release(p);}} eg{engine};
 dmg_source_spec spec{sizeof(spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,dex.data(),dex.size(),"reuse","raw",nullptr};
 dmg_source_set_options options{sizeof(options),DMG_ABI_VERSION,"reuse48",0,8,1u<<20};
 CHECK(dmg_snapshot_open_sources(engine,&spec,1,&options,&snapshot,&error)==DMG_OK);
 struct SnapshotGuard{dmg_snapshot* p;~SnapshotGuard(){if(p)dmg_snapshot_release(p);}} sg{snapshot};
 std::unique_ptr<SqlSession> session;CHECK(SqlSession::open_scoped(snapshot,session)==SQLITE_OK);
 SqlStatementReuseStats stats;stats.prepare_attempts=777;
 CHECK(session->statement_reuse_stats(stats)==SQLITE_NOTFOUND&&stats.prepare_attempts==777);
 SqlScopedResult output;CHECK(session->query_scoped_reused_bound("SELECT 1",{},10,1u<<20,output)==SQLITE_MISUSE);
 CHECK(session->enable_statement_reuse(0)==SQLITE_MISUSE&&session->enable_statement_reuse(1u<<20)==SQLITE_OK);
 CHECK(session->enable_statement_reuse(1u<<20)==SQLITE_MISUSE&&session->enable_profiling(true)==SQLITE_OK);
 const char* query="SELECT ordinal,name FROM dmg_method_defs WHERE ordinal=?1 ORDER BY ordinal";
 SqlParameter zero{SqlParameter::Kind::integer,0,{}},one{SqlParameter::Kind::integer,1,{}};
 SqlScopedResult ordinary;CHECK(session->query_scoped_bound(query,std::span<const SqlParameter>(&zero,1),100,1u<<20,ordinary)==SQLITE_OK);
 CHECK(session->query_scoped_reused_bound(query,std::span<const SqlParameter>(&zero,1),100,1u<<20,output)==SQLITE_OK&&same(output,ordinary));
 compare_materialized(output,0);
 CHECK(session->statement_reuse_stats(stats)==SQLITE_OK&&stats.prepare_attempts==1&&stats.cache_hits==0&&stats.cached&&stats.retained_statement_bytes>0&&stats.retained_statement_bytes<=(1u<<20));
 SqlQueryProfile profile;CHECK(session->last_query_profile(profile)==SQLITE_OK&&profile.prepare_attempted&&profile.prepared&&profile.first_step_observed);
 CHECK(session->query_scoped_reused_bound(query,std::span<const SqlParameter>(&one,1),100,1u<<20,output)==SQLITE_OK);
 compare_materialized(output,1);
 SqlScopedResult ordinary_one;CHECK(session->query_scoped_bound(query,std::span<const SqlParameter>(&one,1),100,1u<<20,ordinary_one)==SQLITE_OK&&same(output,ordinary_one));
 CHECK(session->statement_reuse_stats(stats)==SQLITE_OK&&stats.prepare_attempts==1&&stats.cache_hits==1&&stats.cached);
 CHECK(session->query_scoped_reused_bound(query,std::span<const SqlParameter>(&zero,1),100,1u<<20,output)==SQLITE_OK&&same(output,ordinary));
 CHECK(session->last_query_profile(profile)==SQLITE_OK&&!profile.prepare_attempted&&!profile.prepared&&profile.first_step_observed&&profile.rows_committed==output.rows.size());
 CHECK(session->statement_reuse_stats(stats)==SQLITE_OK&&stats.prepare_attempts==1&&stats.cache_hits==2&&stats.automatic_reprepares==0&&stats.cached);
 const auto saved=output;
 CHECK(session->query_scoped_reused_bound(query,{},100,1u<<20,output)==SQLITE_RANGE&&same(output,saved));
 CHECK(session->statement_reuse_stats(stats)==SQLITE_OK&&!stats.cached);
 CHECK(session->query_scoped_reused_bound(query,std::span<const SqlParameter>(&zero,1),100,1u<<20,output)==SQLITE_OK&&same(output,ordinary));
 CHECK(session->statement_reuse_stats(stats)==SQLITE_OK&&stats.prepare_attempts==2&&stats.cache_hits==3&&stats.cached);
 CHECK(session->query_scoped_reused_bound(query,std::span<const SqlParameter>(&zero,1),100,1u<<19,output)==SQLITE_OK&&same(output,ordinary));
 CHECK(session->statement_reuse_stats(stats)==SQLITE_OK&&stats.prepare_attempts==3&&stats.cached);
 const auto before_cancel=output;CHECK(session->query_scoped_reused_bound(query,std::span<const SqlParameter>(&zero,1),100,1u<<19,output,10000,{cancelled,nullptr})==SQLITE_INTERRUPT&&same(output,before_cancel));
 CHECK(session->statement_reuse_stats(stats)==SQLITE_OK&&stats.cached);
 const std::array<SqlParameter,2> mixed{SqlParameter{SqlParameter::Kind::text,0,std::string_view("a\0b",3)},SqlParameter{SqlParameter::Kind::null,0,{}}};
 CHECK(session->query_scoped_reused_bound("SELECT ?1,?2",mixed,100,1u<<20,output)==SQLITE_OK);
 CHECK(output.rows.size()==1&&output.rows[0].size()==2&&output.rows[0][0].kind==SqlValue::Kind::text&&output.rows[0][0].text==std::string("a\0b",3)&&output.rows[0][1].kind==SqlValue::Kind::null);
 const std::array<SqlParameter,2> changed{SqlParameter{SqlParameter::Kind::null,0,{}},SqlParameter{SqlParameter::Kind::text,0,std::string_view{}}};
 CHECK(session->statement_reuse_stats(stats)==SQLITE_OK);const auto mixed_hits=stats.cache_hits;
 CHECK(session->query_scoped_reused_bound("SELECT ?1,?2",changed,100,1u<<20,output)==SQLITE_OK);
 CHECK(output.rows.size()==1&&output.rows[0][0].kind==SqlValue::Kind::null&&output.rows[0][1].kind==SqlValue::Kind::text&&output.rows[0][1].text.empty());
 CHECK(session->statement_reuse_stats(stats)==SQLITE_OK&&stats.cache_hits==mixed_hits+1);
 std::unique_ptr<SqlSession> control;CHECK(SqlSession::open_scoped(snapshot,control)==SQLITE_OK);
 CHECK(control->clear_statement_reuse_cache()==SQLITE_MISUSE);
 CHECK(control->enable_statement_reuse(1u<<20)==SQLITE_OK);
 CHECK(control->clear_statement_reuse_cache()==SQLITE_OK);
 SqlScopedResult control_result;const char* simple="SELECT ?1,?2";
 CHECK(control->query_scoped_reused_bound(simple,mixed,100,1u<<20,control_result)==SQLITE_OK);
 CHECK(control->statement_reuse_stats(stats)==SQLITE_OK&&stats.prepare_attempts==1&&stats.cached);
 CHECK(control->clear_statement_reuse_cache()==SQLITE_OK&&control->clear_statement_reuse_cache()==SQLITE_OK);
 CHECK(control->statement_reuse_stats(stats)==SQLITE_OK&&stats.prepare_attempts==1&&!stats.cached&&stats.retained_statement_bytes==0);
 CHECK(control->query_scoped_reused_bound(simple,mixed,100,1u<<20,control_result)==SQLITE_OK);
 CHECK(control->statement_reuse_stats(stats)==SQLITE_OK&&stats.prepare_attempts==2&&stats.cache_hits==0&&stats.cached);
 const auto saved_control=control_result;CancelOnSecond later;
 CHECK(control->query_scoped_reused_bound(simple,changed,100,1u<<20,control_result,10000,{cancel_on_second,&later})==SQLITE_INTERRUPT);
 CHECK(later.calls>=2&&same(control_result,saved_control));
 CHECK(control->statement_reuse_stats(stats)==SQLITE_OK&&stats.cache_hits==1&&!stats.cached);
 CHECK(control->query_scoped_reused_bound(simple,mixed,100,1u<<20,control_result)==SQLITE_OK);
 CHECK(control->statement_reuse_stats(stats)==SQLITE_OK&&stats.prepare_attempts==3&&stats.cached);
 SqlSessionProbe::fail_row_copy_after(0);
 CHECK(control->query_scoped_reused_bound(simple,changed,100,1u<<20,control_result)==SQLITE_NOMEM&&same(control_result,saved_control));
 SqlSessionProbe::fail_row_copy_after(-1);
 CHECK(control->statement_reuse_stats(stats)==SQLITE_OK&&stats.cache_hits==2&&!stats.cached);
 CHECK(control->query_scoped_reused_bound(simple,changed,100,1u<<20,control_result)==SQLITE_OK);
 CHECK(control_result.rows.size()==1&&control_result.rows[0][0].kind==SqlValue::Kind::null&&control_result.rows[0][1].kind==SqlValue::Kind::text);
 CHECK(control->statement_reuse_stats(stats)==SQLITE_OK&&stats.prepare_attempts==4&&stats.cached);
 CHECK(control->close()==SQLITE_OK&&control->clear_statement_reuse_cache()==SQLITE_MISUSE);
 const auto prior=output;CHECK(session->query_scoped_reused_bound("DROP TABLE dmg_method_defs",{},100,1u<<20,output)!=SQLITE_OK&&same(output,prior));
 CHECK(session->query_scoped_reused_bound("SELECT 1 UNION ALL SELECT 2",{},1,1u<<20,output)==SQLITE_TOOBIG&&same(output,prior));
 CHECK(session->statement_reuse_stats(stats)==SQLITE_OK&&!stats.cached);
 CHECK(session->query_scoped_reused_bound("SELECT 1",{},100,1u<<20,output)==SQLITE_OK&&output.rows.size()==1);
 CHECK(session->close()==SQLITE_OK&&session->close()==SQLITE_OK);
 CHECK(session->statement_reuse_stats(stats)==SQLITE_MISUSE);
 std::unique_ptr<SqlSession> tiny;CHECK(SqlSession::open_scoped(snapshot,tiny)==SQLITE_OK&&tiny->enable_statement_reuse(1)==SQLITE_OK);
 CHECK(tiny->query_scoped_reused_bound("SELECT 1",{},10,1u<<20,output)==SQLITE_OK);
 CHECK(tiny->statement_reuse_stats(stats)==SQLITE_OK&&!stats.cached&&stats.retained_statement_bytes==0);
 CHECK(tiny->query_scoped_reused_bound("SELECT 1",{},10,1u<<20,output)==SQLITE_OK);
 CHECK(tiny->statement_reuse_stats(stats)==SQLITE_OK&&stats.prepare_attempts==2&&stats.cache_hits==0);
 CHECK(tiny->close()==SQLITE_OK);
 std::cout<<"PASS single-slot SQL statement reuse, parameter isolation and strict result boundaries\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
