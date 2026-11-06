#include "method_tables.hpp"
#include "result_commit/cursor.hpp"
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
#define CHECK(x) do { if (!(x)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #x); } while (false)
static std::vector<uint8_t> load(const std::filesystem::path& p){std::ifstream in(p,std::ios::binary);CHECK(in.good());return {std::istreambuf_iterator<char>(in),{}};}
static bool same(const SqlScopedResult& a,const SqlScopedResult& b){return a.rows==b.rows&&a.snapshot_id==b.snapshot_id&&a.source_scope==b.source_scope&&a.input_count==b.input_count&&a.source_count==b.source_count;}
static bool cancelled(void*) noexcept{return true;}
static SqlParameter integer(int64_t value){return {SqlParameter::Kind::integer,value,{}};}
static SqlParameter text(std::string_view value){return {SqlParameter::Kind::text,0,value};}
static SqlParameter null_value(){return {};}
static SqlRows ordinary(sqlite3* db,const char* sql,std::span<const SqlParameter> args){
 sqlite3_stmt* st=nullptr;CHECK(sqlite3_prepare_v2(db,sql,-1,&st,nullptr)==SQLITE_OK&&st);
 struct Guard{sqlite3_stmt* p;~Guard(){if(p)sqlite3_finalize(p);}} guard{st};CHECK(sqlite3_bind_parameter_count(st)==static_cast<int>(args.size()));
 for(size_t i=0;i<args.size();++i){const auto& v=args[i];const int n=static_cast<int>(i+1);int rc;
  if(v.kind==SqlParameter::Kind::null)rc=sqlite3_bind_null(st,n);
  else if(v.kind==SqlParameter::Kind::integer)rc=sqlite3_bind_int64(st,n,v.integer);
  else rc=sqlite3_bind_text(st,n,v.text.empty()?"":v.text.data(),static_cast<int>(v.text.size()),SQLITE_TRANSIENT);
  CHECK(rc==SQLITE_OK);
 }
 SqlRows rows;int rc;while((rc=sqlite3_step(st))==SQLITE_ROW){std::vector<SqlValue> row;for(int i=0;i<sqlite3_column_count(st);++i){SqlValue v;const int type=sqlite3_column_type(st,i);
   if(type==SQLITE_INTEGER){v.kind=SqlValue::Kind::integer;v.integer=sqlite3_column_int64(st,i);}
   else if(type==SQLITE_TEXT){v.kind=SqlValue::Kind::text;const auto* p=reinterpret_cast<const char*>(sqlite3_column_text(st,i));const auto n=sqlite3_column_bytes(st,i);CHECK(p&&n>=0);v.text.assign(p,static_cast<size_t>(n));}
   else CHECK(type==SQLITE_NULL);row.push_back(std::move(v));}rows.push_back(std::move(row));}
 CHECK(rc==SQLITE_DONE);return rows;
}
int main(int argc,char** argv){try{
 CHECK(argc==2);auto dex=load(argv[1]);dmg_engine* engine=nullptr;dmg_error error{};CHECK(dmg_engine_create(nullptr,&engine,&error)==DMG_OK);
 struct EngineGuard{dmg_engine* p;~EngineGuard(){if(p)dmg_engine_release(p);}} eg{engine};
 dmg_source_spec specs[2]={{0},{0}};for(int i=0;i<2;++i){specs[i].struct_size=sizeof(dmg_source_spec);specs[i].abi_version=DMG_ABI_VERSION;specs[i].format=DMG_INPUT_RAW_DEX;specs[i].data=dex.data();specs[i].size=dex.size();specs[i].slot_key=i?"two":"one";specs[i].role="code";}
 dmg_source_set_options options{sizeof(options),DMG_ABI_VERSION,"bind43",0,8,1u<<20};dmg_snapshot* snapshot=nullptr;CHECK(dmg_snapshot_open_sources(engine,specs,2,&options,&snapshot,&error)==DMG_OK);
 struct SnapshotGuard{dmg_snapshot* p;~SnapshotGuard(){if(p)dmg_snapshot_release(p);}} sg{snapshot};
 std::unique_ptr<SqlSession> session;CHECK(SqlSession::open_scoped_planned(snapshot,session,{}, {true,true})==SQLITE_OK);
 sqlite3* db=nullptr;CHECK(sqlite3_open(":memory:",&db)==SQLITE_OK);struct DbGuard{sqlite3* p;~DbGuard(){if(p)sqlite3_close(p);}} dg{db};
 // class_data order is direct methods followed by virtual methods, not method_id order.
 CHECK(sqlite3_exec(db,"CREATE TABLE ordinary(source_index INTEGER,ordinal INTEGER,name TEXT); INSERT INTO ordinary VALUES (0,0,'nativeMethod'),(0,1,'quiet'),(0,2,'uses'),(0,3,'abstractMethod'),(1,0,'nativeMethod'),(1,1,'quiet'),(1,2,'uses'),(1,3,'abstractMethod')",nullptr,nullptr,nullptr)==SQLITE_OK);
 const std::vector<SqlParameter> args{integer(0),integer(1),null_value(),integer(1),integer(0),integer(2),integer(3),text("quiet")};
 const char* query="SELECT source_index,ordinal,name FROM dmg_method_defs WHERE source_index IN (?1,?2,?3,?4) AND ordinal IN (?5,?6,?7) AND name<>?8 ORDER BY source_index,ordinal";
 const char* golden="SELECT source_index,ordinal,name FROM ordinary WHERE source_index IN (?1,?2,?3,?4) AND ordinal IN (?5,?6,?7) AND name<>?8 ORDER BY source_index,ordinal";
 SqlScopedResult result;const int query_rc=session->query_scoped_bound(query,args,100,1u<<20,result);const auto ordinary_rows=ordinary(db,golden,args);
 if(query_rc!=SQLITE_OK || result.rows!=ordinary_rows){std::cerr<<"typed query rc="<<query_rc<<" virtual rows="<<result.rows.size()<<" ordinary rows="<<ordinary_rows.size()<<'\n';for(const auto& row:result.rows){for(const auto& v:row)std::cerr<<" "<<v.integer<<":"<<v.text;std::cerr<<'\n';}}
 CHECK(query_rc==SQLITE_OK && result.rows==ordinary_rows);
 CHECK(result.rows.size()==6 && result.source_scope==SqlScopeCoverage::partial_source_scope && result.source_count==2 && result.input_count==2);
 const auto saved=result;
 const std::vector<SqlParameter> gap{integer(999),null_value(),text("uses")};
 CHECK(session->query_scoped_bound("SELECT ?3,?1",gap,100,1u<<20,result)==SQLITE_OK && result.rows==ordinary(db,"SELECT ?3,?1",gap));
 const std::vector<SqlParameter> repeated{integer(17)};
 CHECK(session->query_scoped_bound("SELECT :same+:same",repeated,100,1u<<20,result)==SQLITE_OK && result.rows==ordinary(db,"SELECT :same+:same",repeated));
 const std::string embedded("x\0y",3),injection("uses' OR 1=1 --");const std::vector<SqlParameter> values{null_value(),integer(INT64_MIN),integer(INT64_MAX),text(embedded),text(""),text(injection)};
 CHECK(session->query_scoped_bound("SELECT ?1,?2,?3,?4,?5,?6",values,100,1u<<20,result)==SQLITE_OK && result.rows==ordinary(db,"SELECT ?1,?2,?3,?4,?5,?6",values));
 CHECK(result.rows[0][3].text==embedded && result.rows[0][4].text.empty());
 const auto before_fail=result;
 CHECK(session->query_scoped_bound("SELECT ?1,?2",repeated,100,1u<<20,result)==SQLITE_RANGE && same(result,before_fail));
 CHECK(session->query_scoped_bound("SELECT 1",repeated,100,1u<<20,result)==SQLITE_RANGE && same(result,before_fail));
 std::vector<SqlParameter> too_many(257);CHECK(session->query_scoped_bound("SELECT 1",too_many,100,1u<<20,result)==SQLITE_MISUSE && same(result,before_fail));
 const std::vector<SqlParameter> invalid{{static_cast<SqlParameter::Kind>(99),0,{}}};CHECK(session->query_scoped_bound("SELECT ?1",invalid,100,1024,result)==SQLITE_MISUSE && same(result,before_fail));
 const std::string long_text(65,'x');const std::vector<SqlParameter> large{text(long_text),text(long_text)};
 CHECK(session->query_scoped_bound("SELECT ?1,?2",large,100,128,result)==SQLITE_TOOBIG && same(result,before_fail));
 CHECK(session->query_scoped_bound(query,args,100,1u<<20,result,10000,{cancelled,nullptr})==SQLITE_INTERRUPT && same(result,before_fail));
 std::unique_ptr<SqlCommittedCursor> cursor;CHECK(session->query_cursor_scoped_bound(query,args,100,1u<<20,60000,cursor)==SQLITE_OK && cursor);
 SqlCommittedPage page;SqlRows joined;while(true){CHECK(cursor->next(2,1u<<20,page)==SQLITE_OK);joined.insert(joined.end(),page.result.rows.begin(),page.result.rows.end());CHECK(page.result.source_scope==SqlScopeCoverage::partial_source_scope);if(page.final_page)break;}
 CHECK(joined==saved.rows && cursor->next(2,1u<<20,page)==SQLITE_DONE);
 std::unique_ptr<SqlCommittedCursor> bad;CHECK(session->query_cursor_scoped_bound("SELECT ?1,?2",repeated,100,1u<<20,60000,bad)==SQLITE_RANGE && !bad);
 SqlRows old;CHECK(session->query("SELECT ?1",std::optional<std::string_view>("uses"),100,1u<<20,old)==SQLITE_MISUSE);
 CHECK(session->close()==SQLITE_OK);CHECK(session->query_scoped_bound("SELECT 1",{},100,1024,result)==SQLITE_MISUSE && same(result,before_fail));
 std::cout<<"PASS typed bounded SQL bindings, strict commit and ordinary SQLite comparison\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
