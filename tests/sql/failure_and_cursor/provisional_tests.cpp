#include "method_tables.hpp"
#include "dexmeguviz/dexmeguviz.h"
#include "sqlite3.h"
#include "../session_probe.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <vector>
using namespace dexmeguviz::desktop_sql;
#define CHECK(x) do { if (!(x)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #x); } while (false)
static std::vector<uint8_t> load(const std::filesystem::path& p){std::ifstream f(p,std::ios::binary);CHECK(f.good());return {std::istreambuf_iterator<char>(f),{}};}
struct Store {
    SqlRows rows;std::string snapshot;SqlScopeCoverage scope=SqlScopeCoverage::declared_complete_source_scope;
    uint32_t inputs=0,sources=0;bool invalid=false,reject=false,cancel=false;
    static int accept(void* context,uint64_t index,const SqlProvisionalScope& scope,const std::vector<SqlValue>& row) noexcept {
        auto& self=*static_cast<Store*>(context);
        try {
            if(index!=self.rows.size())self.invalid=true;
            if(self.rows.empty()){self.snapshot=scope.snapshot_id;self.scope=scope.source_scope;self.inputs=scope.input_count;self.sources=scope.source_count;}
            else if(self.snapshot!=scope.snapshot_id||self.scope!=scope.source_scope||self.inputs!=scope.input_count||self.sources!=scope.source_count)self.invalid=true;
            self.rows.push_back(row);
            return self.reject?1:0;
        } catch (...) {self.invalid=true;return 1;}
    }
    static bool cancelled(void* context) noexcept {return static_cast<Store*>(context)->cancel;}
    static int cancel_after(void* context,uint64_t index,const SqlProvisionalScope& scope,const std::vector<SqlValue>& row) noexcept {
        auto& self=*static_cast<Store*>(context);const int result=accept(context,index,scope,row);self.cancel=true;return result;
    }
};
struct CancelInsideSiteScan {
    int checks=0;
    static bool requested(void* context) noexcept {
        if (!SqlSessionProbe::in_site_cancel_callback()) return false;
        return ++static_cast<CancelInsideSiteScan*>(context)->checks == 6;
    }
};
static SqlRows ordinary(sqlite3* db,const char* sql){
    sqlite3_stmt* st=nullptr;CHECK(sqlite3_prepare_v2(db,sql,-1,&st,nullptr)==SQLITE_OK&&st);
    struct Guard{sqlite3_stmt* p;~Guard(){if(p)sqlite3_finalize(p);}} guard{st};SqlRows rows;int rc;
    while((rc=sqlite3_step(st))==SQLITE_ROW){std::vector<SqlValue> row;for(int i=0;i<sqlite3_column_count(st);++i){SqlValue v;const int type=sqlite3_column_type(st,i);
        if(type==SQLITE_INTEGER){v.kind=SqlValue::Kind::integer;v.integer=sqlite3_column_int64(st,i);}
        else if(type==SQLITE_TEXT){v.kind=SqlValue::Kind::text;const auto* p=reinterpret_cast<const char*>(sqlite3_column_text(st,i));CHECK(p);v.text.assign(p,static_cast<size_t>(sqlite3_column_bytes(st,i)));}
        else CHECK(type==SQLITE_NULL);row.push_back(std::move(v));}rows.push_back(std::move(row));}
    CHECK(rc==SQLITE_DONE);return rows;
}
int main(int argc,char** argv){try{
    CHECK(argc==2);const auto dex=load(argv[1]);dmg_engine* engine=nullptr;dmg_error error{};CHECK(dmg_engine_create(nullptr,&engine,&error)==DMG_OK);
    struct EngineGuard{dmg_engine* p;~EngineGuard(){if(p)dmg_engine_release(p);}} eg{engine};
    dmg_source_spec specs[2]={{0},{0}};for(int i=0;i<2;++i){specs[i].struct_size=sizeof(dmg_source_spec);specs[i].abi_version=DMG_ABI_VERSION;specs[i].format=DMG_INPUT_RAW_DEX;specs[i].data=dex.data();specs[i].size=dex.size();specs[i].slot_key=i?"two":"one";specs[i].role="code";}
    dmg_source_set_options options{sizeof(options),DMG_ABI_VERSION,"provisional45",0,8,1u<<20};dmg_snapshot* snapshot=nullptr;
    CHECK(dmg_snapshot_open_sources(engine,specs,2,&options,&snapshot,&error)==DMG_OK);
    struct SnapshotGuard{dmg_snapshot* p;~SnapshotGuard(){if(p)dmg_snapshot_release(p);}} sg{snapshot};
    dmg_snapshot_overview overview{};CHECK(dmg_snapshot_get_overview(snapshot,&overview)==DMG_OK);const std::string snapshot_id=overview.snapshot_id;
    std::unique_ptr<SqlSession> session;CHECK(SqlSession::open_scoped_planned(snapshot,session,{}, {true,true})==SQLITE_OK);CHECK(session->enable_profiling(true)==SQLITE_OK);
    sqlite3* db=nullptr;CHECK(sqlite3_open(":memory:",&db)==SQLITE_OK);struct DbGuard{sqlite3* p;~DbGuard(){if(p)sqlite3_close(p);}} dg{db};
    CHECK(sqlite3_exec(db,"CREATE TABLE ordinary(source_index INTEGER,ordinal INTEGER,name TEXT); INSERT INTO ordinary VALUES (0,0,'nativeMethod'),(0,1,'quiet'),(0,2,'uses'),(0,3,'abstractMethod'),(1,0,'nativeMethod'),(1,1,'quiet'),(1,2,'uses'),(1,3,'abstractMethod')",nullptr,nullptr,nullptr)==SQLITE_OK);
    const char* sql="SELECT source_index,ordinal,name FROM dmg_method_defs WHERE source_index IN (0,1) ORDER BY source_index,ordinal";
    const auto expected=ordinary(db,"SELECT source_index,ordinal,name FROM ordinary WHERE source_index IN (0,1) ORDER BY source_index,ordinal");
    SqlProvisionalOutcome terminal;Store success;CHECK(session->query_provisional_scoped_bound(sql,{},100,1u<<20,{&success,Store::accept},terminal)==SQLITE_OK);
    CHECK(terminal.terminal&&terminal.execution_status==SQLITE_OK&&terminal.rows_emitted==expected.size()&&!success.invalid&&success.rows==expected);
    CHECK(terminal.scope.snapshot_id==snapshot_id&&success.snapshot==snapshot_id&&terminal.scope.source_scope==SqlScopeCoverage::partial_source_scope&&success.scope==terminal.scope.source_scope&&success.inputs==2&&success.sources==2);
    SqlQueryProfile profile;CHECK(session->last_query_profile(profile)==SQLITE_OK&&profile.execution_status==SQLITE_OK&&profile.rows_staged==expected.size()&&profile.rows_committed==expected.size());
    const SqlParameter params[]={{SqlParameter::Kind::integer,1,{}},{SqlParameter::Kind::text,0,"uses"}};
    const auto expected_bound=ordinary(db,"SELECT source_index,ordinal,name FROM ordinary WHERE source_index=1 AND name='uses' ORDER BY ordinal");
    Store bound;terminal={};CHECK(session->query_provisional_scoped_bound("SELECT source_index,ordinal,name FROM dmg_method_defs WHERE source_index=?1 AND name=?2 ORDER BY ordinal",params,100,1u<<20,{&bound,Store::accept},terminal)==SQLITE_OK);
    CHECK(terminal.terminal&&terminal.rows_emitted==1&&bound.rows==expected_bound&&!bound.invalid);
    // BLOB is supported; REAL must still fail after the provisional integer prefix.
    Store late;terminal={};CHECK(session->query_provisional_scoped_bound("SELECT 1 UNION ALL SELECT 2.5",{},8,1024,{&late,Store::accept},terminal)==SQLITE_MISMATCH);
    CHECK(terminal.terminal&&terminal.execution_status==SQLITE_MISMATCH&&terminal.rows_emitted==1&&late.rows.size()==1);
    CHECK(session->last_query_profile(profile)==SQLITE_OK&&profile.execution_status==SQLITE_MISMATCH&&profile.rows_staged==1&&profile.rows_committed==0);
    Store budget;terminal={};CHECK(session->query_provisional_scoped_bound("SELECT 1 UNION ALL SELECT 2",{},1,1024,{&budget,Store::accept},terminal)==SQLITE_TOOBIG);
    CHECK(terminal.terminal&&terminal.rows_emitted==1&&budget.rows.size()==1);
    Store memory;terminal={};SqlSessionProbe::fail_row_copy_after(1);
    const int memory_rc=session->query_provisional_scoped_bound("SELECT 1 UNION ALL SELECT 2",{},8,1024,{&memory,Store::accept},terminal);
    SqlSessionProbe::fail_row_copy_after(-1);
    CHECK(memory_rc==SQLITE_NOMEM&&terminal.terminal&&terminal.execution_status==SQLITE_NOMEM&&terminal.rows_emitted==1&&memory.rows.size()==1);
    CHECK(session->last_query_profile(profile)==SQLITE_OK&&profile.execution_status==SQLITE_NOMEM&&profile.rows_staged==1&&profile.rows_committed==0);
    Store recovered;terminal={};CHECK(session->query_provisional_scoped_bound("SELECT 1 UNION ALL SELECT 2",{},8,1024,{&recovered,Store::accept},terminal)==SQLITE_OK);
    CHECK(terminal.terminal&&terminal.rows_emitted==2&&recovered.rows.size()==2);
    Store cancelled;terminal={};CHECK(session->query_provisional_scoped_bound("SELECT 1 UNION ALL SELECT 2",{},8,1024,{&cancelled,Store::cancel_after},terminal,10000,{Store::cancelled,&cancelled})==SQLITE_INTERRUPT);
    CHECK(terminal.terminal&&terminal.rows_emitted==1&&cancelled.rows.size()==1);
    Store stopped;stopped.reject=true;terminal={};CHECK(session->query_provisional_scoped_bound("SELECT 1 UNION ALL SELECT 2",{},8,1024,{&stopped,Store::accept},terminal)==SQLITE_ABORT);
    CHECK(terminal.terminal&&terminal.execution_status==SQLITE_ABORT&&terminal.rows_emitted==1&&stopped.rows.size()==1);
    // Each compound query emits a provisional row before entering the native
    // scan. A later scan cancellation or injected allocation failure must
    // produce a failed terminal rather than confirming that earlier row.
    const std::pair<const char*,const char*> scan_queries[] = {
        {"SELECT 1 UNION ALL SELECT count(*) FROM dmg_string_uses", "SELECT 1 UNION ALL SELECT 2"},
        {"SELECT 1 UNION ALL SELECT NOT EXISTS(SELECT 1 FROM dmg_invoke_sites WHERE dex_pc=-1)", "SELECT 1 UNION ALL SELECT 1"},
        {"SELECT 1 UNION ALL SELECT NOT EXISTS(SELECT 1 FROM dmg_invoke_sites WHERE dex_pc=2)", "SELECT 1 UNION ALL SELECT 0"}
    };
    for (const auto& [statement,oracle_sql] : scan_queries) {
        Store interrupted;terminal={};CancelInsideSiteScan scan;
        CHECK(session->query_provisional_scoped_bound(statement,{},8,1024,{&interrupted,Store::accept},terminal,10000,{CancelInsideSiteScan::requested,&scan})==SQLITE_INTERRUPT);
        CHECK(scan.checks==6 && terminal.terminal && terminal.execution_status==SQLITE_INTERRUPT && terminal.rows_emitted==1 && interrupted.rows.size()==1 && !interrupted.invalid);
        CHECK(terminal.scope.snapshot_id==snapshot_id && terminal.scope.source_scope==SqlScopeCoverage::partial_source_scope && terminal.scope.input_count==2 && terminal.scope.source_count==2);
        CHECK(session->last_query_profile(profile)==SQLITE_OK && profile.execution_status==SQLITE_INTERRUPT && profile.rows_staged==1 && profile.rows_committed==0);
        Store fault;terminal={};SqlSessionProbe::fail_scratch_after(0);
        const int fault_rc=session->query_provisional_scoped_bound(statement,{},8,1024,{&fault,Store::accept},terminal);
        SqlSessionProbe::fail_scratch_after(-1);
        CHECK(fault_rc==SQLITE_NOMEM && terminal.terminal && terminal.execution_status==SQLITE_NOMEM && terminal.rows_emitted==1 && fault.rows.size()==1);
        CHECK(session->last_query_profile(profile)==SQLITE_OK && profile.execution_status==SQLITE_NOMEM && profile.rows_staged==1 && profile.rows_committed==0);
        Store retry;terminal={};CHECK(session->query_provisional_scoped_bound(statement,{},8,1024,{&retry,Store::accept},terminal)==SQLITE_OK);
        CHECK(terminal.terminal && terminal.execution_status==SQLITE_OK && terminal.rows_emitted==2 && retry.rows==ordinary(db,oracle_sql) && !retry.invalid);
    }
    Store none;terminal={};CHECK(session->query_provisional_scoped_bound("SELECT 1 WHERE 0",{},8,1024,{&none,Store::accept},terminal)==SQLITE_OK);
    CHECK(terminal.terminal&&terminal.rows_emitted==0&&none.rows.empty()&&terminal.scope.snapshot_id==snapshot_id);
    Store invalid;terminal={};CHECK(session->query_provisional_scoped_bound("SELECT ?1",{},8,1024,{&invalid,Store::accept},terminal)==SQLITE_RANGE);
    CHECK(terminal.terminal&&terminal.execution_status==SQLITE_RANGE&&terminal.rows_emitted==0&&invalid.rows.empty());
    SqlScopedResult strict;CHECK(session->query_scoped(sql,std::nullopt,100,1u<<20,strict)==SQLITE_OK&&strict.rows==expected);
    CHECK(session->close()==SQLITE_OK);terminal.scope.snapshot_id="unchanged";terminal.terminal=false;
    CHECK(session->query_provisional_scoped_bound("SELECT 1",{},8,1024,{&none,Store::accept},terminal)==SQLITE_MISUSE&&!terminal.terminal&&terminal.scope.snapshot_id=="unchanged");
    std::cout<<"PASS explicit provisional rows, terminal status, rollback boundary and SQLite comparison\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
