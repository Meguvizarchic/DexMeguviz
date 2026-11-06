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
static bool same(const SqlScopedResult& a,const SqlScopedResult& b) {
    return a.rows==b.rows && a.snapshot_id==b.snapshot_id && a.source_scope==b.source_scope &&
           a.input_count==b.input_count && a.source_count==b.source_count;
}
static int64_t scalar(const SqlScopedResult& r) {
    CHECK(r.rows.size()==1 && r.rows[0].size()==1 && r.rows[0][0].kind==SqlValue::Kind::integer);
    return r.rows[0][0].integer;
}
static bool cancelled(void*) noexcept { return true; }
int main(int argc,char** argv){try {
    CHECK(argc==2); const std::filesystem::path root(argv[1]);
    auto dex=load(root/"raw-a.dex"), resource=load(root/"resource-only.apk");
    dmg_engine* engine=nullptr; dmg_error error{}; CHECK(dmg_engine_create(nullptr,&engine,&error)==DMG_OK);
    struct EngineGuard { dmg_engine* p; ~EngineGuard(){if(p)dmg_engine_release(p);} } eg{engine};
    dmg_source_spec inputs[]{
        {sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,dex.data(),dex.size(),"one","raw",nullptr},
        {sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,dex.data(),dex.size(),"two","raw",nullptr},
        {sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_APK,1,resource.data(),resource.size(),"assets","res",nullptr}};
    dmg_source_set_options opts{sizeof(dmg_source_set_options),DMG_ABI_VERSION,"scope35",0,16,8u<<20};
    auto open_snapshot=[&](const dmg_source_spec* specs,uint32_t n,bool complete){
        dmg_snapshot* snapshot=nullptr; opts.scope_complete=complete?1:0;
        CHECK(dmg_snapshot_open_sources(engine,specs,n,&opts,&snapshot,&error)==DMG_OK && snapshot);return snapshot;
    };
    struct Guard { dmg_snapshot* p; ~Guard(){if(p)dmg_snapshot_release(p);} };
    Guard incomplete{open_snapshot(inputs,1,false)}, larger{open_snapshot(inputs,2,true)}, empty{open_snapshot(&inputs[2],1,false)};
    dmg_snapshot_overview overview{};CHECK(dmg_snapshot_get_overview(incomplete.p,&overview)==DMG_OK);
    const std::string expected_id=overview.snapshot_id;
    std::unique_ptr<SqlSession> legacy;
    CHECK(SqlSession::open(incomplete.p,legacy)==SQLITE_MISUSE && !legacy);
    std::unique_ptr<SqlSession> scoped;
    CHECK(SqlSession::open_scoped(incomplete.p,scoped)==SQLITE_OK && scoped);
    SqlRows bare{{SqlValue{SqlValue::Kind::text,0,"unchanged"}}}; const auto bare_saved=bare;
    CHECK(scoped->query("SELECT 1",std::nullopt,10,1024,bare)==SQLITE_MISUSE && bare==bare_saved);
    SqlScopedResult r;
    CHECK(scoped->query_scoped("SELECT count(*) FROM dmg_method_defs",std::nullopt,100,1u<<20,r)==SQLITE_OK);
    const auto partial_count=scalar(r);
    CHECK(partial_count>0 && r.source_scope==SqlScopeCoverage::partial_source_scope &&
          r.snapshot_id==expected_id && r.input_count==1 && r.source_count==1);
    CHECK(scoped->query_scoped("SELECT scope_complete FROM dmg_snapshot",std::nullopt,100,1u<<20,r)==SQLITE_OK);
    CHECK(scalar(r)==0 && r.source_scope==SqlScopeCoverage::partial_source_scope);
    CHECK(scoped->query_scoped("SELECT NOT EXISTS(SELECT 1 FROM dmg_method_defs WHERE name='not_present')",std::nullopt,100,1u<<20,r)==SQLITE_OK);
    CHECK(scalar(r)==1 && r.source_scope==SqlScopeCoverage::partial_source_scope); // no global absence claim
    const auto saved=r;
    CHECK(scoped->query_scoped("SELECT not_a_column FROM dmg_method_defs",std::nullopt,100,1u<<20,r)!=SQLITE_OK && same(r,saved));
    CHECK(scoped->query_scoped("SELECT 1 UNION ALL SELECT 2",std::nullopt,1,1u<<20,r)==SQLITE_TOOBIG && same(r,saved));
    CHECK(scoped->query_scoped("SELECT 1",std::nullopt,100,1u<<20,r,10000,{cancelled,nullptr})==SQLITE_INTERRUPT && same(r,saved));
    CHECK(scoped->query_scoped("DELETE FROM dmg_method_defs",std::nullopt,100,1u<<20,r)!=SQLITE_OK && same(r,saved));
    std::unique_ptr<SqlSession> planned;
    CHECK(SqlSession::open_scoped_planned(incomplete.p,planned,{}, {true})==SQLITE_OK && planned);
    SqlScopedResult planned_result;
    CHECK(planned->query_scoped("SELECT count(*) FROM dmg_method_defs WHERE source_index=0",std::nullopt,100,1u<<20,planned_result)==SQLITE_OK);
    CHECK(scalar(planned_result)==partial_count && planned_result.snapshot_id==expected_id &&
          planned_result.source_scope==SqlScopeCoverage::partial_source_scope);
    const auto planned_saved=planned_result;
    CHECK(planned->query_scoped("SELECT ordinal FROM dmg_method_defs WHERE source_index=0 UNION ALL SELECT 0",std::nullopt,1,1u<<20,planned_result)==SQLITE_TOOBIG && same(planned_result,planned_saved));
    CHECK(planned->query_scoped("SELECT ordinal FROM dmg_method_defs WHERE source_index=0",std::nullopt,100,1u<<20,planned_result,10000,{cancelled,nullptr})==SQLITE_INTERRUPT && same(planned_result,planned_saved));
    CHECK(planned->close()==SQLITE_OK);
    dmg_snapshot_release(incomplete.p); incomplete.p=nullptr; // session retains immutable dataset
    CHECK(scoped->query_scoped("SELECT count(*) FROM dmg_method_defs",std::nullopt,100,1u<<20,r)==SQLITE_OK);
    CHECK(scalar(r)==partial_count && r.snapshot_id==expected_id && r.source_scope==SqlScopeCoverage::partial_source_scope);
    CHECK(scoped->close()==SQLITE_OK); const auto post_close=r;
    CHECK(scoped->query_scoped("SELECT 1",std::nullopt,100,1u<<20,r)==SQLITE_MISUSE && same(r,post_close));
    std::unique_ptr<SqlSession> full;CHECK(SqlSession::open_scoped(larger.p,full)==SQLITE_OK);
    CHECK(full->query_scoped("SELECT count(*) FROM dmg_method_defs",std::nullopt,100,1u<<20,r)==SQLITE_OK);
    CHECK(scalar(r)==2*partial_count && r.input_count==2 && r.source_count==2 &&
          r.source_scope==SqlScopeCoverage::declared_complete_source_scope && r.snapshot_id!=expected_id);
    CHECK(full->query("SELECT 1",std::nullopt,100,1u<<20,bare)==SQLITE_MISUSE && bare==bare_saved);
    CHECK(full->close()==SQLITE_OK);
    std::unique_ptr<SqlSession> plain;CHECK(SqlSession::open(larger.p,plain)==SQLITE_OK);
    CHECK(plain->query_scoped("SELECT 1",std::nullopt,100,1u<<20,r)==SQLITE_MISUSE);CHECK(plain->close()==SQLITE_OK);
    std::unique_ptr<SqlSession> no_dex;CHECK(SqlSession::open_scoped(empty.p,no_dex)==SQLITE_OK);
    CHECK(no_dex->query_scoped("SELECT count(*) FROM dmg_sources",std::nullopt,100,1u<<20,r)==SQLITE_OK);
    CHECK(scalar(r)==0 && r.input_count==1 && r.source_count==0 && r.source_scope==SqlScopeCoverage::partial_source_scope);
    CHECK(no_dex->close()==SQLITE_OK);
    std::cout<<"PASS scoped SQL atomic rows and partial source coverage\n";return 0;
}catch(const std::exception& ex){std::cerr<<ex.what()<<'\n';return 1;}}
