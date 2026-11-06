#include "background_session.hpp"
#include "dexmeguviz/dexmeguviz.h"
#include "sqlite3.h"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
using namespace dexmeguviz::desktop_sql;
namespace dexmeguviz::desktop_sql {
void test_background_fail_next(int) noexcept;
void test_background_pause(bool);
bool test_background_wait_paused();
void test_background_finish_pause(bool);
bool test_background_wait_finish();
void test_background_reset_checks() noexcept;
int test_background_checks() noexcept;
int test_background_destroyed_on_owner() noexcept;
int test_background_destroyed_wrong_thread() noexcept;
}
#define CHECK(x) do { if(!(x)) throw std::runtime_error("line "+std::to_string(__LINE__)+": " #x); } while(false)
static std::vector<uint8_t> load(const std::filesystem::path& p){std::ifstream f(p,std::ios::binary);CHECK(f.good());return {std::istreambuf_iterator<char>(f),{}};}
static ResidentFinal wait_final(BackgroundSession& s,uint64_t id){
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(10);ResidentFinal out;
    for(;;){const int rc=s.final(id,out);if(rc==SQLITE_OK)return out;CHECK(rc==SQLITE_BUSY);CHECK(std::chrono::steady_clock::now()<deadline);std::this_thread::yield();}
}
int main(int argc,char** argv){try{
    CHECK(argc==2);const auto dex=load(argv[1]);dmg_engine* engine=nullptr;dmg_snapshot* snapshot=nullptr;dmg_error error{};
    CHECK(dmg_engine_create(nullptr,&engine,&error)==DMG_OK);
    struct E {dmg_engine* p;~E(){if(p)dmg_engine_release(p);}} eg{engine};
    dmg_source_spec spec{sizeof(spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,dex.data(),dex.size(),"worker","raw",nullptr};
    dmg_source_set_options opts{sizeof(opts),DMG_ABI_VERSION,"worker",0,8,1u<<20};
    CHECK(dmg_snapshot_open_sources(engine,&spec,1,&opts,&snapshot,&error)==DMG_OK);
    struct S {dmg_snapshot* p;~S(){if(p)dmg_snapshot_release(p);}} sg{snapshot};
    const ResidentLimits limits{4,8192,4096,1u<<20};std::unique_ptr<BackgroundSession> session;
    CHECK(BackgroundSession::open(snapshot,limits,session)==SQLITE_OK && session);
    auto* original=session.get();CHECK(BackgroundSession::open(snapshot,limits,session)==SQLITE_MISUSE && session.get()==original);
    std::unique_ptr<BackgroundSession> shutdown_session;CHECK(BackgroundSession::open(snapshot,limits,shutdown_session)==SQLITE_OK);

    dmg_snapshot_release(snapshot);sg.p=nullptr;dmg_engine_release(engine);eg.p=nullptr;
    // A worker paused after admission permits deterministic queued/running cancellation.
    test_background_pause(true);uint64_t first=0,second=0,third=0;
    CHECK(session->submit("SELECT 11",{},10,1024,10000,first)==SQLITE_OK && test_background_wait_paused());
    CHECK(session->submit("SELECT 22",{},10,1024,10000,second)==SQLITE_OK);
    ResidentFinal unchanged;unchanged.id=999;CHECK(session->final(first,unchanged)==SQLITE_BUSY && unchanged.id==999);
    CHECK(session->cancel(second)==SQLITE_OK);auto cancelled=wait_final(*session,second);
    CHECK(cancelled.id==second && cancelled.execution_status==SQLITE_INTERRUPT && cancelled.result.rows.empty());
    test_background_fail_next(2);CHECK(session->final(second,unchanged)==SQLITE_NOMEM && unchanged.id==999);
    CHECK(session->final(second,unchanged)==SQLITE_OK && unchanged.id==second && unchanged.execution_status==SQLITE_INTERRUPT);
    CHECK(session->acknowledge(second)==SQLITE_OK);
    uint64_t unchanged_id=777;test_background_fail_next(1);
    CHECK(session->submit("SELECT 3",{},10,1024,10000,unchanged_id)==SQLITE_NOMEM && unchanged_id==777);
    std::string text="original";SqlParameter parameter{SqlParameter::Kind::text,0,text};
    CHECK(session->submit("SELECT ?1",{&parameter,1},10,1024,10000,third)==SQLITE_OK);text="changed";
    CHECK(session->cancel(first)==SQLITE_OK);test_background_pause(false);
    auto final_first=wait_final(*session,first);auto final_third=wait_final(*session,third);
    CHECK(final_first.execution_status==SQLITE_INTERRUPT && final_first.result.rows.empty());
    CHECK(final_third.execution_status==SQLITE_OK && final_third.result.rows.size()==1 && final_third.result.rows[0][0].text=="original");
    CHECK(final_third.result.source_scope==SqlScopeCoverage::partial_source_scope && !final_third.result.snapshot_id.empty());
    CHECK(session->acknowledge(first)==SQLITE_OK && session->acknowledge(third)==SQLITE_OK);
    // Failure after admission still has a retained terminal and releases input.
    test_background_pause(true);uint64_t faulted=0;CHECK(session->submit("SELECT 4",{},10,1024,10000,faulted)==SQLITE_OK && test_background_wait_paused());
    test_background_fail_next(3);test_background_pause(false);auto failure=wait_final(*session,faulted);
    CHECK(failure.execution_status==SQLITE_NOMEM && failure.result.rows.empty());
    BackgroundStats stats;CHECK(session->stats(stats)==SQLITE_OK && stats.terminal==1 && stats.input_bytes==0 && stats.reserved_result_bytes==1024);
    CHECK(session->acknowledge(faulted)==SQLITE_OK);
    // The SQL execution has returned, but publication is paused. Cancellation
    // winning the state lock must reject that successful lower-level result.
    test_background_finish_pause(true);uint64_t commit_race=0;
    CHECK(session->submit("SELECT 42",{},10,1024,10000,commit_race)==SQLITE_OK && test_background_wait_finish());
    CHECK(session->cancel(commit_race)==SQLITE_OK);test_background_finish_pause(false);
    auto after_race=wait_final(*session,commit_race);
    CHECK(after_race.execution_status==SQLITE_INTERRUPT && after_race.result.rows.empty() && after_race.has_profile && after_race.profile.execution_status==SQLITE_OK);
    CHECK(session->acknowledge(commit_race)==SQLITE_OK);
    // An earlier execution error takes precedence over a later cancellation.
    test_background_finish_pause(true);test_background_fail_next(3);uint64_t error_race=0;
    CHECK(session->submit("SELECT 55",{},10,1024,10000,error_race)==SQLITE_OK && test_background_wait_finish());
    CHECK(session->cancel(error_race)==SQLITE_OK);test_background_finish_pause(false);
    CHECK(wait_final(*session,error_race).execution_status==SQLITE_NOMEM && session->acknowledge(error_race)==SQLITE_OK);
    // Observe SQLite cancel callback progress, then request cancellation while running.
    test_background_reset_checks();uint64_t busy=0;
    CHECK(session->submit("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000000000) SELECT count(*) FROM n",{},10,1024,1000000,busy)==SQLITE_OK);
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
    while(test_background_checks()<5 && std::chrono::steady_clock::now()<deadline)std::this_thread::yield();
    CHECK(test_background_checks()>=5 && session->cancel(busy)==SQLITE_OK);
    CHECK(wait_final(*session,busy).execution_status==SQLITE_INTERRUPT && session->acknowledge(busy)==SQLITE_OK);
    // SQLite progress budget exhaustion also reports SQLITE_INTERRUPT; the
    // counter records terminal codes, not just explicit cancel requests.
    BackgroundStats before_budget;CHECK(session->stats(before_budget)==SQLITE_OK);uint64_t budgeted=0;
    CHECK(session->submit("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000000) SELECT count(*) FROM n",{},10,1024,1,budgeted)==SQLITE_OK);
    CHECK(wait_final(*session,budgeted).execution_status==SQLITE_INTERRUPT);
    CHECK(session->stats(stats)==SQLITE_OK && stats.interrupted==before_budget.interrupted+1);
    CHECK(session->acknowledge(budgeted)==SQLITE_OK);
    // Four slots are a hard admission cap under concurrent submitters.
    test_background_pause(true);uint64_t blocker=0;CHECK(session->submit("SELECT 1",{},10,1024,10000,blocker)==SQLITE_OK && test_background_wait_paused());
    struct Attempt {int rc=0;uint64_t id=0;};std::vector<Attempt> attempts(6);std::vector<std::thread> clients;
    for(int i=0;i<6;++i)clients.emplace_back([&,i]{int64_t value=i+100;SqlParameter p{SqlParameter::Kind::integer,value,{}};attempts[i].rc=session->submit("SELECT ?1",{&p,1},10,1024,10000,attempts[i].id);});
    for(auto& t:clients)t.join();std::vector<uint64_t> ids{blocker};
    for(const auto& a:attempts){CHECK(a.rc==SQLITE_OK || a.rc==SQLITE_FULL);if(a.rc==SQLITE_OK)ids.push_back(a.id);else CHECK(a.id==0);}
    CHECK(ids.size()==4);std::sort(ids.begin(),ids.end());CHECK(std::adjacent_find(ids.begin(),ids.end())==ids.end());
    CHECK(session->shutdown(false)==SQLITE_OK);CHECK(session->submit("SELECT 2",{},1,10,1,unchanged_id)==SQLITE_MISUSE);
    CHECK(session->close()==SQLITE_BUSY);test_background_pause(false);
    uint64_t last_sequence=0;
    for(auto id:ids){const auto done=wait_final(*session,id);CHECK(done.execution_status==SQLITE_OK && done.has_profile && done.profile.sequence>last_sequence);last_sequence=done.profile.sequence;}
    // Multiple concurrent readers get independent copies; ack controls retention.
    std::vector<ResidentFinal> copies(4);clients.clear();std::vector<int> reads(4);
    for(int i=0;i<4;++i)clients.emplace_back([&,i]{reads[i]=session->final(ids[0],copies[i]);});
    for(auto& t:clients)t.join();for(int i=0;i<4;++i)CHECK(reads[i]==SQLITE_OK && copies[i].id==ids[0] && copies[i].execution_status==SQLITE_OK);
    CHECK(session->close()==SQLITE_BUSY);for(auto id:ids)CHECK(session->acknowledge(id)==SQLITE_OK);
    CHECK(session->final(ids[0],unchanged)==SQLITE_NOTFOUND && copies[0].id==ids[0]);
    test_background_fail_next(4);CHECK(session->close()==SQLITE_BUSY);CHECK(session->close()==SQLITE_OK && session->close()==SQLITE_OK);
    CHECK(session->stats(stats)==SQLITE_OK && stats.closed && stats.queued==0 && stats.running==0 && stats.terminal==0 && stats.input_bytes==0 && stats.reserved_result_bytes==0);
    test_background_pause(true);uint64_t live=0,queued=0;
    CHECK(shutdown_session->submit("SELECT 1",{},10,1024,10000,live)==SQLITE_OK && test_background_wait_paused());
    CHECK(shutdown_session->submit("SELECT 2",{},10,1024,10000,queued)==SQLITE_OK);
    CHECK(shutdown_session->shutdown(true)==SQLITE_OK && shutdown_session->close()==SQLITE_BUSY);
    CHECK(wait_final(*shutdown_session,queued).execution_status==SQLITE_INTERRUPT);
    test_background_pause(false);CHECK(wait_final(*shutdown_session,live).execution_status==SQLITE_INTERRUPT);
    CHECK(shutdown_session->acknowledge(queued)==SQLITE_OK && shutdown_session->acknowledge(live)==SQLITE_OK && shutdown_session->close()==SQLITE_OK);
    CHECK(test_background_destroyed_on_owner()==2 && test_background_destroyed_wrong_thread()==0);
    std::cout<<"PASS background resident queue, retained finals, worker cancellation and shutdown\n";return 0;
}catch(const std::exception& e){test_background_pause(false);test_background_finish_pause(false);test_background_fail_next(0);std::cerr<<e.what()<<'\n';return 1;}}
