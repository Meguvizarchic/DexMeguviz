#include "resident_session.hpp"
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
#define CHECK(x) do { if(!(x)) throw std::runtime_error("line "+std::to_string(__LINE__)+": " #x); } while(false)
static std::vector<uint8_t> load(const std::filesystem::path& path){std::ifstream in(path,std::ios::binary);CHECK(in.good());return {std::istreambuf_iterator<char>(in),{}};}
static bool cancel(void*) noexcept {return true;}
int main(int argc,char** argv){try{
 CHECK(argc==2);auto dex=load(argv[1]);dmg_engine* engine=nullptr;dmg_snapshot* snapshot=nullptr;dmg_error error{};
 CHECK(dmg_engine_create(nullptr,&engine,&error)==DMG_OK);
 struct E {dmg_engine* p;~E(){if(p)dmg_engine_release(p);}} eg{engine};
 dmg_source_spec spec{sizeof(spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,dex.data(),dex.size(),"resident","raw",nullptr};
 dmg_source_set_options opt{sizeof(opt),DMG_ABI_VERSION,"resident52",0,8,1u<<20};
 CHECK(dmg_snapshot_open_sources(engine,&spec,1,&opt,&snapshot,&error)==DMG_OK);
 struct S {dmg_snapshot* p;~S(){if(p)dmg_snapshot_release(p);}} sg{snapshot};
 std::unique_ptr<ResidentSession> session;
 CHECK(ResidentSession::open(snapshot,{2,4096,2048,1u<<20},session)==SQLITE_OK);
 std::unique_ptr<ResidentSession> quota,input;
 CHECK(ResidentSession::open(snapshot,{3,4096,1024,1u<<20},quota)==SQLITE_OK);
 CHECK(ResidentSession::open(snapshot,{3,8,4096,1u<<20},input)==SQLITE_OK);
 std::unique_ptr<ResidentSession> retained;
 CHECK(ResidentSession::open(snapshot,{2,4096,2048,1u<<20},retained)==SQLITE_OK);
 uint64_t retained_id=0;CHECK(retained->submit("SELECT 7",{},10,1024,10000,retained_id)==SQLITE_OK);
 auto* original=retained.get();
 CHECK(ResidentSession::open(snapshot,{2,4096,2048,1u<<20},retained)==SQLITE_MISUSE && retained.get()==original);
 CHECK(retained->run_next()==SQLITE_OK);
 const ResidentFinal* retained_view=nullptr;
 CHECK(retained->final(retained_id,retained_view)==SQLITE_OK && retained_view->execution_status==SQLITE_OK && retained_view->result.rows[0][0].integer==7);
 CHECK(ResidentSession::open(snapshot,{2,4096,2048,1u<<20},retained)==SQLITE_MISUSE && retained.get()==original);
 const ResidentFinal* after_reopen=nullptr;
 CHECK(retained->final(retained_id,after_reopen)==SQLITE_OK && after_reopen==retained_view && after_reopen->result.rows[0][0].integer==7);
 CHECK(retained->close()==SQLITE_BUSY && retained->acknowledge(retained_id)==SQLITE_OK && retained->close()==SQLITE_OK);
 CHECK(ResidentSession::open(snapshot,{2,4096,2048,1u<<20},retained)==SQLITE_MISUSE && retained.get()==original);
 retained.reset();

 dmg_snapshot_release(snapshot);sg.p=nullptr;dmg_engine_release(engine);eg.p=nullptr;
 uint64_t q1=0,q2=99;
 CHECK(quota->submit("SELECT 1",{},10,600,10000,q1)==SQLITE_OK);
 CHECK(quota->submit("SELECT 2",{},10,600,10000,q2)==SQLITE_FULL && q2==99);
 CHECK(quota->acknowledge(q1)==SQLITE_BUSY && quota->cancel_queued(q1)==SQLITE_OK);
 CHECK(quota->submit("SELECT 2",{},10,600,10000,q2)==SQLITE_FULL && q2==99);
 CHECK(quota->acknowledge(q1)==SQLITE_OK && quota->submit("SELECT 2",{},10,600,10000,q2)==SQLITE_OK);
 CHECK(quota->run_next()==SQLITE_OK && quota->acknowledge(q2)==SQLITE_OK && quota->close()==SQLITE_OK);
 uint64_t i1=0,i2=99;
 CHECK(input->submit("SELECT 1",{},10,100,10000,i1)==SQLITE_OK);
 CHECK(input->submit("SELECT 2",{},10,100,10000,i2)==SQLITE_FULL && i2==99);
 CHECK(input->cancel_queued(i1)==SQLITE_OK && input->submit("SELECT 2",{},10,100,10000,i2)==SQLITE_OK);
 CHECK(input->run_next()==SQLITE_OK && input->acknowledge(i1)==SQLITE_OK && input->acknowledge(i2)==SQLITE_OK && input->close()==SQLITE_OK);

 std::string sql="SELECT ?1",value="before";
 SqlParameter param{SqlParameter::Kind::text,0,value};uint64_t a=0,b=0,c=888;
 CHECK(session->submit(sql,{&param,1},10,1024,10000,a)==SQLITE_OK && a==1);
 CHECK(session->submit("SELECT 2",{},10,1024,10000,b)==SQLITE_OK && b==2);
 CHECK(session->submit("SELECT 3",{},10,1,10000,c)==SQLITE_FULL && c==888);
 const ResidentFinal* view=reinterpret_cast<const ResidentFinal*>(uintptr_t(1));
 CHECK(session->final(a,view)==SQLITE_BUSY && view==reinterpret_cast<const ResidentFinal*>(uintptr_t(1)));
 CHECK(session->cancel_queued(b)==SQLITE_OK);
 CHECK(session->final(b,view)==SQLITE_OK && view->id==b && view->execution_status==SQLITE_INTERRUPT && !view->has_profile && view->result.rows.empty());
 CHECK(session->close()==SQLITE_BUSY);
 sql="broken";value="after";
 CHECK(session->run_next()==SQLITE_OK);
 CHECK(session->final(a,view)==SQLITE_OK && view->execution_status==SQLITE_OK && view->has_profile && view->profile.prepared);
 CHECK(view->result.rows.size()==1 && view->result.rows[0].size()==1 && view->result.rows[0][0].text=="before");
 CHECK(view->result.source_scope==SqlScopeCoverage::partial_source_scope && !view->result.snapshot_id.empty());
 ResidentStats stats;CHECK(session->stats(stats)==SQLITE_OK && stats.queued==0 && stats.terminal==2 && stats.input_bytes==0 && stats.reserved_result_bytes==2048 && stats.cancelled==1);
 CHECK(session->submit("SELECT 3",{},10,1,10000,c)==SQLITE_FULL && c==888);
 CHECK(session->acknowledge(b)==SQLITE_OK && session->acknowledge(a)==SQLITE_OK);
 std::string again="next";param.text=again;
 CHECK(session->submit("SELECT ?1",{&param,1},10,1024,10000,c)==SQLITE_OK && c==3);
 CHECK(session->run_next()==SQLITE_OK && session->final(c,view)==SQLITE_OK && view->execution_status==SQLITE_OK);
 CHECK(view->result.rows[0][0].text=="next" && !view->profile.prepare_attempted && view->reuse.cache_hits==1);
 CHECK(session->acknowledge(c)==SQLITE_OK);
 uint64_t interrupted=0;
 CHECK(session->submit("SELECT ?1",{&param,1},10,1024,10000,interrupted)==SQLITE_OK);
 CHECK(session->run_next({cancel,nullptr})==SQLITE_OK && session->final(interrupted,view)==SQLITE_OK && view->execution_status==SQLITE_INTERRUPT && view->result.rows.empty());
 CHECK(session->acknowledge(interrupted)==SQLITE_OK);
 uint64_t failed=0;CHECK(session->submit("SELECT ?1",{&param,1},10,1024,10000,failed)==SQLITE_OK);
 SqlSessionProbe::fail_row_copy_after(0);
 CHECK(session->run_next()==SQLITE_OK && session->final(failed,view)==SQLITE_OK && view->execution_status==SQLITE_NOMEM && view->result.rows.empty());
 SqlSessionProbe::fail_row_copy_after(-1);
 CHECK(session->acknowledge(failed)==SQLITE_OK);
 uint64_t recovered=0;CHECK(session->submit("SELECT ?1",{&param,1},10,1024,10000,recovered)==SQLITE_OK);
 CHECK(session->run_next()==SQLITE_OK && session->final(recovered,view)==SQLITE_OK && view->execution_status==SQLITE_OK && view->result.rows[0][0].text=="next");
 CHECK(session->acknowledge(recovered)==SQLITE_OK);
 uint64_t invalid=0;CHECK(session->submit("SELECT",{},10,1024,10000,invalid)==SQLITE_OK);
 CHECK(session->run_next()==SQLITE_OK && session->final(invalid,view)==SQLITE_OK && view->execution_status==SQLITE_ERROR && view->result.rows.empty());
 CHECK(session->acknowledge(invalid)==SQLITE_OK);
 CHECK(session->run_next()==SQLITE_NOTFOUND && session->acknowledge(recovered)==SQLITE_NOTFOUND);
 CHECK(session->stats(stats)==SQLITE_OK && stats.queued==0 && stats.terminal==0 && stats.input_bytes==0 && stats.reserved_result_bytes==0 && stats.accepted==7 && stats.completed==7 && stats.cancelled==2);
 CHECK(session->close()==SQLITE_OK && session->close()==SQLITE_OK && session->stats(stats)==SQLITE_OK && stats.closed);
 CHECK(session->submit("SELECT 1",{},1,64,10000,c)==SQLITE_MISUSE);
 std::cout<<"PASS resident bounded queue, retained terminal and snapshot lifetime\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
