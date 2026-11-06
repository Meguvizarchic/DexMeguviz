#include "dexmeguviz/dexmeguviz.h"
#include "execution/budget/account.hpp"
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>
using namespace dexmeguviz;
struct CancelAt {uint64_t calls=0,limit=0;};
static uint32_t count_or_cancel(void* p){auto& v=*static_cast<CancelAt*>(p);++v.calls;return v.limit&&v.calls>=v.limit?1u:0u;}
#define CHECK(x) do{if(!(x))throw std::runtime_error("reverse page fault line "+std::to_string(__LINE__)+": " #x);}while(0)
int main(int argc,char** argv){try{
 CHECK(argc==3);std::ifstream f(std::filesystem::path(argv[1]),std::ios::binary);CHECK(f.good());std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(f),{}};
 dmg_engine* engine=nullptr;dmg_error err{};CHECK(dmg_engine_create(nullptr,&engine,&err)==DMG_OK);dmg_source_spec source{sizeof(source),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,bytes.data(),bytes.size(),"a","test",nullptr};dmg_source_set_options so{sizeof(so),DMG_ABI_VERSION,"page-fault",1,8,8u<<20};dmg_reverse_options_v1 opt{sizeof(opt),DMG_ABI_VERSION,1000000,1u<<20,1000,0,nullptr,nullptr};
 unsigned failures=0;bool completed=false;
 for(int n=0;n<64&&!completed;++n){dmg_snapshot* s=nullptr;CHECK(dmg_snapshot_open_sources(engine,&source,1,&so,&s,&err)==DMG_OK);dmg_engine_stats before{},after{};CHECK(dmg_engine_get_stats(engine,&before)==DMG_OK);
  dmg_reverse_event_v1 rows[2],old[2];std::memset(rows,0x5a,sizeof(rows));std::memcpy(old,rows,sizeof(rows));uint32_t count=77;uint64_t total=88;
  test_fail_allocation_after(n);const auto status=dmg_snapshot_reverse_page_v1(s,0,1,2,4,UINT32_MAX,&opt,0,rows,2,&count,&total,&err);test_fail_allocation_after(-1);
  dmg_reverse_profile_v1 p{};CHECK(dmg_snapshot_reverse_profile_v1(s,&p,sizeof(p))==DMG_OK);
  if(status==DMG_OUT_OF_MEMORY){++failures;CHECK(count==77&&total==88&&std::memcmp(rows,old,sizeof(rows))==0&&p.builds==0&&p.build_failures==1&&p.published_indexes==0);CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&after.owned_bytes==before.owned_bytes);}
  else {CHECK(status==DMG_OK&&count==2&&total==2&&rows[0].dex_pc==0&&rows[1].dex_pc==3&&p.builds==1);completed=true;}
  dmg_snapshot_release(s);
 }
 CHECK(completed&&failures>=3);
 // Existing index hit needs exactly one page allocation; failure must retain
 // the already complete index and must not count as a successful reuse.
 {dmg_snapshot* s=nullptr;CHECK(dmg_snapshot_open_sources(engine,&source,1,&so,&s,&err)==DMG_OK);uint64_t hit=0;CHECK(dmg_snapshot_reverse_count_v1(s,0,1,2,4,UINT32_MAX,&opt,&hit,&err)==DMG_OK&&hit==2);
  dmg_engine_stats before{},after{};CHECK(dmg_engine_get_stats(engine,&before)==DMG_OK);dmg_reverse_event_v1 rows[2],old[2];std::memset(rows,0x5a,sizeof(rows));std::memcpy(old,rows,sizeof(rows));uint32_t count=77;uint64_t total=88;
  test_fail_allocation_after(0);const auto status=dmg_snapshot_reverse_page_v1(s,0,1,2,4,UINT32_MAX,&opt,0,rows,2,&count,&total,&err);test_fail_allocation_after(-1);
  dmg_reverse_profile_v1 p{};CHECK(status==DMG_OUT_OF_MEMORY&&count==77&&total==88&&std::memcmp(rows,old,sizeof(rows))==0);
  CHECK(dmg_snapshot_reverse_profile_v1(s,&p,sizeof(p))==DMG_OK&&p.builds==1&&p.reuses==0&&p.published_indexes==1);
  CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&after.owned_bytes==before.owned_bytes);
  CHECK(dmg_snapshot_reverse_page_v1(s,0,1,2,4,UINT32_MAX,&opt,0,rows,2,&count,&total,&err)==DMG_OK&&count==2&&total==2);
  CHECK(dmg_snapshot_reverse_profile_v1(s,&p,sizeof(p))==DMG_OK&&p.builds==1&&p.reuses==1);dmg_snapshot_release(s);
 }
 // Cancel just before publication after a large result has been staged.
 {std::ifstream input(std::filesystem::path(argv[2]),std::ios::binary);CHECK(input.good());std::vector<uint8_t> many{std::istreambuf_iterator<char>(input),{}};
  dmg_source_spec big{sizeof(big),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,many.data(),many.size(),"big","test",nullptr};dmg_snapshot* reference=nullptr;
  CHECK(dmg_snapshot_open_sources(engine,&big,1,&so,&reference,&err)==DMG_OK);std::vector<dmg_reverse_event_v1> rows(1024);uint32_t count=0;uint64_t total=0;CancelAt calls{};
  auto pageOpt=opt;pageOpt.max_records=2000;pageOpt.cancelled=count_or_cancel;pageOpt.cancel_context=&calls;
  CHECK(dmg_snapshot_reverse_page_v1(reference,0,1,2,1,UINT32_MAX,&pageOpt,0,rows.data(),1024,&count,&total,&err)==DMG_OK&&count==1024&&total==1024&&calls.calls>100);
  dmg_snapshot_release(reference);dmg_snapshot* cancelledSnapshot=nullptr;CHECK(dmg_snapshot_open_sources(engine,&big,1,&so,&cancelledSnapshot,&err)==DMG_OK);
  dmg_engine_stats before{},after{};CHECK(dmg_engine_get_stats(engine,&before)==DMG_OK);std::memset(rows.data(),0x5a,rows.size()*sizeof(rows[0]));const auto old=rows;count=77;total=88;CancelAt late{0,calls.calls-2};pageOpt.cancel_context=&late;
  CHECK(dmg_snapshot_reverse_page_v1(cancelledSnapshot,0,1,2,1,UINT32_MAX,&pageOpt,0,rows.data(),1024,&count,&total,&err)==DMG_CANCELLED&&count==77&&total==88&&std::memcmp(rows.data(),old.data(),rows.size()*sizeof(rows[0]))==0);
  dmg_reverse_profile_v1 p{};CHECK(dmg_snapshot_reverse_profile_v1(cancelledSnapshot,&p,sizeof(p))==DMG_OK&&p.builds==0&&p.build_failures==1&&p.published_indexes==0);
  CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&after.owned_bytes==before.owned_bytes);dmg_snapshot_release(cancelledSnapshot);
 }
 dmg_engine_release(engine);std::cout<<"PASS reverse page allocation-failure sweep and existing-cache rollback: "<<failures<<" failure positions\n";return 0;
}catch(const std::exception& e){test_fail_allocation_after(-1);std::cerr<<e.what()<<'\n';return 1;}}
