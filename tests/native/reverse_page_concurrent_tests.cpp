#include "dexmeguviz/dexmeguviz.h"
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>
#define CHECK(x) do{if(!(x))throw std::runtime_error("reverse page concurrent line "+std::to_string(__LINE__)+": " #x);}while(0)
struct Block {std::mutex mutex;std::condition_variable cv;unsigned calls=0;bool entered=false,release=false;};
static uint32_t cancel_wait(void* p){return ++*static_cast<unsigned*>(p)>=2;}
static uint32_t block_build(void* p){auto& b=*static_cast<Block*>(p);std::unique_lock lock(b.mutex);if(++b.calls==3){b.entered=true;b.cv.notify_all();b.cv.wait_for(lock,std::chrono::seconds(10),[&]{return b.release;});}return 0;}
int main(int argc,char** argv){try{
 CHECK(argc==2);std::ifstream f(std::filesystem::path(argv[1]),std::ios::binary);CHECK(f.good());std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(f),{}};
 dmg_engine* engine=nullptr;dmg_snapshot* snapshot=nullptr;dmg_error error{};CHECK(dmg_engine_create(nullptr,&engine,&error)==DMG_OK);
 dmg_source_spec source{sizeof(source),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,bytes.data(),bytes.size(),"a","test",nullptr};dmg_source_set_options so{sizeof(so),DMG_ABI_VERSION,"page-concurrent",1,8,8u<<20};CHECK(dmg_snapshot_open_sources(engine,&source,1,&so,&snapshot,&error)==DMG_OK);
 dmg_reverse_options_v1 opt{sizeof(opt),DMG_ABI_VERSION,1000000,1u<<20,1000,0,nullptr,nullptr};constexpr unsigned N=8;std::atomic<bool> go=false;std::atomic<unsigned> ready=0;std::vector<std::thread> threads;std::array<dmg_status,N> status{};std::array<dmg_reverse_event_v1,N> rows{};std::array<uint32_t,N> counts{};std::array<uint64_t,N> totals{};
 for(unsigned i=0;i<N;++i)threads.emplace_back([&,i]{ready.fetch_add(1);while(!go.load())std::this_thread::yield();status[i]=dmg_snapshot_reverse_page_v1(snapshot,0,1,2,4,UINT32_MAX,&opt,i%2,&rows[i],1,&counts[i],&totals[i],nullptr);});
 while(ready.load()!=N)std::this_thread::yield();go.store(true);for(auto& t:threads)t.join();
 for(unsigned i=0;i<N;++i)CHECK(status[i]==DMG_OK&&counts[i]==1&&totals[i]==2&&rows[i].dex_pc==(i%2?3u:0u));
 dmg_reverse_profile_v1 p{};CHECK(dmg_snapshot_reverse_profile_v1(snapshot,&p,sizeof(p))==DMG_OK&&p.build_attempts==1&&p.builds==1&&p.reuses==N-1&&p.published_indexes==1);
 dmg_snapshot_release(snapshot);snapshot=nullptr;CHECK(dmg_snapshot_open_sources(engine,&source,1,&so,&snapshot,&error)==DMG_OK);
 // A queued reader may cancel while another thread owns the registry lock.
 Block blocking;auto build=opt;build.cancelled=block_build;build.cancel_context=&blocking;dmg_status buildStatus=DMG_INTERNAL_ERROR;dmg_reverse_event_v1 buildEvent{};uint32_t buildCount=0;uint64_t buildTotal=0;
 std::thread builder([&]{buildStatus=dmg_snapshot_reverse_page_v1(snapshot,0,1,2,4,UINT32_MAX,&build,0,&buildEvent,1,&buildCount,&buildTotal,nullptr);});
 {std::unique_lock lock(blocking.mutex);if(!blocking.cv.wait_for(lock,std::chrono::seconds(5),[&]{return blocking.entered;})){blocking.release=true;blocking.cv.notify_all();lock.unlock();builder.join();throw std::runtime_error("build did not enter");}}
 unsigned checks=0;auto cancelled=opt;cancelled.cancelled=cancel_wait;cancelled.cancel_context=&checks;dmg_reverse_event_v1 event{};event.dex_pc=99;uint32_t n=77;uint64_t t=88;dmg_status waiting=DMG_INTERNAL_ERROR;
 std::thread waiter([&]{waiting=dmg_snapshot_reverse_page_v1(snapshot,0,1,2,4,UINT32_MAX,&cancelled,1,&event,1,&n,&t,nullptr);});waiter.join();
 {std::lock_guard lock(blocking.mutex);blocking.release=true;blocking.cv.notify_all();}builder.join();
 CHECK(waiting==DMG_CANCELLED&&event.dex_pc==99&&n==77&&t==88&&checks>=2&&buildStatus==DMG_OK&&buildCount==1&&buildTotal==2);
 CHECK(dmg_snapshot_reverse_profile_v1(snapshot,&p,sizeof(p))==DMG_OK&&p.builds==1&&p.build_failures==0&&p.reuses==0);
 dmg_snapshot_release(snapshot);snapshot=nullptr;CHECK(dmg_snapshot_open_sources(engine,&source,1,&so,&snapshot,&error)==DMG_OK);
 Block block;auto accepted=opt;accepted.cancelled=block_build;accepted.cancel_context=&block;dmg_status acceptedStatus=DMG_INTERNAL_ERROR;dmg_reverse_event_v1 copied{};uint32_t count=77;uint64_t total=88;
 std::thread worker([&]{acceptedStatus=dmg_snapshot_reverse_page_v1(snapshot,0,1,2,4,UINT32_MAX,&accepted,0,&copied,1,&count,&total,nullptr);});
 {std::unique_lock lock(block.mutex);if(!block.cv.wait_for(lock,std::chrono::seconds(5),[&]{return block.entered;})){block.release=true;block.cv.notify_all();lock.unlock();worker.join();throw std::runtime_error("worker did not enter");}}
 dmg_snapshot_close(snapshot);{std::lock_guard lock(block.mutex);block.release=true;block.cv.notify_all();}worker.join();
 CHECK(acceptedStatus==DMG_OK&&count==1&&total==2&&copied.dex_pc==0);dmg_reverse_event_v1 untouched=copied;count=77;total=88;
 CHECK(dmg_snapshot_reverse_page_v1(snapshot,0,1,2,4,UINT32_MAX,&opt,0,&untouched,1,&count,&total,nullptr)==DMG_CLOSED&&count==77&&total==88&&untouched.dex_pc==copied.dex_pc);
 CHECK(dmg_snapshot_reverse_profile_v1(snapshot,&p,sizeof(p))==DMG_OK&&p.builds==1);dmg_snapshot_release(snapshot);dmg_engine_release(engine);
 CHECK(copied.caller_ordinal==2&&copied.caller_method_ref==3&&copied.dex_pc==0&&copied.target_index==4);
 std::cout<<"PASS reverse page concurrent ordering, admission and copied lifetime\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
