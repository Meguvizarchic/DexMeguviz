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
#define CHECK(x) do{if(!(x))throw std::runtime_error("reverse concurrent line "+std::to_string(__LINE__)+": " #x);}while(0)
struct Block {std::mutex mutex;std::condition_variable cv;unsigned calls=0;bool entered=false,release=false;};
static uint32_t block_during_build(void* p){auto& b=*static_cast<Block*>(p);std::unique_lock lock(b.mutex);if(++b.calls==3){b.entered=true;b.cv.notify_all();b.cv.wait_for(lock,std::chrono::seconds(10),[&]{return b.release;});}return 0;}
static uint32_t cancel_while_waiting(void* p){return ++*static_cast<unsigned*>(p)>=2;}
int main(int argc,char** argv){try{
 CHECK(argc==2);std::ifstream f(std::filesystem::path(argv[1]),std::ios::binary);CHECK(f.good());std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(f),{}};
 dmg_engine* engine=nullptr;dmg_snapshot* snapshot=nullptr;dmg_error error{};CHECK(dmg_engine_create(nullptr,&engine,&error)==DMG_OK);
 dmg_source_spec source{sizeof(source),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,bytes.data(),bytes.size(),"a","test",nullptr};
 dmg_source_set_options so{sizeof(so),DMG_ABI_VERSION,"reverse-concurrent",1,8,8u<<20};CHECK(dmg_snapshot_open_sources(engine,&source,1,&so,&snapshot,&error)==DMG_OK);
 dmg_reverse_options_v1 opt{sizeof(opt),DMG_ABI_VERSION,1000000,1u<<20,1000,0,nullptr,nullptr};
 constexpr unsigned N=8;std::atomic<bool> go=false;std::atomic<unsigned> ready=0;std::vector<std::thread> threads;std::array<dmg_status,N> status{};std::array<uint64_t,N> result{};
 for(unsigned i=0;i<N;++i)threads.emplace_back([&,i]{ready.fetch_add(1);while(!go.load())std::this_thread::yield();status[i]=dmg_snapshot_reverse_count_v1(snapshot,0,1,2,4,UINT32_MAX,&opt,&result[i],nullptr);});
 while(ready.load()!=N)std::this_thread::yield();go.store(true);for(auto& t:threads)t.join();
 for(unsigned i=0;i<N;++i)CHECK(status[i]==DMG_OK&&result[i]==2);
 dmg_reverse_profile_v1 p{};CHECK(dmg_snapshot_reverse_profile_v1(snapshot,&p,sizeof(p))==DMG_OK&&p.build_attempts==1&&p.builds==1&&p.reuses==N-1&&p.published_indexes==1);
 dmg_snapshot_release(snapshot);snapshot=nullptr;CHECK(dmg_snapshot_open_sources(engine,&source,1,&so,&snapshot,&error)==DMG_OK);
 Block block;auto build=opt;build.cancelled=block_during_build;build.cancel_context=&block;dmg_status buildStatus=DMG_INTERNAL_ERROR;uint64_t built=42;
 std::thread builder([&]{buildStatus=dmg_snapshot_reverse_count_v1(snapshot,0,1,2,4,UINT32_MAX,&build,&built,nullptr);});
 {std::unique_lock lock(block.mutex);const bool entered=block.cv.wait_for(lock,std::chrono::seconds(5),[&]{return block.entered;});if(!entered){block.release=true;block.cv.notify_all();lock.unlock();builder.join();throw std::runtime_error("builder did not enter");}}
 unsigned calls=0;auto wait=opt;wait.cancelled=cancel_while_waiting;wait.cancel_context=&calls;dmg_status waitStatus=DMG_INTERNAL_ERROR;uint64_t untouched=42;
 std::thread waiter([&]{waitStatus=dmg_snapshot_reverse_count_v1(snapshot,0,1,2,4,UINT32_MAX,&wait,&untouched,nullptr);});waiter.join();
 {std::lock_guard lock(block.mutex);block.release=true;block.cv.notify_all();}builder.join();
 CHECK(waitStatus==DMG_CANCELLED&&untouched==42&&calls>=2&&buildStatus==DMG_OK&&built==2);
 CHECK(dmg_snapshot_reverse_profile_v1(snapshot,&p,sizeof(p))==DMG_OK&&p.build_attempts==1&&p.builds==1&&p.build_failures==0&&p.reuses==0);
 dmg_snapshot_release(snapshot);snapshot=nullptr;CHECK(dmg_snapshot_open_sources(engine,&source,1,&so,&snapshot,&error)==DMG_OK);
 Block closing;auto accepted=opt;accepted.cancelled=block_during_build;accepted.cancel_context=&closing;dmg_status acceptedStatus=DMG_INTERNAL_ERROR;uint64_t acceptedCount=42;
 std::thread inflight([&]{acceptedStatus=dmg_snapshot_reverse_count_v1(snapshot,0,1,2,4,UINT32_MAX,&accepted,&acceptedCount,nullptr);});
 {std::unique_lock lock(closing.mutex);const bool entered=closing.cv.wait_for(lock,std::chrono::seconds(5),[&]{return closing.entered;});if(!entered){closing.release=true;closing.cv.notify_all();lock.unlock();inflight.join();throw std::runtime_error("inflight did not enter");}}
 dmg_snapshot_close(snapshot);{std::lock_guard lock(closing.mutex);closing.release=true;closing.cv.notify_all();}inflight.join();
 CHECK(acceptedStatus==DMG_OK&&acceptedCount==2);uint64_t rejected=42;
 CHECK(dmg_snapshot_reverse_count_v1(snapshot,0,1,2,4,UINT32_MAX,&opt,&rejected,nullptr)==DMG_CLOSED&&rejected==42);
 CHECK(dmg_snapshot_reverse_profile_v1(snapshot,&p,sizeof(p))==DMG_OK&&p.builds==1);
 dmg_snapshot_release(snapshot);dmg_engine_release(engine);std::cout<<"PASS reverse concurrent single build, cancellable waiter and close admission\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
