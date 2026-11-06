#include "dexmeguviz/dexmeguviz.h"
#include "execution/budget/account.hpp"
#include <atomic>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#define OPEN(p) _open((p),_O_RDONLY|_O_BINARY)
#define CLOSE _close
#define SEEK _lseeki64
#else
#include <fcntl.h>
#include <unistd.h>
#define OPEN(p) open((p),O_RDONLY)
#define CLOSE close
#define SEEK lseek
#endif
namespace dexmeguviz::runtime {extern std::atomic<void(*)(uint64_t)> test_apk_fd_read_barrier;}
#define CHECK(x) do{if(!(x))throw std::runtime_error("apk fd fault line "+std::to_string(__LINE__)+": " #x);}while(false)
namespace {
const char* mutation_path=nullptr;long mutation_offset=0;bool attempted=false,changed=false;unsigned read_calls=0;bool inject_late=false;
void barrier(uint64_t done){
 ++read_calls;
 if(inject_late&&read_calls==2){dexmeguviz::test_fail_allocation_after(0);return;}
 if(!mutation_path||attempted||done<65536)return;attempted=true;
 auto* f=std::fopen(mutation_path,"r+b");if(!f)return;
 if(std::fseek(f,mutation_offset,SEEK_SET)==0&&std::fgetc(f)==0&&std::fseek(f,mutation_offset,SEEK_SET)==0&&std::fputc(0x6d,f)==0x6d&&std::fflush(f)==0)changed=true;
 std::fclose(f);
}
uint64_t file_size(int fd){auto old=SEEK(fd,0,SEEK_CUR);auto size=SEEK(fd,0,SEEK_END);CHECK(old>=0&&size>0&&SEEK(fd,old,SEEK_SET)==old);return static_cast<uint64_t>(size);}
bool same(const dmg_engine_stats& a,const dmg_engine_stats& b){return a.owned_bytes==b.owned_bytes&&a.source_bytes==b.source_bytes&&a.fact_bytes==b.fact_bytes&&a.scratch_bytes==b.scratch_bytes&&a.query_bytes==b.query_bytes&&a.result_bytes==b.result_bytes&&a.control_bytes==b.control_bytes&&a.borrowed_bytes==b.borrowed_bytes&&a.active_jobs==b.active_jobs;}
}
int main(int argc,char** argv){try{
 CHECK(argc==6);int small=OPEN(argv[1]),resource=OPEN(argv[2]),early=OPEN(argv[3]),late=OPEN(argv[4]);CHECK(small>=0&&resource>=0&&early>=0&&late>=0);
 auto small_size=file_size(small),resource_size=file_size(resource),early_size=file_size(early),late_size=file_size(late);CHECK(early_size>131073&&early_size==late_size);
 dmg_engine_options eo{sizeof(eo),DMG_ABI_VERSION,32ull<<20,0,16ull<<20,4,0};dmg_engine* engine=nullptr;dmg_error error{};CHECK(dmg_engine_create(&eo,&engine,&error)==DMG_OK);
 dmg_apk_fd_options_v1 options{sizeof(options),DMG_ABI_VERSION,"fault",0,64,16ull<<20,32ull<<20,8ull<<20,16ull<<20,100000,0,16ull<<20,8ull<<20};
 dmg_apk_fd_spec_v1 specs[]={{sizeof(dmg_apk_fd_spec_v1),DMG_ABI_VERSION,small,0,0,small_size,"base","apk",nullptr},{sizeof(dmg_apk_fd_spec_v1),DMG_ABI_VERSION,resource,1,0,resource_size,"split","apk",nullptr}};
 dmg_engine_stats baseline{},after{};CHECK(dmg_engine_get_stats(engine,&baseline)==DMG_OK);unsigned failed=0,success=0;
 for(int n=0;n<512;++n){dmg_snapshot* out=reinterpret_cast<dmg_snapshot*>(1);error={};dexmeguviz::test_fail_allocation_after(n);const auto status=dmg_snapshot_open_apk_fds_v1(engine,specs,2,&options,&out,&error);dexmeguviz::test_fail_allocation_after(-1);
  if(status==DMG_OK){CHECK(out);dmg_snapshot_release(out);++success;}
  else {CHECK((status==DMG_OUT_OF_MEMORY||status==DMG_BUDGET_EXCEEDED)&&out==nullptr);++failed;}
  CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&same(baseline,after));}
 CHECK(failed>0&&success>0);
 {dmg_snapshot* out=reinterpret_cast<dmg_snapshot*>(1);error={};read_calls=0;inject_late=true;dexmeguviz::runtime::test_apk_fd_read_barrier.store(&barrier);auto status=dmg_snapshot_open_apk_fds_v1(engine,specs,2,&options,&out,&error);dexmeguviz::runtime::test_apk_fd_read_barrier.store(nullptr);dexmeguviz::test_fail_allocation_after(-1);inject_late=false;CHECK(read_calls>=2&&status==DMG_OUT_OF_MEMORY&&out==nullptr);CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&same(baseline,after));}
 for(int mode=0;mode<2;++mode){int fd=mode?late:early;mutation_path=mode?argv[4]:argv[3];mutation_offset=mode?131072:4096;attempted=changed=false;read_calls=0;
  dmg_apk_fd_spec_v1 s{sizeof(s),DMG_ABI_VERSION,fd,0,0,mode?late_size:early_size,"mutating","apk",argv[5]};dmg_snapshot* out=reinterpret_cast<dmg_snapshot*>(1);error={};CHECK(SEEK(fd,7,SEEK_SET)==7);dexmeguviz::runtime::test_apk_fd_read_barrier.store(&barrier);auto status=dmg_snapshot_open_apk_fds_v1(engine,&s,1,&options,&out,&error);dexmeguviz::runtime::test_apk_fd_read_barrier.store(nullptr);
  CHECK(attempted&&changed&&SEEK(fd,0,SEEK_CUR)==7);
  if(mode){CHECK(status==DMG_SOURCE_MISMATCH&&out==nullptr);}else{dmg_input_info in{};CHECK(status==DMG_OK&&out&&dmg_snapshot_get_input_info(out,0,&in)==DMG_OK&&in.expected_digest_verified&&std::strcmp(in.source_sha256,argv[5])==0);dmg_snapshot_release(out);}
  CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&same(baseline,after));mutation_path=nullptr;
 }
 CHECK(CLOSE(small)==0&&CLOSE(resource)==0&&CLOSE(early)==0&&CLOSE(late)==0);dmg_engine_release(engine);
 std::cout<<"PASS fd allocation failures="<<failed<<" successes="<<success<<" and mutation before/after copied offsets; ledger restored\n";return 0;
 }catch(const std::exception& e){dexmeguviz::runtime::test_apk_fd_read_barrier.store(nullptr);dexmeguviz::test_fail_allocation_after(-1);std::cerr<<e.what()<<'\n';return 1;}}
