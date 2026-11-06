#include "dexmeguviz/dexmeguviz.h"
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
namespace dexmeguviz::runtime {extern std::atomic<void(*)(int)> test_apk_fd_dup_barrier;}
#define CHECK(x) do{if(!(x))throw std::runtime_error("apk fd cloexec line "+std::to_string(__LINE__)+": " #x);}while(false)
namespace {
const char* self_path=nullptr;bool entered=false,flag_set=false,child_clean=false;dev_t target_device{};ino_t target_inode{};
void after_dup(int fd){
 entered=true;const int flags=fcntl(fd,F_GETFD);flag_set=flags>=0&&(flags&FD_CLOEXEC)!=0;
 char f[32],d[64],i[64];std::snprintf(f,sizeof(f),"%d",fd);std::snprintf(d,sizeof(d),"%llu",static_cast<unsigned long long>(target_device));std::snprintf(i,sizeof(i),"%llu",static_cast<unsigned long long>(target_inode));
 const pid_t child=fork();if(child<0)return;if(child==0){execl(self_path,self_path,"--probe",f,d,i,static_cast<char*>(nullptr));_exit(127);}
 int status=0;pid_t done;do{done=waitpid(child,&status,0);}while(done<0&&errno==EINTR);
 child_clean=done==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0;
}
int probe(int fd,dev_t device,ino_t inode){
 struct stat observed{};if(fstat(fd,&observed)<0)return errno==EBADF?0:2;
 // The dynamic loader may reuse the closed descriptor number. Only a still
 // open descriptor to the original fixture counts as inheritance.
 return observed.st_dev==device&&observed.st_ino==inode?3:0;
}
bool same(const dmg_engine_stats& a,const dmg_engine_stats& b){return a.owned_bytes==b.owned_bytes&&a.source_bytes==b.source_bytes&&a.fact_bytes==b.fact_bytes&&a.scratch_bytes==b.scratch_bytes&&a.query_bytes==b.query_bytes&&a.result_bytes==b.result_bytes&&a.control_bytes==b.control_bytes&&a.borrowed_bytes==b.borrowed_bytes&&a.active_jobs==b.active_jobs;}
}
int main(int argc,char** argv){try{
 if(argc==5&&std::strcmp(argv[1],"--probe")==0)return probe(std::atoi(argv[2]),static_cast<dev_t>(std::strtoull(argv[3],nullptr,10)),static_cast<ino_t>(std::strtoull(argv[4],nullptr,10)));
 CHECK(argc==3);self_path=argv[0];int fd=open(argv[1],O_RDONLY|O_CLOEXEC);CHECK(fd>=0);struct stat st{};CHECK(fstat(fd,&st)==0&&S_ISREG(st.st_mode)&&st.st_size>7);target_device=st.st_dev;target_inode=st.st_ino;CHECK(lseek(fd,7,SEEK_SET)==7);
 dmg_engine_options eo{sizeof(eo),DMG_ABI_VERSION,32ull<<20,0,16ull<<20,4,0};dmg_engine* engine=nullptr;dmg_error error{};CHECK(dmg_engine_create(&eo,&engine,&error)==DMG_OK);dmg_engine_stats before{},after{};CHECK(dmg_engine_get_stats(engine,&before)==DMG_OK);
 dmg_apk_fd_options_v1 options{sizeof(options),DMG_ABI_VERSION,"cloexec",0,64,16ull<<20,16ull<<20,8ull<<20,16ull<<20,100000,0,16ull<<20,8ull<<20};
 dmg_apk_fd_spec_v1 spec{sizeof(spec),DMG_ABI_VERSION,fd,0,0,static_cast<uint64_t>(st.st_size),"base","apk",nullptr};dmg_snapshot* snapshot=reinterpret_cast<dmg_snapshot*>(1);
 dexmeguviz::runtime::test_apk_fd_dup_barrier.store(&after_dup);const auto status=dmg_snapshot_open_apk_fds_v1(engine,&spec,1,&options,&snapshot,&error);dexmeguviz::runtime::test_apk_fd_dup_barrier.store(nullptr);
#if defined(DMG_TEST_APK_NO_CLOEXEC) || !defined(F_DUPFD_CLOEXEC)
 CHECK(status==DMG_UNSUPPORTED&&snapshot==nullptr&&!entered);
#else
 CHECK(status==DMG_OK&&snapshot&&entered&&flag_set&&child_clean);dmg_snapshot_release(snapshot);
#endif
 CHECK(lseek(fd,0,SEEK_CUR)==7&&fcntl(fd,F_GETFD)>=0&&dmg_engine_get_stats(engine,&after)==DMG_OK&&same(before,after));
 // The legacy raw entry does not take the APK duplication branch.
 int rawfd=open(argv[2],O_RDONLY|O_CLOEXEC);CHECK(rawfd>=0);struct stat raw{};CHECK(fstat(rawfd,&raw)==0&&raw.st_size>7&&lseek(rawfd,7,SEEK_SET)==7);entered=false;
 dmg_open_options old{sizeof(old),DMG_ABI_VERSION,16ull<<20,"legacy","slot",nullptr};snapshot=nullptr;dexmeguviz::runtime::test_apk_fd_dup_barrier.store(&after_dup);const auto oldstatus=dmg_snapshot_open_fd(engine,rawfd,0,static_cast<uint64_t>(raw.st_size),&old,&snapshot,&error);dexmeguviz::runtime::test_apk_fd_dup_barrier.store(nullptr);
 CHECK(oldstatus==DMG_OK&&snapshot&&!entered&&lseek(rawfd,0,SEEK_CUR)==7);dmg_snapshot_release(snapshot);CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&same(before,after));
 CHECK(close(rawfd)==0&&close(fd)==0);dmg_engine_release(engine);std::cout<<"PASS APK fd close-on-exec and legacy offset\n";return 0;
 }catch(const std::exception& e){dexmeguviz::runtime::test_apk_fd_dup_barrier.store(nullptr);std::cerr<<e.what()<<'\n';return 1;}}
