#include "dexmeguviz/dexmeguviz.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#define CHECK(x) do{if(!(x)){fprintf(stderr,"apk-fd line %d: %s\n",__LINE__,#x);return 1;}}while(0)
static unsigned char* read_file(const char* path,uint64_t* size){
 FILE* f=fopen(path,"rb");long n;unsigned char* p;if(!f)return NULL;
 if(fseek(f,0,SEEK_END)||(n=ftell(f))<0||fseek(f,0,SEEK_SET)){fclose(f);return NULL;}
 p=(unsigned char*)malloc((size_t)n);if(!p||fread(p,1,(size_t)n,f)!=(size_t)n){free(p);fclose(f);return NULL;}
 fclose(f);*size=(uint64_t)n;return p;
}
static uint64_t size_fd(int fd){int64_t old=SEEK(fd,0,SEEK_CUR),n=SEEK(fd,0,SEEK_END);if(old<0||n<0||SEEK(fd,old,SEEK_SET)!=old)return UINT64_MAX;return (uint64_t)n;}
static int same_stats(const dmg_engine_stats* a,const dmg_engine_stats* b){return a->owned_bytes==b->owned_bytes&&a->source_bytes==b->source_bytes&&a->fact_bytes==b->fact_bytes&&a->scratch_bytes==b->scratch_bytes&&a->query_bytes==b->query_bytes&&a->result_bytes==b->result_bytes&&a->control_bytes==b->control_bytes&&a->borrowed_bytes==b->borrowed_bytes&&a->active_jobs==b->active_jobs;}
static int text_equal(const uint16_t* a,uint64_t al,const uint16_t* b,uint64_t bl){return al==bl&&(!al||memcmp(a,b,(size_t)al*sizeof(uint16_t))==0);}
static int same_snapshot(dmg_snapshot* a,dmg_snapshot* b){
 dmg_snapshot_overview x,y;uint32_t i;CHECK(dmg_snapshot_get_overview(a,&x)==DMG_OK&&dmg_snapshot_get_overview(b,&y)==DMG_OK);
 CHECK(strcmp(x.snapshot_id,y.snapshot_id)==0&&x.input_count==y.input_count&&x.source_count==y.source_count&&x.scope_complete==y.scope_complete&&x.input_bytes==y.input_bytes&&x.dex_bytes==y.dex_bytes);
 for(i=0;i<x.input_count;i++){dmg_input_info u,v;CHECK(dmg_snapshot_get_input_info(a,i,&u)==DMG_OK&&dmg_snapshot_get_input_info(b,i,&v)==DMG_OK);CHECK(u.input_index==v.input_index&&u.format==v.format&&u.allow_no_dex==v.allow_no_dex&&u.source_count==v.source_count&&u.input_bytes==v.input_bytes&&u.expected_digest_verified==v.expected_digest_verified&&u.container_metadata_checked==v.container_metadata_checked&&strcmp(u.slot_key,v.slot_key)==0&&strcmp(u.role,v.role)==0&&strcmp(u.source_sha256,v.source_sha256)==0&&strcmp(u.content_id,v.content_id)==0);}
 for(i=0;i<x.source_count;i++){dmg_source_info u,v;CHECK(dmg_snapshot_get_source_info(a,i,&u)==DMG_OK&&dmg_snapshot_get_source_info(b,i,&v)==DMG_OK);CHECK(u.source_index==v.source_index&&u.input_index==v.input_index&&u.archive_entry_index==v.archive_entry_index&&u.crc_verified==v.crc_verified&&u.header_consistency_verified==v.header_consistency_verified&&u.expected_digest_verified==v.expected_digest_verified&&strcmp(u.slot_key,v.slot_key)==0&&strcmp(u.role,v.role)==0&&strcmp(u.archive_entry_name,v.archive_entry_name)==0&&strcmp(u.archive_sha256,v.archive_sha256)==0&&strcmp(u.dex.source_sha256,v.dex.source_sha256)==0&&strcmp(u.dex.occurrence_id,v.dex.occurrence_id)==0&&strcmp(u.logical_dex_id,v.logical_dex_id)==0);}
 return 0;
}
static int same_results(dmg_engine* e,dmg_snapshot* a,dmg_snapshot* b){
 const char* json="{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":true,\"intent\":\"enumerate\",\"max_results\":100}";dmg_query* q=NULL;dmg_result *x=NULL,*y=NULL;dmg_result_info u,v;dmg_error error={0};uint32_t i;
 CHECK(dmg_query_compile_json(e,(const uint8_t*)json,strlen(json),&q,&error)==DMG_OK);
 CHECK(dmg_query_execute(a,q,&x,&error)==DMG_OK&&dmg_query_execute(b,q,&y,&error)==DMG_OK);
 CHECK(dmg_result_get_info(x,&u)==DMG_OK&&dmg_result_get_info(y,&v)==DMG_OK&&u.candidates_count==v.candidates_count&&u.coverage==v.coverage&&u.decision==v.decision&&u.visited_methods==v.visited_methods);
 for(i=0;i<u.candidates_count;i++){dmg_method_row r,s;dmg_source_info p,t;CHECK(dmg_result_get_method(x,i,&r)==DMG_OK&&dmg_result_get_method(y,i,&s)==DMG_OK&&dmg_result_get_origin(x,i,&p)==DMG_OK&&dmg_result_get_origin(y,i,&t)==DMG_OK);CHECK(r.method_index==s.method_index&&r.access_flags==s.access_flags&&r.declaration_offset==s.declaration_offset&&r.code_offset==s.code_offset&&text_equal(r.owner,r.owner_length,s.owner,s.owner_length)&&text_equal(r.name,r.name_length,s.name,s.name_length)&&text_equal(r.prototype,r.prototype_length,s.prototype,s.prototype_length)&&strcmp(p.dex.occurrence_id,t.dex.occurrence_id)==0);}
 dmg_result_release(x);dmg_result_release(y);dmg_query_release(q);return 0;
}
static int failed(dmg_engine* e,dmg_apk_fd_spec_v1* specs,uint32_t count,dmg_apk_fd_options_v1* opts,dmg_status wanted){
 dmg_snapshot* out=(dmg_snapshot*)(uintptr_t)1;dmg_error err={0};dmg_engine_stats before,after;CHECK(dmg_engine_get_stats(e,&before)==DMG_OK);dmg_status got=dmg_snapshot_open_apk_fds_v1(e,specs,count,opts,&out,&err);
 if(got!=wanted)fprintf(stderr,"expected=%u got=%u detail=%s\n",(unsigned)wanted,(unsigned)got,err.message);
 CHECK(got==wanted&&out==NULL);CHECK(dmg_engine_get_stats(e,&after)==DMG_OK&&same_stats(&before,&after));return 0;
}
int main(int argc,char** argv){
 const uint64_t M=1024u*1024u;dmg_engine *engine=NULL,*small_engine=NULL;dmg_snapshot *a=NULL,*b=NULL;dmg_error err={0};dmg_engine_stats start,end;int fds[5];uint64_t size[5];uint64_t small_len,res_len;unsigned char *small,*resource;uint32_t i;
 dmg_engine_options engine_opts={sizeof(engine_opts),DMG_ABI_VERSION,220ull*1024*1024,0,160ull*1024*1024,4,0};
 dmg_apk_fd_options_v1 opts={sizeof(opts),DMG_ABI_VERSION,"fd-case",0,64,160ull*1024*1024,300ull*1024*1024,16ull*1024*1024,32ull*1024*1024,100000,0,16ull*1024*1024,8ull*1024*1024};
 dmg_apk_fd_spec_v1 spec[2];dmg_source_spec old[2];dmg_source_set_options oldopts={sizeof(oldopts),DMG_ABI_VERSION,"fd-case",0,64,32ull*1024*1024};
 CHECK(argc==13);for(i=0;i<5;i++){fds[i]=OPEN(argv[i+1]);CHECK(fds[i]>=0);size[i]=size_fd(fds[i]);CHECK(size[i]!=UINT64_MAX);}
 small=read_file(argv[6],&small_len);resource=read_file(argv[2],&res_len);CHECK(small&&resource&&size[0]==small_len+19&&size[1]==res_len&&size[2]>16*M&&size[3]>128*M);
 CHECK(dmg_engine_create(&engine_opts,&engine,&err)==DMG_OK&&dmg_engine_get_stats(engine,&start)==DMG_OK);
 spec[0]=(dmg_apk_fd_spec_v1){sizeof(spec[0]),DMG_ABI_VERSION,fds[0],0,12,small_len,"base","apk",argv[7]};
 spec[1]=(dmg_apk_fd_spec_v1){sizeof(spec[1]),DMG_ABI_VERSION,fds[1],1,0,res_len,"split","apk",NULL};
 old[0]=(dmg_source_spec){sizeof(old[0]),DMG_ABI_VERSION,DMG_INPUT_APK,0,small,small_len,"base","apk",argv[7]};
 old[1]=(dmg_source_spec){sizeof(old[1]),DMG_ABI_VERSION,DMG_INPUT_APK,1,resource,res_len,"split","apk",NULL};
 CHECK(SEEK(fds[0],3,SEEK_SET)==3&&SEEK(fds[1],1,SEEK_SET)==1);
 CHECK(dmg_snapshot_open_apk_fds_v1(engine,spec,2,&opts,&a,&err)==DMG_OK&&a&&SEEK(fds[0],0,SEEK_CUR)==3&&SEEK(fds[1],0,SEEK_CUR)==1);
 CHECK(dmg_snapshot_open_sources(engine,old,2,&oldopts,&b,&err)==DMG_OK&&b);CHECK(same_snapshot(a,b)==0&&same_results(engine,a,b)==0);
 {dmg_input_info in;dmg_source_info src;CHECK(dmg_snapshot_get_input_info(a,1,&in)==DMG_OK&&in.source_count==0&&in.allow_no_dex);CHECK(dmg_snapshot_get_source_info(a,0,&src)==DMG_OK&&strcmp(src.archive_entry_name,"classes.dex")==0);CHECK(dmg_snapshot_get_source_info(a,1,&src)==DMG_OK&&strcmp(src.archive_entry_name,"classes2.dex")==0);}
 dmg_snapshot_release(a);dmg_snapshot_release(b);a=b=NULL;CHECK(dmg_engine_get_stats(engine,&end)==DMG_OK&&same_stats(&start,&end));
 {dmg_apk_fd_spec_v1 s=spec[0];dmg_apk_fd_options_v1 o=opts;s.expected_sha256="0000000000000000000000000000000000000000000000000000000000000000";CHECK(failed(engine,&s,1,&o,DMG_SOURCE_MISMATCH)==0);{dmg_apk_fd_spec_v1 pair[2]={spec[0],spec[1]};pair[1].expected_sha256=s.expected_sha256;CHECK(failed(engine,pair,2,&o,DMG_SOURCE_MISMATCH)==0);}s=spec[0];o.max_archive_bytes=small_len-1;CHECK(failed(engine,&s,1,&o,DMG_BUDGET_EXCEEDED)==0);o=opts;o.max_total_archive_bytes=small_len+res_len-1;CHECK(failed(engine,spec,2,&o,DMG_BUDGET_EXCEEDED)==0);o=opts;o.max_dex_bytes=1;CHECK(failed(engine,&s,1,&o,DMG_BUDGET_EXCEEDED)==0);o=opts;o.max_total_dex_bytes=1;CHECK(failed(engine,&s,1,&o,DMG_BUDGET_EXCEEDED)==0);o=opts;o.max_entries=1;CHECK(failed(engine,&s,1,&o,DMG_BUDGET_EXCEEDED)==0);o=opts;o.max_central_directory_bytes=1;CHECK(failed(engine,&s,1,&o,DMG_BUDGET_EXCEEDED)==0);o=opts;o.max_total_name_bytes=1;CHECK(failed(engine,&s,1,&o,DMG_BUDGET_EXCEEDED)==0);o=opts;o.max_sources=1;CHECK(failed(engine,&s,1,&o,DMG_BUDGET_EXCEEDED)==0);o=opts;o.reserved=1;CHECK(failed(engine,&s,1,&o,DMG_INVALID_ARGUMENT)==0);s=spec[1];s.allow_no_dex=0;o=opts;CHECK(failed(engine,&s,1,&o,DMG_CORRUPT_INPUT)==0);s=spec[0];s.fd=-1;CHECK(failed(engine,&s,1,&o,DMG_INVALID_ARGUMENT)==0);s=spec[0];s.offset=UINT64_MAX;CHECK(failed(engine,&s,1,&o,DMG_INVALID_ARGUMENT)==0);s=spec[0];s.length=size[0];CHECK(failed(engine,&s,1,&o,DMG_INVALID_ARGUMENT)==0);s=spec[0];s.fd=fds[4];s.offset=0;s.length=size[4];s.expected_sha256=NULL;CHECK(failed(engine,&s,1,&o,DMG_CORRUPT_INPUT)==0);}
 {dmg_apk_fd_spec_v1 duplicate[2]={spec[0],spec[0]};CHECK(failed(engine,duplicate,2,&opts,DMG_INVALID_ARGUMENT)==0);duplicate[1].slot_key="other";CHECK(dmg_snapshot_open_apk_fds_v1(engine,duplicate,2,&opts,&a,&err)==DMG_OK&&a);{dmg_source_info u,v;CHECK(dmg_snapshot_get_source_info(a,0,&u)==DMG_OK&&dmg_snapshot_get_source_info(a,2,&v)==DMG_OK&&strcmp(u.dex.content_id,v.dex.content_id)==0&&strcmp(u.dex.occurrence_id,v.dex.occurrence_id)!=0);}dmg_snapshot_release(a);a=NULL;}
 {dmg_apk_fd_spec_v1 many[9];for(i=0;i<9;i++)many[i]=spec[0];CHECK(failed(engine,many,9,&opts,DMG_INVALID_ARGUMENT)==0);}
 {dmg_apk_fd_spec_v1 many[8];char keys[8][8];dmg_snapshot_overview info;for(i=0;i<8;i++){many[i]=spec[1];snprintf(keys[i],sizeof(keys[i]),"split%u",i);many[i].slot_key=keys[i];}CHECK(dmg_snapshot_open_apk_fds_v1(engine,many,8,&opts,&a,&err)==DMG_OK&&a&&dmg_snapshot_get_overview(a,&info)==DMG_OK&&info.input_count==8&&info.source_count==0);dmg_snapshot_release(a);a=NULL;}
 {int pipefd[2];dmg_apk_fd_spec_v1 s=spec[0];
#ifdef _WIN32
  CHECK(_pipe(pipefd,4096,_O_BINARY)==0);
#else
  CHECK(pipe(pipefd)==0);
#endif
  s.fd=pipefd[0];s.offset=0;s.expected_sha256=NULL;CHECK(failed(engine,&s,1,&opts,DMG_INVALID_ARGUMENT)==0);CHECK(CLOSE(pipefd[0])==0&&CLOSE(pipefd[1])==0);}
 for(i=2;i<=3;i++){const char* expected=i==2?argv[8]:argv[12];dmg_apk_fd_spec_v1 s={sizeof(s),DMG_ABI_VERSION,fds[i],0,0,size[i],"large","apk",expected};dmg_input_info in;CHECK(SEEK(fds[i],7,SEEK_SET)==7);CHECK(dmg_snapshot_open_apk_fds_v1(engine,&s,1,&opts,&a,&err)==DMG_OK&&a&&SEEK(fds[i],0,SEEK_CUR)==7);CHECK(dmg_snapshot_get_input_info(a,0,&in)==DMG_OK&&in.input_bytes==size[i]&&in.source_count==2&&in.expected_digest_verified&&strcmp(in.source_sha256,expected)==0);dmg_snapshot_release(a);a=NULL;}
 {dmg_engine* defaults=NULL;dmg_apk_fd_spec_v1 s={sizeof(s),DMG_ABI_VERSION,fds[3],0,0,size[3],"large","apk",NULL};CHECK(dmg_engine_create(NULL,&defaults,&err)==DMG_OK);CHECK(failed(defaults,&s,1,&opts,DMG_BUDGET_EXCEEDED)==0);dmg_engine_release(defaults);}
 for(i=10;i<=11;i++){int fd=OPEN(argv[i]);uint64_t n;dmg_apk_fd_spec_v1 s;dmg_snapshot_overview info;CHECK(fd>=0);n=size_fd(fd);s=(dmg_apk_fd_spec_v1){sizeof(s),DMG_ABI_VERSION,fd,0,0,n,"many","apk",NULL};if(i==10){dmg_source_info first,last;CHECK(dmg_snapshot_open_apk_fds_v1(engine,&s,1,&opts,&a,&err)==DMG_OK&&a&&dmg_snapshot_get_overview(a,&info)==DMG_OK&&info.source_count==64);CHECK(dmg_snapshot_get_source_info(a,0,&first)==DMG_OK&&dmg_snapshot_get_source_info(a,63,&last)==DMG_OK&&strcmp(first.archive_entry_name,"classes.dex")==0&&strcmp(last.archive_entry_name,"classes64.dex")==0&&strcmp(first.dex.occurrence_id,last.dex.occurrence_id)!=0);dmg_snapshot_release(a);a=NULL;}else CHECK(failed(engine,&s,1,&opts,DMG_BUDGET_EXCEEDED)==0);CHECK(CLOSE(fd)==0);}
 {uint64_t n;unsigned char* big=read_file(argv[3],&n);dmg_open_options oldopen={sizeof(oldopen),DMG_ABI_VERSION,160ull*1024*1024,"legacy","slot",NULL};CHECK(big&&n>DMG_MAX_SOURCE_BYTES);a=(dmg_snapshot*)(uintptr_t)1;CHECK(dmg_snapshot_open_copy(big,n,&oldopen,&a,&err)==DMG_BUDGET_EXCEEDED&&a==NULL);free(big);}
 {const char* json="{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":true,\"max_results\":100}";int fd=OPEN(argv[1]);dmg_apk_fd_spec_v1 s=spec[0];dmg_query* q=NULL;dmg_result* result=NULL;dmg_result_info info;dmg_source_info origin;CHECK(fd>=0);s.fd=fd;CHECK(dmg_snapshot_open_apk_fds_v1(engine,&s,1,&opts,&a,&err)==DMG_OK&&a);CHECK(CLOSE(fd)==0);CHECK(dmg_query_compile_json(engine,(const uint8_t*)json,strlen(json),&q,&err)==DMG_OK&&dmg_query_execute(a,q,&result,&err)==DMG_OK&&result);dmg_query_release(q);dmg_snapshot_release(a);a=NULL;CHECK(dmg_result_get_info(result,&info)==DMG_OK&&info.candidates_count>0&&dmg_result_get_origin(result,0,&origin)==DMG_OK&&origin.dex.occurrence_id);dmg_result_release(result);}
 {int rawfd=OPEN(argv[9]);uint64_t n;dmg_snapshot_info in;dmg_open_options oldopen={sizeof(oldopen),DMG_ABI_VERSION,160ull*1024*1024,"legacy","slot",NULL};CHECK(rawfd>=0);n=size_fd(rawfd);CHECK(n>7&&n!=UINT64_MAX&&SEEK(rawfd,7,SEEK_SET)==7);CHECK(dmg_snapshot_open_fd(engine,rawfd,0,n,&oldopen,&a,&err)==DMG_OK&&a&&SEEK(rawfd,0,SEEK_CUR)==7);CHECK(CLOSE(rawfd)==0&&dmg_snapshot_get_info(a,&in)==DMG_OK&&in.source_bytes==n);dmg_snapshot_release(a);a=NULL;}
 engine_opts.owned_bytes_limit=1024*1024;CHECK(dmg_engine_create(&engine_opts,&small_engine,&err)==DMG_OK);{dmg_apk_fd_spec_v1 s={sizeof(s),DMG_ABI_VERSION,fds[2],0,0,size[2],"large","apk",NULL};int closed=OPEN(argv[3]);CHECK(closed>=0&&CLOSE(closed)==0);s.fd=closed;CHECK(failed(small_engine,&s,1,&opts,DMG_INVALID_ARGUMENT)==0);s.fd=fds[2];s.offset=1;CHECK(failed(small_engine,&s,1,&opts,DMG_INVALID_ARGUMENT)==0);s.offset=0;CHECK(failed(small_engine,&s,1,&opts,DMG_BUDGET_EXCEEDED)==0);}dmg_engine_release(small_engine);
 CHECK(dmg_engine_get_stats(engine,&end)==DMG_OK&&same_stats(&start,&end));dmg_engine_release(engine);for(i=0;i<5;i++)CHECK(CLOSE(fds[i])==0);free(small);free(resource);puts("PASS APK fd SourceSet: parity, source identity, budgets, atomic failures, offsets and large files");return 0;
}
