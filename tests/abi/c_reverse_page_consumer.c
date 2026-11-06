#include "dexmeguviz/dexmeguviz.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"reverse page C line %d: %s\n",__LINE__,#x);return 1;}}while(0)
struct Buffer {unsigned char* data;size_t size;};
static struct Buffer read_file(const char* path){FILE* f=fopen(path,"rb");struct Buffer b={0};long n;if(!f)return b;if(fseek(f,0,SEEK_END)!=0||(n=ftell(f))<=0||fseek(f,0,SEEK_SET)!=0){fclose(f);return b;}b.data=(unsigned char*)malloc((size_t)n);if(b.data&&fread(b.data,1,(size_t)n,f)==(size_t)n)b.size=(size_t)n;fclose(f);return b;}
static uint32_t stop(void* p){(void)p;return 1;}
static int same(const dmg_reverse_event_v1* a,const dmg_use_row* b){return a->source_index==b->source_index&&a->use_kind==1&&a->caller_ordinal==b->caller_ordinal&&a->caller_method_ref==b->caller_method_ref&&a->dex_pc==b->dex_pc&&a->opcode==b->opcode&&a->code_offset==b->code_offset&&a->target_domain==b->target_domain&&a->target_index==b->target_index&&a->extra_proto==b->extra_proto;}
static uint64_t cached_threshold(dmg_snapshot* snapshot,int page){
 uint64_t lo=1,hi=1000000;dmg_error error={0};
 while(lo<hi){uint64_t mid=lo+(hi-lo)/2;dmg_reverse_options_v1 opt={sizeof(opt),DMG_ABI_VERSION,mid,1u<<20,2000,0,NULL,NULL};uint64_t value=88,total=88;uint32_t n=77;dmg_reverse_event_v1 rows[2],saved[2];memset(rows,0x5a,sizeof(rows));memcpy(saved,rows,sizeof(rows));
  dmg_status status=page?dmg_snapshot_reverse_page_v1(snapshot,0,1,2,4,UINT32_MAX,&opt,0,rows,2,&n,&total,&error):dmg_snapshot_reverse_count_v1(snapshot,0,1,2,4,UINT32_MAX,&opt,&value,&error);
  if(status==DMG_OK){if(page?(n!=2||total!=2):(value!=2))return 0;hi=mid;}
  else {if(status!=DMG_BUDGET_EXCEEDED||(page?(n!=77||total!=88||memcmp(rows,saved,sizeof(rows))!=0):(value!=88)))return 0;lo=mid+1;}
 }
 return lo;
}
int main(int argc,char** argv){
 CHECK(argc==5);struct Buffer b=read_file(argv[1]),special=read_file(argv[2]),many=read_file(argv[3]),multiple=read_file(argv[4]);CHECK(b.data&&special.data&&many.data&&multiple.data);
 dmg_engine* engine=NULL;dmg_snapshot *snap=NULL,*poly=NULL,*large=NULL,*callers=NULL,*budget=NULL,*pageEmpty=NULL,*pageFull=NULL,*pageAbsent=NULL;dmg_error err={0};dmg_reverse_profile_v1 profile;
 dmg_source_spec src[2];dmg_source_set_options so={sizeof(so),DMG_ABI_VERSION,"reverse-page",1,16,8u<<20};dmg_reverse_options_v1 opt={sizeof(opt),DMG_ABI_VERSION,1000000,1u<<20,2000,0,NULL,NULL};
 CHECK(dmg_engine_create(NULL,&engine,&err)==DMG_OK);
 src[0]=(dmg_source_spec){sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,b.data,b.size,"one","raw",NULL};src[1]=(dmg_source_spec){sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,b.data,b.size,"two","raw",NULL};
 CHECK(dmg_snapshot_open_sources(engine,src,2,&so,&snap,&err)==DMG_OK);
 dmg_reverse_event_v1 events[2],saved[2];memset(events,0x5a,sizeof(events));memcpy(saved,events,sizeof(events));uint32_t n=77;uint64_t total=88;
 // Invalid initial offset must neither publish nor modify the complete output.
 CHECK(dmg_snapshot_reverse_page_v1(snap,0,1,2,4,UINT32_MAX,&opt,3,events,2,&n,&total,&err)==DMG_INVALID_ARGUMENT);
 CHECK(n==77&&total==88&&memcmp(events,saved,sizeof(events))==0);
 CHECK(dmg_snapshot_reverse_profile_v1(snap,&profile,sizeof(profile))==DMG_OK&&profile.build_attempts==1&&profile.build_failures==1&&profile.builds==0&&profile.published_indexes==0);
 CHECK(dmg_snapshot_reverse_page_v1(snap,0,1,2,4,UINT32_MAX,&opt,0,NULL,0,&n,&total,&err)==DMG_OK&&n==0&&total==2);
 CHECK(dmg_snapshot_reverse_profile_v1(snap,&profile,sizeof(profile))==DMG_OK&&profile.builds==1&&profile.published_records==2);
 CHECK(dmg_snapshot_reverse_page_v1(snap,0,1,2,4,UINT32_MAX,&opt,0,events,1,&n,&total,&err)==DMG_OK&&n==1&&total==2);
 CHECK(events[0].source_index==0&&events[0].use_kind==1&&events[0].caller_ordinal==2&&events[0].caller_method_ref==3&&events[0].dex_pc==0&&events[0].opcode==0x71&&events[0].code_offset==416&&events[0].target_domain==2&&events[0].target_index==4&&events[0].extra_proto==UINT32_MAX);
 CHECK(dmg_snapshot_reverse_page_v1(snap,0,1,2,4,UINT32_MAX,&opt,1,events+1,1,&n,&total,&err)==DMG_OK&&n==1&&total==2&&events[1].dex_pc==3);
 // Differential against the existing forward graph C getter, preserving PC order.
 {const char* json="{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"},\"max_results\":100}";dmg_query* query=NULL;dmg_result* result=NULL;dmg_relation_info_v2 info;unsigned hits=0;
  CHECK(dmg_query_compile_json(engine,(const uint8_t*)json,strlen(json),&query,&err)==DMG_OK&&dmg_query_execute(snap,query,&result,&err)==DMG_OK);
  CHECK(dmg_result_get_relation_info_v2(result,&info,sizeof(info))==DMG_OK&&info.candidates_count==4);
  for(uint32_t i=0;i<info.candidates_count;i++){dmg_value_row_v2 row;CHECK(dmg_result_get_value_v2(result,i,&row,sizeof(row))==DMG_OK&&row.kind==DMG_VALUE_USE);if(row.use.source_index==0){CHECK(hits<2&&same(&events[hits],&row.use));++hits;}}
  CHECK(hits==2);dmg_result_release(result);dmg_query_release(query);
 }
 {uint64_t count=99;CHECK(dmg_snapshot_reverse_count_v1(snap,0,1,2,4,UINT32_MAX,&opt,&count,&err)==DMG_OK&&count==2);CHECK(dmg_snapshot_reverse_profile_v1(snap,&profile,sizeof(profile))==DMG_OK&&profile.builds==1&&profile.reuses==3);}
 CHECK(dmg_snapshot_reverse_page_v1(snap,1,1,2,4,UINT32_MAX,&opt,0,events,2,&n,&total,&err)==DMG_OK&&n==2&&total==2&&events[0].source_index==1&&events[1].source_index==1&&events[0].dex_pc==0&&events[1].dex_pc==3);
 CHECK(dmg_snapshot_reverse_profile_v1(snap,&profile,sizeof(profile))==DMG_OK&&profile.builds==2&&profile.published_records==4);
 memcpy(saved,events,sizeof(events));n=77;total=88;
 CHECK(dmg_snapshot_reverse_page_v1(snap,0,1,2,4,UINT32_MAX,&opt,2,events,2,&n,&total,&err)==DMG_OK&&n==0&&total==2&&memcmp(events,saved,sizeof(events))==0);
 n=77;total=88;CHECK(dmg_snapshot_reverse_page_v1(snap,0,1,2,4,UINT32_MAX,&opt,UINT64_MAX,events,2,&n,&total,&err)==DMG_INVALID_ARGUMENT&&n==77&&total==88&&memcmp(events,saved,sizeof(events))==0);
 CHECK(dmg_snapshot_reverse_page_v1(snap,0,1,2,4,UINT32_MAX,&opt,0,NULL,1,&n,&total,&err)==DMG_INVALID_ARGUMENT&&n==77&&total==88);
 CHECK(dmg_snapshot_reverse_page_v1(snap,0,1,2,4,UINT32_MAX,&opt,0,events,2,NULL,&total,&err)==DMG_INVALID_ARGUMENT&&total==88&&memcmp(events,saved,sizeof(events))==0);
 CHECK(dmg_snapshot_reverse_page_v1(snap,0,1,2,4,UINT32_MAX,&opt,0,events,2,&n,NULL,&err)==DMG_INVALID_ARGUMENT&&n==77&&memcmp(events,saved,sizeof(events))==0);
 CHECK(dmg_snapshot_reverse_page_v1(snap,0,1,2,4,UINT32_MAX,&opt,0,events,4097,&n,&total,&err)==DMG_INVALID_ARGUMENT&&n==77&&total==88);
 opt.max_work=1;CHECK(dmg_snapshot_reverse_page_v1(snap,0,1,2,4,UINT32_MAX,&opt,0,events,2,&n,&total,&err)==DMG_BUDGET_EXCEEDED&&n==77&&total==88&&memcmp(events,saved,sizeof(events))==0);opt.max_work=1000000;
 opt.cancelled=stop;CHECK(dmg_snapshot_reverse_page_v1(snap,0,1,2,4,UINT32_MAX,&opt,0,events,2,&n,&total,&err)==DMG_CANCELLED&&n==77&&total==88&&memcmp(events,saved,sizeof(events))==0);opt.cancelled=NULL;
 // On one already published index, page copying adds exactly one work
 // unit per returned record beyond the same cached count lookup.
 CHECK(dmg_snapshot_open_sources(engine,src,1,&so,&budget,&err)==DMG_OK);
 {uint64_t value=0;CHECK(dmg_snapshot_reverse_count_v1(budget,0,1,2,4,UINT32_MAX,&opt,&value,&err)==DMG_OK&&value==2);
  const uint64_t c=cached_threshold(budget,0),p=cached_threshold(budget,1);CHECK(c>0&&p==c+2);printf("CACHED_WORK count=%llu page_two=%llu\n",(unsigned long long)c,(unsigned long long)p);}
 // First page-copy cost is charged to that call, never to later reuse.
 CHECK(dmg_snapshot_open_sources(engine,src,1,&so,&pageEmpty,&err)==DMG_OK&&dmg_snapshot_open_sources(engine,src,1,&so,&pageFull,&err)==DMG_OK&&dmg_snapshot_open_sources(engine,src,1,&so,&pageAbsent,&err)==DMG_OK);
 CHECK(dmg_snapshot_reverse_page_v1(pageEmpty,0,1,2,4,UINT32_MAX,&opt,0,NULL,0,&n,&total,&err)==DMG_OK&&n==0&&total==2);
 CHECK(dmg_snapshot_reverse_page_v1(pageFull,0,1,2,4,UINT32_MAX,&opt,0,events,2,&n,&total,&err)==DMG_OK&&n==2&&total==2);
 CHECK(dmg_snapshot_reverse_page_v1(pageAbsent,0,1,2,3,UINT32_MAX,&opt,0,events,2,&n,&total,&err)==DMG_OK&&n==0&&total==0);
 {const uint64_t empty=cached_threshold(pageEmpty,0),full=cached_threshold(pageFull,0),absent=cached_threshold(pageAbsent,0);CHECK(empty>0&&empty==full&&empty==absent);printf("FIRST_PAGE_REUSE_WORK empty=%llu full=%llu absent=%llu\n",(unsigned long long)empty,(unsigned long long)full,(unsigned long long)absent);}
 // Same method ref in polymorphic and call-site domains never merges.
 src[0].data=special.data;src[0].size=special.size;CHECK(dmg_snapshot_open_sources(engine,src,1,&so,&poly,&err)==DMG_OK);
 CHECK(dmg_snapshot_reverse_page_v1(poly,0,1,DMG_TARGET_METHOD_AND_PROTO,4,0,&opt,0,events,2,&n,&total,&err)==DMG_OK&&n==1&&total==1&&events[0].dex_pc==0&&events[0].opcode==0xfa&&events[0].extra_proto==0);
 CHECK(dmg_snapshot_reverse_page_v1(poly,0,1,DMG_TARGET_CALL_SITE,0,UINT32_MAX,&opt,0,events,2,&n,&total,&err)==DMG_OK&&n==1&&total==1&&events[0].dex_pc==4&&events[0].opcode==0xfc&&events[0].extra_proto==UINT32_MAX);
 // Same target in two distinct callers is ordered by caller then PC.
 src[0].data=multiple.data;src[0].size=multiple.size;CHECK(dmg_snapshot_open_sources(engine,src,1,&so,&callers,&err)==DMG_OK);
 CHECK(dmg_snapshot_reverse_page_v1(callers,0,1,2,4,UINT32_MAX,&opt,0,events,2,&n,&total,&err)==DMG_OK&&n==2&&total==2);
 CHECK(events[0].caller_ordinal==1&&events[0].caller_method_ref==2&&events[0].dex_pc==0&&events[0].code_offset==396);
 CHECK(events[1].caller_ordinal==2&&events[1].caller_method_ref==3&&events[1].dex_pc==2&&events[1].code_offset==420);
 // A larger fixed fixture verifies every returned PC over multiple page sizes.
 src[0].data=many.data;src[0].size=many.size;CHECK(dmg_snapshot_open_sources(engine,src,1,&so,&large,&err)==DMG_OK);
 for(uint64_t offset=0;offset<1024;offset+=2){CHECK(dmg_snapshot_reverse_page_v1(large,0,1,2,1,UINT32_MAX,&opt,offset,events,2,&n,&total,&err)==DMG_OK&&n==2&&total==1024&&events[0].dex_pc==offset*3&&events[1].dex_pc==(offset+1)*3);}
 CHECK(dmg_snapshot_reverse_profile_v1(large,&profile,sizeof(profile))==DMG_OK&&profile.builds==1&&profile.reuses==511);
 // Records are copied values and remain readable after every handle is closed.
 dmg_reverse_event_v1 retained=events[1];dmg_snapshot_close(snap);n=77;total=88;CHECK(dmg_snapshot_reverse_page_v1(snap,0,1,2,4,UINT32_MAX,&opt,0,events,2,&n,&total,&err)==DMG_CLOSED&&n==77&&total==88);
 dmg_snapshot_release(snap);dmg_snapshot_release(poly);dmg_snapshot_release(callers);dmg_snapshot_release(budget);dmg_snapshot_release(pageEmpty);dmg_snapshot_release(pageFull);dmg_snapshot_release(pageAbsent);dmg_snapshot_release(large);dmg_engine_release(engine);CHECK(retained.dex_pc==3069&&retained.caller_ordinal==0&&retained.target_index==1);free(b.data);free(special.data);free(many.data);free(multiple.data);
 puts("PASS C reverse page order, scope, domains, differential and lifetime");return 0;
}
