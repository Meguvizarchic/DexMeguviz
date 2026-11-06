#include "dexmeguviz/dexmeguviz.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"bounds C ABI line %d: %s\n",__LINE__,#x);return 1;}}while(0)
static unsigned char* read_file(const char* path,long* n){FILE* f=fopen(path,"rb");unsigned char* p;if(!f)return NULL;if(fseek(f,0,SEEK_END)||(*n=ftell(f))<=0||fseek(f,0,SEEK_SET)){fclose(f);return NULL;}p=(unsigned char*)malloc((size_t)*n);if(!p||fread(p,1,(size_t)*n,f)!=(size_t)*n){fclose(f);free(p);return NULL;}fclose(f);return p;}
static int same_stats(const dmg_engine_stats* a,const dmg_engine_stats* b){return a->owned_bytes==b->owned_bytes&&a->source_bytes==b->source_bytes&&a->fact_bytes==b->fact_bytes&&a->scratch_bytes==b->scratch_bytes&&a->query_bytes==b->query_bytes&&a->result_bytes==b->result_bytes&&a->control_bytes==b->control_bytes&&a->borrowed_bytes==b->borrowed_bytes&&a->active_jobs==b->active_jobs;}
static int run(dmg_engine* engine,const char* name,const unsigned char* data,long bytes,int empty,int low_work,int old_status,int new_status,uint32_t count,int index_expected){
 char text[600];dmg_query *q=NULL;dmg_snapshot* snap=NULL;dmg_result *old=NULL,*fresh=(dmg_result*)(uintptr_t)1;dmg_error e={0};dmg_relation_info_v2 a={0},b={0};dmg_reverse_profile_v1 prof={0};dmg_source_spec source={sizeof(source),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,data,(uint64_t)bytes,"a","string",NULL};dmg_source_set_options so={sizeof(so),DMG_ABI_VERSION,"bounds-string",1,8,4u<<20};dmg_reverse_join_options_v1 o={sizeof(o),DMG_ABI_VERSION,100000000,4u<<20,100000000,100000,1,0,0};uint32_t i;
 if(strcmp(name,"left4097")==0)o.max_page_calls=2;
 CHECK(snprintf(text,sizeof(text),"{\"schema_version\":1,\"relation\":{\"op\":\"join\",\"on\":\"target_ref\",\"left\":{\"op\":\"scan\",\"relation\":\"string_uses\"%s},\"right\":{\"op\":\"scan\",\"relation\":\"string_values\"}},\"max_results\":10000,\"max_work\":%u}",empty?",\"where\":{\"pc\":999999}":"",low_work?200:100000000)>0);
 CHECK(dmg_snapshot_open_sources(engine,&source,1,&so,&snap,&e)==DMG_OK);CHECK(dmg_query_compile_json(engine,(const uint8_t*)text,strlen(text),&q,&e)==DMG_OK);CHECK(dmg_query_execute(snap,q,&old,&e)==old_status);CHECK((old_status==DMG_OK)==(old!=NULL));CHECK(dmg_query_execute_reverse_intersection_v2(snap,q,&o,&fresh,&e)==new_status);CHECK((new_status==DMG_OK)==(fresh!=NULL));if(new_status!=DMG_OK)CHECK(fresh==NULL);
 if(old){CHECK(dmg_result_get_relation_info_v2(old,&a,sizeof(a))==DMG_OK&&a.candidates_count==count);if(fresh){CHECK(dmg_result_get_relation_info_v2(fresh,&b,sizeof(b))==DMG_OK&&b.candidates_count==count&&a.coverage==b.coverage&&a.decision==b.decision);for(i=0;i<count;++i){dmg_value_row_v2 x={0},y={0};dmg_relation_link_v2 l={0};CHECK(dmg_result_get_value_v2(old,i,&x,sizeof(x))==DMG_OK&&dmg_result_get_value_v2(fresh,i,&y,sizeof(y))==DMG_OK&&x.kind==DMG_VALUE_USE&&y.kind==DMG_VALUE_USE);CHECK(x.use.source_index==y.use.source_index&&x.use.dex_pc==y.use.dex_pc&&x.use.opcode==y.use.opcode&&x.use.target_index==y.use.target_index&&x.use.target_domain==y.use.target_domain);CHECK(dmg_result_get_link_v2(fresh,i,0,&l,sizeof(l))==DMG_OK&&l.left.source_index==0&&l.right.source_index==0&&l.right.local_index==y.use.target_index);}}}
 CHECK(dmg_snapshot_reverse_profile_v1(snap,&prof,sizeof(prof))==DMG_OK&&prof.builds==(uint64_t)index_expected&&prof.published_indexes==(uint64_t)index_expected);if(old)dmg_result_release(old);if(fresh)dmg_result_release(fresh);dmg_query_release(q);dmg_snapshot_release(snap);printf("CASE %s old=%d new=%d count=%u builds=%llu\n",name,old_status,new_status,count,(unsigned long long)prof.builds);return 0;
}
int main(int argc,char** argv){dmg_engine* e=NULL;dmg_error error={0};dmg_engine_stats before={0},after={0};unsigned char* d[5]={0};long n[5]={0};int i;CHECK(argc==6);for(i=0;i<5;++i){d[i]=read_file(argv[i+1],&n[i]);CHECK(d[i]);}CHECK(dmg_engine_create(NULL,&e,&error)==DMG_OK);CHECK(dmg_engine_get_stats(e,&before)==DMG_OK);
 CHECK(run(e,"right4096",d[0],n[0],0,0,DMG_OK,DMG_OK,1,1)==0);
 CHECK(run(e,"right4097",d[1],n[1],0,0,DMG_OK,DMG_OK,1,1)==0);
 CHECK(run(e,"empty-left-right4097",d[1],n[1],1,0,DMG_OK,DMG_OK,0,0)==0);
 CHECK(run(e,"right4097-lowwork",d[1],n[1],0,1,DMG_BUDGET_EXCEEDED,DMG_BUDGET_EXCEEDED,0,0)==0);
 CHECK(run(e,"left4096",d[2],n[2],0,0,DMG_OK,DMG_OK,4096,1)==0);
 CHECK(run(e,"left4097",d[3],n[3],0,0,DMG_OK,DMG_OK,4097,1)==0);
 CHECK(run(e,"left4097-onepage",d[3],n[3],0,0,DMG_OK,DMG_BUDGET_EXCEEDED,4097,1)==0);
 CHECK(run(e,"corrupt-before-bound",d[4],n[4],0,0,DMG_CORRUPT_INPUT,DMG_CORRUPT_INPUT,0,0)==0);
 CHECK(dmg_engine_get_stats(e,&after)==DMG_OK&&same_stats(&before,&after));dmg_engine_release(e);for(i=0;i<5;++i)free(d[i]);puts("PASS string reverse 4096 bounds, errors and ledger");return 0;}
