#include "dexmeguviz/dexmeguviz.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"C reverse join line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char** argv){
 FILE* f;long n;unsigned char* bytes;dmg_engine* engine=NULL;dmg_snapshot* snapshot=NULL;dmg_query* query=NULL;dmg_result *old=NULL,*fast=NULL;dmg_error e={0};dmg_reverse_profile_v1 before={0},after={0};
 const char* text="{\"schema_version\":1,\"relation\":{\"op\":\"join\",\"on\":\"target_ref\",\"left\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"},\"right\":{\"op\":\"scan\",\"relation\":\"method_refs\"}},\"max_results\":100}";
 dmg_source_set_options so={sizeof(so),DMG_ABI_VERSION,"c-reverse-join",1,8,1u<<20};dmg_reverse_join_options_v1 options={sizeof(options),DMG_ABI_VERSION,1000000,1u<<20,1000000,100000,10000,0,0};
 CHECK(argc==2&&(f=fopen(argv[1],"rb"))!=NULL);CHECK(fseek(f,0,SEEK_END)==0&&(n=ftell(f))>0&&fseek(f,0,SEEK_SET)==0);bytes=(unsigned char*)malloc((size_t)n);CHECK(bytes&&fread(bytes,1,(size_t)n,f)==(size_t)n);fclose(f);
 CHECK(dmg_engine_create(NULL,&engine,&e)==DMG_OK);{dmg_source_spec source={sizeof(source),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,bytes,(uint64_t)n,"c","test",NULL};CHECK(dmg_snapshot_open_sources(engine,&source,1,&so,&snapshot,&e)==DMG_OK);}
 CHECK(dmg_query_compile_json(engine,(const uint8_t*)text,strlen(text),&query,&e)==DMG_OK);CHECK(dmg_query_execute(snapshot,query,&old,&e)==DMG_OK&&old);
 CHECK(dmg_snapshot_reverse_profile_v1(snapshot,&before,sizeof(before))==DMG_OK&&before.builds==0);
 CHECK(dmg_query_execute_reverse_intersection_v2(snapshot,query,&options,&fast,&e)==DMG_OK&&fast);
 CHECK(dmg_snapshot_reverse_profile_v1(snapshot,&after,sizeof(after))==DMG_OK&&after.builds==1);
 {dmg_relation_info_v2 a={0},b={0};CHECK(dmg_result_get_relation_info_v2(old,&a,sizeof(a))==DMG_OK&&dmg_result_get_relation_info_v2(fast,&b,sizeof(b))==DMG_OK&&a.candidates_count==2&&b.candidates_count==2);
  for(uint32_t i=0;i<2;++i){dmg_value_row_v2 x={0},y={0};CHECK(dmg_result_get_value_v2(old,i,&x,sizeof(x))==DMG_OK&&dmg_result_get_value_v2(fast,i,&y,sizeof(y))==DMG_OK&&x.kind==DMG_VALUE_USE&&y.kind==DMG_VALUE_USE&&x.use.dex_pc==y.use.dex_pc&&x.use.target_index==y.use.target_index&&x.use.source_index==y.use.source_index);}}
 dmg_result_release(old);{dmg_result* held=fast;fast=(dmg_result*)(uintptr_t)1;CHECK(dmg_query_execute_reverse_intersection_v2(snapshot,query,NULL,&fast,&e)==DMG_INVALID_ARGUMENT&&fast==NULL);
 CHECK(dmg_query_execute_reverse_intersection_v2(snapshot,query,&options,NULL,&e)==DMG_INVALID_ARGUMENT);
 fast=(dmg_result*)(uintptr_t)1;options.struct_size--;CHECK(dmg_query_execute_reverse_intersection_v2(snapshot,query,&options,&fast,&e)==DMG_INVALID_ARGUMENT&&fast==NULL);options.struct_size++;
 fast=(dmg_result*)(uintptr_t)1;options.reserved0=1;CHECK(dmg_query_execute_reverse_intersection_v2(snapshot,query,&options,&fast,&e)==DMG_INVALID_ARGUMENT&&fast==NULL);
 dmg_query_release(query);dmg_snapshot_release(snapshot);dmg_engine_release(engine);free(bytes);
 {dmg_value_row_v2 retained={0};dmg_relation_link_v2 link={0};CHECK(dmg_result_get_value_v2(held,0,&retained,sizeof(retained))==DMG_OK&&retained.kind==DMG_VALUE_USE&&retained.use.dex_pc==0&&retained.use.target_index==4);CHECK(dmg_result_get_link_v2(held,0,0,&link,sizeof(link))==DMG_OK&&link.left.dex_pc==0&&link.right.local_index==4);}dmg_result_release(held);}
 puts("PASS C experimental reverse target join");return 0;
}
