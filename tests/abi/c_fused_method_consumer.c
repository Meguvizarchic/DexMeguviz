#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"fused C line %d: %s\n",__LINE__,#x); return 1; } } while(0)
static dmg_query* compile(dmg_engine* engine,const char* json) { dmg_query* q=NULL;dmg_error e={0};return dmg_query_compile_json(engine,(const uint8_t*)json,strlen(json),&q,&e)==DMG_OK?q:NULL; }
static int equal_results(dmg_result* a,dmg_result* b) {
 dmg_result_info x={0},y={0};dmg_query_info qx={0},qy={0};dmg_query_profile px={0},py={0};uint32_t i;
 CHECK(dmg_result_get_info(a,&x)==DMG_OK&&dmg_result_get_info(b,&y)==DMG_OK);
 CHECK(x.execution_status==y.execution_status&&x.coverage==y.coverage&&x.decision==y.decision&&x.reason==y.reason&&x.candidates_count==y.candidates_count);
 CHECK(dmg_result_get_query_info(a,&qx)==DMG_OK&&dmg_result_get_query_info(b,&qy)==DMG_OK&&strcmp(qx.query_id,qy.query_id)==0);
 CHECK(dmg_result_get_profile(a,&px)==DMG_OK&&dmg_result_get_profile(b,&py)==DMG_OK&&px.work_units==py.work_units&&px.scope_complete==py.scope_complete);
 for(i=0;i<x.candidates_count;i++){dmg_method_row u={0},v={0};dmg_source_info su={0},sv={0};
  CHECK(dmg_result_get_method(a,i,&u)==DMG_OK&&dmg_result_get_method(b,i,&v)==DMG_OK&&u.method_index==v.method_index);
  CHECK(dmg_result_get_origin(a,i,&su)==DMG_OK&&dmg_result_get_origin(b,i,&sv)==DMG_OK&&strcmp(su.dex.occurrence_id,sv.dex.occurrence_id)==0);
 }return 0;
}
int main(int argc,char** argv) {
 const char* a="{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\",\"using_strings\":{\"all\":[\"used-string\"]}}}";
 const char* b="{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\",\"using_strings\":{\"all\":[{\"op\":\"contains\",\"value\":\"string\"}]}}}";
 const char* scoped="{\"schema_version\":1,\"relation\":\"method_defs\",\"scope\":{\"slots\":[\"a\"]},\"where\":{\"name\":\"uses\"}}";
 FILE* f;long size;uint8_t* bytes;dmg_engine* engine=NULL;dmg_snapshot* snapshot=NULL;dmg_query* qs[3]={0};dmg_error error={0};dmg_multi_batch_v1 *serial=NULL,*fused=NULL;uint32_t failed,i;
 dmg_engine_options eo={sizeof(eo),DMG_ABI_VERSION,64u<<20,0,16u<<20,2,0};dmg_source_spec src={0};dmg_source_set_options so={sizeof(so),DMG_ABI_VERSION,"fused-c",0,1,16u<<20};dmg_multi_options_v1 opt={sizeof(opt),DMG_ABI_VERSION,1u<<20,1000000,0,0};
 CHECK(argc==2);f=fopen(argv[1],"rb");CHECK(f);CHECK(fseek(f,0,SEEK_END)==0);size=ftell(f);CHECK(size>0);rewind(f);bytes=(uint8_t*)malloc((size_t)size);CHECK(bytes&&fread(bytes,1,(size_t)size,f)==(size_t)size);fclose(f);
 CHECK(dmg_engine_create(&eo,&engine,&error)==DMG_OK);src=(dmg_source_spec){sizeof(src),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,bytes,(uint64_t)size,"a","raw",NULL};CHECK(dmg_snapshot_open_sources(engine,&src,1,&so,&snapshot,&error)==DMG_OK);
 qs[0]=compile(engine,a);qs[1]=compile(engine,b);qs[2]=compile(engine,scoped);CHECK(qs[0]&&qs[1]&&qs[2]);
 CHECK(dmg_multi_execute_v1(snapshot,qs,2,&opt,&serial,&failed,&error)==DMG_OK);opt.flags=DMG_MULTI_FUSE_METHOD_ENUM_V1;CHECK(dmg_multi_execute_v1(snapshot,qs,2,&opt,&fused,&failed,&error)==DMG_OK);
 for(i=0;i<2;i++){dmg_result *x=NULL,*y=NULL;CHECK(dmg_multi_batch_get_result_v1(serial,i,&x)==DMG_OK&&dmg_multi_batch_get_result_v1(fused,i,&y)==DMG_OK&&equal_results(x,y)==0);dmg_result_release(x);dmg_result_release(y);}
 dmg_multi_batch_release_v1(serial);dmg_multi_batch_release_v1(fused);serial=fused=NULL;
 {dmg_query* mixed[]={qs[0],qs[2]};CHECK(dmg_multi_execute_v1(snapshot,mixed,2,&opt,&fused,&failed,&error)==DMG_OK);dmg_multi_batch_release_v1(fused);fused=NULL;}
 opt.flags=2;CHECK(dmg_multi_execute_v1(snapshot,qs,2,&opt,&fused,&failed,&error)==DMG_INVALID_ARGUMENT&&fused==NULL);
 for(i=0;i<3;i++)dmg_query_release(qs[i]);dmg_snapshot_release(snapshot);dmg_engine_release(engine);free(bytes);puts("PASS C fused opt-in, result identity, fallback and unknown flags");return 0;
}
