#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"multi C ABI line %d: %s\n",__LINE__,#x);return 1;}}while(0)
static dmg_query* compile(dmg_engine* engine,const char* json){dmg_query* q=NULL;dmg_error e;return dmg_query_compile_json(engine,(const uint8_t*)json,strlen(json),&q,&e)==DMG_OK?q:NULL;}
static int equal_text(const uint16_t* a,uint64_t na,const uint16_t* b,uint64_t nb){return na==nb&&(!na||memcmp(a,b,(size_t)na*sizeof(uint16_t))==0);}
static int same_result(dmg_result* a,dmg_result* b){
 dmg_relation_info ra,rb;dmg_query_info qa,qb;dmg_query_profile pa,pb;uint32_t i,j;
 CHECK(dmg_result_get_relation_info(a,&ra,sizeof(ra))==DMG_OK&&dmg_result_get_relation_info(b,&rb,sizeof(rb))==DMG_OK);
 CHECK(ra.relation==rb.relation&&ra.execution_status==rb.execution_status&&ra.coverage==rb.coverage&&ra.decision==rb.decision&&ra.reason==rb.reason&&ra.candidates_count==rb.candidates_count&&ra.unknown_rows==rb.unknown_rows);
 CHECK(dmg_result_get_query_info(a,&qa)==DMG_OK&&dmg_result_get_query_info(b,&qb)==DMG_OK&&strcmp(qa.query_id,qb.query_id)==0);
 CHECK(dmg_result_get_profile(a,&pa)==DMG_OK&&dmg_result_get_profile(b,&pb)==DMG_OK&&pa.work_units==pb.work_units&&pa.fact_requests==pb.fact_requests&&pa.methods_decoded==pb.methods_decoded&&pa.scope_complete==pb.scope_complete);
 for(i=0;i<ra.candidates_count;i++){
  dmg_value_row_v2 x,y;dmg_source_info sx,sy;uint32_t na,nb;
  CHECK(dmg_result_get_value_v2(a,i,&x,sizeof(x))==DMG_OK&&dmg_result_get_value_v2(b,i,&y,sizeof(y))==DMG_OK&&x.kind==DMG_VALUE_ENTITY&&y.kind==x.kind);
  CHECK(x.entity.relation==y.entity.relation&&x.entity.source_index==y.entity.source_index&&x.entity.local_index==y.entity.local_index&&x.entity.reference_index==y.entity.reference_index);
  CHECK(equal_text(x.entity.owner,x.entity.owner_length,y.entity.owner,y.entity.owner_length)&&equal_text(x.entity.name,x.entity.name_length,y.entity.name,y.entity.name_length)&&equal_text(x.entity.prototype,x.entity.prototype_length,y.entity.prototype,y.entity.prototype_length));
  CHECK(dmg_result_get_origin(a,i,&sx)==DMG_OK&&dmg_result_get_origin(b,i,&sy)==DMG_OK&&strcmp(sx.dex.occurrence_id,sy.dex.occurrence_id)==0);
  CHECK(dmg_result_get_binding_count(a,i,&na)==DMG_OK&&dmg_result_get_binding_count(b,i,&nb)==DMG_OK&&na==nb);
  for(j=0;j<na;j++){dmg_binding_row_v2 u,v;dmg_binding_path pu,pv;CHECK(dmg_result_get_binding_v2(a,i,j,&u,sizeof(u))==DMG_OK&&dmg_result_get_binding_v2(b,i,j,&v,sizeof(v))==DMG_OK);CHECK((!u.label&&!v.label)||(u.label&&v.label&&strcmp(u.label,v.label)==0));CHECK(u.value.kind==v.value.kind&&u.value.entity.source_index==v.value.entity.source_index&&u.value.entity.local_index==v.value.entity.local_index);CHECK(dmg_result_get_binding_path(a,i,j,&pu,sizeof(pu))==DMG_OK&&dmg_result_get_binding_path(b,i,j,&pv,sizeof(pv))==DMG_OK&&pu.length==pv.length&&(!pu.length||memcmp(pu.sides,pv.sides,pu.length)==0));}
  CHECK(dmg_result_get_witness_count(a,i,&na)==DMG_OK&&dmg_result_get_witness_count(b,i,&nb)==DMG_OK&&na==nb);
  for(j=0;j<na;j++){dmg_relation_witness_v2 u,v;CHECK(dmg_result_get_relation_witness_v2(a,i,j,&u,sizeof(u))==DMG_OK&&dmg_result_get_relation_witness_v2(b,i,j,&v,sizeof(v))==DMG_OK);CHECK(u.witness.kind==v.witness.kind&&u.witness.node_id==v.witness.node_id&&u.witness.matched==v.witness.matched&&u.witness.dex_pc==v.witness.dex_pc&&u.witness.opcode==v.witness.opcode&&u.witness.reference_index==v.witness.reference_index&&u.entity.source_index==v.entity.source_index&&u.entity.local_index==v.entity.local_index);}
 }
 return 0;
}
int main(int argc,char** argv){
 const char* exact="{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\",\"using_strings\":{\"all\":[\"used-string\"]}}}}";
 const char* contains="{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\",\"using_strings\":{\"all\":[{\"op\":\"contains\",\"value\":\"string\"}]}}}}";
 const char* left="{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"scope\":{\"slots\":[\"a\"]},\"where\":{\"name\":\"uses\",\"using_strings\":{\"all\":[\"used-string\"]}}}}";
 const char* filter="{\"schema_version\":1,\"required_capabilities\":[\"booleans\"],\"relation\":{\"op\":\"filter\",\"input\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"scope\":{\"slots\":[\"a\"]},\"where\":{\"name\":\"uses\"}},\"where\":{\"using_strings\":{\"all\":[{\"op\":\"contains\",\"value\":\"string\"}]}}}}";
 const char* filter_different="{\"schema_version\":1,\"relation\":{\"op\":\"filter\",\"input\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"scope\":{\"slots\":[\"a\"]},\"where\":{\"name\":\"uses\"}},\"where\":{\"using_strings\":{\"all\":[{\"op\":\"contains\",\"value\":\"string\"}]}}}}";
 const char* label="{\"schema_version\":1,\"relation\":{\"op\":\"label\",\"label\":\"X\",\"input\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\",\"using_strings\":{\"all\":[\"used-string\"]}}}}}";
 const char* graph17="{\"schema_version\":1,\"required_capabilities\":[\"reflection_flags_static\",\"reflection_relational\",\"reflection_body_relational\"],\"relation\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"all\":[{\"name\":\"uses\"},{\"flags\":{\"domain\":\"reflection\",\"mode\":\"contains\",\"value\":8}},{\"using_strings\":{\"all\":[\"used-string\"]}}]}}}";
 const char* join="{\"schema_version\":1,\"relation\":{\"op\":\"join\",\"on\":\"same_entity\",\"left\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\",\"using_strings\":{\"all\":[\"used-string\"]}}},\"right\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\",\"using_strings\":{\"all\":[\"used-string\"]}}}}}";
 const char* bag="{\"schema_version\":1,\"relation\":{\"op\":\"union\",\"semantics\":\"bag\",\"inputs\":[{\"op\":\"label\",\"label\":\"A\",\"input\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\",\"using_strings\":{\"all\":[\"used-string\"]}}}},{\"op\":\"label\",\"label\":\"B\",\"input\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\",\"using_strings\":{\"all\":[\"used-string\"]}}}}]}}";
 const char* mixed="{\"schema_version\":1,\"relation\":{\"op\":\"union\",\"semantics\":\"bag\",\"inputs\":[{\"op\":\"scan\",\"relation\":\"method_defs\",\"scope\":{\"slots\":[\"a\"]},\"where\":{\"name\":\"uses\",\"using_strings\":{\"all\":[\"used-string\"]}}},{\"op\":\"scan\",\"relation\":\"method_defs\",\"scope\":{\"slots\":[\"b\"]},\"where\":{\"name\":\"uses\",\"using_strings\":{\"all\":[\"used-string\"]}}}]}}";
 const char* true_over_unknown="{\"schema_version\":1,\"required_capabilities\":[\"reflection_flags_static\",\"reflection_relational\",\"reflection_body_relational\"],\"relation\":{\"op\":\"distinct\",\"identity\":\"entity\",\"input\":{\"op\":\"union\",\"semantics\":\"bag\",\"inputs\":[{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"all\":[{\"name\":\"uses\"},{\"using_strings\":{\"all\":[\"used-string\"]}},{\"flags\":{\"domain\":\"reflection\",\"mode\":\"contains\",\"value\":8}}]}},{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\",\"using_strings\":{\"all\":[\"used-string\"]}}}]}}}";
 FILE* f;long size;unsigned char* bytes;dmg_engine* engine=NULL;dmg_snapshot *snap=NULL,*partial=NULL;dmg_query *q[11];dmg_error e;uint32_t i,j,index;dmg_source_spec src[2];dmg_source_set_options so={sizeof(so),DMG_ABI_VERSION,"graph-cache",1,16,8u<<20};dmg_multi_options_v1 on={sizeof(on),DMG_ABI_VERSION,1u<<20,1000000,0,0},off={sizeof(off),DMG_ABI_VERSION,0,0,0,0};dmg_engine_stats before,after;
 CHECK(argc==3);f=fopen(argv[1],"rb");CHECK(f);fseek(f,0,SEEK_END);size=ftell(f);rewind(f);CHECK(size>0);bytes=(unsigned char*)malloc((size_t)size);CHECK(bytes&&fread(bytes,1,(size_t)size,f)==(size_t)size);fclose(f);
 src[0]=(dmg_source_spec){sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,bytes,(uint64_t)size,"a","raw",NULL};src[1]=(dmg_source_spec){sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,bytes,(uint64_t)size,"b","raw",NULL};CHECK(dmg_engine_create(NULL,&engine,&e)==DMG_OK&&dmg_snapshot_open_sources(engine,src,2,&so,&snap,&e)==DMG_OK);
 q[0]=compile(engine,exact);q[1]=compile(engine,contains);q[2]=compile(engine,left);q[3]=compile(engine,filter);q[4]=compile(engine,graph17);q[5]=compile(engine,join);q[6]=compile(engine,filter_different);q[7]=compile(engine,label);q[8]=compile(engine,bag);q[9]=compile(engine,mixed);q[10]=compile(engine,true_over_unknown);for(i=0;i<11;i++)CHECK(q[i]);CHECK(dmg_engine_get_stats(engine,&before)==DMG_OK);
 {
  dmg_query* cases[][2]={{q[0],q[1]},{q[0],q[2]},{q[2],q[3]},{q[0],q[4]},{q[4],q[4]},{q[5],q[5]},{q[2],q[6]},{q[0],q[7]},{q[8],q[8]},{q[9],q[9]}};
  const int hits[]={1,0,1,0,1,0,0,1,1,0};
  for(i=0;i<10;i++){dmg_multi_batch_v1 *cached=NULL,*plain=NULL;dmg_multi_profile_v1 p;dmg_query_info qi,qj;CHECK(dmg_query_get_info(cases[i][0],&qi)==DMG_OK&&dmg_query_get_info(cases[i][1],&qj)==DMG_OK);fprintf(stderr,"case %u cap %u %u demand %u %u\n",i,qi.required_capabilities,qj.required_capabilities,qi.demand_mask,qj.demand_mask);CHECK(dmg_multi_execute_v1(snap,cases[i],2,&on,&cached,&index,&e)==DMG_OK&&dmg_multi_execute_v1(snap,cases[i],2,&off,&plain,&index,&e)==DMG_OK);
   CHECK(dmg_multi_batch_profile_v1(cached,&p,sizeof(p))==DMG_OK);fprintf(stderr,"case %u hits %llu builds %llu collects %llu charged %llu\n",i,(unsigned long long)p.cache_hits,(unsigned long long)p.cache_builds,(unsigned long long)p.physical_collects,(unsigned long long)p.cache_work_charged);CHECK((p.cache_hits>0)==hits[i]);
   for(j=0;j<2;j++){dmg_result *a=NULL,*b=NULL,*single=NULL;dmg_graph_info ga,gb;uint32_t k;
    CHECK(dmg_multi_batch_get_result_v1(cached,j,&a)==DMG_OK&&dmg_multi_batch_get_result_v1(plain,j,&b)==DMG_OK&&dmg_query_execute(snap,cases[i][j],&single,&e)==DMG_OK);
    CHECK(same_result(a,b)==0&&same_result(a,single)==0);CHECK(dmg_result_get_graph_info(a,&ga,sizeof(ga))==DMG_OK&&dmg_result_get_graph_info(b,&gb,sizeof(gb))==DMG_OK&&ga.root_node==gb.root_node&&ga.operator_count==gb.operator_count&&ga.identity_count==gb.identity_count);
    for(k=0;k<ga.operator_count;k++){dmg_operator_profile x,y;CHECK(dmg_result_get_operator_profile(a,k,&x,sizeof(x))==DMG_OK&&dmg_result_get_operator_profile(b,k,&y,sizeof(y))==DMG_OK&&x.node_id==y.node_id&&x.op==y.op&&x.input_rows==y.input_rows&&x.output_rows==y.output_rows&&x.unknown_rows==y.unknown_rows&&x.visited_rows==y.visited_rows&&x.total_rows==y.total_rows&&x.complete==y.complete);}
    dmg_result_release(a);dmg_result_release(b);dmg_result_release(single);
   }dmg_multi_batch_release_v1(cached);dmg_multi_batch_release_v1(plain);
  }
 }
 {
  const char* low_json="{\"schema_version\":1,\"max_work\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\",\"using_strings\":{\"all\":[\"used-string\"]}}}}";
  dmg_query* low=compile(engine,low_json);dmg_query* rules[]={q[0],low,q[1]};dmg_multi_batch_v1* absent=NULL;CHECK(low);CHECK(dmg_multi_execute_v1(snap,rules,3,&on,&absent,&index,&e)==DMG_BUDGET_EXCEEDED&&absent==NULL&&index==1);dmg_query_release(low);
 }
 {
  dmg_multi_batch_v1 *cached=NULL,*plain=NULL;dmg_multi_profile_v1 p;dmg_result *a=NULL,*b=NULL;dmg_query* rules[]={q[8]};
  CHECK(dmg_multi_execute_v1(snap,rules,1,&on,&cached,&index,&e)==DMG_OK&&dmg_multi_execute_v1(snap,rules,1,&off,&plain,&index,&e)==DMG_OK);
  CHECK(dmg_multi_batch_profile_v1(cached,&p,sizeof(p))==DMG_OK&&p.cache_hits==2&&p.cache_builds==2&&p.physical_collects==2);
  CHECK(dmg_multi_batch_get_result_v1(cached,0,&a)==DMG_OK&&dmg_multi_batch_get_result_v1(plain,0,&b)==DMG_OK&&same_result(a,b)==0);
  dmg_result_release(a);dmg_result_release(b);dmg_multi_batch_release_v1(cached);dmg_multi_batch_release_v1(plain);
 }
 {
  dmg_multi_options_v1 tiny=on;dmg_multi_batch_v1 *cached=NULL,*plain=NULL;dmg_multi_profile_v1 p;dmg_result *a=NULL,*b=NULL;dmg_query* rules[]={q[8]};tiny.max_cache_work=1;
  CHECK(dmg_multi_execute_v1(snap,rules,1,&tiny,&cached,&index,&e)==DMG_OK&&dmg_multi_execute_v1(snap,rules,1,&off,&plain,&index,&e)==DMG_OK);
  CHECK(dmg_multi_batch_profile_v1(cached,&p,sizeof(p))==DMG_OK&&p.cache_hits==0&&p.cache_work_charged<=1);
  CHECK(dmg_multi_batch_get_result_v1(cached,0,&a)==DMG_OK&&dmg_multi_batch_get_result_v1(plain,0,&b)==DMG_OK&&same_result(a,b)==0);
  dmg_result_release(a);dmg_result_release(b);dmg_multi_batch_release_v1(cached);dmg_multi_batch_release_v1(plain);
 }
 {dmg_multi_options_v1 tiny=on;dmg_multi_batch_v1* cached=NULL;dmg_multi_profile_v1 p;dmg_query* rules[]={q[0],q[1]};tiny.max_cache_work=1;CHECK(dmg_multi_execute_v1(snap,rules,2,&tiny,&cached,&index,&e)==DMG_OK);CHECK(dmg_multi_batch_profile_v1(cached,&p,sizeof(p))==DMG_OK&&p.cache_hits==0&&p.cache_work_charged<=1);dmg_multi_batch_release_v1(cached);}
 {
  unsigned char* unknown;long n;dmg_snapshot* unknown_snap=NULL;dmg_multi_batch_v1 *cached=NULL,*plain=NULL;dmg_query* rules[]={q[4],q[4]};dmg_multi_profile_v1 p;dmg_result *a=NULL,*b=NULL;dmg_relation_info info;
  f=fopen(argv[2],"rb");CHECK(f);fseek(f,0,SEEK_END);n=ftell(f);rewind(f);CHECK(n>0);unknown=(unsigned char*)malloc((size_t)n);CHECK(unknown&&fread(unknown,1,(size_t)n,f)==(size_t)n);fclose(f);
  {dmg_source_spec u={sizeof(u),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,unknown,(uint64_t)n,"a","raw",NULL};CHECK(dmg_snapshot_open_sources(engine,&u,1,&so,&unknown_snap,&e)==DMG_OK);}free(unknown);
  CHECK(dmg_multi_execute_v1(unknown_snap,rules,2,&on,&cached,&index,&e)==DMG_OK&&dmg_multi_execute_v1(unknown_snap,rules,2,&off,&plain,&index,&e)==DMG_OK);CHECK(dmg_multi_batch_profile_v1(cached,&p,sizeof(p))==DMG_OK&&p.cache_hits>0);
  CHECK(dmg_multi_batch_get_result_v1(cached,1,&a)==DMG_OK&&dmg_multi_batch_get_result_v1(plain,1,&b)==DMG_OK&&same_result(a,b)==0);CHECK(dmg_result_get_relation_info(a,&info,sizeof(info))==DMG_OK&&info.unknown_rows>0&&info.coverage==DMG_COVERAGE_PARTIAL);dmg_result_release(a);dmg_result_release(b);dmg_multi_batch_release_v1(cached);dmg_multi_batch_release_v1(plain);dmg_snapshot_release(unknown_snap);
 }
 {
  unsigned char* unknown;long n;dmg_snapshot* unknown_snap=NULL;dmg_multi_batch_v1 *cached=NULL,*plain=NULL;dmg_query* rules[]={q[10],q[10]};dmg_multi_profile_v1 p;dmg_result *a=NULL,*b=NULL;dmg_relation_info info;
  f=fopen(argv[2],"rb");CHECK(f);fseek(f,0,SEEK_END);n=ftell(f);rewind(f);CHECK(n>0);unknown=(unsigned char*)malloc((size_t)n);CHECK(unknown&&fread(unknown,1,(size_t)n,f)==(size_t)n);fclose(f);
  {dmg_source_spec u={sizeof(u),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,unknown,(uint64_t)n,"a","raw",NULL};CHECK(dmg_snapshot_open_sources(engine,&u,1,&so,&unknown_snap,&e)==DMG_OK);}free(unknown);
  CHECK(dmg_multi_execute_v1(unknown_snap,rules,2,&on,&cached,&index,&e)==DMG_OK&&dmg_multi_execute_v1(unknown_snap,rules,2,&off,&plain,&index,&e)==DMG_OK);
  CHECK(dmg_multi_batch_profile_v1(cached,&p,sizeof(p))==DMG_OK&&p.cache_hits>0);
  CHECK(dmg_multi_batch_get_result_v1(cached,1,&a)==DMG_OK&&dmg_multi_batch_get_result_v1(plain,1,&b)==DMG_OK&&same_result(a,b)==0);
  CHECK(dmg_result_get_relation_info(a,&info,sizeof(info))==DMG_OK&&info.candidates_count==1&&info.unknown_rows==0&&info.coverage==DMG_COVERAGE_COMPLETE);
  dmg_result_release(a);dmg_result_release(b);dmg_multi_batch_release_v1(cached);dmg_multi_batch_release_v1(plain);dmg_snapshot_release(unknown_snap);
 }
 so.scope_complete=0;CHECK(dmg_snapshot_open_sources(engine,src,2,&so,&partial,&e)==DMG_OK);
 {dmg_multi_batch_v1 *cached=NULL,*plain=NULL;dmg_query* rules[]={q[0],q[1]};dmg_multi_profile_v1 p;CHECK(dmg_multi_execute_v1(partial,rules,2,&on,&cached,&index,&e)==DMG_OK&&dmg_multi_execute_v1(partial,rules,2,&off,&plain,&index,&e)==DMG_OK);CHECK(dmg_multi_batch_profile_v1(cached,&p,sizeof(p))==DMG_OK&&p.cache_hits>0);
  for(j=0;j<2;j++){dmg_result *a=NULL,*b=NULL;dmg_query_profile prof;CHECK(dmg_multi_batch_get_result_v1(cached,j,&a)==DMG_OK&&dmg_multi_batch_get_result_v1(plain,j,&b)==DMG_OK&&same_result(a,b)==0);CHECK(dmg_result_get_profile(a,&prof)==DMG_OK&&prof.scope_complete==0);dmg_result_release(a);dmg_result_release(b);}dmg_multi_batch_release_v1(cached);dmg_multi_batch_release_v1(plain);}
 dmg_snapshot_release(partial);CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&after.owned_bytes==before.owned_bytes&&after.scratch_bytes==before.scratch_bytes&&after.result_bytes==before.result_bytes);
 for(i=0;i<11;i++)dmg_query_release(q[i]);dmg_snapshot_release(snap);dmg_engine_release(engine);free(bytes);puts("PASS C graph cache sharing, scope/profile separation, scalar and batch parity");return 0;
}
