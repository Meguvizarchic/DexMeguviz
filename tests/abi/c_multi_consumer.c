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
  CHECK(dmg_result_get_witness_count(a,i,&na)==DMG_OK&&dmg_result_get_witness_count(b,i,&nb)==DMG_OK&&na==nb);
  for(j=0;j<na;j++){dmg_relation_witness_v2 u,v;CHECK(dmg_result_get_relation_witness_v2(a,i,j,&u,sizeof(u))==DMG_OK&&dmg_result_get_relation_witness_v2(b,i,j,&v,sizeof(v))==DMG_OK);CHECK(u.witness.kind==v.witness.kind&&u.witness.node_id==v.witness.node_id&&u.witness.matched==v.witness.matched&&u.witness.dex_pc==v.witness.dex_pc&&u.witness.opcode==v.witness.opcode&&u.witness.reference_index==v.witness.reference_index&&u.entity.source_index==v.entity.source_index&&u.entity.local_index==v.entity.local_index);}
 }
 return 0;
}
int main(int argc,char** argv){
 const char* qone="{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\",\"using_strings\":{\"all\":[\"used-string\"]}}}";
 const char* qtwo="{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\",\"using_strings\":{\"all\":[{\"op\":\"contains\",\"value\":\"string\"}]}}}";
 const char* qleft="{\"schema_version\":1,\"relation\":\"method_defs\",\"scope\":{\"slots\":[\"a\"]},\"where\":{\"name\":\"uses\",\"using_strings\":{\"all\":[\"used-string\"]}}}";
 const char* qlimit="{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\"},\"max_results\":1}";
 const char* qlow="{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":true,\"max_work\":1}";
 FILE* file;long size;unsigned char* bytes;dmg_engine *engine=NULL,*other=NULL;dmg_snapshot *snapshot=NULL,*partial=NULL;dmg_query *q[5]={0},*foreign=NULL;dmg_multi_batch_v1* batch=NULL;dmg_result *scalar=NULL,*r0=NULL,*r1=NULL;dmg_error e={0};uint32_t failed=0,count=0,i;dmg_multi_profile_v1 profile;dmg_engine_stats before,after;
 dmg_multi_options_v1 mo={sizeof(mo),DMG_ABI_VERSION,1u<<20,1000000,0,0};dmg_source_spec source[2];dmg_source_set_options so={sizeof(so),DMG_ABI_VERSION,"c-multi",1,16,8u<<20};
 CHECK(argc==4);file=fopen(argv[1],"rb");CHECK(file);fseek(file,0,SEEK_END);size=ftell(file);rewind(file);CHECK(size>0);bytes=(unsigned char*)malloc((size_t)size);CHECK(bytes&&fread(bytes,1,(size_t)size,file)==(size_t)size);fclose(file);
 source[0]=(dmg_source_spec){sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,bytes,(uint64_t)size,"a","raw",NULL};source[1]=(dmg_source_spec){sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,bytes,(uint64_t)size,"b","raw",NULL};
 CHECK(dmg_engine_create(NULL,&engine,&e)==DMG_OK&&dmg_snapshot_open_sources(engine,source,2,&so,&snapshot,&e)==DMG_OK);
 q[0]=compile(engine,qone);q[1]=compile(engine,qtwo);q[2]=compile(engine,qleft);q[3]=compile(engine,qlimit);q[4]=compile(engine,qlow);for(i=0;i<5;i++)CHECK(q[i]);
 CHECK(dmg_engine_get_stats(engine,&before)==DMG_OK);
 CHECK(dmg_multi_execute_v1(snapshot,q,2,&mo,&batch,&failed,&e)==DMG_OK&&batch&&failed==UINT32_MAX);
 CHECK(dmg_multi_batch_count_v1(batch,&count)==DMG_OK&&count==2&&dmg_multi_batch_profile_v1(batch,&profile,sizeof(profile))==DMG_OK&&profile.cache_hits>0&&profile.cache_builds>0);
 for(i=0;i<2;i++){dmg_result* shared=NULL;CHECK(dmg_multi_batch_get_result_v1(batch,i,&shared)==DMG_OK&&dmg_query_execute(snapshot,q[i],&scalar,&e)==DMG_OK);CHECK(same_result(shared,scalar)==0);dmg_result_release(shared);dmg_result_release(scalar);scalar=NULL;}
 {dmg_multi_profile_v1 sentinel;memset(&sentinel,0x5a,sizeof(sentinel));CHECK(dmg_multi_batch_profile_v1(batch,&sentinel,sizeof(sentinel)-1)==DMG_INVALID_ARGUMENT);for(i=0;i<sizeof(sentinel);++i)CHECK(((unsigned char*)&sentinel)[i]==0x5a);}
 dmg_multi_batch_release_v1(batch);batch=NULL;CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&after.owned_bytes==before.owned_bytes&&after.result_bytes==before.result_bytes&&after.scratch_bytes==before.scratch_bytes);
 {dmg_multi_options_v1 oversized=mo;oversized.cache_bytes=1ull<<30;CHECK(dmg_multi_execute_v1(snapshot,q,2,&oversized,&batch,&failed,&e)==DMG_OK);CHECK(dmg_multi_batch_profile_v1(batch,&profile,sizeof(profile))==DMG_OK&&profile.arena_budget_unavailable==1&&profile.cache_hits==0);dmg_multi_batch_release_v1(batch);batch=NULL;}
 {dmg_query* rules[]={q[0],q[2]};CHECK(dmg_multi_execute_v1(snapshot,rules,2,&mo,&batch,&failed,&e)==DMG_OK);CHECK(dmg_multi_batch_profile_v1(batch,&profile,sizeof(profile))==DMG_OK&&profile.cache_hits==0);dmg_multi_batch_release_v1(batch);batch=NULL;}
 {dmg_query* rules[]={q[3],q[0]};dmg_result_info info;CHECK(dmg_multi_execute_v1(snapshot,rules,2,&mo,&batch,&failed,&e)==DMG_OK);CHECK(dmg_multi_batch_get_result_v1(batch,0,&r0)==DMG_OK&&dmg_result_get_info(r0,&info)==DMG_OK&&info.execution_status==DMG_BUDGET_EXCEEDED&&info.reason==DMG_RESULT_LIMIT&&info.candidates_count==1);dmg_result_release(r0);r0=NULL;dmg_multi_batch_release_v1(batch);batch=NULL;}
 {dmg_query* rules[]={q[0],q[4],q[1]};CHECK(dmg_multi_execute_v1(snapshot,rules,3,&mo,&batch,&failed,&e)==DMG_BUDGET_EXCEEDED&&batch==NULL&&failed==1);CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&after.owned_bytes==before.owned_bytes&&after.result_bytes==before.result_bytes&&after.scratch_bytes==before.scratch_bytes);}
 CHECK(dmg_multi_execute_v1(snapshot,NULL,0,&mo,&batch,&failed,&e)==DMG_OK&&dmg_multi_batch_count_v1(batch,&count)==DMG_OK&&count==0);dmg_multi_batch_release_v1(batch);batch=NULL;
 {dmg_multi_options_v1 bad=mo;bad.abi_version++;CHECK(dmg_multi_execute_v1(snapshot,q,2,&bad,&batch,&failed,&e)==DMG_INVALID_ARGUMENT&&batch==NULL&&failed==UINT32_MAX);}
 CHECK(dmg_engine_create(NULL,&other,&e)==DMG_OK);foreign=compile(other,qone);CHECK(foreign);{dmg_query* rules[]={q[0],foreign};CHECK(dmg_multi_execute_v1(snapshot,rules,2,&mo,&batch,&failed,&e)==DMG_INVALID_ARGUMENT&&batch==NULL&&failed==1);}
 {dmg_query* rules[]={q[4],foreign};CHECK(dmg_multi_execute_v1(snapshot,rules,2,&mo,&batch,&failed,&e)==DMG_INVALID_ARGUMENT&&batch==NULL&&failed==1);}dmg_query_release(foreign);dmg_engine_release(other);
 so.scope_complete=0;CHECK(dmg_snapshot_open_sources(engine,source,2,&so,&partial,&e)==DMG_OK);CHECK(dmg_multi_execute_v1(partial,q,2,&mo,&batch,&failed,&e)==DMG_OK);CHECK(dmg_multi_batch_get_result_v1(batch,0,&r0)==DMG_OK);{dmg_query_profile p;CHECK(dmg_result_get_profile(r0,&p)==DMG_OK&&p.scope_complete==0);}dmg_result_release(r0);dmg_multi_batch_release_v1(batch);batch=NULL;dmg_snapshot_close(partial);CHECK(dmg_multi_execute_v1(partial,q,2,&mo,&batch,&failed,&e)==DMG_CLOSED&&batch==NULL);dmg_snapshot_release(partial);
 {
  const char* graph="{\"schema_version\":1,\"relation\":{\"op\":\"join\",\"on\":\"same_entity\",\"left\":{\"op\":\"label\",\"label\":\"L\",\"input\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\"}}},\"right\":{\"op\":\"label\",\"label\":\"R\",\"input\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\"}}}}}";
  dmg_query* g=compile(engine,graph);dmg_query* gs[]={g,g};dmg_graph_info ga,gb;dmg_relation_info info;uint32_t j;CHECK(g);
  CHECK(dmg_multi_execute_v1(snapshot,gs,2,&mo,&batch,&failed,&e)==DMG_OK&&dmg_multi_batch_profile_v1(batch,&profile,sizeof(profile))==DMG_OK&&profile.cache_hits==0);
  CHECK(dmg_multi_batch_get_result_v1(batch,0,&r0)==DMG_OK&&dmg_query_execute(snapshot,g,&scalar,&e)==DMG_OK&&same_result(r0,scalar)==0);
  CHECK(dmg_result_get_graph_info(r0,&ga,sizeof(ga))==DMG_OK&&dmg_result_get_graph_info(scalar,&gb,sizeof(gb))==DMG_OK&&ga.root_node==gb.root_node&&ga.operator_count==gb.operator_count);
  CHECK(dmg_result_get_relation_info(r0,&info,sizeof(info))==DMG_OK&&info.candidates_count>0);
  for(j=0;j<info.candidates_count;j++){uint32_t na,nb,k;CHECK(dmg_result_get_link_count(r0,j,&na)==DMG_OK&&dmg_result_get_link_count(scalar,j,&nb)==DMG_OK&&na==nb&&na>0);
   for(k=0;k<na;k++){dmg_relation_link_v2 a,b;CHECK(dmg_result_get_link_v2(r0,j,k,&a,sizeof(a))==DMG_OK&&dmg_result_get_link_v2(scalar,j,k,&b,sizeof(b))==DMG_OK&&a.node_id==b.node_id&&a.key==b.key&&a.left.source_index==b.left.source_index&&a.left.local_index==b.left.local_index&&a.right.source_index==b.right.source_index&&a.right.local_index==b.right.local_index);}}
  dmg_result_release(r0);r0=NULL;dmg_result_release(scalar);scalar=NULL;dmg_multi_batch_release_v1(batch);batch=NULL;dmg_query_release(g);
 }
 {
  const char* grouped="{\"schema_version\":1,\"relation\":{\"op\":\"group_by_owner\",\"inputs\":[{\"op\":\"label\",\"label\":\"A\",\"input\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\",\"using_strings\":{\"all\":[\"used-string\"]}}}},{\"op\":\"label\",\"label\":\"B\",\"input\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\",\"using_strings\":{\"all\":[\"used-string\"]}}}}],\"min\":1,\"max\":1,\"required_roles\":[\"A\",\"B\"],\"role_policy\":\"shared\"}}";
  dmg_query* g=compile(engine,grouped);dmg_query* gs[]={g,g};dmg_relation_info info;uint32_t j,k;CHECK(g);
  CHECK(dmg_multi_execute_v1(snapshot,gs,2,&mo,&batch,&failed,&e)==DMG_OK&&dmg_multi_batch_profile_v1(batch,&profile,sizeof(profile))==DMG_OK&&profile.cache_hits>0);
  CHECK(dmg_multi_batch_get_result_v1(batch,0,&r0)==DMG_OK&&dmg_query_execute(snapshot,g,&scalar,&e)==DMG_OK&&same_result(r0,scalar)==0);
  CHECK(dmg_result_get_relation_info(r0,&info,sizeof(info))==DMG_OK&&info.candidates_count==2);
  for(j=0;j<info.candidates_count;j++){uint32_t a,b;CHECK(dmg_result_get_binding_count(r0,j,&a)==DMG_OK&&dmg_result_get_binding_count(scalar,j,&b)==DMG_OK&&a==b&&a>=2);
   for(k=0;k<a;k++){dmg_binding_row_v2 x,y;dmg_binding_path px,py;CHECK(dmg_result_get_binding_v2(r0,j,k,&x,sizeof(x))==DMG_OK&&dmg_result_get_binding_v2(scalar,j,k,&y,sizeof(y))==DMG_OK);
    CHECK((!x.label&&!y.label)||(x.label&&y.label&&strcmp(x.label,y.label)==0));
    CHECK(x.value.kind==y.value.kind&&x.value.entity.relation==y.value.entity.relation&&x.value.entity.source_index==y.value.entity.source_index&&x.value.entity.local_index==y.value.entity.local_index);
    CHECK(dmg_result_get_binding_path(r0,j,k,&px,sizeof(px))==DMG_OK&&dmg_result_get_binding_path(scalar,j,k,&py,sizeof(py))==DMG_OK&&px.length==py.length&&(!px.length||memcmp(px.sides,py.sides,px.length)==0));}}
  dmg_result_release(r0);r0=NULL;dmg_result_release(scalar);scalar=NULL;dmg_multi_batch_release_v1(batch);batch=NULL;dmg_query_release(g);
 }
 {
  const char* v18="{\"schema_version\":1,\"required_capabilities\":[\"inherited_fields\",\"use_target_symbol\",\"inherited_target_symbol\"],\"relation\":{\"op\":\"join\",\"on\":\"target_symbol\",\"left\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"},\"right\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"all\":[{\"name\":\"uses\"},{\"declares_fields\":{\"scope\":\"inherited\",\"where\":{\"name\":\"unseen\"},\"min\":0,\"max\":0}}]}}},\"max_results\":100}";
  unsigned char *one,*two;long n1,n2;dmg_source_spec src[2];dmg_snapshot* snap=NULL;dmg_query* g;dmg_query* gs[2];dmg_relation_info_v2 x,y;uint32_t j,k,seen=0;
  file=fopen(argv[2],"rb");CHECK(file);fseek(file,0,SEEK_END);n1=ftell(file);rewind(file);CHECK(n1>0);one=(unsigned char*)malloc((size_t)n1);CHECK(one&&fread(one,1,(size_t)n1,file)==(size_t)n1);fclose(file);
  file=fopen(argv[3],"rb");CHECK(file);fseek(file,0,SEEK_END);n2=ftell(file);rewind(file);CHECK(n2>0);two=(unsigned char*)malloc((size_t)n2);CHECK(two&&fread(two,1,(size_t)n2,file)==(size_t)n2);fclose(file);
  src[0]=(dmg_source_spec){sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,one,(uint64_t)n1,"a","raw",NULL};src[1]=(dmg_source_spec){sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,two,(uint64_t)n2,"b","raw",NULL};
  so.scope_complete=1;CHECK(dmg_snapshot_open_sources(engine,src,2,&so,&snap,&e)==DMG_OK);g=compile(engine,v18);CHECK(g);gs[0]=g;gs[1]=g;
  CHECK(dmg_multi_execute_v1(snap,gs,2,&mo,&batch,&failed,&e)==DMG_OK&&dmg_multi_batch_profile_v1(batch,&profile,sizeof(profile))==DMG_OK&&profile.cache_hits==0);
  CHECK(dmg_multi_batch_get_result_v1(batch,0,&r0)==DMG_OK&&dmg_query_execute(snap,g,&scalar,&e)==DMG_OK);
  CHECK(dmg_result_get_relation_info_v2(r0,&x,sizeof(x))==DMG_OK&&dmg_result_get_relation_info_v2(scalar,&y,sizeof(y))==DMG_OK&&x.candidates_count>0&&x.candidates_count==y.candidates_count&&x.coverage==y.coverage&&x.unknown_rows==y.unknown_rows);
  for(j=0;j<x.candidates_count;j++){uint32_t n,m;CHECK(dmg_result_get_witness_count(r0,j,&n)==DMG_OK&&dmg_result_get_witness_count(scalar,j,&m)==DMG_OK&&n==m);
   for(k=0;k<n;k++){dmg_relation_witness_v2 a,b;CHECK(dmg_result_get_relation_witness_v2(r0,j,k,&a,sizeof(a))==DMG_OK&&dmg_result_get_relation_witness_v2(scalar,j,k,&b,sizeof(b))==DMG_OK&&a.witness.kind==b.witness.kind&&a.entity.source_index==b.entity.source_index&&a.entity.local_index==b.entity.local_index);
    if(a.witness.kind==DMG_WITNESS_INHERITED){dmg_inherited_witness ia,ib;CHECK(dmg_result_get_inherited_witness(r0,j,k,&ia,sizeof(ia))==DMG_OK&&dmg_result_get_inherited_witness(scalar,j,k,&ib,sizeof(ib))==DMG_OK&&ia.node_id==ib.node_id&&ia.item_kind==ib.item_kind&&ia.path_index==ib.path_index&&ia.aux==ib.aux&&ia.branch_index==ib.branch_index&&ia.detail==ib.detail&&ia.source_index==ib.source_index&&ia.local_index==ib.local_index);seen++;}}}
  CHECK(seen>0);dmg_result_release(r0);r0=NULL;dmg_result_release(scalar);scalar=NULL;dmg_multi_batch_release_v1(batch);batch=NULL;dmg_query_release(g);dmg_snapshot_release(snap);free(one);free(two);
 }
 CHECK(dmg_multi_execute_v1(snapshot,q,2,&mo,&batch,&failed,&e)==DMG_OK);CHECK(dmg_multi_batch_get_result_v1(batch,0,&r0)==DMG_OK&&dmg_multi_batch_get_result_v1(batch,0,&r1)==DMG_OK&&r0==r1);
 {dmg_result* invalid=(dmg_result*)1;CHECK(dmg_multi_batch_get_result_v1(batch,2,&invalid)==DMG_INVALID_ARGUMENT&&invalid==NULL);}
 CHECK(dmg_engine_shutdown(engine,0)==DMG_OK);{dmg_multi_batch_v1* denied=NULL;CHECK(dmg_multi_execute_v1(snapshot,q,2,&mo,&denied,&failed,&e)==DMG_CLOSED&&denied==NULL);}
 for(i=0;i<5;i++)dmg_query_release(q[i]);dmg_snapshot_close(snapshot);dmg_snapshot_release(snapshot);dmg_engine_release(engine);free(bytes);
 dmg_multi_batch_release_v1(batch);{dmg_query_info qi;dmg_result_info ri;CHECK(dmg_result_get_query_info(r0,&qi)==DMG_OK&&qi.query_id&&dmg_result_get_info(r0,&ri)==DMG_OK&&ri.candidates_count>0);dmg_result_release(r0);CHECK(dmg_result_get_info(r1,&ri)==DMG_OK);dmg_result_release(r1);}
 puts("PASS C multi v1 sharing, scope, atomic error, ResultLimit, refcount and lifetime");return 0;
}
