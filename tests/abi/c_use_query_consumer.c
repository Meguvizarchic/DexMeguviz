#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do{if(!(x)){fprintf(stderr,"use C ABI check %d: %s\n",__LINE__,#x);return 1;}}while(0)
#define EVENTS "{\"op\":\"scan\",\"relation\":\"invoke_sites\"}"
#define CALLERS "{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\"}}"
#define PAIRS "{\"op\":\"join\",\"on\":\"caller\",\"left\":" CALLERS ",\"right\":" EVENTS "}"
static const char event_query[]="{\"schema_version\":1,\"relation\":" EVENTS ",\"intent\":\"unique\"}";
static const char pair_query[]="{\"schema_version\":1,\"relation\":" PAIRS ",\"intent\":\"unique\",\"unique_by\":\"tuple\"}";
static const char semi_query[]="{\"schema_version\":1,\"relation\":{\"op\":\"semi_join\",\"left\":" CALLERS ",\"right\":{\"op\":\"scan\",\"relation\":\"invoke_sites\",\"where\":{\"pc\":3}},\"on\":\"caller\"}}";
static const char budget_query[]="{\"schema_version\":1,\"relation\":" EVENTS ",\"max_work\":1}";
static int has_capability(const char* capabilities,const char* wanted){size_t n=strlen(wanted);const char* p=capabilities;if(!p)return 0;while(*p){const char* end=strchr(p,';');size_t length=end?(size_t)(end-p):strlen(p);if(length==n&&memcmp(p,wanted,n)==0)return 1;if(!end)break;p=end+1;}return 0;}
static int untouched(const void* pointer,size_t length){const unsigned char* p=(const unsigned char*)pointer;size_t i;for(i=0;i<length;++i)if(p[i]!=0xa5)return 0;return 1;}
static int same_live(const dmg_engine_stats* a,const dmg_engine_stats* b){return a->owned_bytes==b->owned_bytes&&a->source_bytes==b->source_bytes&&a->fact_bytes==b->fact_bytes&&a->scratch_bytes==b->scratch_bytes&&a->query_bytes==b->query_bytes&&a->result_bytes==b->result_bytes&&a->control_bytes==b->control_bytes&&a->borrowed_bytes==b->borrowed_bytes&&a->active_jobs==b->active_jobs;}
static int units_equal(const uint16_t* text,uint64_t length,const char* ascii){size_t i,n=strlen(ascii);if(length!=n||(!text&&n))return 0;for(i=0;i<n;++i)if(text[i]!=(unsigned char)ascii[i])return 0;return 1;}
static int compile(dmg_engine* engine,const char* input,dmg_query** out){dmg_error error={0};dmg_status status=dmg_query_compile_json(engine,(const uint8_t*)input,strlen(input),out,&error);if(status!=DMG_OK)fprintf(stderr,"compile: %u %s\n",status,error.message);CHECK(status==DMG_OK&&*out);return 0;}
static int sized(const dmg_result* result){
 dmg_value_row_v2 row;dmg_relation_info_v2 info;dmg_operator_profile_v2 op;
 memset(&row,0xa5,sizeof(row));memset(&info,0xa5,sizeof(info));memset(&op,0xa5,sizeof(op));
 CHECK(dmg_result_get_value_v2(result,0,&row,(uint32_t)sizeof(row)-1)==DMG_INVALID_ARGUMENT&&untouched(&row,sizeof(row)));
 CHECK(dmg_result_get_relation_info_v2(result,&info,(uint32_t)sizeof(info)-1)==DMG_INVALID_ARGUMENT&&untouched(&info,sizeof(info)));
 CHECK(dmg_result_get_operator_profile_v2(result,0,&op,(uint32_t)sizeof(op)-1)==DMG_INVALID_ARGUMENT&&untouched(&op,sizeof(op)));return 0;
}
static int event_record(const dmg_value_row_v2* row,uint32_t pc){
 CHECK(row->kind==DMG_VALUE_USE&&row->use.relation==DMG_INVOKE_SITES&&row->use.source_index==0&&row->use.caller_ordinal==2&&row->use.caller_method_ref==3);
 CHECK(row->use.dex_pc==pc&&row->use.opcode==0x71&&row->use.code_offset==416&&row->use.target_domain==DMG_TARGET_METHOD_REF&&row->use.target_index==4&&row->use.extra_proto==UINT32_MAX);
 CHECK(units_equal(row->use.owner,row->use.owner_length,"Lfacts/Example;")&&units_equal(row->use.name,row->use.name_length,"uses")&&units_equal(row->use.prototype,row->use.prototype_length,"()V"));return 0;
}
static int check_events(const dmg_result* result){
 dmg_relation_info old;dmg_relation_info_v2 info;dmg_operator_profile old_op;dmg_operator_profile_v2 op;dmg_entity_row old_row;uint32_t i;
 memset(&old,0xa5,sizeof(old));memset(&old_op,0xa5,sizeof(old_op));memset(&old_row,0xa5,sizeof(old_row));
 CHECK(dmg_result_get_relation_info(result,&old,sizeof(old))==DMG_UNSUPPORTED&&untouched(&old,sizeof(old)));
 CHECK(dmg_result_get_operator_profile(result,0,&old_op,sizeof(old_op))==DMG_UNSUPPORTED&&untouched(&old_op,sizeof(old_op)));
 CHECK(dmg_result_get_entity(result,0,&old_row,sizeof(old_row))==DMG_UNSUPPORTED&&untouched(&old_row,sizeof(old_row)));
 CHECK(dmg_result_get_relation_info_v2(result,&info,sizeof(info))==DMG_OK&&info.relation==DMG_INVOKE_SITES&&info.coverage==DMG_COVERAGE_COMPLETE&&info.decision==DMG_PROVEN_FALSE&&info.reason==DMG_AMBIGUOUS&&info.candidates_count==2);
 CHECK(info.entity_visited==0&&info.entity_total==0&&info.method_visited==4&&info.method_total==4&&info.events_collected==2&&info.unknown_rows==0);
 CHECK(dmg_result_get_operator_profile_v2(result,0,&op,sizeof(op))==DMG_OK&&op.op==DMG_REL_SCAN&&op.scan_domain==DMG_SCAN_DOMAIN_METHOD_DEFS&&op.total==4&&op.visited==4&&op.no_body_methods==2&&op.decoded_methods==2&&op.events_collected==2);
 for(i=0;i<2;++i){dmg_value_row_v2 row;dmg_relation_witness old_witness;dmg_relation_witness_v2 witness;uint32_t count=0,j,matched_pc=0;
  CHECK(dmg_result_get_value_v2(result,i,&row,sizeof(row))==DMG_OK&&event_record(&row,i*3)==0);
  CHECK(dmg_result_get_witness_count(result,i,&count)==DMG_OK&&count>0);
  for(j=0;j<count;++j){dmg_witness simple;memset(&simple,0xa5,sizeof(simple));memset(&witness,0xa5,sizeof(witness));
   CHECK(dmg_result_get_witness(result,i,j,&simple)==DMG_UNSUPPORTED&&untouched(&simple,sizeof(simple)));
   CHECK(dmg_result_get_relation_witness_v2(result,i,j,&witness,(uint32_t)sizeof(witness)-1)==DMG_INVALID_ARGUMENT&&untouched(&witness,sizeof(witness)));
   memset(&old_witness,0xa5,sizeof(old_witness));CHECK(dmg_result_get_relation_witness(result,i,j,&old_witness,sizeof(old_witness))==DMG_UNSUPPORTED&&untouched(&old_witness,sizeof(old_witness)));
   CHECK(dmg_result_get_relation_witness_v2(result,i,j,&witness,sizeof(witness))==DMG_OK&&witness.entity.relation==DMG_INVOKE_SITES&&witness.entity.local_index==2&&witness.entity.dex_pc==i*3);
   if(witness.witness.dex_pc==i*3)matched_pc=1;
  }CHECK(matched_pc);
 }
 CHECK(sized(result)==0);return 0;
}
static int check_pair(const dmg_result* result,uint32_t index,int batch){
 dmg_relation_info old;dmg_relation_info_v2 info;dmg_value_row_v2 value;dmg_entity_row entity;dmg_relation_link old_link;dmg_relation_link_v2 link;uint32_t n=0,j,events=0;
 memset(&old,0xa5,sizeof(old));memset(&old_link,0xa5,sizeof(old_link));
 CHECK(dmg_result_get_relation_info(result,&old,sizeof(old))==DMG_UNSUPPORTED&&untouched(&old,sizeof(old)));
 CHECK(dmg_result_get_relation_info_v2(result,&info,sizeof(info))==DMG_OK&&info.relation==DMG_METHOD_DEFS&&info.candidates_count==(batch?1u:2u));
 CHECK(info.entity_total==4&&info.entity_visited==4&&info.method_total==4&&info.method_visited==4&&info.events_collected==2);
 CHECK(dmg_result_get_value_v2(result,index,&value,sizeof(value))==DMG_OK&&value.kind==DMG_VALUE_ENTITY&&value.entity.relation==DMG_METHOD_DEFS&&value.entity.local_index==2);
 CHECK(dmg_result_get_entity(result,index,&entity,sizeof(entity))==DMG_OK&&entity.relation==DMG_METHOD_DEFS);
 CHECK(dmg_result_get_link_count(result,index,&n)==DMG_OK&&n==1);
 CHECK(dmg_result_get_link(result,index,0,&old_link,sizeof(old_link))==DMG_UNSUPPORTED&&untouched(&old_link,sizeof(old_link)));
 memset(&link,0xa5,sizeof(link));CHECK(dmg_result_get_link_v2(result,index,0,&link,(uint32_t)sizeof(link)-1)==DMG_INVALID_ARGUMENT&&untouched(&link,sizeof(link)));
 CHECK(dmg_result_get_link_v2(result,index,0,&link,sizeof(link))==DMG_OK&&link.key==DMG_JOIN_CALLER&&link.left.relation==DMG_METHOD_DEFS&&link.left.local_index==2&&link.left.dex_pc==UINT32_MAX);
 CHECK(link.right.relation==DMG_INVOKE_SITES&&link.right.local_index==2&&(link.right.dex_pc==0||link.right.dex_pc==3));
 CHECK(dmg_result_get_binding_count(result,index,&n)==DMG_OK);
 for(j=0;j<n;++j){dmg_binding_row_v2 binding;dmg_binding_row legacy;
  memset(&binding,0xa5,sizeof(binding));CHECK(dmg_result_get_binding_v2(result,index,j,&binding,(uint32_t)sizeof(binding)-1)==DMG_INVALID_ARGUMENT&&untouched(&binding,sizeof(binding)));
  CHECK(dmg_result_get_binding_v2(result,index,j,&binding,sizeof(binding))==DMG_OK);
  if(binding.value.kind==DMG_VALUE_USE){memset(&legacy,0xa5,sizeof(legacy));CHECK(dmg_result_get_binding(result,index,j,&legacy,sizeof(legacy))==DMG_UNSUPPORTED&&untouched(&legacy,sizeof(legacy)));CHECK(event_record(&binding.value,link.right.dex_pc)==0);++events;}
 }CHECK(events==1);return 0;
}
static int check_semi(const dmg_result* result){
 dmg_relation_info_v2 info;dmg_value_row_v2 row;uint32_t count=0,i,events=0;
 CHECK(dmg_result_get_relation_info_v2(result,&info,sizeof(info))==DMG_OK&&info.candidates_count==1);
 CHECK(dmg_result_get_value_v2(result,0,&row,sizeof(row))==DMG_OK&&row.kind==DMG_VALUE_ENTITY&&row.entity.relation==DMG_METHOD_DEFS&&row.entity.local_index==2);
 CHECK(dmg_result_get_proof_binding_count(result,0,&count)==DMG_OK&&count>0);
 for(i=0;i<count;++i){dmg_proof_binding_row legacy;dmg_proof_binding_row_v2 proof;dmg_binding_path path;
  memset(&proof,0xa5,sizeof(proof));CHECK(dmg_result_get_proof_binding_v2(result,0,i,&proof,(uint32_t)sizeof(proof)-1)==DMG_INVALID_ARGUMENT&&untouched(&proof,sizeof(proof)));
  CHECK(dmg_result_get_proof_binding_v2(result,0,i,&proof,sizeof(proof))==DMG_OK);
  if(proof.binding.value.kind==DMG_VALUE_USE){
   memset(&legacy,0xa5,sizeof(legacy));CHECK(dmg_result_get_proof_binding(result,0,i,&legacy,sizeof(legacy))==DMG_UNSUPPORTED&&untouched(&legacy,sizeof(legacy)));
   CHECK(event_record(&proof.binding.value,3)==0);
   CHECK(dmg_result_get_proof_binding_path(result,0,i,&path,sizeof(path))==DMG_OK&&path.length>0&&path.sides);
   ++events;
  }
 }
 CHECK(events==1);return 0;
}
static int job_sizes(dmg_job* job){
 dmg_relation_job_status_v2 status;dmg_operator_profile_v2 op;
 memset(&status,0xa5,sizeof(status));CHECK(dmg_job_get_relation_status_v2(job,&status,(uint32_t)sizeof(status)-1)==DMG_INVALID_ARGUMENT&&untouched(&status,sizeof(status)));
 CHECK(dmg_job_wait_relation_v2(job,0,&status,(uint32_t)sizeof(status)-1)==DMG_INVALID_ARGUMENT&&untouched(&status,sizeof(status)));
 memset(&op,0xa5,sizeof(op));CHECK(dmg_job_get_operator_profile_v2(job,0,&op,(uint32_t)sizeof(op)-1)==DMG_INVALID_ARGUMENT&&untouched(&op,sizeof(op)));
 return 0;
}
int main(int argc,char** argv){
 FILE* file;long length;unsigned char* bytes;dmg_engine* engine=NULL;dmg_snapshot* snapshot=NULL;dmg_query* query=NULL;dmg_result* result=NULL;dmg_job* job=NULL;dmg_batch *batch=NULL,*saved=NULL;dmg_error error={0};dmg_engine_stats initial,after;dmg_open_options open={sizeof(open),DMG_ABI_VERSION,DMG_MAX_SOURCE_BYTES,"c-use","fixture",NULL};
 dmg_job_options options={sizeof(options),DMG_ABI_VERSION,1,1,0};dmg_relation_job_status legacy_status;dmg_relation_job_status_v2 status;uint32_t delivered=0;
 CHECK(argc==2&&has_capability(dmg_capabilities(),"dex-query-use-v4"));file=fopen(argv[1],"rb");CHECK(file&&fseek(file,0,SEEK_END)==0);length=ftell(file);CHECK(length==608);rewind(file);bytes=(unsigned char*)malloc((size_t)length);CHECK(bytes&&fread(bytes,1,(size_t)length,file)==(size_t)length);fclose(file);
 CHECK(dmg_engine_create(NULL,&engine,&error)==DMG_OK&&dmg_engine_get_stats(engine,&initial)==DMG_OK);
 CHECK(dmg_snapshot_open_copy_in(engine,bytes,(uint64_t)length,&open,&snapshot,&error)==DMG_OK);
 CHECK(compile(engine,event_query,&query)==0&&dmg_query_execute(snapshot,query,&result,&error)==DMG_OK&&check_events(result)==0);
 dmg_result_release(result);result=NULL;dmg_query_release(query);query=NULL;
 CHECK(compile(engine,budget_query,&query)==0);
 CHECK(dmg_query_execute(snapshot,query,&result,&error)==DMG_BUDGET_EXCEEDED&&result==NULL);
 CHECK(dmg_job_start(snapshot,query,&options,&job,&error)==DMG_OK&&job_sizes(job)==0);
 CHECK(dmg_job_next(job,5000,&batch,&error)==DMG_END_OF_STREAM&&batch==NULL);
 CHECK(dmg_job_wait_relation_v2(job,5000,&status,sizeof(status))==DMG_OK&&status.terminal&&status.lifecycle==DMG_JOB_FAILED&&status.outcome.execution_status==DMG_BUDGET_EXCEEDED);
 {dmg_graph_info graph;dmg_operator_profile_v2 op;CHECK(dmg_job_get_graph_info(job,&graph,sizeof(graph))==DMG_OK&&graph.operator_count==1);
  CHECK(dmg_job_get_operator_profile_v2(job,0,&op,sizeof(op))==DMG_OK&&op.node_id==graph.root_node&&op.op==DMG_REL_SCAN&&op.scan_domain==DMG_SCAN_DOMAIN_METHOD_DEFS&&!op.complete);}
 dmg_job_release(job);job=NULL;dmg_query_release(query);query=NULL;
 CHECK(compile(engine,pair_query,&query)==0&&dmg_query_execute(snapshot,query,&result,&error)==DMG_OK&&check_pair(result,0,0)==0&&check_pair(result,1,0)==0);
 dmg_result_release(result);result=NULL;
 CHECK(dmg_job_start(snapshot,query,&options,&job,&error)==DMG_OK);memset(&legacy_status,0xa5,sizeof(legacy_status));
 CHECK(dmg_job_get_relation_status(job,&legacy_status,sizeof(legacy_status))==DMG_UNSUPPORTED&&untouched(&legacy_status,sizeof(legacy_status)));
 for(;;){dmg_status next=dmg_job_next(job,5000,&batch,&error);if(next==DMG_END_OF_STREAM)break;CHECK(next==DMG_OK&&batch&&check_pair(batch,0,1)==0);++delivered;if(!saved)saved=batch;else dmg_batch_release(batch);batch=NULL;}
 CHECK(delivered==2&&dmg_job_wait_relation_v2(job,5000,&status,sizeof(status))==DMG_OK&&status.terminal&&status.lifecycle==DMG_JOB_COMPLETED);
 CHECK(status.outcome.decision==DMG_PROVEN_FALSE&&status.outcome.reason==DMG_AMBIGUOUS&&status.outcome.method_visited==4&&status.outcome.entity_visited==4);
 dmg_job_release(job);job=NULL;dmg_query_release(query);query=NULL;dmg_snapshot_release(snapshot);snapshot=NULL;
 CHECK(check_pair(saved,0,1)==0);dmg_batch_release(saved);saved=NULL;
 CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&same_live(&initial,&after));
 CHECK(dmg_snapshot_open_copy_in(engine,bytes,(uint64_t)length,&open,&snapshot,&error)==DMG_OK);free(bytes);bytes=NULL;
 CHECK(compile(engine,semi_query,&query)==0&&dmg_query_execute(snapshot,query,&result,&error)==DMG_OK&&check_semi(result)==0);
 dmg_result_release(result);result=NULL;
 CHECK(dmg_job_start(snapshot,query,&options,&job,&error)==DMG_OK&&job_sizes(job)==0);
 CHECK(dmg_job_next(job,5000,&saved,&error)==DMG_OK&&saved&&check_semi(saved)==0);
 CHECK(dmg_job_next(job,5000,&batch,&error)==DMG_END_OF_STREAM&&batch==NULL);
 CHECK(dmg_job_wait_relation_v2(job,5000,&status,sizeof(status))==DMG_OK&&status.terminal&&status.lifecycle==DMG_JOB_COMPLETED);
 dmg_job_release(job);dmg_query_release(query);dmg_snapshot_release(snapshot);dmg_engine_release(engine);
 CHECK(check_semi(saved)==0);dmg_batch_release(saved);
 puts("PASS C use QueryIR: event PC identity, tagged bindings/proofs, old ABI rejection, sized getters and retained lifetime");return 0;
}
