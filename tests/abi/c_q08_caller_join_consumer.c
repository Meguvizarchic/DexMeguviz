#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"Q08 caller C line %d: %s\n",__LINE__,#x);return 1;}}while(0)
static const char* head="{\"schema_version\":1,\"required_capabilities\":[\"field_declaration_static\"],\"scope\":{\"slots\":[\"callerA\",\"callerB\",\"child\",\"parent\",\"object\"]},\"relation\":{\"op\":\"";
static const char* tail="\",\"on\":\"caller\",\"left\":{\"op\":\"scan\",\"relation\":\"method_defs\"},\"right\":{\"op\":\"scan\",\"relation\":\"field_uses\",\"where\":{\"target_field_declaration\":{\"scope\":\"inherited\"}}}}}";
static int inspect(const dmg_result* result,uint32_t row,int semi){
 dmg_value_row_v2 value;dmg_relation_link_v2 link;uint32_t n,i;unsigned steps=0,terminal=0;
 CHECK(dmg_result_get_value_v2(result,row,&value,sizeof(value))==DMG_OK&&value.kind==DMG_VALUE_ENTITY&&value.entity.relation==DMG_METHOD_DEFS&&value.entity.source_index<2);
 CHECK(dmg_result_get_link_count(result,row,&n)==DMG_OK&&n==1&&dmg_result_get_link_v2(result,row,0,&link,sizeof(link))==DMG_OK);
 CHECK(link.key==DMG_JOIN_CALLER&&link.left.source_index==value.entity.source_index&&link.right.source_index==value.entity.source_index&&link.right.relation==DMG_FIELD_USES&&(link.right.dex_pc==0||link.right.dex_pc==2));
 if(semi){dmg_proof_binding_row_v2 proof;CHECK(dmg_result_get_proof_binding_count(result,row,&n)==DMG_OK&&n==1&&dmg_result_get_proof_binding_v2(result,row,0,&proof,sizeof(proof))==DMG_OK);CHECK(proof.binding.value.kind==DMG_VALUE_USE&&proof.binding.value.use.dex_pc==0&&proof.binding.value.use.source_index==value.entity.source_index);}
 else {CHECK(dmg_result_get_binding_count(result,row,&n)==DMG_OK&&n==2);}
 CHECK(dmg_result_get_witness_count(result,row,&n)==DMG_OK);
 for(i=0;i<n;++i){dmg_field_declaration_witness_v1 proof;dmg_status s=dmg_result_get_field_declaration_witness_v1(result,row,i,&proof,sizeof(proof));if(s==DMG_UNSUPPORTED)continue;CHECK(s==DMG_OK);
  if(proof.item_kind==0){CHECK(proof.path_index==steps&&proof.source_index==2+steps&&proof.edge_kind==(steps?2u:0u));++steps;}
  else{CHECK(proof.item_kind==1&&proof.source_index==3&&proof.local_index==0&&proof.path_index==1);++terminal;}}
 CHECK(steps==2&&terminal==1);return 0;
}
int main(int argc,char** argv){
 const char* names[]={"caller-a.dex","caller-b.dex","child.dex","parent.dex","object.dex"};const char* slots[]={"callerA","callerB","child","parent","object"};
 dmg_source_spec specs[5]={0};unsigned char* buffers[5]={0};dmg_source_set_options o={sizeof(o),DMG_ABI_VERSION,"q08-caller",0,8,1u<<20};dmg_engine* engine=NULL;dmg_snapshot* snapshot=NULL;dmg_query* query=NULL;dmg_result* result=NULL;dmg_error error;dmg_relation_info_v2 info;unsigned i;char text[2048];
 CHECK(argc==2&&dmg_engine_create(NULL,&engine,&error)==DMG_OK);
 for(i=0;i<5;++i){char path[2048];FILE* f;long n;CHECK(snprintf(path,sizeof(path),"%s/%s",argv[1],names[i])>0);f=fopen(path,"rb");CHECK(f&&fseek(f,0,SEEK_END)==0);n=ftell(f);CHECK(n>0&&fseek(f,0,SEEK_SET)==0);buffers[i]=(unsigned char*)malloc((size_t)n);CHECK(buffers[i]&&fread(buffers[i],1,(size_t)n,f)==(size_t)n);fclose(f);specs[i].struct_size=sizeof(specs[i]);specs[i].abi_version=DMG_ABI_VERSION;specs[i].format=DMG_INPUT_RAW_DEX;specs[i].data=buffers[i];specs[i].size=(uint64_t)n;specs[i].slot_key=slots[i];specs[i].role=i?"code-split":"base";}
 CHECK(dmg_snapshot_open_sources(engine,specs,5,&o,&snapshot,&error)==DMG_OK);for(i=0;i<5;++i)free(buffers[i]);
 for(i=0;i<2;++i){unsigned row;CHECK(snprintf(text,sizeof(text),"%s%s%s",head,i?"semi_join":"join",tail)>0);CHECK(dmg_query_compile_json(engine,(const uint8_t*)text,strlen(text),&query,&error)==DMG_OK);CHECK(dmg_query_execute(snapshot,query,&result,&error)==DMG_OK);CHECK(dmg_result_get_relation_info_v2(result,&info,sizeof(info))==DMG_OK&&info.candidates_count==(i?2u:4u)&&info.unknown_rows==(i?0u:4u));for(row=0;row<info.candidates_count;++row)CHECK(inspect(result,row,(int)i)==0);dmg_result_release(result);result=NULL;
  if(i==0){dmg_job* job=NULL;dmg_batch* first=NULL;dmg_relation_info_v2 batchinfo;dmg_relation_job_status_v2 status;dmg_job_options opts={sizeof(opts),DMG_ABI_VERSION,1,1,0};CHECK(dmg_job_start(snapshot,query,&opts,&job,&error)==DMG_OK);CHECK(dmg_job_next(job,15000,&first,&error)==DMG_OK&&first);CHECK(dmg_result_get_relation_info_v2(first,&batchinfo,sizeof(batchinfo))==DMG_OK&&batchinfo.coverage==DMG_COVERAGE_PARTIAL&&batchinfo.decision==DMG_NOT_APPLICABLE);CHECK(inspect(first,0,0)==0);dmg_job_cancel(job);CHECK(dmg_job_wait_relation_v2(job,15000,&status,sizeof(status))==DMG_OK&&status.terminal&&status.outcome.execution_status==DMG_CANCELLED);dmg_job_release(job);CHECK(inspect(first,0,0)==0);dmg_batch_release(first);}
  dmg_query_release(query);query=NULL;
 }
 dmg_snapshot_release(snapshot);dmg_engine_release(engine);puts("PASS Q08 caller Join/SemiJoin, source identity, single path and provisional cancelled Job");return 0;
}
