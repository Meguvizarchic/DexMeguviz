#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"field declaration C consumer line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char** argv){
 const char* names[]={"child.dex","parent.dex","object.dex"};const char* slots[]={"child","parent","object"};
 const char* text="{\"schema_version\":1,\"required_capabilities\":[\"field_declaration_static\"],\"scope\":{\"slots\":[\"child\",\"parent\",\"object\"]},\"relation\":{\"op\":\"scan\",\"relation\":\"field_uses\",\"where\":{\"target_field_declaration\":{\"scope\":\"inherited\"}}}}";
 unsigned char* buffers[3]={0};dmg_source_spec specs[3]={0};dmg_engine* engine=NULL;dmg_snapshot* snapshot=NULL;dmg_query* query=NULL;dmg_result* result=NULL;dmg_error error;
 dmg_source_set_options options={sizeof(options),DMG_ABI_VERSION,"q08-field",0,8,1u<<20};dmg_relation_info_v2 info;uint32_t i,row,count;
 CHECK(argc==2&&dmg_engine_create(NULL,&engine,&error)==DMG_OK);
 for(i=0;i<3;++i){char path[2048];FILE* f;long n;CHECK(snprintf(path,sizeof(path),"%s/%s",argv[1],names[i])>0);f=fopen(path,"rb");CHECK(f&&fseek(f,0,SEEK_END)==0);n=ftell(f);CHECK(n>0&&fseek(f,0,SEEK_SET)==0);buffers[i]=(unsigned char*)malloc((size_t)n);CHECK(buffers[i]&&fread(buffers[i],1,(size_t)n,f)==(size_t)n);fclose(f);
  specs[i].struct_size=sizeof(specs[i]);specs[i].abi_version=DMG_ABI_VERSION;specs[i].format=DMG_INPUT_RAW_DEX;specs[i].data=buffers[i];specs[i].size=(uint64_t)n;specs[i].slot_key=slots[i];specs[i].role=i?"code-split":"base";}
 CHECK(dmg_snapshot_open_sources(engine,specs,3,&options,&snapshot,&error)==DMG_OK);for(i=0;i<3;++i)free(buffers[i]);
 CHECK(dmg_query_compile_json(engine,(const uint8_t*)text,strlen(text),&query,&error)==DMG_OK);
 CHECK(dmg_query_execute(snapshot,query,&result,&error)==DMG_OK);
 {dmg_job* job=NULL;dmg_batch* batch=NULL;dmg_relation_job_status_v2 state;unsigned delivered=0;dmg_job_options opts={sizeof(opts),DMG_ABI_VERSION,1,2,0};
  CHECK(dmg_job_start(snapshot,query,&opts,&job,&error)==DMG_OK);
  for(;;){dmg_status status=dmg_job_next(job,15000,&batch,&error);if(status==DMG_END_OF_STREAM)break;CHECK(status==DMG_OK&&batch);CHECK(dmg_result_get_relation_info_v2(batch,&info,sizeof(info))==DMG_OK&&info.candidates_count==1);++delivered;dmg_batch_release(batch);batch=NULL;}
  CHECK(delivered==2&&dmg_job_wait_relation_v2(job,15000,&state,sizeof(state))==DMG_OK&&state.terminal&&state.outcome.execution_status==DMG_OK&&state.outcome.unknown_rows==2);dmg_job_release(job);
 }
 dmg_query_release(query);dmg_snapshot_close(snapshot);dmg_snapshot_release(snapshot);
 CHECK(dmg_result_get_relation_info_v2(result,&info,sizeof(info))==DMG_OK&&info.candidates_count==2&&info.unknown_rows==2);
 for(row=0;row<2;++row){unsigned path=0,terminal=0;dmg_value_row_v2 value;CHECK(dmg_result_get_value_v2(result,row,&value,sizeof(value))==DMG_OK&&value.kind==DMG_VALUE_USE&&value.use.source_index==0&&value.use.dex_pc==2*row);
  CHECK(dmg_result_get_witness_count(result,row,&count)==DMG_OK);
  for(i=0;i<count;++i){dmg_field_declaration_witness_v1 proof;dmg_relation_witness_v2 legacy;dmg_status st=dmg_result_get_field_declaration_witness_v1(result,row,i,&proof,sizeof(proof));
   if(st==DMG_UNSUPPORTED)continue;CHECK(st==DMG_OK);CHECK(dmg_result_get_relation_witness_v2(result,row,i,&legacy,sizeof(legacy))==DMG_UNSUPPORTED);
   if(proof.item_kind==0){CHECK(proof.path_index==path&&proof.relation==DMG_CLASS_DEFS&&proof.source_index==path&&proof.edge_kind==(path?2u:0u));++path;}
   else {CHECK(proof.item_kind==1&&proof.relation==DMG_FIELD_DEFS&&proof.source_index==1&&proof.local_index==0&&proof.path_index==1);++terminal;}
   {unsigned char sentinel[sizeof(proof)];memset(sentinel,0x5a,sizeof(sentinel));CHECK(dmg_result_get_field_declaration_witness_v1(result,row,i,(dmg_field_declaration_witness_v1*)sentinel,sizeof(proof)-1)==DMG_INVALID_ARGUMENT);for(size_t k=0;k<sizeof(sentinel);++k)CHECK(sentinel[k]==0x5a);}
  }CHECK(path==2&&terminal==1);
 }
 dmg_result_release(result);dmg_engine_release(engine);puts("PASS Q08 field declaration C ABI, paths and old getter rejection");return 0;
}
