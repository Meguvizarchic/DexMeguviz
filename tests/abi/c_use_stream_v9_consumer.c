#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"v9 C consumer line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char** argv){
 FILE* in;long n;unsigned char* bytes;dmg_engine* engine=NULL;dmg_snapshot* snapshot=NULL;dmg_query* query=NULL;dmg_job* job=NULL;dmg_batch* held=NULL;dmg_error error;
 dmg_open_options open={sizeof(open),DMG_ABI_VERSION,0,"v9-c-consumer","base",NULL};dmg_job_options options={sizeof(options),DMG_ABI_VERSION,1,2,0};dmg_query_info query_info;dmg_relation_job_status_v2 status;unsigned seen=0;
 const char* text="{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"},\"intent\":\"unique\",\"required_capabilities\":[\"use_streaming\"]}";
 CHECK(argc==2);in=fopen(argv[1],"rb");CHECK(in&&fseek(in,0,SEEK_END)==0);n=ftell(in);CHECK(n>0&&fseek(in,0,SEEK_SET)==0);
 bytes=(unsigned char*)malloc((size_t)n);CHECK(bytes&&fread(bytes,1,(size_t)n,in)==(size_t)n);fclose(in);
 CHECK(dmg_engine_create(NULL,&engine,&error)==DMG_OK&&engine);CHECK(dmg_snapshot_open_copy_in(engine,bytes,(uint64_t)n,&open,&snapshot,&error)==DMG_OK&&snapshot);memset(bytes,0,(size_t)n);free(bytes);
 CHECK(dmg_query_compile_json(engine,(const uint8_t*)text,strlen(text),&query,&error)==DMG_OK&&query);CHECK(dmg_query_get_info(query,&query_info)==DMG_OK&&(query_info.required_capabilities&131072u)&&strncmp(query_info.query_id,"query:v9:",9)==0);
 CHECK(dmg_job_start(snapshot,query,&options,&job,&error)==DMG_OK&&job);
 for(;;){dmg_batch* batch=NULL;dmg_value_row_v2 value;dmg_relation_info_v2 info;dmg_status rc=dmg_job_next(job,15000,&batch,&error);if(rc==DMG_END_OF_STREAM)break;CHECK(rc==DMG_OK&&batch);
  CHECK(dmg_result_get_relation_info_v2(batch,&info,sizeof(info))==DMG_OK&&info.coverage==DMG_COVERAGE_PARTIAL&&info.candidates_count==1);
  CHECK(dmg_result_get_value_v2(batch,0,&value,sizeof(value))==DMG_OK&&value.kind==DMG_VALUE_USE&&value.use.relation==DMG_INVOKE_SITES&&value.use.source_index==0&&value.use.target_index==4);
  if(seen==0){CHECK(value.use.caller_ordinal==1&&value.use.dex_pc==0);held=batch;}else{CHECK(seen==1&&value.use.caller_ordinal==2&&value.use.dex_pc==2);dmg_batch_release(batch);}++seen;
 }
 CHECK(seen==2&&dmg_job_wait_relation_v2(job,15000,&status,sizeof(status))==DMG_OK&&status.terminal&&status.outcome.execution_status==DMG_OK&&status.outcome.candidates_count==2&&status.outcome.decision==DMG_PROVEN_FALSE&&status.outcome.reason==DMG_AMBIGUOUS);
 dmg_job_release(job);dmg_query_release(query);dmg_snapshot_close(snapshot);dmg_snapshot_release(snapshot);dmg_engine_release(engine);
 {dmg_value_row_v2 value;CHECK(held&&dmg_result_get_value_v2(held,0,&value,sizeof(value))==DMG_OK&&value.use.caller_ordinal==1&&value.use.dex_pc==0);}
 dmg_batch_release(held);puts("PASS C v9 Job/Batch: separate callers, event PCs, final status and retained Batch");return 0;
}
