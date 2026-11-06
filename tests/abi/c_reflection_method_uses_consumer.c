#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"v15 C consumer line %d: %s\n",__LINE__,#x);return 1;}} while(0)
int main(int argc,char** argv){
 const char* query_text="{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"all\":[{\"name\":\"uses\"},{\"flags\":{\"domain\":\"reflection\",\"value\":8}},{\"using_strings\":{\"all\":[\"used-string\"]}}]},\"intent\":\"unique\",\"max_results\":100,\"required_capabilities\":[\"reflection_flags_static\",\"reflection_method_uses\"]}";
 FILE* f;long size;unsigned char* bytes;dmg_engine* engine=NULL;dmg_snapshot* snapshot=NULL;dmg_query* query=NULL;dmg_result* result=NULL;dmg_job* job=NULL;dmg_batch* batch=NULL;dmg_error error={0};dmg_query_info qi={0};dmg_relation_info info={0};dmg_relation_job_status status={0};
 dmg_job_options options={sizeof(options),DMG_ABI_VERSION,1,4,0};dmg_source_spec spec={0};dmg_source_set_options set={sizeof(set),DMG_ABI_VERSION,"v15-c",1,8,1u<<20};unsigned seen=0;int unknown=argc==3&&strcmp(argv[2],"unknown")==0;
 CHECK(argc==2||unknown);f=fopen(argv[1],"rb");CHECK(f&&fseek(f,0,SEEK_END)==0);size=ftell(f);CHECK(size>0&&fseek(f,0,SEEK_SET)==0);bytes=(unsigned char*)malloc((size_t)size);CHECK(bytes&&fread(bytes,1,(size_t)size,f)==(size_t)size);fclose(f);
 CHECK(dmg_engine_create(NULL,&engine,&error)==DMG_OK);spec.struct_size=sizeof(spec);spec.abi_version=DMG_ABI_VERSION;spec.format=DMG_INPUT_RAW_DEX;spec.data=bytes;spec.size=(uint64_t)size;spec.slot_key="base";spec.role="base";
 CHECK(dmg_snapshot_open_sources(engine,&spec,1,&set,&snapshot,&error)==DMG_OK);free(bytes);
 CHECK(dmg_query_compile_json(engine,(const uint8_t*)query_text,strlen(query_text),&query,&error)==DMG_OK);
 CHECK(dmg_query_get_info(query,&qi)==DMG_OK&&strncmp(qi.query_id,"query:v15:",10)==0&&(qi.required_capabilities&8388608u)&&qi.demand_mask==1);
 CHECK(dmg_query_execute(snapshot,query,&result,&error)==DMG_OK);CHECK(dmg_result_get_relation_info(result,&info,sizeof(info))==DMG_OK);
 CHECK(info.execution_status==DMG_OK&&info.coverage==(unknown?DMG_COVERAGE_PARTIAL:DMG_COVERAGE_COMPLETE)&&info.candidates_count==(unknown?0u:1u)&&info.unknown_rows==(unknown?1u:0u)&&info.decision==(unknown?DMG_UNDETERMINED:DMG_PROVEN_TRUE));
 CHECK(dmg_job_start(snapshot,query,&options,&job,&error)==DMG_OK);
 for(;;){dmg_status rc=dmg_job_next(job,15000,&batch,&error);if(rc==DMG_END_OF_STREAM)break;CHECK(rc==DMG_OK&&batch);CHECK(dmg_result_get_relation_info(batch,&info,sizeof(info))==DMG_OK&&info.candidates_count==1&&info.coverage==DMG_COVERAGE_PARTIAL&&info.decision==DMG_NOT_APPLICABLE);++seen;dmg_batch_release(batch);batch=NULL;}
 CHECK(seen==(unknown?0u:1u)&&dmg_job_wait_relation(job,15000,&status,sizeof(status))==DMG_OK&&status.terminal);
 CHECK(status.outcome.execution_status==DMG_OK&&status.outcome.coverage==(unknown?DMG_COVERAGE_PARTIAL:DMG_COVERAGE_COMPLETE)&&status.outcome.candidates_count==(unknown?0u:1u)&&status.outcome.unknown_rows==(unknown?1u:0u)&&status.outcome.decision==(unknown?DMG_UNDETERMINED:DMG_PROVEN_TRUE));
 dmg_job_release(job);dmg_result_release(result);dmg_query_release(query);dmg_snapshot_release(snapshot);dmg_engine_release(engine);
 puts("PASS v15 C ABI sync and Job terminal status");return 0;
}
