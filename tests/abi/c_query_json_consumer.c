#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"JSON C ABI check %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char** argv){
    const char* specification="{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\",\"using_strings\":{\"all\":[\"used-string\"]},\"invokes\":{\"all\":[{\"name\":\"sink\"}]}},\"intent\":\"unique\"}";
    FILE* file;long size;unsigned char* bytes;dmg_engine* engine=NULL;dmg_snapshot* snapshot=NULL;dmg_query* query=NULL;dmg_result* result=NULL;dmg_job* job=NULL;dmg_batch* batch=NULL;
    dmg_error error={0};dmg_query_info query_info;dmg_query_profile profile;dmg_result_info info;dmg_job_status final;
    dmg_open_options options={sizeof(options),DMG_ABI_VERSION,DMG_MAX_SOURCE_BYTES,"c-json","input",NULL};uint32_t count=0,i,strings=0,invokes=0;
    CHECK(argc==2);file=fopen(argv[1],"rb");CHECK(file!=NULL);fseek(file,0,SEEK_END);size=ftell(file);rewind(file);CHECK(size>0);
    bytes=(unsigned char*)malloc((size_t)size);CHECK(bytes!=NULL);CHECK(fread(bytes,1,(size_t)size,file)==(size_t)size);fclose(file);
    CHECK(dmg_engine_create(NULL,&engine,&error)==DMG_OK);
    {size_t length=strlen(specification);char* mutable_text=(char*)malloc(length);CHECK(mutable_text!=NULL);memcpy(mutable_text,specification,length);
     CHECK(dmg_query_compile_json(engine,(const uint8_t*)mutable_text,length,&query,&error)==DMG_OK);memset(mutable_text,'?',length);free(mutable_text);}
    CHECK(dmg_query_get_info(query,&query_info)==DMG_OK && query_info.demand_mask==3 && strncmp(query_info.query_id,"query:v1:",9)==0);
    CHECK(dmg_snapshot_open_copy_in(engine,bytes,(uint64_t)size,&options,&snapshot,&error)==DMG_OK);free(bytes);
    CHECK(dmg_query_execute(snapshot,query,&result,&error)==DMG_OK);
    CHECK(dmg_result_get_info(result,&info)==DMG_OK && info.decision==DMG_PROVEN_TRUE && info.candidates_count==1);
    CHECK(dmg_result_get_profile(result,&profile)==DMG_OK && profile.methods_decoded==1 && profile.code_units==8);
    CHECK(dmg_result_get_witness_count(result,0,&count)==DMG_OK);
    for(i=0;i<count;++i){dmg_witness w;CHECK(dmg_result_get_witness(result,0,i,&w)==DMG_OK);if(w.kind==DMG_WITNESS_STRING){CHECK(w.dex_pc==0&&w.reference_index==10);++strings;}if(w.kind==DMG_WITNESS_INVOKE){CHECK(w.dex_pc==2&&w.reference_index==4);++invokes;}}
    CHECK(strings==1&&invokes==1);dmg_result_release(result);
    {const char* constrained="{\"schema_version\":1,\"relation\":\"method_defs\",\"intent\":\"unique\",\"max_work\":1}";dmg_query* limited=NULL;dmg_job* failed_job=NULL;dmg_batch* absent=NULL;
     CHECK(dmg_query_compile_json(engine,(const uint8_t*)constrained,strlen(constrained),&limited,&error)==DMG_OK);
     result=NULL;CHECK(dmg_query_execute(snapshot,limited,&result,&error)==DMG_BUDGET_EXCEEDED && result==NULL);
     CHECK(dmg_job_start(snapshot,limited,NULL,&failed_job,&error)==DMG_OK);
     CHECK(dmg_job_wait(failed_job,2000,&final)==DMG_OK && final.outcome.execution_status==DMG_BUDGET_EXCEEDED && final.outcome.decision==DMG_UNDETERMINED);
     CHECK(dmg_job_next(failed_job,0,&absent,&error)==DMG_END_OF_STREAM && absent==NULL);
     dmg_job_release(failed_job);dmg_query_release(limited);}
    CHECK(dmg_job_start(snapshot,query,NULL,&job,&error)==DMG_OK);
    CHECK(dmg_job_next(job,2000,&batch,&error)==DMG_OK);
    CHECK(dmg_job_wait(job,2000,&final)==DMG_OK && final.outcome.decision==DMG_PROVEN_TRUE);
    dmg_snapshot_release(snapshot);dmg_query_release(query);dmg_job_release(job);dmg_engine_release(engine);
    CHECK(dmg_result_get_query_info(batch,&query_info)==DMG_OK && query_info.demand_mask==3);
    CHECK(dmg_result_get_witness_count(batch,0,&count)==DMG_OK && count>=3);dmg_batch_release(batch);
    puts("PASS C JSON QueryIR: compile/reuse/sync/Job, real PC witnesses and retained Plan/Batch lifetime");return 0;
}
