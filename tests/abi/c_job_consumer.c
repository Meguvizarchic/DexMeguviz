#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"C Job check failed at %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char** argv){
    dmg_engine* engine=NULL;dmg_snapshot* source=NULL;dmg_query* query=NULL;dmg_job* job=NULL;dmg_batch* batch=NULL;
    dmg_error error={0};dmg_method_query spec={0};dmg_job_status status={0};
    dmg_open_options open={sizeof(open),DMG_ABI_VERSION,DMG_MAX_SOURCE_BYTES,"c-job","fixture",NULL};
    unsigned rows=0;long length;unsigned char* bytes;FILE* file;
    CHECK(argc==2);file=fopen(argv[1],"rb");CHECK(file!=NULL);CHECK(fseek(file,0,SEEK_END)==0);length=ftell(file);CHECK(length>0);rewind(file);
    bytes=(unsigned char*)malloc((size_t)length);CHECK(bytes!=NULL);CHECK(fread(bytes,1,(size_t)length,file)==(size_t)length);fclose(file);
    CHECK(dmg_engine_create(NULL,&engine,&error)==DMG_OK);
    CHECK(dmg_snapshot_open_copy_in(engine,bytes,(uint64_t)length,&open,&source,&error)==DMG_OK);free(bytes);
    spec.struct_size=sizeof(spec);spec.abi_version=DMG_ABI_VERSION;spec.max_results=16;
    CHECK(dmg_query_compile_methods(engine,&spec,&query,&error)==DMG_OK);
    CHECK(dmg_job_start(source,query,NULL,&job,&error)==DMG_OK);
    for(;;){
        dmg_status next=dmg_job_next(job,2000,&batch,&error);dmg_result_info info;
        if(next==DMG_END_OF_STREAM)break;
        CHECK(next==DMG_OK && batch!=NULL);CHECK(dmg_batch_get_info(batch,&info)==DMG_OK);rows+=info.candidates_count;dmg_batch_release(batch);batch=NULL;
    }
    CHECK(dmg_job_get_status(job,&status)==DMG_OK && status.terminal==1);
    CHECK(status.outcome.execution_status==DMG_OK && status.outcome.coverage==DMG_COVERAGE_COMPLETE && rows==2);
    dmg_job_release(job);dmg_query_release(query);dmg_snapshot_release(source);dmg_engine_release(engine);
    puts("PASS C ABI compiled Query -> Job -> Batch -> final status");return 0;
}
