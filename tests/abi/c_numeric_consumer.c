#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"numeric C check %d: %s\n",__LINE__,#x);return 1;}}while(0)
static const char* query_json="{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":\"uses\",\"numeric_bits\":{\"width\":64,\"bits\":\"fffffffffffffffe\",\"kind\":\"constant\"}},\"intent\":\"unique\"}";
static int check_witness(dmg_result* result){
    uint32_t count=0,i,found=0;CHECK(dmg_result_get_witness_count(result,0,&count)==DMG_OK);
    for(i=0;i<count;++i){
        dmg_numeric_witness_v1 w={0};const dmg_status status=dmg_result_get_numeric_witness_v1(result,0,i,&w,sizeof(w));
        if(status==DMG_UNSUPPORTED)continue;CHECK(status==DMG_OK);++found;
        CHECK(w.matched==DMG_MATCH_TRUE&&w.dex_pc==1&&w.opcode==0x16&&w.width_bits==64&&w.literal_kind==0&&w.bits==UINT64_C(0xfffffffffffffffe));
        CHECK(w.source_index==0&&w.relation==DMG_METHOD_DEFS&&w.entity_pc==UINT32_MAX);
        {dmg_witness old;CHECK(dmg_result_get_witness(result,0,i,&old)==DMG_UNSUPPORTED);}
        {dmg_numeric_witness_v1 guard;memset(&guard,0xa5,sizeof(guard));CHECK(dmg_result_get_numeric_witness_v1(result,0,i,&guard,sizeof(guard)-1)==DMG_INVALID_ARGUMENT);CHECK(((unsigned char*)&guard)[0]==0xa5);}
    }
    CHECK(found==1);return 0;
}
int main(int argc,char** argv){
    FILE* file;long size;unsigned char* bytes;dmg_engine* engine=NULL;dmg_snapshot* snapshot=NULL;dmg_query* query=NULL;dmg_result* result=NULL;dmg_job* job=NULL;dmg_batch* batch=NULL;
    dmg_error error={0};dmg_query_info qi;dmg_result_info info;dmg_job_status final;
    const dmg_open_options options={sizeof(options),DMG_ABI_VERSION,DMG_MAX_SOURCE_BYTES,"numeric-c","input",NULL};
    CHECK(argc==2);file=fopen(argv[1],"rb");CHECK(file);fseek(file,0,SEEK_END);size=ftell(file);rewind(file);CHECK(size>0);
    bytes=(unsigned char*)malloc((size_t)size);CHECK(bytes&&fread(bytes,1,(size_t)size,file)==(size_t)size);fclose(file);
    CHECK(dmg_engine_create(NULL,&engine,&error)==DMG_OK);CHECK(dmg_query_compile_json(engine,(const uint8_t*)query_json,strlen(query_json),&query,&error)==DMG_OK);
    CHECK(dmg_query_get_info(query,&qi)==DMG_OK&&qi.demand_mask==8&&(qi.required_capabilities&32768)&&strncmp(qi.query_id,"query:v7:",9)==0);
    CHECK(dmg_snapshot_open_copy_in(engine,bytes,(uint64_t)size,&options,&snapshot,&error)==DMG_OK);free(bytes);
    CHECK(dmg_query_execute(snapshot,query,&result,&error)==DMG_OK);CHECK(dmg_result_get_info(result,&info)==DMG_OK&&info.decision==DMG_PROVEN_TRUE&&info.candidates_count==1);
    CHECK(check_witness(result)==0);dmg_result_release(result);
    CHECK(dmg_job_start(snapshot,query,NULL,&job,&error)==DMG_OK);CHECK(dmg_job_next(job,5000,&batch,&error)==DMG_OK&&batch);
    CHECK(dmg_job_wait(job,5000,&final)==DMG_OK&&final.terminal&&final.outcome.execution_status==DMG_OK&&final.outcome.decision==DMG_PROVEN_TRUE);
    dmg_snapshot_release(snapshot);dmg_query_release(query);dmg_job_release(job);dmg_engine_release(engine);
    CHECK(check_witness(batch)==0);dmg_batch_release(batch);
    puts("PASS numeric C ABI: v7 sync and Job, 64-bit witness, strict size, legacy rejection and retained Batch");return 0;
}
