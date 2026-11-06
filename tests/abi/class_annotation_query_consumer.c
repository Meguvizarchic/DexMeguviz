#include "dexmeguviz/dexmeguviz.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "class annotation query test line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
#define HEAD "{\"schema_version\":1,\"relation\":\"class_defs\",\"required_capabilities\":[\"class_annotation_static\"],"
#define HEAD_SCOPE "{\"schema_version\":1,\"relation\":\"class_defs\",\"required_capabilities\":[\"class_annotation_static\"],\"scope\":{\"slots\":[\"one\"]},"
#define TYPE "\"type\":\"Lfixture/Complex;\""

static void check_row(const dmg_entity_row* row) {
    static const char expected[] = "Lfixture/Annotated;";
    size_t i;
    CHECK(row->relation == DMG_CLASS_DEFS && row->local_index == 0 && row->reference_index == 2);
    CHECK(row->type_descriptor_length == sizeof(expected)-1);
    for (i=0; i<sizeof(expected)-1; ++i) CHECK(row->type_descriptor[i] == (unsigned char)expected[i]);
}
static dmg_result* execute(dmg_engine* engine, dmg_snapshot* snapshot, const char* json, dmg_query_info* info) {
    dmg_query* query=NULL; dmg_result* result=NULL; dmg_error error={0};
    dmg_status status=dmg_query_compile_json(engine,(const uint8_t*)json,strlen(json),&query,&error);
    if (status!=DMG_OK) fprintf(stderr,"compile status %u: %s\n",status,error.message);
    CHECK(status==DMG_OK && query);
    { dmg_query_info_v2 newer={0}, sentinel;dmg_query_info old;dmg_query_explain_v1 explain;memset(&old,0x5a,sizeof(old));
      CHECK(dmg_query_get_info(query,&old)==DMG_UNSUPPORTED && ((unsigned char*)&old)[0]==0x5a);
      memset(&newer,0x5a,sizeof(newer));sentinel=newer;CHECK(dmg_query_get_info_v2(query,&newer,sizeof(newer)-1)==DMG_INVALID_ARGUMENT && memcmp(&newer,&sentinel,sizeof(newer))==0);
      CHECK(dmg_query_get_info_v2(query,&newer,sizeof(newer))==DMG_OK && strcmp(newer.extended_capabilities,"class_annotation_static")==0);
      CHECK(newer.legacy.query_id && strncmp(newer.legacy.query_id,"query:v24:",10)==0);*info=newer.legacy;
      memset(&explain,0x5a,sizeof(explain));CHECK(dmg_query_get_explain_v1(query,&explain,sizeof(explain))==DMG_UNSUPPORTED && ((unsigned char*)&explain)[0]==0x5a);
    }
    status=dmg_query_execute(snapshot,query,&result,&error);
    if (status!=DMG_OK) fprintf(stderr,"execute status %u: %s\n",status,error.message);
    CHECK(status==DMG_OK && result);
    {dmg_query_info old;dmg_query_info_v2 newer,sentinel;memset(&old,0x5a,sizeof(old));CHECK(dmg_result_get_query_info(result,&old)==DMG_UNSUPPORTED&&((unsigned char*)&old)[0]==0x5a);
     memset(&newer,0x5a,sizeof(newer));sentinel=newer;CHECK(dmg_result_get_query_info_v2(result,&newer,sizeof(newer)-1)==DMG_INVALID_ARGUMENT&&memcmp(&newer,&sentinel,sizeof(newer))==0);
     CHECK(dmg_result_get_query_info_v2(result,&newer,sizeof(newer))==DMG_OK&&strcmp(newer.extended_capabilities,"class_annotation_static")==0&&strncmp(newer.legacy.query_id,"query:v24:",10)==0);}
    dmg_query_release(query);return result;
}
static void run(dmg_engine* engine,dmg_snapshot* snapshot,const char* json,
                uint32_t expected_count,uint64_t expected_unknown,uint32_t expected_sources_mask,int matching_rows) {
    dmg_query_info qi={0};dmg_result* result=execute(engine,snapshot,json,&qi);
    dmg_relation_info info={0};uint32_t seen=0,i;
    CHECK(dmg_result_get_relation_info(result,&info,sizeof(info))==DMG_OK);
    CHECK(info.relation==DMG_CLASS_DEFS && info.execution_status==DMG_OK);
    CHECK(info.candidates_count==expected_count && info.unknown_rows==expected_unknown);
    if (expected_unknown) CHECK(info.coverage==DMG_COVERAGE_PARTIAL && info.reason==DMG_UNKNOWN_ATTRIBUTE);
    for(i=0;i<info.candidates_count;i++) {
        dmg_entity_row row={0};CHECK(dmg_result_get_entity(result,i,&row,sizeof(row))==DMG_OK);
        CHECK(row.source_index<2);seen|=1u<<row.source_index;
        if(matching_rows) check_row(&row); else CHECK(row.local_index!=0);
    }
    CHECK(seen==expected_sources_mask);dmg_result_release(result);
}
static void reject(dmg_engine* engine,const char* json) {
    dmg_query* query=NULL;dmg_error error={0};
    dmg_status status=dmg_query_compile_json(engine,(const uint8_t*)json,strlen(json),&query,&error);
    if (status!=DMG_INVALID_ARGUMENT && status!=DMG_UNSUPPORTED) fprintf(stderr,"unexpected rejection status %u: %s\n",status,error.message);
    CHECK((status==DMG_INVALID_ARGUMENT || status==DMG_UNSUPPORTED) && query==NULL);
}
static void budget(dmg_engine* engine,dmg_snapshot* snapshot) {
    const char* json=HEAD "\"max_work\":1,\"where\":{\"annotation\":{" TYPE ",\"element\":{\"name\":\"n\",\"int\":-7}}}}";
    dmg_query* query=NULL;dmg_result* result=NULL;dmg_error error={0};
    CHECK(dmg_query_compile_json(engine,(const uint8_t*)json,strlen(json),&query,&error)==DMG_OK && query);
    CHECK(dmg_query_execute(snapshot,query,&result,&error)==DMG_BUDGET_EXCEEDED && result==NULL);
    dmg_query_release(query);
}
static void old_info_v2(dmg_engine* engine) {
    const char* json="{\"schema_version\":1,\"relation\":\"class_defs\"}";dmg_query* q=NULL;dmg_error error={0};dmg_query_info old={0};dmg_query_info_v2 next={0};
    CHECK(dmg_query_compile_json(engine,(const uint8_t*)json,strlen(json),&q,&error)==DMG_OK);
    CHECK(dmg_query_get_info(q,&old)==DMG_OK && dmg_query_get_info_v2(q,&next,sizeof(next))==DMG_OK);
    CHECK(strcmp(old.query_id,next.legacy.query_id)==0 && strcmp(next.extended_capabilities,"")==0);dmg_query_release(q);
}
static void distinct_ids(dmg_engine* engine) {
    const char* list[]={HEAD "\"where\":{\"annotation\":{" TYPE ",\"element\":{\"name\":\"n\",\"int\":-7}}}}",
        HEAD "\"where\":{\"annotation\":{" TYPE ",\"element\":{\"name\":\"n\",\"int\":7}}}}",
        HEAD "\"where\":{\"annotation\":{" TYPE ",\"element\":{\"name\":\"other\",\"int\":-7}}}}"};
    char ids[3][128];unsigned i,j;dmg_error error={0};
    for(i=0;i<3;i++){dmg_query* q=NULL;dmg_query_info info={0};CHECK(dmg_query_compile_json(engine,(const uint8_t*)list[i],strlen(list[i]),&q,&error)==DMG_OK);{dmg_query_info_v2 newer={0};CHECK(dmg_query_get_info_v2(q,&newer,sizeof(newer))==DMG_OK);info=newer.legacy;}CHECK(strlen(info.query_id)<sizeof(ids[i]));strcpy(ids[i],info.query_id);dmg_query_release(q);}
    for(i=0;i<3;i++)for(j=i+1;j<3;j++)CHECK(strcmp(ids[i],ids[j])!=0);
}
static void cancellation(dmg_engine* engine,dmg_snapshot* snapshot) {
    const char* json=HEAD "\"where\":{\"annotation\":{" TYPE "}}}";
    dmg_query* query=NULL;dmg_job* job=NULL;dmg_error error={0};dmg_relation_job_status status={0};
    dmg_job_options options={sizeof(options),DMG_ABI_VERSION,1,1,0};
    CHECK(dmg_query_compile_json(engine,(const uint8_t*)json,strlen(json),&query,&error)==DMG_OK);
    CHECK(dmg_job_start(snapshot,query,&options,&job,&error)==DMG_OK);
    dmg_query_release(query);query=NULL;
    {dmg_query_info_v2 newer={0},sentinel;memset(&newer,0x5a,sizeof(newer));sentinel=newer;
     CHECK(dmg_job_get_query_info_v2(job,&newer,sizeof(newer)-1)==DMG_INVALID_ARGUMENT&&memcmp(&newer,&sentinel,sizeof(newer))==0);
     CHECK(dmg_job_get_query_info_v2(job,&newer,sizeof(newer))==DMG_OK&&strcmp(newer.extended_capabilities,"class_annotation_static")==0&&strncmp(newer.legacy.query_id,"query:v24:",10)==0);}

    CHECK(dmg_job_wait_relation(job,1000,&status,sizeof(status))==DMG_NOT_READY && !status.terminal);
    dmg_job_cancel(job);CHECK(dmg_job_wait_relation(job,10000,&status,sizeof(status))==DMG_OK);
    CHECK(status.terminal && status.outcome.execution_status==DMG_CANCELLED);
    dmg_job_release(job);if(query)dmg_query_release(query);
}
int main(int argc,char** argv) {
    dmg_engine* engine=NULL;dmg_snapshot* snapshot=NULL;dmg_error error={0};
    dmg_source_spec spec[2]={{0},{0}};dmg_source_set_options options={sizeof(options),DMG_ABI_VERSION,"class-annotation-test",1,8,1u<<20};
    FILE* f;long size;uint8_t* data;unsigned i;
    CHECK(argc==2);f=fopen(argv[1],"rb");CHECK(f && fseek(f,0,SEEK_END)==0);size=ftell(f);CHECK(size>0 && fseek(f,0,SEEK_SET)==0);
    data=(uint8_t*)malloc((size_t)size);CHECK(data && fread(data,1,(size_t)size,f)==(size_t)size);fclose(f);
    CHECK(strstr(dmg_capabilities(),"dex-query-class-annotation-static-v24")!=NULL);
    CHECK(dmg_engine_create(NULL,&engine,&error)==DMG_OK);
    for(i=0;i<2;i++) {spec[i].struct_size=sizeof(spec[i]);spec[i].abi_version=DMG_ABI_VERSION;spec[i].format=DMG_INPUT_RAW_DEX;spec[i].data=data;spec[i].size=(uint64_t)size;spec[i].slot_key=i?"two":"one";spec[i].role="base";}
    CHECK(dmg_snapshot_open_sources(engine,spec,2,&options,&snapshot,&error)==DMG_OK && snapshot);free(data);

    run(engine,snapshot,HEAD "\"where\":{\"annotation\":{" TYPE "}}}",2,0,3,1);
    run(engine,snapshot,HEAD "\"where\":{\"annotation\":{" TYPE ",\"visibility\":1,\"element\":{\"name\":\"n\",\"int\":-7}}}}",2,0,3,1);
    run(engine,snapshot,HEAD_SCOPE "\"where\":{\"annotation\":{" TYPE ",\"visibility\":1,\"element\":{\"name\":\"n\",\"int\":-7}}}}",1,0,1,1);
    run(engine,snapshot,HEAD "\"where\":{\"annotation\":{" TYPE ",\"element\":{\"name\":\"n\",\"int\":7}}}}",0,0,0,1);
    run(engine,snapshot,HEAD "\"where\":{\"annotation\":{" TYPE ",\"visibility\":0}}}",0,0,0,1);
    run(engine,snapshot,HEAD "\"where\":{\"annotation\":{\"type\":\"Lfixture/Missing;\"}}}",0,0,0,1);
    run(engine,snapshot,HEAD "\"where\":{\"annotation\":{" TYPE ",\"element\":{\"name\":\"absent\",\"int\":0}}}}",0,2,0,1);
    run(engine,snapshot,HEAD "\"where\":{\"not\":{\"annotation\":{" TYPE ",\"element\":{\"name\":\"absent\",\"int\":0}}}}}",6,2,3,0);
    budget(engine,snapshot);cancellation(engine,snapshot);distinct_ids(engine);old_info_v2(engine);

    reject(engine,"{\"schema_version\":1,\"relation\":\"class_defs\",\"where\":{\"annotation\":{" TYPE "}}}");
    reject(engine,HEAD "\"where\":{\"annotation\":{\"type\":12}}}");
    reject(engine,HEAD "\"where\":{\"annotation\":{\"type\":\"L/;\"}}}");
    reject(engine,HEAD "\"where\":{\"annotation\":{\"type\":\"Lfoo//Bar;\"}}}");
    reject(engine,HEAD "\"where\":{\"annotation\":{" TYPE ",\"element\":{\"name\":\"bad/name\",\"int\":1}}}}");
    run(engine,snapshot,HEAD "\"where\":{\"annotation\":{\"type\":\"Lfoo/Hello world;\"}}}",0,0,0,1);

    reject(engine,HEAD "\"where\":{\"annotation\":{" TYPE ",\"element\":{\"name\":\"n\",\"int\":\"-7\"}}}}");
    reject(engine,HEAD "\"where\":{\"annotation\":{" TYPE ",\"element\":{\"name\":\"n\",\"int\":2147483648}}}}");
    reject(engine,HEAD "\"scope\":{\"slots\":\"one\"},\"where\":{\"annotation\":{" TYPE "}}}");
    reject(engine,"{\"schema_version\":1,\"relation\":\"method_defs\",\"required_capabilities\":[\"class_annotation_static\"],\"where\":{\"annotation\":{" TYPE "}}}");
    reject(engine,HEAD "\"order_by\":[{\"field\":\"descriptor\",\"direction\":\"asc\"}],\"where\":{\"annotation\":{" TYPE "}}}");
    reject(engine,"{\"schema_version\":1,\"relation\":\"class_defs\",\"required_capabilities\":[\"class_annotation_static\",\"opcode_sequence\"],\"where\":{\"annotation\":{" TYPE "}}}");
    dmg_snapshot_release(snapshot);dmg_engine_release(engine);
    puts("PASS C class annotation query, tri-state, source scope, bounds and rejection");return 0;
}
