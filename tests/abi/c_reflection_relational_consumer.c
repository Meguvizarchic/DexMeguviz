#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if(!(x)){fprintf(stderr,"reflection C check line %d: %s\n",__LINE__,#x);return 1;} } while(0)

static int verify(dmg_snapshot* snapshot,dmg_query* query,const char* expected_id,
                  unsigned rows,unsigned unknown,uint32_t decision,uint32_t reason){
    dmg_error error={0};dmg_result* result=NULL;dmg_job* job=NULL;dmg_batch* batch=NULL;
    dmg_relation_info info={0};dmg_relation_job_status status={0};dmg_query_info query_info={0};
    dmg_job_options options={sizeof(options),DMG_ABI_VERSION,1,4,0};unsigned count=0,source_bits=0;
    CHECK(dmg_query_execute(snapshot,query,&result,&error)==DMG_OK&&result);
    CHECK(dmg_result_get_relation_info(result,&info,sizeof(info))==DMG_OK);
    CHECK(info.execution_status==DMG_OK&&info.coverage==DMG_COVERAGE_PARTIAL&&info.candidates_count==rows&&info.unknown_rows==unknown&&info.decision==decision&&info.reason==reason);
    CHECK(dmg_result_get_query_info(result,&query_info)==DMG_OK&&strcmp(query_info.query_id,expected_id)==0);
    CHECK(dmg_job_start(snapshot,query,&options,&job,&error)==DMG_OK&&job);
    for(;;){
        dmg_status rc=dmg_job_next(job,15000,&batch,&error);
        if(rc==DMG_END_OF_STREAM)break;
        CHECK(rc==DMG_OK&&batch);
        CHECK(dmg_result_get_relation_info(batch,&info,sizeof(info))==DMG_OK);
        CHECK(info.coverage==DMG_COVERAGE_PARTIAL&&info.decision==DMG_NOT_APPLICABLE&&info.candidates_count==1);
        CHECK(dmg_result_get_query_info(batch,&query_info)==DMG_OK&&strcmp(query_info.query_id,expected_id)==0);
        {dmg_entity_row row={0};CHECK(dmg_result_get_entity(batch,0,&row,sizeof(row))==DMG_OK&&row.relation==DMG_CLASS_DEFS&&row.local_index==4&&row.source_index<2);source_bits|=1u<<row.source_index;}
        ++count;dmg_batch_release(batch);batch=NULL;
    }
    CHECK(count==rows&&source_bits==((1u<<rows)-1u));
    CHECK(dmg_job_wait_relation(job,15000,&status,sizeof(status))==DMG_OK&&status.terminal);
    CHECK(status.outcome.execution_status==DMG_OK&&status.outcome.coverage==DMG_COVERAGE_PARTIAL&&status.outcome.candidates_count==rows&&status.outcome.unknown_rows==unknown&&status.outcome.decision==decision&&status.outcome.reason==reason);
    dmg_job_release(job);dmg_result_release(result);return 0;
}
int main(int argc,char** argv){
    const char* text="{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"class_defs\",\"where\":{\"all\":[{\"any\":[{\"descriptor\":\"Lcatalog/Base;\"},{\"descriptor\":\"Lcatalog/Child;\"}]},{\"flags\":{\"domain\":\"reflection\",\"mode\":\"contains\",\"value\":1}}]}},\"intent\":\"unique\",\"max_results\":100,\"required_capabilities\":[\"reflection_flags_static\",\"reflection_relational\"]}";
    const char* disabled="{\"schema_version\":1,\"relation\":\"class_defs\",\"where\":{\"flags\":{\"domain\":\"reflection\",\"mode\":\"contains\",\"value\":1}}}";
    dmg_error error={0};dmg_engine* engine=NULL;dmg_query* query=NULL;dmg_query_info qinfo={0};dmg_snapshot* one=NULL;dmg_snapshot* two=NULL;
    dmg_source_spec specs[2]={{0},{0}};dmg_source_set_options options={sizeof(options),DMG_ABI_VERSION,"reflection-c",1,8,1u<<20};
    char query_id[100];unsigned char* bytes;long length;FILE* file;unsigned i;
    CHECK(argc==2);file=fopen(argv[1],"rb");CHECK(file&&fseek(file,0,SEEK_END)==0);length=ftell(file);CHECK(length>0&&fseek(file,0,SEEK_SET)==0);
    bytes=(unsigned char*)malloc((size_t)length);CHECK(bytes&&fread(bytes,1,(size_t)length,file)==(size_t)length);fclose(file);
    CHECK(dmg_engine_create(NULL,&engine,&error)==DMG_OK);
    for(i=0;i<2;++i){specs[i].struct_size=sizeof(specs[i]);specs[i].abi_version=DMG_ABI_VERSION;specs[i].format=DMG_INPUT_RAW_DEX;specs[i].data=bytes;specs[i].size=(uint64_t)length;specs[i].slot_key=i?"split":"base";specs[i].role=i?"code-split":"base";}
    CHECK(dmg_snapshot_open_sources(engine,specs,1,&options,&one,&error)==DMG_OK);
    CHECK(dmg_snapshot_open_sources(engine,specs,2,&options,&two,&error)==DMG_OK);free(bytes);
    CHECK(dmg_query_compile_json(engine,(const uint8_t*)disabled,strlen(disabled),&query,&error)==DMG_UNSUPPORTED&&!query);
    CHECK(dmg_query_compile_json(engine,(const uint8_t*)text,strlen(text),&query,&error)==DMG_OK&&query);
    CHECK(dmg_query_get_info(query,&qinfo)==DMG_OK&&qinfo.query_id&&strncmp(qinfo.query_id,"query:v14:",10)==0&&((qinfo.required_capabilities&6291456u)==6291456u));
    CHECK(strlen(qinfo.query_id)<sizeof(query_id));strcpy(query_id,qinfo.query_id);
    CHECK(verify(one,query,query_id,1,1,DMG_UNDETERMINED,DMG_UNKNOWN_ATTRIBUTE)==0);
    CHECK(verify(two,query,query_id,2,2,DMG_PROVEN_FALSE,DMG_AMBIGUOUS)==0);
    dmg_query_release(query);dmg_snapshot_release(one);dmg_snapshot_release(two);dmg_engine_release(engine);
    puts("PASS C ABI v14 QueryID, Unknown, provisional Job batches and final outcomes");return 0;
}
