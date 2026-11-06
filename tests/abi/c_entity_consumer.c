#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"Entity C ABI check %d: %s\n",__LINE__,#x);return 1;}}while(0)

static int units_equal(const uint16_t* value,uint64_t length,const char* expected){
    uint64_t i;if(length!=strlen(expected))return 0;
    for(i=0;i<length;++i)if(value[i]!=(unsigned char)expected[i])return 0;return 1;
}
static int unchanged(const void* bytes,size_t length){
    const unsigned char* p=(const unsigned char*)bytes;size_t i;
    for(i=0;i<length;++i)if(p[i]!=0xa5)return 0;return 1;
}
static int same_live_bytes(const dmg_engine_stats* a,const dmg_engine_stats* b){
    return a->owned_bytes==b->owned_bytes&&a->source_bytes==b->source_bytes&&a->fact_bytes==b->fact_bytes&&
        a->scratch_bytes==b->scratch_bytes&&a->query_bytes==b->query_bytes&&a->result_bytes==b->result_bytes&&
        a->control_bytes==b->control_bytes&&a->borrowed_bytes==b->borrowed_bytes&&a->active_jobs==b->active_jobs;
}
int main(int argc,char** argv){
    const char* names[]={"method_defs","class_defs","field_defs","method_refs","field_refs","string_values","type_refs"};
    const uint32_t counts[]={1,5,3,1,4,13,9};
    const char* unknown_query="{\"schema_version\":1,\"relation\":\"field_refs\",\"where\":{\"owner\":\"Lexternal/External;\",\"not\":{\"flags_any\":8}},\"intent\":\"unique\"}";
    const char* external_query="{\"schema_version\":1,\"relation\":\"field_refs\",\"where\":{\"has_local_definition\":false},\"intent\":\"unique\"}";
    const char* job_query="{\"schema_version\":1,\"relation\":\"field_refs\"}";
    dmg_engine* engine=NULL;dmg_snapshot* snapshot=NULL;dmg_query* query=NULL;dmg_result* result=NULL;
    dmg_job* job=NULL;dmg_batch* batch=NULL;dmg_batch* retained=NULL;
    dmg_error error={0};dmg_engine_stats initial,opened,after;dmg_query_info query_info;dmg_query_profile profile;
    dmg_relation_info info;dmg_entity_row row;dmg_relation_job_status final;dmg_job_status legacy_status;
    dmg_result_info legacy_info;dmg_method_row legacy_row;dmg_source_info origin;
    dmg_open_options options={sizeof(options),DMG_ABI_VERSION,DMG_MAX_SOURCE_BYTES,"c-entity","fixture",NULL};
    dmg_job_options job_options={sizeof(job_options),DMG_ABI_VERSION,2,1,0};
    FILE* file;long length;unsigned char* bytes;uint32_t relation,i,rows=0;char specification[160];
    CHECK(argc==2);file=fopen(argv[1],"rb");CHECK(file!=NULL);
    CHECK(fseek(file,0,SEEK_END)==0);length=ftell(file);CHECK(length>0);rewind(file);
    bytes=(unsigned char*)malloc((size_t)length);CHECK(bytes!=NULL);
    CHECK(fread(bytes,1,(size_t)length,file)==(size_t)length);fclose(file);
    CHECK(dmg_engine_create(NULL,&engine,&error)==DMG_OK);
    CHECK(dmg_engine_get_stats(engine,&initial)==DMG_OK);
    CHECK(dmg_snapshot_open_copy_in(engine,bytes,(uint64_t)length,&options,&snapshot,&error)==DMG_OK);
    CHECK(dmg_engine_get_stats(engine,&opened)==DMG_OK);
    for(relation=0;relation<7;++relation){
        CHECK(snprintf(specification,sizeof(specification),"{\"schema_version\":1,\"relation\":\"%s\"}",names[relation])>0);
        CHECK(dmg_query_compile_json(engine,(const uint8_t*)specification,strlen(specification),&query,&error)==DMG_OK);
        CHECK(dmg_query_get_info(query,&query_info)==DMG_OK);
        CHECK(strncmp(query_info.query_id,relation==DMG_METHOD_DEFS?"query:v1:":"query:v2:",9)==0);
        CHECK(dmg_query_execute(snapshot,query,&result,&error)==DMG_OK);
        CHECK(dmg_result_get_relation_info(result,&info,sizeof(info))==DMG_OK);
        CHECK(info.relation==relation&&info.execution_status==DMG_OK&&info.coverage==DMG_COVERAGE_COMPLETE);
        CHECK(info.decision==DMG_NOT_APPLICABLE&&info.candidates_count==counts[relation]);
        CHECK(info.visited_rows==counts[relation]&&info.total_rows==counts[relation]&&info.unknown_rows==0);
        CHECK(dmg_result_get_profile(result,&profile)==DMG_OK&&profile.scope_complete==1&&profile.methods_decoded==0);
        memset(&info,0xa5,sizeof(info));
        CHECK(dmg_result_get_relation_info(result,&info,sizeof(info)-1)==DMG_INVALID_ARGUMENT&&unchanged(&info,sizeof(info)));
        memset(&row,0xa5,sizeof(row));
        CHECK(dmg_result_get_entity(result,0,&row,sizeof(row)-1)==DMG_INVALID_ARGUMENT&&unchanged(&row,sizeof(row)));
        CHECK(dmg_result_get_entity(result,counts[relation],&row,sizeof(row))==DMG_INVALID_ARGUMENT&&unchanged(&row,sizeof(row)));
        if(relation!=DMG_METHOD_DEFS){
            memset(&legacy_info,0xa5,sizeof(legacy_info));memset(&legacy_row,0xa5,sizeof(legacy_row));
            CHECK(dmg_result_get_info(result,&legacy_info)==DMG_UNSUPPORTED&&unchanged(&legacy_info,sizeof(legacy_info)));
            CHECK(dmg_result_get_method(result,0,&legacy_row)==DMG_UNSUPPORTED&&unchanged(&legacy_row,sizeof(legacy_row)));
        }else{
            CHECK(dmg_result_get_info(result,&legacy_info)==DMG_OK&&legacy_info.total_methods==1);
            CHECK(dmg_result_get_method(result,0,&legacy_row)==DMG_OK&&legacy_row.method_index==0&&legacy_row.declaration_offset==621);
        }
        for(i=0;i<counts[relation];++i){
            CHECK(dmg_result_get_entity(result,i,&row,sizeof(row))==DMG_OK);
            CHECK(row.relation==relation&&row.local_index==i&&row.source_index==0);
            CHECK(dmg_result_get_origin(result,i,&origin)==DMG_OK&&origin.source_index==0&&origin.input_index==0);
            CHECK(origin.dex.source_sha256!=NULL&&strcmp(origin.slot_key,"fixture")==0);
            if(relation==DMG_CLASS_DEFS){
                const uint32_t refs[]={7,4,5,2,3},flags[]={1,0x601,0x601,1,0x401};
                CHECK(row.reference_index==refs[i]&&row.record_offset==252+32*i);
                CHECK(row.definition_known&&row.flags_known&&row.definition_offset==row.record_offset&&row.access_flags==flags[i]);
                CHECK(!row.code_known&&row.type_descriptor_length>0&&row.owner_length==0&&row.name_length==0);
            }else if(relation==DMG_FIELD_DEFS){
                const uint32_t refs[]={1,0,2},offsets[]={611,613,619},flags[]={9,1,1};
                CHECK(row.reference_index==refs[i]&&row.record_offset==offsets[i]&&row.definition_offset==offsets[i]);
                CHECK(row.definition_known&&row.flags_known&&row.access_flags==flags[i]&&!row.code_known);
                CHECK(row.owner_length>0&&row.name_length>0&&row.type_descriptor_length==1&&row.prototype_length==0);
            }else if(relation==DMG_FIELD_REFS){
                CHECK(row.reference_index==i&&row.record_offset==212+8*i&&!row.code_known);
                CHECK(row.definition_known==(i<3)&&row.flags_known==(i<3));
                if(i==3)CHECK(units_equal(row.owner,row.owner_length,"Lexternal/External;")&&units_equal(row.name,row.name_length,"externalField"));
            }else if(relation==DMG_METHOD_DEFS||relation==DMG_METHOD_REFS){
                CHECK(row.reference_index==0&&row.flags_known&&row.definition_known&&row.access_flags==0x401&&row.definition_offset==621);
                CHECK(row.code_known==(relation==DMG_METHOD_DEFS)&&row.code_offset==0);
                CHECK(row.record_offset==(relation==DMG_METHOD_DEFS?621u:244u));
                CHECK(units_equal(row.name,row.name_length,"abstractMethod")&&units_equal(row.prototype,row.prototype_length,"()V"));
            }else if(relation==DMG_STRING_VALUES){
                CHECK(row.reference_index==i&&row.record_offset==112+4*i);
                CHECK(!row.definition_known&&!row.flags_known&&!row.code_known&&row.string_value_length>0);
                CHECK(row.owner_length==0&&row.name_length==0&&row.type_descriptor_length==0);
            }else{
                CHECK(row.reference_index==i&&row.record_offset==164+4*i&&!row.code_known);
                CHECK(row.definition_known==(i==2||i==3||i==4||i==5||i==7));
                CHECK(row.flags_known==row.definition_known&&row.type_descriptor_length>0&&row.owner_length==0);
            }
        }
        dmg_result_release(result);result=NULL;dmg_query_release(query);query=NULL;
        CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&same_live_bytes(&after,&opened));
    }
    CHECK(dmg_query_compile_json(engine,(const uint8_t*)unknown_query,strlen(unknown_query),&query,&error)==DMG_OK);
    CHECK(dmg_query_execute(snapshot,query,&result,&error)==DMG_OK);
    CHECK(dmg_result_get_relation_info(result,&info,sizeof(info))==DMG_OK);
    CHECK(info.coverage==DMG_COVERAGE_PARTIAL&&info.decision==DMG_UNDETERMINED&&info.reason==DMG_UNKNOWN_ATTRIBUTE);
    CHECK(info.candidates_count==0&&info.unknown_rows==1&&info.visited_rows==4&&info.total_rows==4);
    CHECK(dmg_result_get_profile(result,&profile)==DMG_OK&&profile.scope_complete==1&&!profile.order_verified);
    dmg_result_release(result);result=NULL;
    CHECK(dmg_job_start(snapshot,query,NULL,&job,&error)==DMG_OK);
    CHECK(dmg_job_wait_relation(job,5000,&final,sizeof(final))==DMG_OK&&final.terminal==1);
    CHECK(final.outcome.coverage==DMG_COVERAGE_PARTIAL&&final.outcome.decision==DMG_UNDETERMINED&&final.outcome.reason==DMG_UNKNOWN_ATTRIBUTE&&final.outcome.unknown_rows==1);
    CHECK(dmg_job_next(job,0,&batch,&error)==DMG_END_OF_STREAM&&batch==NULL);
    dmg_job_release(job);job=NULL;dmg_query_release(query);query=NULL;
    CHECK(dmg_query_compile_json(engine,(const uint8_t*)external_query,strlen(external_query),&query,&error)==DMG_OK);
    CHECK(dmg_query_execute(snapshot,query,&result,&error)==DMG_OK);
    CHECK(dmg_result_get_relation_info(result,&info,sizeof(info))==DMG_OK&&info.coverage==DMG_COVERAGE_COMPLETE&&info.decision==DMG_PROVEN_TRUE&&info.unknown_rows==0);
    CHECK(info.candidates_count==1&&dmg_result_get_entity(result,0,&row,sizeof(row))==DMG_OK&&row.reference_index==3&&!row.definition_known&&!row.flags_known);
    {uint32_t count=0;dmg_witness witness;
        CHECK(dmg_result_get_witness_count(result,0,&count)==DMG_OK&&count==1);
        CHECK(dmg_result_get_witness(result,0,0,&witness)==DMG_OK&&witness.kind==DMG_WITNESS_METADATA&&witness.matched==DMG_MATCH_TRUE);}
    dmg_result_release(result);result=NULL;dmg_query_release(query);query=NULL;
    {const char* negated="{\"schema_version\":1,\"relation\":\"field_refs\",\"where\":{\"name\":\"instanceField\",\"not\":{\"flags_any\":8}},\"intent\":\"unique\"}";uint32_t count=0,false_leaves=0;
        CHECK(dmg_query_compile_json(engine,(const uint8_t*)negated,strlen(negated),&query,&error)==DMG_OK);
        CHECK(dmg_query_execute(snapshot,query,&result,&error)==DMG_OK);
        CHECK(dmg_result_get_relation_info(result,&info,sizeof(info))==DMG_OK&&info.coverage==DMG_COVERAGE_COMPLETE&&info.decision==DMG_PROVEN_TRUE&&info.unknown_rows==0);
        CHECK(dmg_result_get_witness_count(result,0,&count)==DMG_OK);
        for(i=0;i<count;++i){dmg_witness witness;CHECK(dmg_result_get_witness(result,0,i,&witness)==DMG_OK);
            CHECK(witness.matched!=DMG_MATCH_UNKNOWN);if(witness.matched==DMG_MATCH_FALSE)++false_leaves;}
        CHECK(false_leaves==1);dmg_result_release(result);result=NULL;dmg_query_release(query);query=NULL;
    }
    CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&same_live_bytes(&after,&opened));

    CHECK(dmg_query_compile_json(engine,(const uint8_t*)job_query,strlen(job_query),&query,&error)==DMG_OK);
    CHECK(dmg_job_start(snapshot,query,&job_options,&job,&error)==DMG_OK);
    memset(&final,0xa5,sizeof(final));memset(&legacy_status,0xa5,sizeof(legacy_status));
    CHECK(dmg_job_get_relation_status(job,&final,sizeof(final)-1)==DMG_INVALID_ARGUMENT&&unchanged(&final,sizeof(final)));
    CHECK(dmg_job_wait_relation(job,0,&final,sizeof(final)-1)==DMG_INVALID_ARGUMENT&&unchanged(&final,sizeof(final)));
    CHECK(dmg_job_get_status(job,&legacy_status)==DMG_UNSUPPORTED&&unchanged(&legacy_status,sizeof(legacy_status)));
    CHECK(dmg_job_wait(job,0,&legacy_status)==DMG_UNSUPPORTED&&unchanged(&legacy_status,sizeof(legacy_status)));
    for(;;){
        dmg_status status=dmg_job_next(job,5000,&batch,&error);
        if(status==DMG_END_OF_STREAM)break;
        CHECK(status==DMG_OK&&batch!=NULL);
        CHECK(dmg_result_get_relation_info(batch,&info,sizeof(info))==DMG_OK&&info.relation==DMG_FIELD_REFS&&info.candidates_count==2);
        CHECK(info.coverage==DMG_COVERAGE_PARTIAL&&info.unknown_rows==0);
        CHECK(dmg_result_get_entity(batch,0,&row,sizeof(row))==DMG_OK&&row.local_index==rows);
        rows+=info.candidates_count;
        if(retained==NULL)retained=batch;else dmg_batch_release(batch);batch=NULL;
    }
    CHECK(rows==4&&retained!=NULL);
    CHECK(dmg_job_wait_relation(job,5000,&final,sizeof(final))==DMG_OK&&final.terminal==1&&final.lifecycle==DMG_JOB_COMPLETED);
    CHECK(final.outcome.execution_status==DMG_OK&&final.outcome.coverage==DMG_COVERAGE_COMPLETE&&final.outcome.candidates_count==4&&final.outcome.visited_rows==4&&final.outcome.total_rows==4);
    CHECK(dmg_job_get_relation_status(job,&final,sizeof(final))==DMG_OK&&final.terminal==1);
    dmg_job_release(job);job=NULL;dmg_query_release(query);query=NULL;dmg_snapshot_release(snapshot);snapshot=NULL;
    CHECK(dmg_result_get_entity(retained,1,&row,sizeof(row))==DMG_OK&&row.reference_index==1&&row.definition_offset==611);
    CHECK(units_equal(row.name,row.name_length,"shared")&&units_equal(row.type_descriptor,row.type_descriptor_length,"J"));
    dmg_batch_release(retained);retained=NULL;
    CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&same_live_bytes(&after,&initial));

    CHECK(dmg_snapshot_open_copy_in(engine,bytes,(uint64_t)length,&options,&snapshot,&error)==DMG_OK);free(bytes);
    CHECK(dmg_query_compile_json(engine,(const uint8_t*)external_query,strlen(external_query),&query,&error)==DMG_OK);
    CHECK(dmg_job_start(snapshot,query,NULL,&job,&error)==DMG_OK);
    CHECK(dmg_job_next(job,5000,&retained,&error)==DMG_OK&&retained!=NULL);
    CHECK(dmg_job_wait_relation(job,5000,&final,sizeof(final))==DMG_OK&&final.outcome.decision==DMG_PROVEN_TRUE);
    dmg_snapshot_release(snapshot);dmg_query_release(query);dmg_job_release(job);dmg_engine_release(engine);
    CHECK(dmg_result_get_entity(retained,0,&row,sizeof(row))==DMG_OK&&row.reference_index==3&&!row.flags_known);
    CHECK(units_equal(row.owner,row.owner_length,"Lexternal/External;")&&units_equal(row.name,row.name_length,"externalField"));
    CHECK(dmg_result_get_query_info(retained,&query_info)==DMG_OK&&strncmp(query_info.query_id,"query:v2:",9)==0);
    CHECK(dmg_result_get_origin(retained,0,&origin)==DMG_OK&&strcmp(origin.slot_key,"fixture")==0);
    dmg_batch_release(retained);
    puts("PASS C entity ABI: seven roots, sized outputs, unknown attributes, legacy rejection, Job batches, retained lifetime and resource reclamation");return 0;
}
