#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"Relational C ABI check %d: %s\n",__LINE__,#x);return 1;}}while(0)
#define METHOD_SCAN "{\"op\":\"scan\",\"relation\":\"method_defs\"}"
#define FIELD_SCAN "{\"op\":\"scan\",\"relation\":\"field_defs\"}"
#define METHOD_UNION "{\"op\":\"union\",\"semantics\":\"bag\",\"inputs\":[" METHOD_SCAN "," METHOD_SCAN "]}"

static const char group_query[]=
    "{\"schema_version\":1,\"relation\":{\"op\":\"group_by_owner\",\"inputs\":["
    "{\"op\":\"label\",\"label\":\"field\",\"input\":{\"op\":\"scan\",\"relation\":\"field_defs\",\"where\":{\"owner\":\"Lcatalog/Child;\",\"name\":\"shared\",\"type\":\"I\"}}},"
    "{\"op\":\"label\",\"label\":\"method\",\"input\":{\"op\":\"scan\",\"relation\":\"method_defs\",\"where\":{\"owner\":\"Lcatalog/Child;\",\"name\":\"abstractMethod\"}}}"
    "],\"min\":2,\"max\":2,\"required_roles\":[\"field\",\"method\"],\"role_policy\":\"distinct\"},\"intent\":\"unique\"}";
static const char union_query[]="{\"schema_version\":1,\"relation\":" METHOD_UNION "}";
static const char unique_query[]="{\"schema_version\":1,\"relation\":" METHOD_UNION ",\"intent\":\"unique\"}";
static const char tuple_query[]=
    "{\"schema_version\":1,\"relation\":{\"op\":\"union\",\"semantics\":\"bag\",\"inputs\":["
    "{\"op\":\"label\",\"label\":\"A\",\"input\":" METHOD_SCAN "},"
    "{\"op\":\"label\",\"label\":\"B\",\"input\":" METHOD_SCAN "}]},\"intent\":\"unique\",\"unique_by\":\"tuple\"}";
static const char limited_query[]="{\"schema_version\":1,\"relation\":" FIELD_SCAN ",\"max_results\":1}";
static const char intermediate_query[]="{\"schema_version\":1,\"relation\":" FIELD_SCAN ",\"max_intermediate_rows\":1}";
static const char cancel_query[]="{\"schema_version\":1,\"relation\":" FIELD_SCAN "}";
static const char simple_query[]="{\"schema_version\":1,\"relation\":\"method_defs\"}";

static int units_equal(const uint16_t* value,uint64_t length,const char* expected){
    uint64_t i;if(length!=strlen(expected))return 0;
    for(i=0;i<length;++i)if(value[i]!=(unsigned char)expected[i])return 0;return 1;
}
static int unchanged(const void* bytes,size_t length){
    const unsigned char* p=(const unsigned char*)bytes;size_t i;
    for(i=0;i<length;++i)if(p[i]!=0xa5)return 0;return 1;
}
static uint32_t wrong_size(size_t size,uint32_t larger){return (uint32_t)(larger?size+1:size-1);}
static int same_live_bytes(const dmg_engine_stats* a,const dmg_engine_stats* b){
    return a->owned_bytes==b->owned_bytes&&a->source_bytes==b->source_bytes&&a->fact_bytes==b->fact_bytes&&
        a->scratch_bytes==b->scratch_bytes&&a->query_bytes==b->query_bytes&&a->result_bytes==b->result_bytes&&
        a->control_bytes==b->control_bytes&&a->borrowed_bytes==b->borrowed_bytes&&a->active_jobs==b->active_jobs;
}
static int baseline(dmg_engine* engine,const dmg_engine_stats* expected){
    dmg_engine_stats current;CHECK(dmg_engine_get_stats(engine,&current)==DMG_OK);CHECK(same_live_bytes(&current,expected));return 0;
}
static int compile_result(dmg_engine* engine,dmg_snapshot* snapshot,const char* json,dmg_query** query,dmg_result** result){
    dmg_error error={0};CHECK(dmg_query_compile_json(engine,(const uint8_t*)json,strlen(json),query,&error)==DMG_OK);
    CHECK(dmg_query_execute(snapshot,*query,result,&error)==DMG_OK);return 0;
}
static int legacy_result_rejected(const dmg_result* result){
    dmg_result_info info;dmg_method_row row;
    memset(&info,0xa5,sizeof(info));memset(&row,0xa5,sizeof(row));
    CHECK(dmg_result_get_info(result,&info)==DMG_UNSUPPORTED&&unchanged(&info,sizeof(info)));
    CHECK(dmg_batch_get_info(result,&info)==DMG_UNSUPPORTED&&unchanged(&info,sizeof(info)));
    CHECK(dmg_result_get_method(result,0,&row)==DMG_UNSUPPORTED&&unchanged(&row,sizeof(row)));
    CHECK(dmg_batch_get_method(result,0,&row)==DMG_UNSUPPORTED&&unchanged(&row,sizeof(row)));return 0;
}
static int legacy_job_rejected(dmg_job* job){
    dmg_job_status status;memset(&status,0xa5,sizeof(status));
    CHECK(dmg_job_get_status(job,&status)==DMG_UNSUPPORTED&&unchanged(&status,sizeof(status)));
    CHECK(dmg_job_wait(job,0,&status)==DMG_UNSUPPORTED&&unchanged(&status,sizeof(status)));return 0;
}
static int check_group(const dmg_result* result){
    dmg_entity_row row;dmg_binding_row binding;dmg_graph_info graph;dmg_query_info query_info;
    dmg_operator_profile profile;dmg_relation_witness proof;dmg_witness leaf;dmg_source_info origin;
    uint32_t i,count,field_bindings=0,method_bindings=0,field_proofs=0,method_proofs=0,seen=0,scans=0,labels=0,groups=0;
    uint64_t scanned=0,scan_output=0;
    CHECK(dmg_result_get_entity(result,0,&row,sizeof(row))==DMG_OK);
    CHECK(row.relation==DMG_CLASS_DEFS&&row.source_index==0&&row.local_index==4&&row.reference_index==3);
    CHECK(row.record_offset==380&&row.definition_known&&row.definition_offset==380&&row.flags_known&&row.access_flags==0x401&&!row.code_known);
    CHECK(units_equal(row.type_descriptor,row.type_descriptor_length,"Lcatalog/Child;"));
    CHECK(dmg_result_get_graph_info(result,&graph,sizeof(graph))==DMG_OK);
    CHECK(graph.root_node==0&&graph.unique_identity==DMG_IDENTITY_ENTITY&&graph.identity_count==1&&graph.operator_count==5);
    CHECK(dmg_result_get_query_info(result,&query_info)==DMG_OK&&strncmp(query_info.query_id,"query:v3:",9)==0);
    CHECK(dmg_result_get_binding_count(result,0,&count)==DMG_OK&&count>=2);
    for(i=0;i<count;++i){
        CHECK(dmg_result_get_binding(result,0,i,&binding,sizeof(binding))==DMG_OK);
        CHECK(binding.entity.source_index==0&&binding.entity.definition_known&&binding.entity.flags_known);
        CHECK(dmg_result_get_source_info(result,binding.entity.source_index,&origin)==DMG_OK&&strcmp(origin.slot_key,"fixture")==0);
        if(binding.label&&strcmp(binding.label,"field")==0){
            ++field_bindings;CHECK(binding.entity.relation==DMG_FIELD_DEFS&&binding.entity.local_index==2&&binding.entity.reference_index==2);
            CHECK(binding.entity.record_offset==619&&binding.entity.definition_offset==619&&binding.entity.access_flags==1&&!binding.entity.code_known);
            CHECK(units_equal(binding.entity.owner,binding.entity.owner_length,"Lcatalog/Child;"));
            CHECK(units_equal(binding.entity.name,binding.entity.name_length,"shared")&&units_equal(binding.entity.type_descriptor,binding.entity.type_descriptor_length,"I"));
        }else if(binding.label&&strcmp(binding.label,"method")==0){
            ++method_bindings;CHECK(binding.entity.relation==DMG_METHOD_DEFS&&binding.entity.local_index==0&&binding.entity.reference_index==0);
            CHECK(binding.entity.record_offset==621&&binding.entity.definition_offset==621&&binding.entity.access_flags==0x401&&binding.entity.code_known&&binding.entity.code_offset==0);
            CHECK(units_equal(binding.entity.owner,binding.entity.owner_length,"Lcatalog/Child;"));
            CHECK(units_equal(binding.entity.name,binding.entity.name_length,"abstractMethod")&&units_equal(binding.entity.prototype,binding.entity.prototype_length,"()V"));
        }
    }
    CHECK(field_bindings==1&&method_bindings==1);
    CHECK(dmg_result_get_witness_count(result,0,&count)==DMG_OK&&count>=2);
    for(i=0;i<count;++i){
        uint32_t j,found_operator=0;
        CHECK(dmg_result_get_relation_witness(result,0,i,&proof,sizeof(proof))==DMG_OK);
        CHECK(dmg_result_get_witness(result,0,i,&leaf)==DMG_OK);
        CHECK(proof.witness.kind==DMG_WITNESS_METADATA&&proof.witness.matched==DMG_MATCH_TRUE);
        CHECK(proof.witness.node_id<query_info.node_count&&proof.operator_node<graph.operator_count&&proof.source_index==0);
        CHECK(leaf.node_id==proof.witness.node_id&&leaf.kind==proof.witness.kind&&leaf.matched==proof.witness.matched);
        if(proof.relation==DMG_FIELD_DEFS){CHECK(proof.local_index==2);++field_proofs;}
        else if(proof.relation==DMG_METHOD_DEFS){CHECK(proof.local_index==0);++method_proofs;}
        else CHECK(0);
        for(j=0;j<graph.operator_count;++j){
            CHECK(dmg_result_get_operator_profile(result,j,&profile,sizeof(profile))==DMG_OK);
            if(profile.node_id==proof.operator_node){found_operator=1;CHECK(profile.op==DMG_REL_SCAN&&profile.total_rows==(proof.relation==DMG_FIELD_DEFS?3u:1u));}
        }
        CHECK(found_operator);
    }
    CHECK(field_proofs>0&&method_proofs>0);
    for(i=0;i<graph.operator_count;++i){
        CHECK(dmg_result_get_operator_profile(result,i,&profile,sizeof(profile))==DMG_OK);
        CHECK(profile.node_id<5&&!(seen&(1u<<profile.node_id))&&profile.complete&&profile.unknown_rows==0);seen|=1u<<profile.node_id;
        if(profile.op==DMG_REL_SCAN){
            ++scans;CHECK(profile.visited_rows==profile.total_rows&&(profile.total_rows==1||profile.total_rows==3));
            CHECK(profile.output_rows==1);scanned+=profile.visited_rows;scan_output+=profile.output_rows;
        }else if(profile.op==DMG_REL_LABEL){++labels;CHECK(profile.input_rows==1&&profile.output_rows==1);}
        else{CHECK(profile.op==DMG_REL_GROUP_BY_OWNER&&profile.node_id==graph.root_node);++groups;CHECK(profile.input_rows==2&&profile.output_rows==1);}
    }
    CHECK(seen==31&&scans==2&&labels==2&&groups==1&&scanned==4&&scan_output==2);return 0;
}
static int result_sizes(const dmg_result* result){
    dmg_graph_info graph;dmg_binding_row binding;dmg_relation_witness witness;dmg_operator_profile profile;
    uint32_t i;for(i=0;i<2;++i){
        memset(&graph,0xa5,sizeof(graph));memset(&binding,0xa5,sizeof(binding));memset(&witness,0xa5,sizeof(witness));memset(&profile,0xa5,sizeof(profile));
        CHECK(dmg_result_get_graph_info(result,&graph,wrong_size(sizeof(graph),i))==DMG_INVALID_ARGUMENT&&unchanged(&graph,sizeof(graph)));
        CHECK(dmg_result_get_binding(result,0,0,&binding,wrong_size(sizeof(binding),i))==DMG_INVALID_ARGUMENT&&unchanged(&binding,sizeof(binding)));
        CHECK(dmg_result_get_relation_witness(result,0,0,&witness,wrong_size(sizeof(witness),i))==DMG_INVALID_ARGUMENT&&unchanged(&witness,sizeof(witness)));
        CHECK(dmg_result_get_operator_profile(result,0,&profile,wrong_size(sizeof(profile),i))==DMG_INVALID_ARGUMENT&&unchanged(&profile,sizeof(profile)));
    }
    memset(&binding,0xa5,sizeof(binding));memset(&witness,0xa5,sizeof(witness));memset(&profile,0xa5,sizeof(profile));
    CHECK(dmg_result_get_binding(result,0,UINT32_MAX,&binding,sizeof(binding))==DMG_INVALID_ARGUMENT&&unchanged(&binding,sizeof(binding)));
    CHECK(dmg_result_get_relation_witness(result,0,UINT32_MAX,&witness,sizeof(witness))==DMG_INVALID_ARGUMENT&&unchanged(&witness,sizeof(witness)));
    CHECK(dmg_result_get_operator_profile(result,UINT32_MAX,&profile,sizeof(profile))==DMG_INVALID_ARGUMENT&&unchanged(&profile,sizeof(profile)));return 0;
}
static int job_sizes(dmg_job* job){
    dmg_graph_info graph;dmg_operator_profile profile;dmg_relation_job_status status;uint32_t i;
    for(i=0;i<2;++i){
        memset(&graph,0xa5,sizeof(graph));memset(&profile,0xa5,sizeof(profile));memset(&status,0xa5,sizeof(status));
        CHECK(dmg_job_get_graph_info(job,&graph,wrong_size(sizeof(graph),i))==DMG_INVALID_ARGUMENT&&unchanged(&graph,sizeof(graph)));
        CHECK(dmg_job_get_operator_profile(job,0,&profile,wrong_size(sizeof(profile),i))==DMG_INVALID_ARGUMENT&&unchanged(&profile,sizeof(profile)));
        CHECK(dmg_job_get_relation_status(job,&status,wrong_size(sizeof(status),i))==DMG_INVALID_ARGUMENT&&unchanged(&status,sizeof(status)));
        CHECK(dmg_job_wait_relation(job,0,&status,wrong_size(sizeof(status),i))==DMG_INVALID_ARGUMENT&&unchanged(&status,sizeof(status)));
    }
    return 0;
}

int main(int argc,char** argv){
    dmg_engine* engine=NULL;dmg_snapshot* snapshot=NULL;dmg_query* query=NULL;dmg_result* result=NULL;
    dmg_job* job=NULL;dmg_batch* batch=NULL;dmg_batch* retained=NULL;
    dmg_error error={0};dmg_engine_stats initial,opened,after;dmg_relation_info info;dmg_entity_row row;
    dmg_graph_info graph;dmg_operator_profile profile;dmg_relation_job_status final;dmg_query_info query_info;dmg_result_info legacy_info;
    dmg_open_options open={sizeof(open),DMG_ABI_VERSION,DMG_MAX_SOURCE_BYTES,"c-relational","fixture",NULL};
    dmg_job_options options={sizeof(options),DMG_ABI_VERSION,1,1,0};
    FILE* file;long length;unsigned char* bytes;uint32_t i,rows,scan_count;uint64_t visited;char query_id[80];
    CHECK(argc==2);file=fopen(argv[1],"rb");CHECK(file!=NULL);CHECK(fseek(file,0,SEEK_END)==0);length=ftell(file);CHECK(length==804);rewind(file);
    bytes=(unsigned char*)malloc((size_t)length);CHECK(bytes!=NULL);CHECK(fread(bytes,1,(size_t)length,file)==(size_t)length);fclose(file);
    CHECK(bytes[380]==3&&bytes[619]==2&&bytes[620]==1&&bytes[621]==0&&bytes[622]==0x81&&bytes[623]==8&&bytes[624]==0);
    CHECK(dmg_engine_create(NULL,&engine,&error)==DMG_OK);CHECK(dmg_engine_get_stats(engine,&initial)==DMG_OK);
    CHECK(dmg_snapshot_open_copy_in(engine,bytes,(uint64_t)length,&open,&snapshot,&error)==DMG_OK);CHECK(dmg_engine_get_stats(engine,&opened)==DMG_OK);

    CHECK(compile_result(engine,snapshot,simple_query,&query,&result)==0);
    memset(&graph,0xa5,sizeof(graph));memset(&profile,0xa5,sizeof(profile));
    CHECK(dmg_result_get_graph_info(result,&graph,sizeof(graph))==DMG_UNSUPPORTED&&unchanged(&graph,sizeof(graph)));
    CHECK(dmg_result_get_operator_profile(result,0,&profile,sizeof(profile))==DMG_UNSUPPORTED&&unchanged(&profile,sizeof(profile)));
    CHECK(dmg_result_get_info(result,&legacy_info)==DMG_OK&&legacy_info.candidates_count==1);
    dmg_result_release(result);result=NULL;dmg_query_release(query);query=NULL;CHECK(baseline(engine,&opened)==0);

    CHECK(compile_result(engine,snapshot,group_query,&query,&result)==0);CHECK(check_group(result)==0&&result_sizes(result)==0&&legacy_result_rejected(result)==0);
    CHECK(dmg_result_get_relation_info(result,&info,sizeof(info))==DMG_OK&&info.execution_status==DMG_OK&&info.coverage==DMG_COVERAGE_COMPLETE&&info.decision==DMG_PROVEN_TRUE);
    CHECK(info.candidates_count==1&&info.visited_rows==4&&info.total_rows==4&&info.unknown_rows==0);
    dmg_result_release(result);result=NULL;dmg_query_release(query);query=NULL;CHECK(baseline(engine,&opened)==0);

    CHECK(compile_result(engine,snapshot,union_query,&query,&result)==0);CHECK(legacy_result_rejected(result)==0);
    CHECK(dmg_result_get_relation_info(result,&info,sizeof(info))==DMG_OK&&info.relation==DMG_METHOD_DEFS&&info.candidates_count==2&&info.coverage==DMG_COVERAGE_COMPLETE&&info.decision==DMG_NOT_APPLICABLE);
    for(i=0;i<2;++i){CHECK(dmg_result_get_entity(result,i,&row,sizeof(row))==DMG_OK);CHECK(row.source_index==0&&row.local_index==0&&row.record_offset==621&&row.access_flags==0x401);}
    dmg_result_release(result);result=NULL;
    CHECK(dmg_job_start(snapshot,query,&options,&job,&error)==DMG_OK);CHECK(legacy_job_rejected(job)==0&&job_sizes(job)==0);rows=0;
    for(;;){dmg_status next=dmg_job_next(job,5000,&batch,&error);if(next==DMG_END_OF_STREAM)break;
        CHECK(next==DMG_OK&&batch!=NULL&&legacy_result_rejected(batch)==0);
        CHECK(dmg_result_get_relation_info(batch,&info,sizeof(info))==DMG_OK&&info.candidates_count==1&&info.coverage==DMG_COVERAGE_PARTIAL);rows+=info.candidates_count;
        dmg_batch_release(batch);batch=NULL;
    }
    CHECK(rows==2&&dmg_job_wait_relation(job,5000,&final,sizeof(final))==DMG_OK&&final.terminal&&final.lifecycle==DMG_JOB_COMPLETED);
    CHECK(final.outcome.execution_status==DMG_OK&&final.outcome.candidates_count==2&&final.outcome.coverage==DMG_COVERAGE_COMPLETE);
    dmg_job_release(job);job=NULL;dmg_query_release(query);query=NULL;CHECK(baseline(engine,&opened)==0);

    CHECK(compile_result(engine,snapshot,unique_query,&query,&result)==0);
    CHECK(dmg_result_get_relation_info(result,&info,sizeof(info))==DMG_OK&&info.candidates_count==1&&info.decision==DMG_PROVEN_TRUE&&info.coverage==DMG_COVERAGE_COMPLETE);
    CHECK(dmg_result_get_graph_info(result,&graph,sizeof(graph))==DMG_OK&&graph.identity_count==1&&graph.unique_identity==DMG_IDENTITY_ENTITY);
    dmg_result_release(result);result=NULL;dmg_query_release(query);query=NULL;CHECK(baseline(engine,&opened)==0);
    CHECK(compile_result(engine,snapshot,tuple_query,&query,&result)==0);
    CHECK(dmg_result_get_relation_info(result,&info,sizeof(info))==DMG_OK&&info.candidates_count==2&&info.decision==DMG_PROVEN_FALSE&&info.reason==DMG_AMBIGUOUS);
    CHECK(dmg_result_get_graph_info(result,&graph,sizeof(graph))==DMG_OK&&graph.identity_count==2&&graph.unique_identity==DMG_IDENTITY_TUPLE);
    for(i=0;i<2;++i){dmg_binding_row binding;uint32_t count;
        CHECK(dmg_result_get_binding_count(result,i,&count)==DMG_OK&&count==1);
        CHECK(dmg_result_get_binding(result,i,0,&binding,sizeof(binding))==DMG_OK&&binding.label!=NULL&&strcmp(binding.label,i?"B":"A")==0);
        CHECK(binding.entity.relation==DMG_METHOD_DEFS&&binding.entity.source_index==0&&binding.entity.local_index==0&&binding.entity.record_offset==621);
    }
    dmg_result_release(result);result=NULL;dmg_query_release(query);query=NULL;CHECK(baseline(engine,&opened)==0);

    CHECK(compile_result(engine,snapshot,limited_query,&query,&result)==0);
    CHECK(dmg_result_get_relation_info(result,&info,sizeof(info))==DMG_OK&&info.execution_status==DMG_BUDGET_EXCEEDED&&info.reason==DMG_RESULT_LIMIT&&info.coverage==DMG_COVERAGE_PARTIAL&&info.candidates_count==1);
    CHECK(dmg_result_get_graph_info(result,&graph,sizeof(graph))==DMG_OK&&graph.operator_count==1);
    CHECK(dmg_result_get_operator_profile(result,0,&profile,sizeof(profile))==DMG_OK&&profile.op==DMG_REL_SCAN&&profile.total_rows==3&&profile.visited_rows==3&&profile.output_rows==3);
    dmg_result_release(result);result=NULL;
    CHECK(dmg_job_start(snapshot,query,&options,&job,&error)==DMG_OK);rows=0;
    for(;;){dmg_status next=dmg_job_next(job,5000,&batch,&error);if(next==DMG_END_OF_STREAM)break;
        CHECK(next==DMG_OK&&batch!=NULL);CHECK(dmg_result_get_relation_info(batch,&info,sizeof(info))==DMG_OK&&info.coverage==DMG_COVERAGE_PARTIAL);rows+=info.candidates_count;dmg_batch_release(batch);batch=NULL;
    }
    CHECK(rows==1&&dmg_job_wait_relation(job,5000,&final,sizeof(final))==DMG_OK&&final.terminal&&final.lifecycle==DMG_JOB_FAILED);
    CHECK(final.outcome.execution_status==DMG_BUDGET_EXCEEDED&&final.outcome.reason==DMG_RESULT_LIMIT&&final.outcome.coverage==DMG_COVERAGE_PARTIAL&&final.outcome.candidates_count==1);
    dmg_job_release(job);job=NULL;dmg_query_release(query);query=NULL;CHECK(baseline(engine,&opened)==0);

    CHECK(dmg_query_compile_json(engine,(const uint8_t*)intermediate_query,strlen(intermediate_query),&query,&error)==DMG_OK);
    CHECK(dmg_query_execute(snapshot,query,&result,&error)==DMG_BUDGET_EXCEEDED&&result==NULL);
    CHECK(dmg_job_start(snapshot,query,&options,&job,&error)==DMG_OK);
    CHECK(dmg_job_next(job,5000,&batch,&error)==DMG_END_OF_STREAM&&batch==NULL);
    CHECK(dmg_job_wait_relation(job,5000,&final,sizeof(final))==DMG_OK&&final.terminal&&final.lifecycle==DMG_JOB_FAILED);
    CHECK(final.outcome.execution_status==DMG_BUDGET_EXCEEDED&&final.outcome.coverage==DMG_COVERAGE_PARTIAL&&final.outcome.candidates_count==0);
    dmg_job_release(job);job=NULL;dmg_query_release(query);query=NULL;CHECK(baseline(engine,&opened)==0);

    CHECK(dmg_query_compile_json(engine,(const uint8_t*)cancel_query,strlen(cancel_query),&query,&error)==DMG_OK);
    CHECK(dmg_job_start(snapshot,query,&options,&job,&error)==DMG_OK);
    CHECK(dmg_job_next(job,5000,&batch,&error)==DMG_OK&&batch!=NULL);dmg_batch_release(batch);batch=NULL;rows=1;
    /* Three rows and a one-batch queue prevent completion without another next(). */
    dmg_job_cancel(job);CHECK(dmg_job_wait_relation(job,5000,&final,sizeof(final))==DMG_OK&&final.terminal&&final.lifecycle==DMG_JOB_CANCELLED);
    CHECK(final.outcome.execution_status==DMG_CANCELLED&&final.outcome.coverage==DMG_COVERAGE_PARTIAL);
    for(;;){dmg_status next=dmg_job_next(job,5000,&batch,&error);if(next==DMG_END_OF_STREAM)break;
        CHECK(next==DMG_OK&&batch!=NULL);CHECK(dmg_result_get_relation_info(batch,&info,sizeof(info))==DMG_OK);rows+=info.candidates_count;dmg_batch_release(batch);batch=NULL;
    }
    CHECK(rows>=1&&rows<=2&&rows==final.outcome.candidates_count);
    dmg_job_release(job);job=NULL;dmg_query_release(query);query=NULL;CHECK(baseline(engine,&opened)==0);

    CHECK(dmg_query_compile_json(engine,(const uint8_t*)group_query,strlen(group_query),&query,&error)==DMG_OK);
    CHECK(dmg_job_start(snapshot,query,&options,&job,&error)==DMG_OK);CHECK(legacy_job_rejected(job)==0&&job_sizes(job)==0);
    CHECK(dmg_job_next(job,5000,&retained,&error)==DMG_OK&&retained!=NULL&&check_group(retained)==0);
    CHECK(dmg_result_get_relation_info(retained,&info,sizeof(info))==DMG_OK&&info.coverage==DMG_COVERAGE_PARTIAL);
    CHECK(dmg_job_next(job,5000,&batch,&error)==DMG_END_OF_STREAM&&batch==NULL);
    CHECK(dmg_job_wait_relation(job,5000,&final,sizeof(final))==DMG_OK&&final.terminal&&final.lifecycle==DMG_JOB_COMPLETED);
    CHECK(final.outcome.execution_status==DMG_OK&&final.outcome.decision==DMG_PROVEN_TRUE&&final.outcome.coverage==DMG_COVERAGE_COMPLETE&&final.outcome.candidates_count==1);
    CHECK(final.outcome.visited_rows==4&&final.outcome.total_rows==4);
    CHECK(dmg_job_get_graph_info(job,&graph,sizeof(graph))==DMG_OK&&graph.operator_count==5&&graph.identity_count==1);
    visited=0;scan_count=0;for(i=0;i<graph.operator_count;++i){CHECK(dmg_job_get_operator_profile(job,i,&profile,sizeof(profile))==DMG_OK&&profile.complete);
        if(profile.op==DMG_REL_SCAN){++scan_count;visited+=profile.visited_rows;CHECK(profile.visited_rows==profile.total_rows&&profile.output_rows==1);}
    }
    CHECK(scan_count==2&&visited==4);
    dmg_job_release(job);job=NULL;dmg_query_release(query);query=NULL;dmg_snapshot_release(snapshot);snapshot=NULL;
    CHECK(dmg_engine_get_stats(engine,&after)==DMG_OK&&after.result_bytes>initial.result_bytes&&after.query_bytes>initial.query_bytes&&after.source_bytes>initial.source_bytes);
    CHECK(check_group(retained)==0);dmg_batch_release(retained);retained=NULL;CHECK(baseline(engine,&initial)==0);

    CHECK(dmg_snapshot_open_copy_in(engine,bytes,(uint64_t)length,&open,&snapshot,&error)==DMG_OK);free(bytes);
    CHECK(dmg_query_compile_json(engine,(const uint8_t*)group_query,strlen(group_query),&query,&error)==DMG_OK);
    CHECK(dmg_query_get_info(query,&query_info)==DMG_OK&&strlen(query_info.query_id)<sizeof(query_id));strcpy(query_id,query_info.query_id);
    CHECK(dmg_job_start(snapshot,query,&options,&job,&error)==DMG_OK);
    CHECK(dmg_job_next(job,5000,&retained,&error)==DMG_OK&&retained!=NULL);
    CHECK(dmg_job_wait_relation(job,5000,&final,sizeof(final))==DMG_OK&&final.outcome.decision==DMG_PROVEN_TRUE);
    dmg_snapshot_release(snapshot);dmg_query_release(query);dmg_job_release(job);dmg_engine_release(engine);
    CHECK(check_group(retained)==0&&result_sizes(retained)==0);
    CHECK(dmg_result_get_query_info(retained,&query_info)==DMG_OK&&strcmp(query_info.query_id,query_id)==0);
    dmg_batch_release(retained);
    puts("PASS relational C ABI: mixed owner groups and bound evidence, bag/identity semantics, sized outputs, graph profiles, legacy rejection, failure terminal states, cancellation, retained Batch lifetime and PMR reclamation");return 0;
}
