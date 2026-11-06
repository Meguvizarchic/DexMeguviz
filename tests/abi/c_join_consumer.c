#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do{if(!(x)){fprintf(stderr,"Join C ABI check %d: %s\n",__LINE__,#x);return 1;}}while(0)
#define SCAN "{\"op\":\"scan\",\"relation\":\"method_defs\"}"
#define L1 "{\"op\":\"label\",\"label\":\"L1\",\"input\":" SCAN "}"
#define L2 "{\"op\":\"label\",\"label\":\"L2\",\"input\":" SCAN "}"
#define R1 "{\"op\":\"label\",\"label\":\"R1\",\"input\":" SCAN "}"
#define R2 "{\"op\":\"label\",\"label\":\"R2\",\"input\":" SCAN "}"
#define LEFT_UNION "{\"op\":\"union\",\"semantics\":\"bag\",\"inputs\":[" L1 "," L2 "]}"
#define RIGHT_UNION "{\"op\":\"union\",\"semantics\":\"bag\",\"inputs\":[" R1 "," R2 "]}"
#define JOIN "{\"op\":\"join\",\"on\":\"same_entity\",\"left\":" LEFT_UNION ",\"right\":" RIGHT_UNION "}"
#define SIMPLE_JOIN "{\"op\":\"join\",\"on\":\"same_entity\",\"left\":" SCAN ",\"right\":" SCAN "}"
#define NESTED_JOIN "{\"op\":\"join\",\"on\":\"same_entity\",\"left\":" SIMPLE_JOIN ",\"right\":" SCAN "}"
#define LABELED_METHOD "{\"op\":\"label\",\"label\":\"main\",\"input\":" SCAN "}"
#define GROUP "{\"op\":\"group_by_owner\",\"inputs\":[" \
    "{\"op\":\"label\",\"label\":\"field\",\"input\":{\"op\":\"scan\",\"relation\":\"field_defs\",\"where\":{\"owner\":\"Lcatalog/Child;\",\"name\":\"shared\"}}}," \
    "{\"op\":\"label\",\"label\":\"method\",\"input\":" SCAN "}],\"min\":2,\"max\":2,\"required_roles\":[\"field\",\"method\"],\"role_policy\":\"distinct\"}"
#define SEMI "{\"op\":\"semi_join\",\"on\":\"local_owner\",\"left\":" LABELED_METHOD ",\"right\":" GROUP "}"
static const char join_query[]="{\"schema_version\":1,\"relation\":" JOIN "}";
static const char set_query[]="{\"schema_version\":1,\"relation\":{\"op\":\"union\",\"semantics\":\"bag\",\"inputs\":[" JOIN "," JOIN "]},\"semantics\":\"set\"}";
static const char semi_query[]="{\"schema_version\":1,\"relation\":" SEMI ",\"intent\":\"unique\",\"unique_by\":\"tuple\"}";
static const char nested_query[]="{\"schema_version\":1,\"relation\":" NESTED_JOIN ",\"intent\":\"unique\",\"unique_by\":\"tuple\"}";
static const char budget_query[]="{\"schema_version\":1,\"relation\":" JOIN ",\"max_intermediate_rows\":1}";
static const char incomplete_group_query[]=
    "{\"schema_version\":1,\"relation\":{\"op\":\"group_by_owner\",\"max\":1,\"inputs\":["
    "{\"op\":\"join\",\"on\":\"symbol\",\"left\":{\"op\":\"scan\",\"relation\":\"field_defs\","
    "\"where\":{\"owner\":\"Lcatalog/Base;\"},\"scope\":{\"slots\":[\"fixture\"]}},"
    "\"right\":{\"op\":\"scan\",\"relation\":\"field_defs\",\"where\":{\"flags_contains\":8}}}]},\"intent\":\"exists\"}";

static int unchanged(const void* p,size_t size){const unsigned char* b=(const unsigned char*)p;size_t i;for(i=0;i<size;++i)if(b[i]!=0xa5)return 0;return 1;}
static int same_live_bytes(const dmg_engine_stats* a,const dmg_engine_stats* b){
    return a->owned_bytes==b->owned_bytes&&a->source_bytes==b->source_bytes&&a->fact_bytes==b->fact_bytes&&
        a->scratch_bytes==b->scratch_bytes&&a->query_bytes==b->query_bytes&&a->result_bytes==b->result_bytes&&
        a->control_bytes==b->control_bytes&&a->borrowed_bytes==b->borrowed_bytes&&a->active_jobs==b->active_jobs;
}
static int baseline(dmg_engine* engine,const dmg_engine_stats* expected){dmg_engine_stats current;CHECK(dmg_engine_get_stats(engine,&current)==DMG_OK);CHECK(same_live_bytes(&current,expected));return 0;}
static int compile_query(dmg_engine* engine,const char* text,dmg_query** out){dmg_error error={0};CHECK(dmg_query_compile_json(engine,(const uint8_t*)text,strlen(text),out,&error)==DMG_OK);return 0;}
static int query_result(dmg_engine* engine,dmg_snapshot* snapshot,const char* text,dmg_query** query,dmg_result** result){
    dmg_error error={0};CHECK(compile_query(engine,text,query)==0);CHECK(dmg_query_execute(snapshot,*query,result,&error)==DMG_OK);return 0;
}
static int legacy_rejected(const dmg_result* result){
    dmg_result_info info;dmg_method_row row;memset(&info,0xa5,sizeof(info));memset(&row,0xa5,sizeof(row));
    CHECK(dmg_result_get_info(result,&info)==DMG_UNSUPPORTED&&unchanged(&info,sizeof(info)));
    CHECK(dmg_result_get_method(result,0,&row)==DMG_UNSUPPORTED&&unchanged(&row,sizeof(row)));return 0;
}
static int sized_getters(const dmg_result* result,int proof_available){
    uint32_t i;dmg_binding_path path;dmg_proof_binding_row proof;dmg_relation_link link;
    for(i=0;i<2;++i){
        const uint32_t p=(uint32_t)(i?sizeof(path)+1:sizeof(path)-1),q=(uint32_t)(i?sizeof(proof)+1:sizeof(proof)-1),l=(uint32_t)(i?sizeof(link)+1:sizeof(link)-1);
        memset(&path,0xa5,sizeof(path));memset(&proof,0xa5,sizeof(proof));memset(&link,0xa5,sizeof(link));
        CHECK(dmg_result_get_binding_path(result,0,0,&path,p)==DMG_INVALID_ARGUMENT&&unchanged(&path,sizeof(path)));
        CHECK(dmg_result_get_link(result,0,0,&link,l)==DMG_INVALID_ARGUMENT&&unchanged(&link,sizeof(link)));
        if(proof_available){
            CHECK(dmg_result_get_proof_binding(result,0,0,&proof,q)==DMG_INVALID_ARGUMENT&&unchanged(&proof,sizeof(proof)));
            CHECK(dmg_result_get_proof_binding_path(result,0,0,&path,p)==DMG_INVALID_ARGUMENT&&unchanged(&path,sizeof(path)));
        }
    }
    memset(&path,0xa5,sizeof(path));memset(&proof,0xa5,sizeof(proof));memset(&link,0xa5,sizeof(link));
    CHECK(dmg_result_get_binding_path(result,0,UINT32_MAX,&path,sizeof(path))==DMG_INVALID_ARGUMENT&&unchanged(&path,sizeof(path)));
    CHECK(dmg_result_get_link(result,0,UINT32_MAX,&link,sizeof(link))==DMG_INVALID_ARGUMENT&&unchanged(&link,sizeof(link)));
    CHECK(dmg_result_get_proof_binding(result,0,UINT32_MAX,&proof,sizeof(proof))==DMG_INVALID_ARGUMENT&&unchanged(&proof,sizeof(proof)));
    CHECK(dmg_result_get_proof_binding_path(result,0,UINT32_MAX,&path,sizeof(path))==DMG_INVALID_ARGUMENT&&unchanged(&path,sizeof(path)));
    return 0;
}
static int check_link(const dmg_relation_link* link,uint32_t left_relation,uint32_t left_local,uint32_t right_relation,uint32_t right_local,uint32_t key){
    CHECK(link->key==key&&link->left_source==0&&link->left_relation==left_relation&&link->left_local==left_local);
    CHECK(link->right_source==0&&link->right_relation==right_relation&&link->right_local==right_local);return 0;
}
static int check_join(const dmg_result* result){
    dmg_relation_info info;dmg_graph_info graph;uint32_t i,j,seen=0;
    CHECK(dmg_result_get_relation_info(result,&info,sizeof(info))==DMG_OK&&info.candidates_count==4&&info.coverage==DMG_COVERAGE_COMPLETE);
    CHECK(dmg_result_get_graph_info(result,&graph,sizeof(graph))==DMG_OK);
    for(i=0;i<4;++i){
        uint32_t n=0,left_bare=0,right_bare=0,left_label=0,right_label=0,variant=0;dmg_relation_link link;
        CHECK(dmg_result_get_binding_count(result,i,&n)==DMG_OK&&n==4);
        for(j=0;j<n;++j){dmg_binding_row b;dmg_binding_path path;
            CHECK(dmg_result_get_binding(result,i,j,&b,sizeof(b))==DMG_OK&&b.entity.relation==DMG_METHOD_DEFS&&b.entity.local_index==0&&b.entity.source_index==0&&b.entity.record_offset==621);
            CHECK(dmg_result_get_binding_path(result,i,j,&path,sizeof(path))==DMG_OK&&path.length==1&&path.sides!=NULL);
            if(!b.label){if(path.sides[0]==DMG_PATH_LEFT)++left_bare;else if(path.sides[0]==DMG_PATH_RIGHT)++right_bare;else CHECK(0);}
            else if(strcmp(b.label,"L1")==0||strcmp(b.label,"L2")==0){CHECK(path.sides[0]==DMG_PATH_LEFT);++left_label;if(b.label[1]=='2')variant|=2;}
            else if(strcmp(b.label,"R1")==0||strcmp(b.label,"R2")==0){CHECK(path.sides[0]==DMG_PATH_RIGHT);++right_label;if(b.label[1]=='2')variant|=1;}
            else CHECK(0);
        }
        CHECK(left_bare==1&&right_bare==1&&left_label==1&&right_label==1&&!(seen&(1u<<variant)));seen|=1u<<variant;
        CHECK(dmg_result_get_link_count(result,i,&n)==DMG_OK&&n==1&&dmg_result_get_link(result,i,0,&link,sizeof(link))==DMG_OK);
        CHECK(check_link(&link,DMG_METHOD_DEFS,0,DMG_METHOD_DEFS,0,DMG_JOIN_SAME_ENTITY)==0);
        CHECK(dmg_result_get_proof_binding_count(result,i,&n)==DMG_OK&&n==0);
    }
    CHECK(seen==15);CHECK(sized_getters(result,0)==0);CHECK(legacy_rejected(result)==0);return 0;
}
static int check_nested(const dmg_result* result){
    uint32_t count=0,i,seen=0;dmg_relation_info info;dmg_relation_link link;
    CHECK(dmg_result_get_relation_info(result,&info,sizeof(info))==DMG_OK&&info.candidates_count==1);
    CHECK(dmg_result_get_binding_count(result,0,&count)==DMG_OK&&count==4);
    for(i=0;i<count;++i){dmg_binding_row row;dmg_binding_path path;uint32_t bit;
        CHECK(dmg_result_get_binding(result,0,i,&row,sizeof(row))==DMG_OK&&!row.label&&row.entity.relation==DMG_METHOD_DEFS&&row.entity.local_index==0);
        CHECK(dmg_result_get_binding_path(result,0,i,&path,sizeof(path))==DMG_OK&&path.sides!=NULL);
        if(path.length==1&&path.sides[0]==DMG_PATH_RIGHT)bit=1;
        else if(path.length==1&&path.sides[0]==DMG_PATH_LEFT)bit=8;
        else if(path.length==2&&path.sides[0]==DMG_PATH_LEFT&&path.sides[1]==DMG_PATH_LEFT)bit=2;
        else if(path.length==2&&path.sides[0]==DMG_PATH_LEFT&&path.sides[1]==DMG_PATH_RIGHT)bit=4;
        else {CHECK(0);return 1;}CHECK(!(seen&bit));seen|=bit;
    }
    CHECK(seen==15&&dmg_result_get_link_count(result,0,&count)==DMG_OK&&count==2);
    for(i=0;i<count;++i){CHECK(dmg_result_get_link(result,0,i,&link,sizeof(link))==DMG_OK);CHECK(check_link(&link,DMG_METHOD_DEFS,0,DMG_METHOD_DEFS,0,DMG_JOIN_SAME_ENTITY)==0);}
    return 0;
}
static int check_semi(const dmg_result* result,int is_batch){
    uint32_t i,n,field=0,method=0;dmg_relation_info info;dmg_binding_row left;dmg_binding_path path;dmg_relation_link link;
    CHECK(dmg_result_get_relation_info(result,&info,sizeof(info))==DMG_OK&&info.candidates_count==1&&info.decision==(is_batch?DMG_NOT_APPLICABLE:DMG_PROVEN_TRUE));
    CHECK(dmg_result_get_binding_count(result,0,&n)==DMG_OK&&n==1&&dmg_result_get_binding(result,0,0,&left,sizeof(left))==DMG_OK);
    CHECK(left.label&&strcmp(left.label,"main")==0&&left.entity.relation==DMG_METHOD_DEFS&&left.entity.local_index==0);
    CHECK(dmg_result_get_binding_path(result,0,0,&path,sizeof(path))==DMG_OK&&path.length==0);
    CHECK(dmg_result_get_link_count(result,0,&n)==DMG_OK&&n==1&&dmg_result_get_link(result,0,0,&link,sizeof(link))==DMG_OK);
    CHECK(check_link(&link,DMG_METHOD_DEFS,0,DMG_CLASS_DEFS,4,DMG_JOIN_LOCAL_OWNER)==0);
    CHECK(dmg_result_get_proof_binding_count(result,0,&n)==DMG_OK&&n>=5);
    for(i=0;i<n;++i){dmg_proof_binding_row proof;
        CHECK(dmg_result_get_proof_binding(result,0,i,&proof,sizeof(proof))==DMG_OK);
        CHECK(proof.operator_node==link.node_id&&proof.binding.entity.source_index==0);
        CHECK(dmg_result_get_proof_binding_path(result,0,i,&path,sizeof(path))==DMG_OK&&path.length==1&&path.sides&&path.sides[0]==DMG_PATH_RIGHT);
        if(proof.binding.label&&strcmp(proof.binding.label,"field")==0){++field;CHECK(proof.binding.entity.relation==DMG_FIELD_DEFS&&proof.binding.entity.local_index==2&&proof.binding.entity.record_offset==619);}
        if(proof.binding.label&&strcmp(proof.binding.label,"method")==0){++method;CHECK(proof.binding.entity.relation==DMG_METHOD_DEFS&&proof.binding.entity.local_index==0&&proof.binding.entity.record_offset==621);}
    }
    CHECK(field==1&&method==1&&sized_getters(result,1)==0);return 0;
}
static int retained_job(dmg_engine* engine,dmg_snapshot* snapshot,const char* text,dmg_batch** retained){
    dmg_query* query=NULL;dmg_job* job=NULL;dmg_batch* next=NULL;dmg_error error={0};dmg_relation_job_status status;
    dmg_job_options options={sizeof(options),DMG_ABI_VERSION,1,1,0};dmg_job_status old;
    CHECK(compile_query(engine,text,&query)==0&&dmg_job_start(snapshot,query,&options,&job,&error)==DMG_OK);
    memset(&old,0xa5,sizeof(old));CHECK(dmg_job_get_status(job,&old)==DMG_UNSUPPORTED&&unchanged(&old,sizeof(old)));
    CHECK(dmg_job_next(job,5000,retained,&error)==DMG_OK&&*retained!=NULL);
    CHECK(dmg_job_next(job,5000,&next,&error)==DMG_END_OF_STREAM&&next==NULL);
    CHECK(dmg_job_wait_relation(job,5000,&status,sizeof(status))==DMG_OK&&status.terminal&&status.lifecycle==DMG_JOB_COMPLETED&&status.outcome.execution_status==DMG_OK);
    dmg_query_release(query);dmg_job_release(job);return 0;
}
int main(int argc,char** argv){
    FILE* f;long length;unsigned char* bytes;dmg_engine* engine=NULL;dmg_snapshot* snapshot=NULL;dmg_query* query=NULL;dmg_result* result=NULL;dmg_job* job=NULL;dmg_batch *batch=NULL,*semi=NULL,*nested=NULL;
    dmg_error error={0};dmg_engine_stats initial,opened;dmg_graph_info graph;dmg_relation_job_status status;
    dmg_open_options open={sizeof(open),DMG_ABI_VERSION,DMG_MAX_SOURCE_BYTES,"c-join","fixture",NULL};dmg_job_options options={sizeof(options),DMG_ABI_VERSION,1,1,0};
    CHECK(argc==2);f=fopen(argv[1],"rb");CHECK(f!=NULL&&fseek(f,0,SEEK_END)==0);length=ftell(f);CHECK(length==804);rewind(f);
    bytes=(unsigned char*)malloc((size_t)length);CHECK(bytes&&fread(bytes,1,(size_t)length,f)==(size_t)length);fclose(f);
    CHECK(dmg_engine_create(NULL,&engine,&error)==DMG_OK&&dmg_engine_get_stats(engine,&initial)==DMG_OK);
    CHECK(dmg_snapshot_open_copy_in(engine,bytes,(uint64_t)length,&open,&snapshot,&error)==DMG_OK&&dmg_engine_get_stats(engine,&opened)==DMG_OK);
    CHECK(query_result(engine,snapshot,join_query,&query,&result)==0&&check_join(result)==0);
    dmg_result_release(result);result=NULL;dmg_query_release(query);query=NULL;CHECK(baseline(engine,&opened)==0);
    CHECK(query_result(engine,snapshot,set_query,&query,&result)==0&&check_join(result)==0);
    CHECK(dmg_result_get_graph_info(result,&graph,sizeof(graph))==DMG_OK&&graph.identity_count==1);
    {uint32_t i,join_nodes=0,first=UINT32_MAX;dmg_operator_profile op;
        for(i=0;i<graph.operator_count;++i){CHECK(dmg_result_get_operator_profile(result,i,&op,sizeof(op))==DMG_OK);
            if(op.op==DMG_REL_JOIN){if(first==UINT32_MAX)first=op.node_id;else CHECK(first!=op.node_id);++join_nodes;}}
        CHECK(join_nodes==2);
    }
    dmg_result_release(result);result=NULL;dmg_query_release(query);query=NULL;CHECK(baseline(engine,&opened)==0);
    CHECK(query_result(engine,snapshot,semi_query,&query,&result)==0&&check_semi(result,0)==0);
    dmg_result_release(result);result=NULL;dmg_query_release(query);query=NULL;CHECK(baseline(engine,&opened)==0);
    CHECK(query_result(engine,snapshot,nested_query,&query,&result)==0&&check_nested(result)==0);
    dmg_result_release(result);result=NULL;dmg_query_release(query);query=NULL;CHECK(baseline(engine,&opened)==0);
    CHECK(compile_query(engine,budget_query,&query)==0);
    CHECK(dmg_query_execute(snapshot,query,&result,&error)==DMG_BUDGET_EXCEEDED&&result==NULL);
    CHECK(dmg_job_start(snapshot,query,&options,&job,&error)==DMG_OK);
    CHECK(dmg_job_next(job,5000,&batch,&error)==DMG_END_OF_STREAM&&batch==NULL);
    CHECK(dmg_job_wait_relation(job,5000,&status,sizeof(status))==DMG_OK&&status.terminal&&status.lifecycle==DMG_JOB_FAILED&&status.outcome.execution_status==DMG_BUDGET_EXCEEDED&&status.outcome.coverage==DMG_COVERAGE_PARTIAL);
    dmg_job_release(job);job=NULL;dmg_query_release(query);query=NULL;CHECK(baseline(engine,&opened)==0);
    {
        dmg_snapshot* incomplete=NULL;dmg_relation_info outcome;dmg_snapshot_overview overview;dmg_query_profile profile;
        dmg_source_spec source={sizeof(source),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,bytes,(uint64_t)length,"fixture","base",NULL};
        dmg_source_set_options source_options={sizeof(source_options),DMG_ABI_VERSION,"c-join-incomplete",0,4,DMG_MAX_SOURCE_BYTES};
        CHECK(dmg_snapshot_open_sources(engine,&source,1,&source_options,&incomplete,&error)==DMG_OK);
        CHECK(dmg_snapshot_get_overview(incomplete,&overview)==DMG_OK&&overview.scope_complete==0&&overview.source_count==1);
        CHECK(query_result(engine,incomplete,incomplete_group_query,&query,&result)==0);
        CHECK(dmg_result_get_relation_info(result,&outcome,sizeof(outcome))==DMG_OK&&outcome.execution_status==DMG_OK);
        CHECK(outcome.candidates_count==0&&outcome.coverage==DMG_COVERAGE_PARTIAL&&outcome.decision==DMG_UNDETERMINED);
        CHECK(outcome.reason==DMG_SOURCE_SCOPE_INCOMPLETE&&outcome.unknown_rows==1);
        CHECK(dmg_result_get_profile(result,&profile)==DMG_OK&&profile.scope_complete==0);
        dmg_result_release(result);result=NULL;
        CHECK(dmg_job_start(incomplete,query,&options,&job,&error)==DMG_OK);
        CHECK(dmg_job_next(job,5000,&batch,&error)==DMG_END_OF_STREAM&&batch==NULL);
        CHECK(dmg_job_wait_relation(job,5000,&status,sizeof(status))==DMG_OK&&status.terminal&&status.lifecycle==DMG_JOB_COMPLETED);
        CHECK(status.outcome.execution_status==DMG_OK&&status.outcome.candidates_count==0&&status.outcome.coverage==DMG_COVERAGE_PARTIAL);
        CHECK(status.outcome.decision==DMG_UNDETERMINED&&status.outcome.reason==DMG_SOURCE_SCOPE_INCOMPLETE&&status.outcome.unknown_rows==1);
        dmg_job_release(job);job=NULL;dmg_query_release(query);query=NULL;dmg_snapshot_release(incomplete);
        CHECK(baseline(engine,&opened)==0);
    }
    CHECK(retained_job(engine,snapshot,semi_query,&semi)==0&&retained_job(engine,snapshot,nested_query,&nested)==0);
    dmg_snapshot_release(snapshot);snapshot=NULL;CHECK(check_semi(semi,1)==0&&check_nested(nested)==0);
    dmg_batch_release(semi);semi=NULL;dmg_batch_release(nested);nested=NULL;CHECK(baseline(engine,&initial)==0);
    CHECK(dmg_snapshot_open_copy_in(engine,bytes,(uint64_t)length,&open,&snapshot,&error)==DMG_OK);free(bytes);
    CHECK(retained_job(engine,snapshot,semi_query,&semi)==0&&retained_job(engine,snapshot,nested_query,&nested)==0);
    dmg_snapshot_release(snapshot);dmg_engine_release(engine);
    CHECK(check_semi(semi,1)==0&&check_nested(nested)==0);
    dmg_batch_release(semi);dmg_batch_release(nested);
    puts("PASS Join C ABI: four tuples, semijoin proofs, incomplete-scope group maximum, sized outputs, EOF status, retained batches and resource reclamation");
    return 0;
}
