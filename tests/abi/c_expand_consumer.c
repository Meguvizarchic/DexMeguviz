#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"expand C check %d: %s\n",__LINE__,#x); return 1; } } while (0)
#define SEED_SCAN "{\"op\":\"scan\",\"relation\":\"method_defs\",\"scope\":{\"slots\":[\"a\"]}}"
#define SEED_SEMI "{\"op\":\"semi_join\",\"on\":\"same_entity\",\"left\":" SEED_SCAN ",\"right\":" SEED_SCAN "}"
#define SEED "{\"op\":\"label\",\"label\":\"seed\",\"input\":" SEED_SEMI "}"
#define EXPAND_PATHS "{\"op\":\"bounded_expand\",\"input\":" SEED ",\"min_depth\":2,\"max_depth\":2,\"output\":\"paths\",\"walk_where\":true,\"emit_where\":true}"
#define EXPAND_ENDPOINTS "{\"op\":\"bounded_expand\",\"input\":" SEED ",\"min_depth\":2,\"max_depth\":2,\"output\":\"endpoints\",\"walk_where\":true,\"emit_where\":true}"
#define EXPAND_ONE "{\"op\":\"bounded_expand\",\"input\":" SEED ",\"min_depth\":1,\"max_depth\":1}"
static const char paths_query[]="{\"schema_version\":1,\"relation\":" EXPAND_PATHS "}";
static const char endpoints_query[]="{\"schema_version\":1,\"relation\":" EXPAND_ENDPOINTS "}";
static const char cap_query[]="{\"schema_version\":1,\"relation\":" EXPAND_PATHS ",\"max_results\":1}";
static const char budget_query[]="{\"schema_version\":1,\"relation\":{\"op\":\"bounded_expand\",\"input\":" SEED ",\"min_depth\":2,\"max_depth\":2,\"max_paths\":1}}";
static const char frontier_query[]="{\"schema_version\":1,\"relation\":" EXPAND_ONE ",\"intent\":\"exists\"}";

static int unchanged(const void* p,size_t n){const unsigned char* b=(const unsigned char*)p;size_t i;for(i=0;i<n;++i)if(b[i]!=0xa5)return 0;return 1;}
static int units(const uint16_t* p,uint64_t n,const char* ascii){size_t i,z=strlen(ascii);if(n!=z||(!p&&n))return 0;for(i=0;i<z;++i)if(p[i]!=(unsigned char)ascii[i])return 0;return 1;}
static int has_token(const char* list,const char* word){size_t n=strlen(word);const char* p=list;if(!p)return 0;while(*p){const char* e=strchr(p,';');size_t size=e?(size_t)(e-p):strlen(p);if(size==n&&!memcmp(p,word,n))return 1;if(!e)break;p=e+1;}return 0;}
static int compile_query(dmg_engine* engine,const char* text,dmg_query** out){dmg_error error={0};dmg_status status=dmg_query_compile_json(engine,(const uint8_t*)text,strlen(text),out,&error);if(status!=DMG_OK)fprintf(stderr,"compile error %u %s\n",status,error.message);CHECK(status==DMG_OK&&*out);return 0;}
static int open_sources(dmg_engine* engine,const char* directory,unsigned count,unsigned complete,dmg_snapshot** out){
 static const char* names[]={"amb-a.dex","amb-b1.dex","amb-b2.dex","amb-c1.dex","amb-c2.dex"};
 static const char* slots[]={"a","b1","b2","c1","c2"};
 dmg_source_spec specs[5];unsigned char* buffers[5]={0};dmg_source_set_options options={sizeof(options),DMG_ABI_VERSION,"c-expand",complete,16,16u<<20};
 dmg_error error={0};unsigned i;dmg_status status;
 CHECK(count<=5);
 for(i=0;i<count;++i){char path[2048];FILE* file;long size;int n=snprintf(path,sizeof(path),"%s/%s",directory,names[i]);CHECK(n>0&&(size_t)n<sizeof(path));file=fopen(path,"rb");CHECK(file&&fseek(file,0,SEEK_END)==0);size=ftell(file);CHECK(size>0);rewind(file);buffers[i]=(unsigned char*)malloc((size_t)size);CHECK(buffers[i]&&fread(buffers[i],1,(size_t)size,file)==(size_t)size);fclose(file);
  specs[i]=(dmg_source_spec){sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,buffers[i],(uint64_t)size,slots[i],"source",NULL};}
 status=dmg_snapshot_open_sources(engine,specs,count,&options,out,&error);for(i=0;i<count;++i)free(buffers[i]);if(status!=DMG_OK)fprintf(stderr,"open error %u %s\n",status,error.message);CHECK(status==DMG_OK&&*out);return 0;
}
static int legacy_result(const dmg_result* result){
 dmg_result_info info;dmg_relation_info old;dmg_relation_info_v2 v2;dmg_entity_row entity;dmg_value_row_v2 value;dmg_graph_info graph;dmg_method_row method;dmg_source_info origin;dmg_query_profile profile;dmg_witness witness;dmg_binding_row binding;dmg_binding_row_v2 binding_v2;dmg_binding_path bpath;dmg_proof_binding_row proof;dmg_proof_binding_row_v2 proof_v2;dmg_relation_link link;dmg_relation_link_v2 link_v2;dmg_relation_witness rwitness;dmg_relation_witness_v2 rwitness_v2;dmg_operator_profile op;dmg_operator_profile_v2 op_v2;uint32_t count=0xa5a5a5a5;
 memset(&info,0xa5,sizeof(info));memset(&old,0xa5,sizeof(old));memset(&v2,0xa5,sizeof(v2));memset(&entity,0xa5,sizeof(entity));memset(&value,0xa5,sizeof(value));memset(&graph,0xa5,sizeof(graph));memset(&method,0xa5,sizeof(method));memset(&origin,0xa5,sizeof(origin));memset(&profile,0xa5,sizeof(profile));memset(&witness,0xa5,sizeof(witness));memset(&binding,0xa5,sizeof(binding));memset(&binding_v2,0xa5,sizeof(binding_v2));memset(&bpath,0xa5,sizeof(bpath));memset(&proof,0xa5,sizeof(proof));memset(&proof_v2,0xa5,sizeof(proof_v2));memset(&link,0xa5,sizeof(link));memset(&link_v2,0xa5,sizeof(link_v2));memset(&rwitness,0xa5,sizeof(rwitness));memset(&rwitness_v2,0xa5,sizeof(rwitness_v2));memset(&op,0xa5,sizeof(op));memset(&op_v2,0xa5,sizeof(op_v2));
 CHECK(dmg_result_get_info(result,&info)==DMG_UNSUPPORTED&&unchanged(&info,sizeof(info)));
 CHECK(dmg_result_get_method(result,0,&method)==DMG_UNSUPPORTED&&unchanged(&method,sizeof(method)));
 CHECK(dmg_result_get_origin(result,0,&origin)==DMG_UNSUPPORTED&&unchanged(&origin,sizeof(origin)));
 CHECK(dmg_result_get_profile(result,&profile)==DMG_UNSUPPORTED&&unchanged(&profile,sizeof(profile)));
 CHECK(dmg_result_get_relation_info(result,&old,sizeof(old))==DMG_UNSUPPORTED&&unchanged(&old,sizeof(old)));
 CHECK(dmg_result_get_relation_info_v2(result,&v2,sizeof(v2))==DMG_UNSUPPORTED&&unchanged(&v2,sizeof(v2)));
 CHECK(dmg_result_get_entity(result,0,&entity,sizeof(entity))==DMG_UNSUPPORTED&&unchanged(&entity,sizeof(entity)));
 CHECK(dmg_result_get_value_v2(result,0,&value,sizeof(value))==DMG_UNSUPPORTED&&unchanged(&value,sizeof(value)));
 CHECK(dmg_result_get_graph_info(result,&graph,sizeof(graph))==DMG_UNSUPPORTED&&unchanged(&graph,sizeof(graph)));
 CHECK(dmg_result_get_operator_profile(result,0,&op,sizeof(op))==DMG_UNSUPPORTED&&unchanged(&op,sizeof(op)));
 CHECK(dmg_result_get_operator_profile_v2(result,0,&op_v2,sizeof(op_v2))==DMG_UNSUPPORTED&&unchanged(&op_v2,sizeof(op_v2)));
 CHECK(dmg_result_get_binding_count(result,0,&count)==DMG_UNSUPPORTED&&count==0xa5a5a5a5);
 CHECK(dmg_result_get_binding(result,0,0,&binding,sizeof(binding))==DMG_UNSUPPORTED&&unchanged(&binding,sizeof(binding)));
 CHECK(dmg_result_get_binding_v2(result,0,0,&binding_v2,sizeof(binding_v2))==DMG_UNSUPPORTED&&unchanged(&binding_v2,sizeof(binding_v2)));
 CHECK(dmg_result_get_binding_path(result,0,0,&bpath,sizeof(bpath))==DMG_UNSUPPORTED&&unchanged(&bpath,sizeof(bpath)));
 CHECK(dmg_result_get_proof_binding_count(result,0,&count)==DMG_UNSUPPORTED&&count==0xa5a5a5a5);
 CHECK(dmg_result_get_proof_binding(result,0,0,&proof,sizeof(proof))==DMG_UNSUPPORTED&&unchanged(&proof,sizeof(proof)));
 CHECK(dmg_result_get_proof_binding_v2(result,0,0,&proof_v2,sizeof(proof_v2))==DMG_UNSUPPORTED&&unchanged(&proof_v2,sizeof(proof_v2)));
 CHECK(dmg_result_get_proof_binding_path(result,0,0,&bpath,sizeof(bpath))==DMG_UNSUPPORTED&&unchanged(&bpath,sizeof(bpath)));
 CHECK(dmg_result_get_link_count(result,0,&count)==DMG_UNSUPPORTED&&count==0xa5a5a5a5);
 CHECK(dmg_result_get_link(result,0,0,&link,sizeof(link))==DMG_UNSUPPORTED&&unchanged(&link,sizeof(link)));
 CHECK(dmg_result_get_link_v2(result,0,0,&link_v2,sizeof(link_v2))==DMG_UNSUPPORTED&&unchanged(&link_v2,sizeof(link_v2)));
 CHECK(dmg_result_get_witness_count(result,0,&count)==DMG_UNSUPPORTED&&count==0xa5a5a5a5);
 CHECK(dmg_result_get_witness(result,0,0,&witness)==DMG_UNSUPPORTED&&unchanged(&witness,sizeof(witness)));
 CHECK(dmg_result_get_relation_witness(result,0,0,&rwitness,sizeof(rwitness))==DMG_UNSUPPORTED&&unchanged(&rwitness,sizeof(rwitness)));
 CHECK(dmg_result_get_relation_witness_v2(result,0,0,&rwitness_v2,sizeof(rwitness_v2))==DMG_UNSUPPORTED&&unchanged(&rwitness_v2,sizeof(rwitness_v2)));
 {
  dmg_numeric_witness_v1 numeric;dmg_inherited_witness inherited;dmg_interface_witness_v1 interface_value;
  memset(&numeric,0xa5,sizeof(numeric));memset(&inherited,0xa5,sizeof(inherited));memset(&interface_value,0xa5,sizeof(interface_value));
  CHECK(dmg_result_get_numeric_witness_v1(result,0,0,&numeric,sizeof(numeric))==DMG_UNSUPPORTED&&unchanged(&numeric,sizeof(numeric)));
  CHECK(dmg_result_get_inherited_witness(result,0,0,&inherited,sizeof(inherited))==DMG_UNSUPPORTED&&unchanged(&inherited,sizeof(inherited)));
  CHECK(dmg_result_get_interface_witness_v1(result,0,0,&interface_value,sizeof(interface_value))==DMG_UNSUPPORTED&&unchanged(&interface_value,sizeof(interface_value)));
  CHECK(dmg_result_get_interface_resolved_witness_v1(result,0,0,&interface_value,sizeof(interface_value))==DMG_UNSUPPORTED&&unchanged(&interface_value,sizeof(interface_value)));
 }
 return 0;
}
#define BAD_SIZE(obj,call) do{memset(&(obj),0xa5,sizeof(obj));CHECK((call)==DMG_INVALID_ARGUMENT&&unchanged(&(obj),sizeof(obj)));}while(0)
static int path_checks(const dmg_result* result,uint32_t row,uint32_t path_index,uint32_t first_pc,uint32_t mid,uint32_t endpoint){
 dmg_expand_path_info path;dmg_expand_binding binding;dmg_expand_hop hop;dmg_relation_link_v2 link;dmg_expand_proof proof;dmg_relation_witness_v2 witness;dmg_entity_row e;uint32_t count=0;
 CHECK(dmg_result_get_expand_endpoint(result,row,&e,sizeof(e))==DMG_OK&&e.source_index==endpoint&&e.relation==DMG_METHOD_DEFS&&units(e.name,e.name_length,"c"));
 CHECK(dmg_result_get_expand_path_count(result,row,&count)==DMG_OK&&count>path_index);
 CHECK(dmg_result_get_expand_path(result,row,path_index,&path,sizeof(path))==DMG_OK&&path.hop_count==2&&!path.uncertain&&path.seed.source_index==0&&path.seed.local_index==0&&path.endpoint.source_index==endpoint);
 CHECK(path.seed_binding_count==1&&path.seed_link_count==1&&path.seed_proof_count==1&&path.seed_witness_count>0&&path.walk_witness_count>0&&path.emit_witness_count>0);
 CHECK(dmg_result_get_expand_path_binding(result,row,path_index,0,&binding,sizeof(binding))==DMG_OK&&binding.label&&!strcmp(binding.label,"seed")&&binding.value.kind==DMG_VALUE_ENTITY&&binding.value.entity.source_index==0);
 CHECK(dmg_result_get_expand_path_seed_link(result,row,path_index,0,&link,sizeof(link))==DMG_OK&&link.key==DMG_JOIN_SAME_ENTITY&&link.left.source_index==0&&link.right.source_index==0);
 CHECK(dmg_result_get_expand_path_seed_proof(result,row,path_index,0,&proof,sizeof(proof))==DMG_OK&&proof.binding.value.kind==DMG_VALUE_ENTITY&&proof.binding.value.entity.source_index==0&&proof.binding.path.length==1&&proof.binding.path.sides[0]==DMG_PATH_RIGHT);
 CHECK(dmg_result_get_expand_path_witness(result,row,path_index,DMG_EXPAND_SEED_WITNESS,0,&witness,sizeof(witness))==DMG_OK&&witness.entity.source_index==0);
 CHECK(dmg_result_get_expand_path_witness(result,row,path_index,DMG_EXPAND_WALK_WITNESS,0,&witness,sizeof(witness))==DMG_OK&&witness.entity.source_index==mid);
 CHECK(dmg_result_get_expand_path_witness(result,row,path_index,DMG_EXPAND_EMIT_WITNESS,0,&witness,sizeof(witness))==DMG_OK&&witness.entity.source_index==endpoint);
 CHECK(dmg_result_get_expand_path_hop(result,row,path_index,0,&hop,sizeof(hop))==DMG_OK&&hop.caller.source_index==0&&hop.resolved.source_index==mid&&hop.dex_pc==first_pc&&hop.code_offset==260&&hop.opcode==0x71&&hop.target_method_ref==1&&hop.candidate_count==2&&hop.resolution_complete);
 CHECK(hop.target_symbol.relation==DMG_METHOD_REFS&&hop.target_symbol.source_index==0&&units(hop.target_symbol.owner,hop.target_symbol.owner_length,"Lamb/B;")&&units(hop.target_symbol.name,hop.target_symbol.name_length,"b")&&units(hop.target_symbol.prototype,hop.target_symbol.prototype_length,"()V"));
 CHECK(dmg_result_get_expand_path_hop(result,row,path_index,1,&hop,sizeof(hop))==DMG_OK&&hop.caller.source_index==mid&&hop.resolved.source_index==endpoint&&hop.dex_pc==0&&hop.code_offset==260&&hop.opcode==0x71&&hop.target_method_ref==1&&hop.candidate_count==1&&hop.resolution_complete);
 return 0;
}
static int sized_path(const dmg_result* result){
 dmg_expand_info info;dmg_expand_profile profile;dmg_operator_profile_v2 op;dmg_entity_row endpoint;dmg_expand_path_info path;dmg_expand_binding binding;dmg_expand_hop hop;dmg_relation_link_v2 link;dmg_expand_proof proof;dmg_relation_witness_v2 witness;uint32_t count=0xa5a5a5a5;
 BAD_SIZE(info,dmg_result_get_expand_info(result,&info,sizeof(info)-1));
 BAD_SIZE(profile,dmg_result_get_expand_profile(result,0,&profile,sizeof(profile)-1));
 BAD_SIZE(op,dmg_result_get_expand_operator(result,0,&op,sizeof(op)-1));
 BAD_SIZE(endpoint,dmg_result_get_expand_endpoint(result,0,&endpoint,sizeof(endpoint)-1));
 BAD_SIZE(path,dmg_result_get_expand_path(result,0,0,&path,sizeof(path)-1));
 BAD_SIZE(binding,dmg_result_get_expand_path_binding(result,0,0,0,&binding,sizeof(binding)-1));
 BAD_SIZE(hop,dmg_result_get_expand_path_hop(result,0,0,0,&hop,sizeof(hop)-1));
 BAD_SIZE(link,dmg_result_get_expand_path_seed_link(result,0,0,0,&link,sizeof(link)-1));
 BAD_SIZE(proof,dmg_result_get_expand_path_seed_proof(result,0,0,0,&proof,sizeof(proof)-1));
 BAD_SIZE(witness,dmg_result_get_expand_path_witness(result,0,0,DMG_EXPAND_SEED_WITNESS,0,&witness,sizeof(witness)-1));
 memset(&hop,0xa5,sizeof(hop));CHECK(dmg_result_get_expand_path_hop(result,0,0,UINT32_MAX,&hop,sizeof(hop))==DMG_INVALID_ARGUMENT&&unchanged(&hop,sizeof(hop)));
 CHECK(dmg_result_get_expand_path_count(result,UINT32_MAX,&count)==DMG_INVALID_ARGUMENT&&count==0xa5a5a5a5);return 0;
}
static int check_paths(const dmg_result* result){
 dmg_expand_info info;dmg_expand_profile profile;uint32_t i;static const uint32_t pc[]={0,0,3,3},mid[]={1,2,1,2},end[]={3,4,3,4};
 CHECK(legacy_result(result)==0&&dmg_result_get_expand_info(result,&info,sizeof(info))==DMG_OK&&info.outcome.candidates_count==4&&info.outcome.coverage==DMG_COVERAGE_COMPLETE&&info.frontier_count==0&&info.expand_profile_count==1);
 CHECK(dmg_result_get_expand_profile(result,0,&profile,sizeof(profile))==DMG_OK&&profile.visited==9&&profile.edges==8&&profile.paths==9&&profile.reverse_builds==0);
 for(i=0;i<4;++i)CHECK(path_checks(result,i,0,pc[i],mid[i],end[i])==0);CHECK(sized_path(result)==0);return 0;
}
static int job_sizes(dmg_job* job){dmg_expand_job_status status;dmg_expand_profile profile;dmg_operator_profile_v2 op;dmg_relation_job_status_v2 old;dmg_relation_job_status rel_old;dmg_job_status method_old;dmg_graph_info graph;dmg_operator_profile op_old;dmg_query_profile qprof;
 BAD_SIZE(status,dmg_job_get_expand_status(job,&status,sizeof(status)-1));BAD_SIZE(status,dmg_job_wait_expand(job,0,&status,sizeof(status)-1));BAD_SIZE(profile,dmg_job_get_expand_profile(job,0,&profile,sizeof(profile)-1));BAD_SIZE(op,dmg_job_get_expand_operator(job,0,&op,sizeof(op)-1));
 memset(&old,0xa5,sizeof(old));memset(&rel_old,0xa5,sizeof(rel_old));memset(&method_old,0xa5,sizeof(method_old));memset(&graph,0xa5,sizeof(graph));memset(&op_old,0xa5,sizeof(op_old));memset(&op,0xa5,sizeof(op));memset(&qprof,0xa5,sizeof(qprof));
 CHECK(dmg_job_get_status(job,&method_old)==DMG_UNSUPPORTED&&unchanged(&method_old,sizeof(method_old)));
 CHECK(dmg_job_wait(job,0,&method_old)==DMG_UNSUPPORTED&&unchanged(&method_old,sizeof(method_old)));
 CHECK(dmg_job_get_relation_status(job,&rel_old,sizeof(rel_old))==DMG_UNSUPPORTED&&unchanged(&rel_old,sizeof(rel_old)));
 CHECK(dmg_job_wait_relation(job,0,&rel_old,sizeof(rel_old))==DMG_UNSUPPORTED&&unchanged(&rel_old,sizeof(rel_old)));
 CHECK(dmg_job_get_relation_status_v2(job,&old,sizeof(old))==DMG_UNSUPPORTED&&unchanged(&old,sizeof(old)));
 CHECK(dmg_job_wait_relation_v2(job,0,&old,sizeof(old))==DMG_UNSUPPORTED&&unchanged(&old,sizeof(old)));
 CHECK(dmg_job_get_graph_info(job,&graph,sizeof(graph))==DMG_UNSUPPORTED&&unchanged(&graph,sizeof(graph)));
 CHECK(dmg_job_get_operator_profile(job,0,&op_old,sizeof(op_old))==DMG_UNSUPPORTED&&unchanged(&op_old,sizeof(op_old)));
 CHECK(dmg_job_get_operator_profile_v2(job,0,&op,sizeof(op))==DMG_UNSUPPORTED&&unchanged(&op,sizeof(op)));
 CHECK(dmg_job_get_profile(job,&qprof)==DMG_UNSUPPORTED&&unchanged(&qprof,sizeof(qprof)));
 return 0;}
static int frontier_checks(const dmg_result* result,uint32_t reason){
 dmg_expand_info info;dmg_expand_frontier front;dmg_expand_binding binding;dmg_relation_link_v2 link;dmg_expand_proof proof;dmg_relation_witness_v2 witness;uint32_t i;
 CHECK(dmg_result_get_expand_info(result,&info,sizeof(info))==DMG_OK&&info.outcome.candidates_count==0&&info.frontier_count==2);
 if(reason==DMG_EXPAND_UNRESOLVED)CHECK(info.outcome.coverage==DMG_COVERAGE_COMPLETE&&info.outcome.decision==DMG_PROVEN_FALSE);
 else CHECK(info.outcome.coverage==DMG_COVERAGE_PARTIAL&&info.outcome.decision==DMG_UNDETERMINED&&info.outcome.unknown_rows>0);
 for(i=0;i<2;++i){CHECK(dmg_result_get_expand_frontier(result,i,&front,sizeof(front))==DMG_OK&&front.reason==reason&&front.dex_pc==i*3&&front.target_method_ref==1&&front.has_target_symbol&&front.seed.source_index==0&&front.caller.source_index==0);
  CHECK(units(front.target_symbol.owner,front.target_symbol.owner_length,"Lamb/B;")&&front.seed_binding_count==1&&front.seed_link_count==1&&front.seed_proof_count==1&&front.seed_witness_count>0&&front.prefix_count==0);
  CHECK(dmg_result_get_expand_frontier_binding(result,i,0,&binding,sizeof(binding))==DMG_OK&&binding.label&&!strcmp(binding.label,"seed"));
  CHECK(dmg_result_get_expand_frontier_seed_link(result,i,0,&link,sizeof(link))==DMG_OK&&link.key==DMG_JOIN_SAME_ENTITY);
  CHECK(dmg_result_get_expand_frontier_seed_proof(result,i,0,&proof,sizeof(proof))==DMG_OK);
  CHECK(dmg_result_get_expand_frontier_witness(result,i,DMG_EXPAND_SEED_WITNESS,0,&witness,sizeof(witness))==DMG_OK);
 }
 BAD_SIZE(front,dmg_result_get_expand_frontier(result,0,&front,sizeof(front)-1));
 BAD_SIZE(binding,dmg_result_get_expand_frontier_binding(result,0,0,&binding,sizeof(binding)-1));
 BAD_SIZE(link,dmg_result_get_expand_frontier_seed_link(result,0,0,&link,sizeof(link)-1));
 BAD_SIZE(proof,dmg_result_get_expand_frontier_seed_proof(result,0,0,&proof,sizeof(proof)-1));
 BAD_SIZE(witness,dmg_result_get_expand_frontier_witness(result,0,DMG_EXPAND_SEED_WITNESS,0,&witness,sizeof(witness)-1));
 return 0;
}
int main(int argc,char** argv){
 dmg_engine *engine=NULL;dmg_snapshot *snapshot=NULL;dmg_query *query=NULL;dmg_result *result=NULL;dmg_job *job=NULL;dmg_batch *batch=NULL,*saved=NULL;dmg_error error={0};dmg_expand_info info;dmg_expand_job_status status;dmg_job_options options={sizeof(options),DMG_ABI_VERSION,1,1,0};uint32_t i,count;
 CHECK(argc==2&&has_token(dmg_capabilities(),"dex-query-expand-v5"));
 CHECK(dmg_engine_create(NULL,&engine,&error)==DMG_OK&&open_sources(engine,argv[1],5,1,&snapshot)==0&&compile_query(engine,paths_query,&query)==0);
 CHECK(dmg_query_execute(snapshot,query,&result,&error)==DMG_OK&&result&&check_paths(result)==0);
 dmg_query_release(query);query=NULL;dmg_snapshot_release(snapshot);snapshot=NULL;dmg_engine_release(engine);engine=NULL;
 CHECK(check_paths(result)==0);dmg_result_release(result);result=NULL;

 CHECK(dmg_engine_create(NULL,&engine,&error)==DMG_OK&&open_sources(engine,argv[1],5,1,&snapshot)==0&&compile_query(engine,endpoints_query,&query)==0);
 CHECK(dmg_query_execute(snapshot,query,&result,&error)==DMG_OK&&result&&dmg_result_get_expand_info(result,&info,sizeof(info))==DMG_OK&&info.outcome.candidates_count==2);
 for(i=0;i<2;++i){CHECK(dmg_result_get_expand_path_count(result,i,&count)==DMG_OK&&count==2);CHECK(path_checks(result,i,0,0,i+1,i+3)==0&&path_checks(result,i,1,3,i+1,i+3)==0);}
 dmg_result_release(result);result=NULL;dmg_query_release(query);query=NULL;

 CHECK(compile_query(engine,paths_query,&query)==0&&dmg_job_start(snapshot,query,&options,&job,&error)==DMG_OK&&job_sizes(job)==0);
 CHECK(dmg_job_wait_expand(job,10000,&status,sizeof(status))==DMG_OK&&status.terminal&&status.lifecycle==DMG_JOB_COMPLETED&&status.info.outcome.execution_status==DMG_OK&&status.info.total_candidates==4);
 for(i=0;i<4;++i){CHECK(dmg_job_next(job,10000,&batch,&error)==DMG_OK&&batch);CHECK(legacy_result(batch)==0&&dmg_result_get_expand_info(batch,&info,sizeof(info))==DMG_OK&&info.outcome.candidates_count==1&&info.total_candidates==4);CHECK(path_checks(batch,0,0,i<2?0:3,i%2+1,i%2+3)==0);if(i==0)saved=batch;else dmg_batch_release(batch);batch=NULL;}
 CHECK(dmg_job_next(job,10000,&batch,&error)==DMG_END_OF_STREAM&&batch==NULL);
 dmg_job_release(job);job=NULL;dmg_query_release(query);query=NULL;dmg_snapshot_release(snapshot);snapshot=NULL;dmg_engine_release(engine);engine=NULL;
 CHECK(saved&&path_checks(saved,0,0,0,1,3)==0);dmg_batch_release(saved);saved=NULL;

 CHECK(dmg_engine_create(NULL,&engine,&error)==DMG_OK&&open_sources(engine,argv[1],5,1,&snapshot)==0&&compile_query(engine,cap_query,&query)==0);
 CHECK(dmg_query_execute(snapshot,query,&result,&error)==DMG_OK&&result&&dmg_result_get_expand_info(result,&info,sizeof(info))==DMG_OK&&info.outcome.execution_status==DMG_BUDGET_EXCEEDED&&info.outcome.reason==DMG_RESULT_LIMIT&&info.outcome.coverage==DMG_COVERAGE_PARTIAL&&info.outcome.candidates_count==1);
 dmg_result_release(result);result=NULL;CHECK(dmg_job_start(snapshot,query,&options,&job,&error)==DMG_OK&&dmg_job_wait_expand(job,10000,&status,sizeof(status))==DMG_OK&&status.terminal&&status.lifecycle==DMG_JOB_COMPLETED&&status.info.outcome.execution_status==DMG_BUDGET_EXCEEDED&&status.info.outcome.reason==DMG_RESULT_LIMIT);
 CHECK(dmg_job_next(job,10000,&batch,&error)==DMG_OK&&batch);dmg_batch_release(batch);batch=NULL;CHECK(dmg_job_next(job,10000,&batch,&error)==DMG_END_OF_STREAM&&batch==NULL);dmg_job_release(job);job=NULL;dmg_query_release(query);query=NULL;

 CHECK(compile_query(engine,budget_query,&query)==0&&dmg_query_execute(snapshot,query,&result,&error)==DMG_BUDGET_EXCEEDED&&result==NULL);
 CHECK(dmg_job_start(snapshot,query,&options,&job,&error)==DMG_OK&&dmg_job_wait_expand(job,10000,&status,sizeof(status))==DMG_OK&&status.terminal&&status.lifecycle==DMG_JOB_FAILED&&status.info.outcome.execution_status==DMG_BUDGET_EXCEEDED);
 CHECK(dmg_job_next(job,10000,&batch,&error)==DMG_END_OF_STREAM&&batch==NULL);dmg_job_release(job);job=NULL;dmg_query_release(query);query=NULL;dmg_snapshot_release(snapshot);snapshot=NULL;

 CHECK(open_sources(engine,argv[1],1,1,&snapshot)==0&&compile_query(engine,frontier_query,&query)==0&&dmg_query_execute(snapshot,query,&result,&error)==DMG_OK&&result&&frontier_checks(result,DMG_EXPAND_UNRESOLVED)==0);
 dmg_result_release(result);result=NULL;dmg_snapshot_release(snapshot);snapshot=NULL;
 CHECK(open_sources(engine,argv[1],1,0,&snapshot)==0&&dmg_query_execute(snapshot,query,&result,&error)==DMG_OK&&result&&frontier_checks(result,DMG_EXPAND_INCOMPLETE)==0);
 dmg_result_release(result);result=NULL;dmg_query_release(query);dmg_snapshot_release(snapshot);dmg_engine_release(engine);
 puts("PASS C expand: ordered paths, frontiers, ABI rejection, sized outputs, atomic Job, retained lifetimes and budgets");return 0;
}
