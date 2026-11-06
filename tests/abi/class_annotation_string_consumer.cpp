#include "dexmeguviz/dexmeguviz.h"
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>
#include <cstring>
#define CHECK(x) do{if(!(x))throw std::runtime_error(std::string("line ")+std::to_string(__LINE__)+": " #x);}while(0)
static std::vector<uint8_t> read(const char* p){std::ifstream f(p,std::ios::binary);CHECK(f.good());return {(std::istreambuf_iterator<char>(f)),{}};}
static std::string makeq(const char* name,const char* jsonString,const char* extra=""){
 return std::string("{\"schema_version\":1,\"relation\":\"class_defs\",\"required_capabilities\":[\"class_annotation_static\",\"class_annotation_string_static\"],\"where\":{\"annotation\":{\"type\":\"Lstringfixture/Tag;\",\"element\":{\"name\":\"")+name+"\",\"string\":"+jsonString+"}}}"+extra+"}";
}
static dmg_query* compile(dmg_engine* e,const std::string& q,dmg_status want=DMG_OK){dmg_query* out=nullptr;dmg_error err{};auto status=dmg_query_compile_json(e,(const uint8_t*)q.data(),q.size(),&out,&err);if(status!=want)std::cerr<<"compile status "<<status<<" expected "<<want<<" "<<err.message<<"\n";CHECK(status==want);CHECK((out!=nullptr)==(want==DMG_OK));return out;}
static void query(dmg_engine* e,dmg_snapshot* s,const std::string& text,uint32_t expected,uint64_t unknown,int source=-1){
 auto q=compile(e,text);dmg_query_info old{};std::memset(&old,0x5a,sizeof(old));auto before=old;CHECK(dmg_query_get_info(q,&old)==DMG_UNSUPPORTED&&!std::memcmp(&old,&before,sizeof(old)));
 dmg_query_info_v2 qi{};CHECK(dmg_query_get_info_v2(q,&qi,sizeof(qi))==DMG_OK&&std::string(qi.legacy.query_id).starts_with("query:v25:")&&std::string(qi.extended_capabilities)=="class_annotation_static;class_annotation_string_static");
 dmg_result* result=nullptr;dmg_error err{};auto status=dmg_query_execute(s,q,&result,&err);if(status!=DMG_OK)std::cerr<<"execute "<<status<<" "<<err.message<<"\n";CHECK(status==DMG_OK&&result);
 dmg_relation_info ri{};CHECK(dmg_result_get_relation_info(result,&ri,sizeof(ri))==DMG_OK&&ri.candidates_count==expected&&ri.unknown_rows==unknown);
 dmg_query_info_v2 qri{};CHECK(dmg_result_get_query_info_v2(result,&qri,sizeof(qri))==DMG_OK&&std::string(qri.legacy.query_id)==qi.legacy.query_id&&std::string(qri.extended_capabilities)==qi.extended_capabilities);
 if(unknown)CHECK(ri.coverage==DMG_COVERAGE_PARTIAL&&ri.reason==DMG_UNKNOWN_ATTRIBUTE);
 if(source>=0){CHECK(expected==1);dmg_entity_row row{};CHECK(dmg_result_get_entity(result,0,&row,sizeof(row))==DMG_OK&&row.source_index==(uint32_t)source);}
 dmg_result_release(result);dmg_query_release(q);
}
static void verify_v24(dmg_engine* engine,const char* fixture){
 auto bytes=read(fixture);dmg_error err{};dmg_source_spec spec{};spec.struct_size=sizeof(spec);spec.abi_version=DMG_ABI_VERSION;spec.format=DMG_INPUT_RAW_DEX;spec.data=bytes.data();spec.size=bytes.size();spec.slot_key="single";spec.role="base";
 dmg_source_set_options opt{sizeof(opt),DMG_ABI_VERSION,"old-id",1,8,1u<<20};dmg_snapshot* snapshot=nullptr;CHECK(dmg_snapshot_open_sources(engine,&spec,1,&opt,&snapshot,&err)==DMG_OK);
 const char* where[]={R"({"annotation":{"type":"Lfixture/Complex;"}})",R"({"annotation":{"type":"Lfixture/Complex;","element":{"name":"n","int":-7}}})",R"({"annotation":{"type":"Lfixture/Complex;","element":{"name":"absent","int":0}}})"};
 const char* ids[]={"query:v24:f3d6d0cd8287fcb726be74292f8d0196127d168e5524c66eb11d12ee9f4f21d2","query:v24:703c6deea6ad0fa665a27c80736ed8347e6ae099eb508ee7b9ba0ce767c9bc33","query:v24:808acba043d6e1fd4866a17c7807463247c7c8d9940be0c56a89472b43344d54"};
 const uint64_t work[]={955,960,985},unknown[]={0,0,1};const uint32_t counts[]={1,1,0};
 for(int i=0;i<3;i++){const std::string text=std::string("{\"schema_version\":1,\"relation\":\"class_defs\",\"required_capabilities\":[\"class_annotation_static\"],\"where\":")+where[i]+"}";auto q=compile(engine,text);dmg_query_info_v2 qi{};CHECK(dmg_query_get_info_v2(q,&qi,sizeof(qi))==DMG_OK&&std::string(qi.legacy.query_id)==ids[i]&&std::string(qi.extended_capabilities)=="class_annotation_static");dmg_result* result=nullptr;CHECK(dmg_query_execute(snapshot,q,&result,&err)==DMG_OK);dmg_relation_info ri{};dmg_query_profile profile{};CHECK(dmg_result_get_relation_info(result,&ri,sizeof(ri))==DMG_OK&&dmg_result_get_profile(result,&profile)==DMG_OK);CHECK(ri.candidates_count==counts[i]&&ri.unknown_rows==unknown[i]&&profile.work_units==work[i]);dmg_result_release(result);dmg_query_release(q);}
 dmg_snapshot_release(snapshot);
}
int main(int argc,char** argv){try{CHECK(argc==4);auto a=read(argv[1]),b=read(argv[2]);dmg_engine* engine=nullptr;dmg_error err{};CHECK(dmg_engine_create(nullptr,&engine,&err)==DMG_OK);
 dmg_source_spec specs[2]{};for(int i=0;i<2;i++){auto& x=specs[i];x.struct_size=sizeof(x);x.abi_version=DMG_ABI_VERSION;x.format=DMG_INPUT_RAW_DEX;x.data=i?b.data():a.data();x.size=i?b.size():a.size();x.slot_key=i?"two":"one";x.role="base";}
 dmg_source_set_options opt{sizeof(opt),DMG_ABI_VERSION,"v25",1,8,1u<<20};dmg_snapshot* snapshot=nullptr;CHECK(dmg_snapshot_open_sources(engine,specs,2,&opt,&snapshot,&err)==DMG_OK);
 query(engine,snapshot,makeq("value","\"aaaa\""),1,0,0);query(engine,snapshot,makeq("value","\"bbbb\""),1,0,1);
 query(engine,snapshot,makeq("value","\"\""),2,0);query(engine,snapshot,makeq("value","\"\\u96ea\""),2,0);
 query(engine,snapshot,makeq("value","\"\\ud83d\\ude00\""),2,0);query(engine,snapshot,makeq("value","\"\\ud800\""),2,0);query(engine,snapshot,makeq("value","\"a\\u0000b\""),2,0);
 query(engine,snapshot,makeq("value","\"nope\""),0,0);query(engine,snapshot,makeq("missing","\"x\""),0,12);
 auto neg=makeq("missing","\"x\"");auto position=neg.find("\"where\":{");CHECK(position!=std::string::npos);neg.replace(position,9,"\"where\":{\"not\":{");neg.insert(neg.size()-1,"}");query(engine,snapshot,neg,4,12);
 query(engine,snapshot,makeq("value","\"aaaa\"",",\"scope\":{\"slots\":[\"one\"]}"),1,0,0);
 auto idA=compile(engine,makeq("value","\"aaaa\""));auto idB=compile(engine,makeq("value","\"bbbb\""));auto idEsc=compile(engine,makeq("value","\"\\u0061aaa\""));dmg_query_info_v2 ia{},ib{},ie{};CHECK(dmg_query_get_info_v2(idA,&ia,sizeof(ia))==DMG_OK&&dmg_query_get_info_v2(idB,&ib,sizeof(ib))==DMG_OK&&dmg_query_get_info_v2(idEsc,&ie,sizeof(ie))==DMG_OK);CHECK(std::string(ia.legacy.query_id)!=ib.legacy.query_id&&std::string(ia.legacy.query_id)==ie.legacy.query_id);dmg_query_release(idA);dmg_query_release(idB);dmg_query_release(idEsc);
 auto scoped=compile(engine,makeq("value","\"aaaa\"",",\"scope\":{\"slots\":[\"one\"]}"));dmg_query_scope_v2 scope{};CHECK(dmg_query_get_scope_v2(scoped,&scope,sizeof(scope))==DMG_OK&&scope.explicit_scope==1&&scope.slot_count==1);const char* slot=nullptr;CHECK(dmg_query_get_scope_slot_v2(scoped,0,&slot)==DMG_OK&&std::string(slot)=="one");dmg_query_release(scoped);
 auto noNew=makeq("value","\"aaaa\"");auto k=noNew.find(",\"class_annotation_string_static\"");CHECK(k!=std::string::npos);noNew.erase(k,strlen(",\"class_annotation_string_static\""));compile(engine,noNew,DMG_UNSUPPORTED);
 auto noBase=makeq("value","\"aaaa\"");k=noBase.find("\"class_annotation_static\",");CHECK(k!=std::string::npos);noBase.erase(k,strlen("\"class_annotation_static\","));compile(engine,noBase,DMG_UNSUPPORTED);
 auto noString=makeq("value","\"aaaa\"");k=noString.find(",\"string\":\"aaaa\"");CHECK(k!=std::string::npos);noString.replace(k,strlen(",\"string\":\"aaaa\""),",\"int\":1");compile(engine,noString,DMG_UNSUPPORTED);
 auto both=makeq("value","\"aaaa\"");k=both.find(",\"string\":\"aaaa\"");CHECK(k!=std::string::npos);both.insert(k,",\"int\":1");compile(engine,both,DMG_INVALID_ARGUMENT);
 auto limit=makeq("value","\"aaaa\"",",\"max_work\":1");auto q=compile(engine,limit);dmg_result* result=nullptr;CHECK(dmg_query_execute(snapshot,q,&result,&err)==DMG_BUDGET_EXCEEDED&&result==nullptr);dmg_query_release(q);
 auto jq=compile(engine,makeq("value","\"\""));dmg_job* job=nullptr;dmg_job_options jo{sizeof(jo),DMG_ABI_VERSION,1,1,0};CHECK(dmg_job_start(snapshot,jq,&jo,&job,&err)==DMG_OK&&job);dmg_query_release(jq);
 dmg_query_info_v2 ji{};CHECK(dmg_job_get_query_info_v2(job,&ji,sizeof(ji))==DMG_OK&&std::string(ji.legacy.query_id).starts_with("query:v25:")&&std::string(ji.extended_capabilities)=="class_annotation_static;class_annotation_string_static");
 dmg_relation_job_status js{};CHECK(dmg_job_wait_relation(job,1000,&js,sizeof(js))==DMG_NOT_READY&&!js.terminal);dmg_job_cancel(job);CHECK(dmg_job_wait_relation(job,10000,&js,sizeof(js))==DMG_OK&&js.terminal&&js.outcome.execution_status==DMG_CANCELLED);dmg_job_release(job);
 dmg_snapshot_release(snapshot);verify_v24(engine,argv[3]);dmg_engine_release(engine);std::cout<<"PASS v25 string exact UTF16, source-local indices, unknown, limits, cancellation and rejection\n";return 0;
 }catch(const std::exception& ex){std::cerr<<ex.what()<<"\n";return 1;}}
