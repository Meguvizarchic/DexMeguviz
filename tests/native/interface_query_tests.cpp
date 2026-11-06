#include "dexmeguviz/dexmeguviz.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#define CHECK(x) do{if(!(x))throw std::runtime_error("interface query line "+std::to_string(__LINE__)+": " #x);}while(0)
using Engine=std::unique_ptr<dmg_engine,decltype(&dmg_engine_release)>;using Snapshot=std::unique_ptr<dmg_snapshot,decltype(&dmg_snapshot_release)>;
using Query=std::unique_ptr<dmg_query,decltype(&dmg_query_release)>;using Result=std::unique_ptr<dmg_result,decltype(&dmg_result_release)>;using Batch=std::unique_ptr<dmg_batch,decltype(&dmg_batch_release)>;
static std::vector<uint8_t> load(const std::filesystem::path& p){std::ifstream f(p,std::ios::binary);CHECK(f.good());return {std::istreambuf_iterator<char>(f),{}};}
static Snapshot open(dmg_engine* e,const std::vector<std::vector<uint8_t>>& bytes,bool complete=true){
 std::vector<std::string> slots;for(size_t i=0;i<bytes.size();++i)slots.push_back("slot"+std::to_string(i));std::vector<dmg_source_spec> inputs(bytes.size());
 for(size_t i=0;i<bytes.size();++i){auto& s=inputs[i];s.struct_size=sizeof(s);s.abi_version=DMG_ABI_VERSION;s.format=DMG_INPUT_RAW_DEX;s.data=bytes[i].data();s.size=bytes[i].size();s.slot_key=slots[i].c_str();s.role=i?"code-split":"base";}
 dmg_source_set_options options{sizeof(options),DMG_ABI_VERSION,"interface-v8",complete?1u:0u,16,1u<<20};dmg_snapshot* raw=nullptr;dmg_error error{};
 auto code=dmg_snapshot_open_sources(e,inputs.data(),static_cast<uint32_t>(inputs.size()),&options,&raw,&error);if(code!=DMG_OK)std::cerr<<error.message<<'\n';CHECK(code==DMG_OK&&raw);return Snapshot(raw,&dmg_snapshot_release);
}
static std::string predicate(const char* name,uint32_t count){return std::string("{\"all\":[{\"descriptor\":\"Lifx/Child;\"},{\"declares_fields\":{\"scope\":\"inherited_interfaces\",\"where\":{\"name\":\"")+name+"\"},\"min\":"+std::to_string(count)+",\"max\":"+std::to_string(count)+"}}]}";}
static std::string query(const char* name,uint32_t count,bool relational=false){return relational?std::string("{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"class_defs\",\"where\":")+predicate(name,count)+"},\"intent\":\"unique\"}":std::string("{\"schema_version\":1,\"relation\":\"class_defs\",\"where\":")+predicate(name,count)+",\"intent\":\"unique\"}";}
static Query compile(dmg_engine* e,const std::string& text){dmg_error error{};dmg_query* raw=nullptr;auto code=dmg_query_compile_json(e,reinterpret_cast<const uint8_t*>(text.data()),text.size(),&raw,&error);if(code!=DMG_OK)std::cerr<<error.message<<'\n';CHECK(code==DMG_OK&&raw);dmg_query_info info{};CHECK(dmg_query_get_info(raw,&info)==DMG_OK&&std::string(info.query_id).starts_with("query:v8:")&&(info.required_capabilities&65536));return Query(raw,&dmg_query_release);}
static Result execute(dmg_engine* e,dmg_snapshot* s,const std::string& text){auto q=compile(e,text);dmg_error error{};dmg_result* raw=nullptr;auto code=dmg_query_execute(s,q.get(),&raw,&error);if(code!=DMG_OK)std::cerr<<error.message<<'\n';CHECK(code==DMG_OK&&raw);return Result(raw,&dmg_result_release);}
static dmg_relation_info info(dmg_result* result){dmg_relation_info value{};CHECK(dmg_result_get_relation_info(result,&value,sizeof(value))==DMG_OK);return value;}
static void inspect(dmg_result* r,unsigned wanted_fields){
 uint32_t count=0;CHECK(dmg_result_get_witness_count(r,0,&count)==DMG_OK);unsigned fields=0,nodes=0,edges=0;
 for(uint32_t i=0;i<count;++i){dmg_interface_witness_v1 x{};auto status=dmg_result_get_interface_witness_v1(r,0,i,&x,sizeof(x));if(status==DMG_UNSUPPORTED)continue;CHECK(status==DMG_OK&&x.matched==DMG_MATCH_TRUE);
  dmg_witness legacy{};CHECK(dmg_result_get_witness(r,0,i,&legacy)==DMG_UNSUPPORTED);
  if(x.item_kind==1)++nodes;else if(x.item_kind==2)++edges;else if(x.item_kind==4)++fields;
  dmg_interface_witness_v1 unchanged{};unchanged.item_kind=999;CHECK(dmg_result_get_interface_witness_v1(r,0,i,&unchanged,sizeof(unchanged)-1)==DMG_INVALID_ARGUMENT&&unchanged.item_kind==999);
 }
 CHECK(nodes>=6&&edges>=6&&fields==wanted_fields);
}
int main(int argc,char** argv){try{
 CHECK(argc==2);const std::filesystem::path dir(argv[1]);std::vector<std::vector<uint8_t>> bytes;
 for(const char* name:{"child.dex","base.dex","root.dex","top.dex","left.dex","right.dex"})bytes.push_back(load(dir/name));
 dmg_error error{};dmg_engine* raw=nullptr;CHECK(dmg_engine_create(nullptr,&raw,&error)==DMG_OK);Engine e(raw,&dmg_engine_release);auto full=open(e.get(),bytes);
 for(auto item:{std::pair{"diamond",1u},std::pair{"same",2u},std::pair{"classSame",2u},std::pair{"override",2u},std::pair{"hidden",0u}}){auto r=execute(e.get(),full.get(),query(item.first,item.second));CHECK(info(r.get()).candidates_count==1&&info(r.get()).decision==DMG_PROVEN_TRUE);inspect(r.get(),item.second);}
 auto relational=execute(e.get(),full.get(),query("diamond",1,true));CHECK(info(relational.get()).candidates_count==1);inspect(relational.get(),1);
 auto partial=open(e.get(),bytes,false);auto unknown=execute(e.get(),partial.get(),query("diamond",1));CHECK(info(unknown.get()).unknown_rows==1&&info(unknown.get()).decision==DMG_UNDETERMINED);
 auto missing=bytes;missing.erase(missing.begin()+3);auto missing_s=open(e.get(),missing);auto absent=execute(e.get(),missing_s.get(),query("diamond",1));CHECK(info(absent.get()).unknown_rows==1&&info(absent.get()).candidates_count==0);
 auto ambiguous=bytes;ambiguous.push_back(load(dir/"left.dex"));auto ambiguous_s=open(e.get(),ambiguous);auto duplicate=execute(e.get(),ambiguous_s.get(),query("same",2));CHECK(info(duplicate.get()).unknown_rows==1&&info(duplicate.get()).decision==DMG_UNDETERMINED);
 auto cyclic=open(e.get(),{load(dir/"child-cycle.dex"),load(dir/"base.dex"),load(dir/"root.dex"),load(dir/"cycle.dex"),load(dir/"cycle2.dex")});auto cycle=execute(e.get(),cyclic.get(),query("cycle",1));CHECK(info(cycle.get()).unknown_rows==1&&info(cycle.get()).decision==DMG_UNDETERMINED);
 for(const char* invalid:{"bad-instance.dex","bad-protected.dex","bad-nofinal.dex"}){
  auto bad=open(e.get(),{load(dir/"child-bad.dex"),load(dir/"base.dex"),load(dir/"root.dex"),load(dir/invalid)});
  auto rejected=execute(e.get(),bad.get(),query("bad",1));CHECK(info(rejected.get()).unknown_rows==1&&info(rejected.get()).decision==DMG_UNDETERMINED);
 }
 {auto bad=open(e.get(),{load(dir/"child-bad.dex"),load(dir/"base.dex"),load(dir/"root.dex"),load(dir/"bad-type.dex")});auto rejected=execute(e.get(),bad.get(),query("bad",1));CHECK(info(rejected.get()).unknown_rows==1);}
 {auto annotation=open(e.get(),{load(dir/"child-bad.dex"),load(dir/"base.dex"),load(dir/"root.dex"),load(dir/"annotation.dex")});auto accepted=execute(e.get(),annotation.get(),query("annotationField",1));CHECK(info(accepted.get()).candidates_count==1&&info(accepted.get()).decision==DMG_PROVEN_TRUE);}
 auto q=compile(e.get(),query("diamond",1));dmg_job_options options{sizeof(options),DMG_ABI_VERSION,1,2,0};dmg_job* job=nullptr;CHECK(dmg_job_start(full.get(),q.get(),&options,&job,&error)==DMG_OK);
 dmg_batch* raw_batch=nullptr;CHECK(dmg_job_next(job,10000,&raw_batch,&error)==DMG_OK&&raw_batch);Batch batch(raw_batch,&dmg_batch_release);dmg_relation_job_status status{};CHECK(dmg_job_wait_relation(job,10000,&status,sizeof(status))==DMG_OK&&status.terminal);dmg_job_release(job);inspect(batch.get(),1);
 auto limited_text=query("diamond",1);limited_text.insert(limited_text.size()-1,",\"max_work\":1");auto limited=compile(e.get(),limited_text);dmg_result* not_published=nullptr;CHECK(dmg_query_execute(full.get(),limited.get(),&not_published,&error)==DMG_BUDGET_EXCEEDED&&!not_published);
 {auto text=query("diamond",1);text.insert(text.size()-1,",\"required_capabilities\":[\"inherited_fields\"]");dmg_query* invalid=nullptr;CHECK(dmg_query_compile_json(e.get(),reinterpret_cast<const uint8_t*>(text.data()),text.size(),&invalid,&error)==DMG_UNSUPPORTED&&!invalid);}
 {auto text=query("diamond",1);text.insert(text.size()-1,",\"required_capabilities\":[\"numeric_literals\"]");dmg_query* raw=nullptr;CHECK(dmg_query_compile_json(e.get(),reinterpret_cast<const uint8_t*>(text.data()),text.size(),&raw,&error)==DMG_OK&&raw);Query combined(raw,&dmg_query_release);dmg_query_info composite{};CHECK(dmg_query_get_info(combined.get(),&composite)==DMG_OK&&(composite.required_capabilities&262144u)&&std::string(composite.query_id).starts_with("query:v10:"));}
 std::cout<<"PASS v8 interface query: graph evidence, partial sources, diamonds, hiding, scope, Job and capability isolation\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
