#include "dexmeguviz/dexmeguviz.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string_view>
#include <vector>
namespace {
std::vector<uint8_t> file(const std::filesystem::path& p,uint64_t cap){auto n=std::filesystem::file_size(p);if(n>cap)throw std::runtime_error("input limit");std::vector<uint8_t> out(static_cast<size_t>(n));std::ifstream in(p,std::ios::binary);in.read(reinterpret_cast<char*>(out.data()),out.size());if(in.gcount()!=out.size()||in.peek()!=std::char_traits<char>::eof())throw std::runtime_error("input changed/read failed");return out;}
void text(const uint16_t* p,uint64_t count){if(!p&&count)throw std::runtime_error("invalid string");std::cout<<'"';constexpr char digits[]="0123456789abcdef";for(uint64_t i=0;i<count;++i){const auto c=p[i];std::cout<<"\\u"<<digits[(c>>12)&15]<<digits[(c>>8)&15]<<digits[(c>>4)&15]<<digits[c&15];}std::cout<<'"';}
void okay(dmg_status status,const dmg_error& error){if(status!=DMG_OK)throw std::runtime_error(std::string(dmg_status_name(status))+": "+error.message+" @"+std::to_string(error.offset));}
void okay(dmg_status status){if(status!=DMG_OK)throw std::runtime_error(dmg_status_name(status));}
int run(const std::vector<std::filesystem::path>& args){
    if(args.size()<3||args.size()>4)throw std::runtime_error("usage: dexmeguviz_041 inspect CONTAINER | query CONTAINER QUERY.json");
    const auto action=args[1].string();if(action!="inspect"&&action!="query")throw std::runtime_error("unsupported command");if((action=="query")!=(args.size()==4))throw std::runtime_error("query path required");
    const auto bytes=file(args[2],256u<<20);dmg_engine* raw_engine=nullptr;dmg_engine_options engine_options{};engine_options.struct_size=sizeof(engine_options);engine_options.abi_version=DMG_ABI_VERSION;engine_options.owned_bytes_limit=512u<<20;engine_options.max_source_bytes=256u<<20;engine_options.max_jobs=1;dmg_error error{};okay(dmg_engine_create(&engine_options,&raw_engine,&error));std::unique_ptr<dmg_engine,decltype(&dmg_engine_release)> engine(raw_engine,dmg_engine_release);
    const dmg_dex041_open_options_v1 options{sizeof(dmg_dex041_open_options_v1),DMG_ABI_VERSION,1,1,64,256u<<20,"dex041-cli-v1","container",nullptr};dmg_snapshot* raw_snapshot=nullptr;okay(dmg_snapshot_open_dex041_copy_v1(engine.get(),bytes.data(),bytes.size(),&options,&raw_snapshot,&error),error);std::unique_ptr<dmg_snapshot,decltype(&dmg_snapshot_release)> snapshot(raw_snapshot,dmg_snapshot_release);dmg_snapshot_overview overview{};okay(dmg_snapshot_get_overview(snapshot.get(),&overview));
    dmg_result* raw_result=nullptr;std::unique_ptr<dmg_result,decltype(&dmg_result_release)> result(nullptr,dmg_result_release);dmg_relation_info info{};dmg_query_info qi{};std::unique_ptr<dmg_query,decltype(&dmg_query_release)> query(nullptr,dmg_query_release);
    if(action=="query"){const auto json=file(args[3],65536);dmg_query* raw_query=nullptr;okay(dmg_query_compile_json(engine.get(),json.data(),json.size(),&raw_query,&error));query.reset(raw_query);okay(dmg_query_get_info(query.get(),&qi));const std::string_view id=qi.query_id?qi.query_id:"";if(!id.starts_with("query:v1:")&&!id.starts_with("query:v2:"))throw std::runtime_error("tool output supports only direct metadata/method profiles; use the C API for other admitted profiles");okay(dmg_query_execute(snapshot.get(),query.get(),&raw_result,&error));result.reset(raw_result);okay(dmg_result_get_relation_info(result.get(),&info,sizeof(info)));}
    std::cout<<"{\"profile\":\"experimental-dex041-container-v1\",\"snapshot_id\":\""<<overview.snapshot_id<<"\",\"physical_bytes\":"<<overview.input_bytes<<",\"sources\":[";
    for(uint32_t i=0;i<overview.source_count;++i){dmg_dex041_source_info_v1 source{};okay(dmg_snapshot_get_dex041_source_info_v1(snapshot.get(),i,&source,sizeof(source)));if(i)std::cout<<',';std::cout<<"{\"source_index\":"<<i<<",\"header_offset\":"<<source.header_offset<<",\"logical_file_size\":"<<source.logical_file_size<<",\"container_size\":"<<source.container_size<<",\"container_id\":\""<<source.container_id<<"\",\"logical_dex_id\":\""<<source.logical_dex_id<<"\",\"occurrence_id\":\""<<source.occurrence_id<<"\"}";}
    std::cout<<']';if(result){std::cout<<",\"query_id\":\""<<qi.query_id<<"\",\"execution_status\":"<<info.execution_status<<",\"coverage\":"<<info.coverage<<",\"decision\":"<<info.decision<<",\"candidates\":[";for(uint32_t i=0;i<info.candidates_count;++i){dmg_entity_row row{};okay(dmg_result_get_entity(result.get(),i,&row,sizeof(row)));if(i)std::cout<<',';std::cout<<"{\"source_index\":"<<row.source_index<<",\"local_index\":"<<row.local_index<<",\"reference_index\":"<<row.reference_index<<",\"record_offset\":"<<row.record_offset<<",\"owner\":";text(row.owner,row.owner_length);std::cout<<",\"name\":";text(row.name,row.name_length);std::cout<<",\"prototype\":";text(row.prototype,row.prototype_length);std::cout<<'}';}std::cout<<']';}std::cout<<"}\n";return 0;
}
}
#ifdef _WIN32
int wmain(int argc,wchar_t** argv){try{std::vector<std::filesystem::path> args;for(int i=0;i<argc;++i)args.emplace_back(argv[i]);return run(args);}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 2;}}
#else
int main(int argc,char** argv){try{std::vector<std::filesystem::path> args;for(int i=0;i<argc;++i)args.emplace_back(argv[i]);return run(args);}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 2;}}
#endif
