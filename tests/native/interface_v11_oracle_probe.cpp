#include "execution/reference/interface_fields_v11.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
using namespace dexmeguviz;namespace h=dexmeguviz::hierarchy;namespace v=h::v11;
static bool matcher(void* p,const Facts& f,const FieldDefinition& d){return std::u16string_view(f.strings[f.field_refs[d.field_ref_index].name])==std::u16string_view(*static_cast<std::u16string*>(p));}
int main(int argc,char** argv){try{
 if(argc<7)return 2;std::string ascii=argv[1];std::u16string name(ascii.begin(),ascii.end());uint32_t lo=std::stoul(argv[2]),hi=std::stoul(argv[3]);bool root_interface=std::stoi(argv[4])!=0,complete=std::stoi(argv[5])!=0;
 std::vector<std::vector<uint8_t>> bytes;std::vector<Facts> facts;std::vector<h::Source> sources;bytes.reserve(argc-6);facts.reserve(argc-6);sources.reserve(argc-6);
 for(int i=6;i<argc;++i){std::ifstream f(std::filesystem::path(argv[i]),std::ios::binary);if(!f)return 3;bytes.emplace_back(std::istreambuf_iterator<char>(f),std::istreambuf_iterator<char>());facts.push_back(read_metadata(bytes.back()));}
 for(uint32_t i=0;i<facts.size();++i)sources.push_back({i,&facts[i]});auto* mem=std::pmr::get_default_resource();h::Budget budget{10000000};h::Result paths(mem);
 if(root_interface){paths.paths.push_back({{0,0},UINT32_MAX,h::Link::root});paths.ends.push_back({0,h::Stop::no_superclass});}else paths=h::resolve(sources,{0,0},complete,budget,mem);
 const auto result=v::interface_fields(sources,paths,complete,lo,hi,matcher,&name,budget,mem);std::cout<<static_cast<unsigned>(result.truth)<<'\n';
 for(const auto& e:result.events)std::cout<<static_cast<unsigned>(e.item)<<' '<<e.branch<<' '<<e.node<<' '<<e.aux<<' '<<e.detail<<' '<<e.source<<' '<<static_cast<unsigned>(e.relation)<<' '<<e.ordinal<<'\n';
 return 0;}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
