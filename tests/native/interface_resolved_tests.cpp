#include "execution/reference/interface_fields_v11.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
using namespace dexmeguviz;
namespace h=dexmeguviz::hierarchy;
namespace v=h::v11;
#define CHECK(x) do { if(!(x)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #x); } while(0)
struct Fixture {
 std::vector<std::vector<uint8_t>> bytes;std::vector<Facts> facts;std::vector<h::Source> sources;
 Fixture(const std::filesystem::path& root,std::vector<std::string> names){
  bytes.reserve(names.size());facts.reserve(names.size());sources.reserve(names.size());
  for(const auto& name:names){std::ifstream f(root/name,std::ios::binary);CHECK(f.good());bytes.emplace_back(std::istreambuf_iterator<char>(f),std::istreambuf_iterator<char>());facts.push_back(read_metadata(bytes.back()));}
  for(uint32_t i=0;i<facts.size();++i)sources.push_back({i,&facts[i]});
 }
};
static bool match(void* p,const Facts& f,const FieldDefinition& d){return std::u16string_view(f.strings[f.field_refs[d.field_ref_index].name])==std::u16string_view(*static_cast<std::u16string*>(p));}
static v::InterfaceFieldResult run(Fixture& f,std::u16string name,uint32_t min,uint32_t max,bool root_interface=false,bool complete=true){
 h::Budget budget{10000000};auto* memory=std::pmr::get_default_resource();
 h::Result paths(memory);
 if(root_interface){paths.paths.push_back({{0,0},UINT32_MAX,h::Link::root});paths.ends.push_back({0,h::Stop::no_superclass});}
 else paths=h::resolve(f.sources,{0,0},complete,budget,memory);
 return v::interface_fields(f.sources,paths,complete,min,max,match,&name,budget,memory);
}
int main(int argc,char** argv){try{
 CHECK(argc==2);std::filesystem::path dir(argv[1]);
 Fixture mixed(dir,{"child.dex","base.dex","root.dex","top.dex","left.dex","left-alt.dex","right.dex"});
 CHECK(run(mixed,u"same",2,2).truth==h::FieldTruth::unknown);
 CHECK(run(mixed,u"diamond",1,1).truth==h::FieldTruth::yes);
 CHECK(run(mixed,u"diamond",2,2).truth==h::FieldTruth::no);
 Fixture diamond(dir,{"child.dex","base.dex","root.dex","top.dex","top.dex","left.dex","right.dex"});
 auto proof=run(diamond,u"diamond",1,1);CHECK(proof.truth==h::FieldTruth::yes);
 unsigned choices=0;uint32_t selected[2]={UINT32_MAX,UINT32_MAX};
 for(const auto& e:proof.events)if(e.item==v::InterfaceItem::choice){CHECK(e.branch<2&&e.aux==2&&(e.source==3||e.source==4));if(selected[e.branch]==UINT32_MAX)selected[e.branch]=e.source;CHECK(selected[e.branch]==e.source);++choices;}CHECK(choices==4&&selected[0]!=selected[1]);
 Fixture differing(dir,{"child.dex","base.dex","root.dex","top.dex","top-alt.dex","left.dex","right.dex"});
 CHECK(run(differing,u"diamond",1,1).truth==h::FieldTruth::unknown);
 Fixture iface(dir,{"left.dex","top.dex","root.dex"});
 CHECK(run(iface,u"diamond",1,1,true).truth==h::FieldTruth::yes);
 CHECK(run(iface,u"override",0,0,true).truth==h::FieldTruth::yes);
 CHECK(run(iface,u"diamond",1,1,true,false).truth==h::FieldTruth::unknown);
 Fixture missing(dir,{"child.dex","base.dex","root.dex","left.dex","right.dex"});CHECK(run(missing,u"diamond",1,1).truth==h::FieldTruth::unknown);
 Fixture cycle(dir,{"child-cycle.dex","base.dex","root.dex","cycle.dex","cycle2.dex"});CHECK(run(cycle,u"cycle",1,1).truth==h::FieldTruth::unknown);
 bool stopped=false;try{h::Budget prep{10000000};auto paths=h::resolve(mixed.sources,{0,0},true,prep,std::pmr::get_default_resource());h::Budget tiny{5};std::u16string n=u"same";(void)v::interface_fields(mixed.sources,paths,true,1,1,match,&n,tiny,std::pmr::get_default_resource());}catch(const ReadError& e){CHECK(e.code==ReadCode::budget);stopped=true;}CHECK(stopped);
 stopped=false;try{h::Budget prep{10000000};auto paths=h::resolve(mixed.sources,{0,0},true,prep,std::pmr::get_default_resource());h::Budget cancelled{10000000};cancelled.cancelled=[](void*)noexcept{return true;};std::u16string n=u"same";(void)v::interface_fields(mixed.sources,paths,true,1,1,match,&n,cancelled,std::pmr::get_default_resource());}catch(const h::Cancelled&){stopped=true;}CHECK(stopped);
 std::cout<<"PASS v11 static interface worlds, roots, incomplete and budget\n";return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
