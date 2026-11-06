#include "query/class_annotation_match.hpp"
#include "format/reader.hpp"
#include "format/dex_names.hpp"
#include "execution/reference/evaluate.hpp"
#include <array>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <vector>
using namespace dexmeguviz;
namespace cm=dexmeguviz::query::class_annotation_match;
#define CHECK(x) do{if(!(x))throw std::runtime_error("line "+std::to_string(__LINE__)+": " #x);}while(0)
int main(int argc,char** argv){try{
 CHECK(!dex_names::simple_name(u"x y",35)&&dex_names::simple_name(u"x y",40));CHECK(!dex_names::class_descriptor(u"Lfoo//Bar;",40));
 CHECK(argc==2);std::ifstream f(argv[1],std::ios::binary);CHECK(f.good());std::vector<uint8_t> b((std::istreambuf_iterator<char>(f)),{});
 auto facts=read_metadata(b);CHECK(facts.class_definitions.size()>0&&b.size()>1514&&b[1514]==0x04&&b[1515]==0xf9);
 auto good=[&](uint64_t){};auto inspect=[&](auto& bytes,auto& charge){return cm::inspect(bytes,facts,facts.class_definitions[0],u"Lfixture/Complex;",2,u"n",true,0xfffffff9u,charge);};
 CHECK(inspect(b,good)==cm::Match::yes);
 uint64_t work=0;auto budget=[&](uint64_t n){work+=n;if(work>80)throw query::Error(query::ErrorCode::budget,"test budget");};
 try{(void)inspect(b,budget);throw std::runtime_error("budget missing");}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::budget);}
 work=0;auto stop=[&](uint64_t n){work+=n;if(work>80)throw query::Error(query::ErrorCode::cancelled,"test cancel");};
 try{(void)inspect(b,stop);throw std::runtime_error("cancel missing");}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::cancelled);}
 auto corrupt=b;corrupt[1514]=0x05;
 try{(void)inspect(corrupt,good);throw std::runtime_error("corruption missing");}catch(const ReadError& e){CHECK(e.code==ReadCode::corrupt);}
 Facts unsupported;unsupported.dex_version=41;reference::SourceView source{0,0,&unsupported,{}};std::array<reference::SourceView,1> sources{source};std::array<std::string_view,1> slots{"empty"};reference::DatasetView view{sources,slots,true,nullptr};
 auto plan=query::compile(R"({"schema_version":1,"relation":"class_defs","required_capabilities":["class_annotation_static"],"where":{"annotation":{"type":"Lfixture/Complex;"}}})",std::pmr::get_default_resource(),std::pmr::get_default_resource());reference::Progress progress;
 try{(void)reference::execute(view,plan,progress,std::pmr::get_default_resource());throw std::runtime_error("empty DEX 041 accepted");}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::unsupported);}

 reference::SourceView broken_source{0,0,&facts,corrupt};std::array<reference::SourceView,1> broken_sources{broken_source};std::array<std::string_view,1> broken_slots{"x"};reference::DatasetView broken{broken_sources,broken_slots,true,nullptr};
 auto negated=query::compile(R"({"schema_version":1,"relation":"class_defs","required_capabilities":["class_annotation_static"],"where":{"not":{"annotation":{"type":"Lfixture/Complex;","element":{"name":"n","int":-7}}}}})",std::pmr::get_default_resource(),std::pmr::get_default_resource());reference::Progress broken_progress;
 try{(void)reference::execute(broken,negated,broken_progress,std::pmr::get_default_resource());throw std::runtime_error("NOT swallowed corrupt data");}catch(const ReadError& e){CHECK(e.code==ReadCode::corrupt);}
 reference::SourceView excluded{0,0,&unsupported,{}},included{1,1,&facts,b};std::array<reference::SourceView,2> mixed{excluded,included};std::array<std::string_view,2> mixed_slots{"old","selected"};reference::DatasetView scoped_view{mixed,mixed_slots,false,nullptr};
 auto scoped=query::compile(R"({"schema_version":1,"relation":"class_defs","scope":{"slots":["selected"]},"required_capabilities":["class_annotation_static"],"where":{"annotation":{"type":"Lfixture/Complex;"}}})",std::pmr::get_default_resource(),std::pmr::get_default_resource());reference::Progress scoped_progress;auto selected=reference::execute(scoped_view,scoped,scoped_progress,std::pmr::get_default_resource());CHECK(selected.rows.size()==1&&selected.rows[0].source_index==1);
 std::cout<<"PASS annotation internal budget, cancellation and corrupted encoded value\n";return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}}
