#include "execution/reference/interface_fields.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <string>
#include <vector>
using namespace dexmeguviz;namespace h=dexmeguviz::hierarchy;
#define CHECK(x) do{if(!(x))throw std::runtime_error("interface field line "+std::to_string(__LINE__)+": " #x);}while(0)
static std::vector<uint8_t> load(const std::filesystem::path& path){std::ifstream f(path,std::ios::binary);CHECK(f.good());return {std::istreambuf_iterator<char>(f),{}};}
struct Fixture {
    std::vector<std::vector<uint8_t>> bytes;std::vector<Facts> facts;std::vector<h::Source> sources;
    Fixture(const std::filesystem::path& root,const std::vector<std::string>& names){
        bytes.reserve(names.size());facts.reserve(names.size());sources.reserve(names.size());
        for(const auto& name:names){bytes.push_back(load(root/name));facts.push_back(read_metadata(bytes.back()));}
        for(uint32_t i=0;i<facts.size();++i)sources.push_back({i,&facts[i]});
    }
};
static bool match(void* context,const Facts& f,const FieldDefinition& d){return std::u16string_view(f.strings[f.field_refs[d.field_ref_index].name])==std::u16string_view(*static_cast<std::u16string*>(context));}
static h::InterfaceFieldResult run(Fixture& f,std::u16string name,uint32_t min,uint32_t max,bool complete=true){
    h::Budget budget{10000000};auto paths=h::resolve(f.sources,{0,0},complete,budget,std::pmr::get_default_resource());
    return h::interface_fields(f.sources,paths,complete,min,max,match,&name,budget,std::pmr::get_default_resource());
}
struct Tracking final:std::pmr::memory_resource{
    size_t active=0,attempts=0,fail_at=std::numeric_limits<size_t>::max();
    void* do_allocate(size_t size,size_t alignment)override{
        if(attempts++==fail_at)throw std::bad_alloc();void* p=std::pmr::new_delete_resource()->allocate(size,alignment);active+=size;return p;
    }
    void do_deallocate(void* p,size_t size,size_t alignment)override{CHECK(active>=size);active-=size;std::pmr::new_delete_resource()->deallocate(p,size,alignment);}
    bool do_is_equal(const std::pmr::memory_resource& other)const noexcept override{return this==&other;}
};
static uint32_t fields(const h::InterfaceFieldResult& result){uint32_t n=0;for(const auto& e:result.events)if(e.item==h::InterfaceItem::field)++n;return n;}
int main(int argc,char** argv){try{
    CHECK(argc==2);const std::filesystem::path dir(argv[1]);
    Fixture complete(dir,{"child.dex","base.dex","root.dex","top.dex","left.dex","right.dex"});
    for(auto item:{std::pair{u"diamond",1u},std::pair{u"hidden",0u},std::pair{u"same",2u},std::pair{u"classSame",2u},std::pair{u"override",2u},std::pair{u"missing",0u}}){
        auto result=run(complete,item.first,item.second,item.second);CHECK(result.truth==h::FieldTruth::yes&&fields(result)==item.second);
    }
    CHECK(run(complete,u"diamond",2,2).truth==h::FieldTruth::no);
    Fixture missing(dir,{"child.dex","base.dex","root.dex","left.dex","right.dex"});CHECK(run(missing,u"diamond",1,1).truth==h::FieldTruth::unknown);
    Fixture ambiguous(dir,{"child.dex","base.dex","root.dex","top.dex","left.dex","right.dex","left.dex"});CHECK(run(ambiguous,u"same",2,2).truth==h::FieldTruth::unknown);
    CHECK(run(complete,u"diamond",1,1,false).truth==h::FieldTruth::unknown);
    Fixture cycle(dir,{"child-cycle.dex","base.dex","root.dex","cycle.dex","cycle2.dex"});CHECK(run(cycle,u"cycle",1,1).truth==h::FieldTruth::unknown);
    for(const char* invalid:{"bad-instance.dex","bad-protected.dex","bad-nofinal.dex"}){
        Fixture bad(dir,{"child-bad.dex","base.dex","root.dex",invalid});auto result=run(bad,u"bad",1,1);
        CHECK(result.truth==h::FieldTruth::unknown);bool frontier=false;
        for(const auto& e:result.events)if(e.item==h::InterfaceItem::frontier&&e.detail==static_cast<uint32_t>(h::InterfaceFrontier::unsupported_interface_field))frontier=true;
        CHECK(frontier);
    }
    {Fixture bad(dir,{"child-bad.dex","base.dex","root.dex","bad-type.dex"});auto result=run(bad,u"bad",1,1);CHECK(result.truth==h::FieldTruth::unknown);bool frontier=false;
     for(const auto& e:result.events)if(e.item==h::InterfaceItem::frontier&&e.detail==static_cast<uint32_t>(h::InterfaceFrontier::unsupported_interface_type))frontier=true;CHECK(frontier);}
    {Fixture annotation(dir,{"child-bad.dex","base.dex","root.dex","annotation.dex"});CHECK(run(annotation,u"annotationField",1,1).truth==h::FieldTruth::yes);}
    CHECK(run(cycle,u"cycle",0,UINT32_MAX).truth==h::FieldTruth::yes);
    bool stopped=false;try{h::Budget budget{1};(void)h::resolve(complete.sources,{0,0},true,budget,std::pmr::get_default_resource());}catch(const ReadError& e){CHECK(e.code==ReadCode::budget);stopped=true;}CHECK(stopped);
    stopped=false;try{h::Budget budget{10000000};budget.cancelled=[](void*)noexcept{return true;};(void)h::resolve(complete.sources,{0,0},true,budget,std::pmr::get_default_resource());}catch(const h::Cancelled&){stopped=true;}CHECK(stopped);
    h::Budget prep{10000000};auto paths=h::resolve(complete.sources,{0,0},true,prep,std::pmr::get_default_resource());std::u16string wanted=u"diamond";
    stopped=false;{Tracking memory;try{h::Budget budget{5};(void)h::interface_fields(complete.sources,paths,true,1,1,match,&wanted,budget,&memory);}catch(const ReadError& e){CHECK(e.code==ReadCode::budget);stopped=true;}CHECK(memory.active==0);}CHECK(stopped);
    stopped=false;{Tracking memory;unsigned calls=0;try{h::Budget budget{10000000};budget.context=&calls;budget.cancelled=[](void* p)noexcept{return ++*static_cast<unsigned*>(p)>=7;};(void)h::interface_fields(complete.sources,paths,true,1,1,match,&wanted,budget,&memory);}catch(const h::Cancelled&){stopped=true;}CHECK(memory.active==0);}CHECK(stopped);
    unsigned failures=0,successes=0;for(size_t point=0;point<128;++point){Tracking memory;memory.fail_at=point;try{h::Budget budget{10000000};auto r=h::interface_fields(complete.sources,paths,true,1,1,match,&wanted,budget,&memory);CHECK(r.truth==h::FieldTruth::yes);++successes;}catch(const std::bad_alloc&){++failures;}CHECK(memory.active==0);}CHECK(failures>0&&successes>0);
    std::cout<<"PASS interface graph: diamond, hiding, same-name fields, missing, ambiguity, scope, cycle, budget and cancel\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
