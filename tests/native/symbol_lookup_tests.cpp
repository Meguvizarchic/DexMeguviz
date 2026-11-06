#include "facts/symbols.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>
using namespace dexmeguviz;
#define CHECK(x) do{if(!(x))throw std::runtime_error("symbol check at "+std::to_string(__LINE__)+": " #x);}while(0)
int main(int argc,char** argv){try{
    CHECK(argc==2);const std::filesystem::path root(argv[1]);unsigned checked=0;
    for(const auto* file:{"generated/minimal.dex","generated/extended/shared-items.dex","generated/method_facts/method-uses.dex","generated/definition_catalog/definitions.dex"}){
        std::ifstream in(root/file,std::ios::binary);CHECK(in.good());std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)),{});
        const auto f=read_metadata(bytes);
        for(uint32_t i=0;i<f.strings.size();++i){CHECK(symbols::string(f,f.strings[i])==i);++checked;}
        for(uint32_t i=0;i<f.types.size();++i){CHECK(symbols::type(f,f.strings[f.types[i]])==i);++checked;}
        for(uint32_t i=0;i<f.prototypes.size();++i){const auto& p=f.prototypes[i];CHECK(symbols::prototype(f,p.return_type,p.parameters)==i);++checked;}
        for(uint32_t i=0;i<f.method_refs.size();++i){
            const auto& r=f.method_refs[i];CHECK(symbols::method_ref(f,r.owner,r.name,r.type)==i);
            uint32_t scalar=UINT32_MAX;for(uint32_t j=0;j<f.methods.size();++j)if(f.methods[j].method_index==i)scalar=j;
            CHECK(symbols::method_definition(f,i)==scalar);++checked;
        }
        for(uint32_t i=0;i<f.field_refs.size();++i){
            const auto& r=f.field_refs[i];CHECK(symbols::field_ref(f,r.owner,r.name,r.type)==i);
            uint32_t scalar=UINT32_MAX;for(uint32_t j=0;j<f.field_definitions.size();++j)if(f.field_definitions[j].field_ref_index==i)scalar=j;
            CHECK(symbols::field_definition(f,i)==scalar);++checked;
        }
        for(uint32_t i=0;i<f.types.size();++i){uint32_t scalar=UINT32_MAX;for(uint32_t j=0;j<f.class_definitions.size();++j)if(f.class_definitions[j].type_id==i)scalar=j;CHECK(symbols::class_definition(f,i)==scalar);++checked;}
        CHECK(symbols::string(f,u"not-present-in-this-fixture")==symbols::no_index);
        CHECK(symbols::type(f,u"Lnot/present;")==symbols::no_index);
        CHECK(symbols::prototype(f,UINT32_MAX,{})==symbols::no_index);
        CHECK(symbols::method_ref(f,UINT32_MAX,UINT32_MAX,UINT32_MAX)==symbols::no_index);
        CHECK(symbols::field_definition(f,UINT32_MAX)==symbols::no_index);checked+=5;
    }
    std::cout<<"PASS symbol lookup: "<<checked<<" exact UTF16/type/prototype/member and reference-to-definition comparisons; external refs remain unresolved\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
