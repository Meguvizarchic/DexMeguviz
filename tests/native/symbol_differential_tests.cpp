#include "facts/symbols.hpp"
#include "format/checked_leb128.hpp"
#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <tuple>
#include <vector>

using namespace dexmeguviz;
#define CHECK(x) do { if (!(x)) throw std::runtime_error("symbol differential line " + std::to_string(__LINE__) + ": " #x); } while (0)

static uint32_t linear_string(const Facts& f, std::u16string_view key) {
    for (uint32_t i=0; i<f.strings.size(); ++i) if (std::u16string_view(f.strings[i])==key) return i;
    return symbols::no_index;
}
struct WorkStop {};
struct WorkProbe {
    uint32_t used=0,limit=UINT32_MAX;
    void charge(){if(used==limit)throw WorkStop{};++used;}
};
// Independent copy of the previously deployed evaluator search and its
// per-unit accounting; used to lock down budget and failure boundaries.
static uint32_t prior_production_lookup(const Facts& f,std::u16string_view text,WorkProbe& work) {
    size_t begin=0,end=f.strings.size();
    auto compare=[&](std::u16string_view value){
        const auto length=std::min(value.size(),text.size());
        for(size_t i=0;i<length;++i){work.charge();if(value[i]!=text[i])return value[i]<text[i]?-1:1;}
        return value.size()==text.size()?0:value.size()<text.size()?-1:1;
    };
    while(begin<end){const auto middle=begin+(end-begin)/2;if(compare(f.strings[middle])<0)begin=middle+1;else end=middle;}
    return begin<f.strings.size()&&compare(f.strings[begin])==0?static_cast<uint32_t>(begin):symbols::no_index;
}
static void checked_string_lookup(const Facts& f,std::u16string_view key,unsigned& checks){
    WorkProbe total;
    const auto expected=prior_production_lookup(f,key,total);
    CHECK(expected==linear_string(f,key));
    for(uint32_t limit=0;limit<=total.used+1;++limit){
        WorkProbe old{0,limit},current{0,limit};
        uint32_t old_result=UINT32_MAX,new_result=UINT32_MAX;bool old_stopped=false,new_stopped=false;
        try{old_result=prior_production_lookup(f,key,old);}catch(const WorkStop&){old_stopped=true;}
        try{new_result=symbols::string_with_work(f,key,[&]{current.charge();});}catch(const WorkStop&){new_stopped=true;}
        CHECK(old_stopped==new_stopped && old.used==current.used && old_result==new_result);
        if(!new_stopped)CHECK(new_result==expected);
        ++checks;
    }
}
static uint32_t linear_type(const Facts& f, std::u16string_view key) {
    for (uint32_t i=0; i<f.types.size(); ++i) if (std::u16string_view(f.strings[f.types[i]])==key) return i;
    return symbols::no_index;
}
static uint32_t linear_proto(const Facts& f, uint32_t result, const std::vector<uint16_t>& params) {
    for (uint32_t i=0; i<f.prototypes.size(); ++i) {
        const auto& p=f.prototypes[i];
        if (p.return_type==result && p.parameters.size()==params.size() &&
            std::equal(p.parameters.begin(),p.parameters.end(),params.begin())) return i;
    }
    return symbols::no_index;
}
template<class Refs> static uint32_t linear_member(const Refs& refs,uint32_t owner,uint32_t name,uint32_t type) {
    for (uint32_t i=0; i<refs.size(); ++i)
        if (refs[i].owner==owner && refs[i].name==name && refs[i].type==type) return i;
    return symbols::no_index;
}
static std::vector<uint8_t> load(const std::filesystem::path& p) {
    std::ifstream in(p,std::ios::binary); CHECK(in.good());
    return {(std::istreambuf_iterator<char>(in)),{}};
}
static void uleb_boundaries(unsigned& checks) {
    struct Vector {std::vector<uint8_t> bytes;uint32_t expected;};
    const std::vector<Vector> vectors{
        {{0x00},0},{{0x7f},127},{{0x80,0x01},128},
        {{0x80,0x00},0},{{0xff,0xff,0xff,0xff,0x0f},UINT32_MAX}
    };
    for (const auto& v:vectors) {
        uint64_t cursor=0;
        CHECK(detail::read_uleb32(v.bytes,cursor,v.bytes.size())==v.expected);
        CHECK(cursor==v.bytes.size());++checks;
    }
    const std::vector<std::vector<uint8_t>> invalid{
        {},{0x80},{0x80,0x80,0x80,0x80,0x10},
        {0x80,0x80,0x80,0x80,0x80}
    };
    for (const auto& v:invalid) {
        bool corrupt=false;uint64_t cursor=0;
        try {(void)detail::read_uleb32(v,cursor,v.size());}
        catch(const ReadError& e){CHECK(e.code==ReadCode::corrupt);corrupt=true;}
        CHECK(corrupt);++checks;
    }
    const std::array<uint8_t,2> bounded{0x80,0};
    for (const auto [initial,end]:std::array<std::pair<uint64_t,uint64_t>,3>{{{0,1},{3,2},{0,3}}}) {
        bool corrupt=false;uint64_t cursor=initial;
        try {(void)detail::read_uleb32(bounded,cursor,end);}
        catch(const ReadError& e){CHECK(e.code==ReadCode::corrupt);corrupt=true;}
        CHECK(corrupt);++checks;
    }
}
static void dex_unicode(const std::filesystem::path& directory,unsigned& checks) {
    struct Case {const char* name; std::vector<uint16_t> units;};
    const std::vector<Case> cases{
        {"lone-high.dex",{0xd800}}, {"lone-low.dex",{0xdc00}},
        {"mixed-unpaired.dex",{0xd800,0x78,0xdc00,0,0xd83d,0xde00}}
    };
    for (const auto& c:cases) {
        const auto bytes=load(directory/c.name); const auto f=read_metadata(bytes);
        const std::u16string key(c.units.begin(),c.units.end());
        const auto index=linear_string(f,key);
        CHECK(index!=symbols::no_index && symbols::string(f,key)==index);
        checked_string_lookup(f,key,checks);
        for (const auto& s:f.strings) {
            std::u16string exact(s.begin(),s.end());
            CHECK(symbols::string(f,exact)==linear_string(f,exact));
            exact.push_back(0);
            CHECK(symbols::string(f,exact)==linear_string(f,exact));
            checks+=2;
        }
        ++checks;
    }
}
static void synthetic(unsigned& checks) {
    Facts f;
    const std::vector<std::u16string> strings{
        std::u16string{0}, u"a", std::u16string{u'a',0}, u"ab",
        std::u16string{0xd7ff}, std::u16string{0xd800},
        std::u16string{0xd800,0xdc00}, std::u16string{0xdc00}, std::u16string{0xffff}
    };
    CHECK(std::is_sorted(strings.begin(),strings.end()));
    for (const auto& s:strings) f.strings.emplace_back(s.begin(),s.end());
    f.types={1,3,5,7};
    const std::vector<std::u16string> needles{
        {},std::u16string{0},std::u16string{1},u"a",std::u16string{u'a',0},
        std::u16string{u'a',1},u"ab",u"abc",std::u16string{0xd7ff},
        std::u16string{0xd800},std::u16string{0xd800,0xdbff},
        std::u16string{0xd800,0xdc00},std::u16string{0xdc00},
        std::u16string{0xffff},std::u16string{0xffff,0}
    };
    unsigned before=0,middle=0,after=0;
    for (const auto& key:needles) {
        const auto expected=linear_string(f,key);
        CHECK(symbols::string(f,key)==expected);
        CHECK(symbols::type(f,key)==linear_type(f,key));
        checked_string_lookup(f,key,checks);
        if (expected==symbols::no_index) {
            size_t insert=0;for(const auto& value:strings) if(value<key) ++insert;
            if(insert==0)++before; else if(insert==strings.size())++after; else ++middle;
        }
        checks+=2;
    }
    // The explicit empty table exercises insertion before the first element.
    Facts empty; CHECK(symbols::string(empty,u"a")==symbols::no_index);
    CHECK(symbols::type(empty,u"a")==symbols::no_index);
    checked_string_lookup(empty,{},checks);
    checked_string_lookup(empty,u"a",checks);
    Facts with_empty;
    with_empty.strings.emplace_back();
    with_empty.strings.emplace_back(u"a");
    checked_string_lookup(with_empty,{},checks);
    checked_string_lookup(with_empty,u"a",checks);
    checked_string_lookup(with_empty,u"b",checks);
    CHECK(before>0 && middle>0 && after>0);checks+=2;
    auto add_proto=[&](uint32_t result,std::initializer_list<uint16_t> args){
        f.prototypes.emplace_back();auto& p=f.prototypes.back();p.return_type=result;p.parameters.assign(args);
    };
    add_proto(0,{});add_proto(0,{0});add_proto(0,{0,1});add_proto(0,{1});
    add_proto(1,{});add_proto(1,{0});add_proto(3,{});
    const std::vector<std::vector<uint16_t>> params{{},{0},{0,0},{0,1},{0,2},{1},{2}};
    for(uint32_t result=0;result<5;++result)for(const auto& args:params){
        CHECK(symbols::prototype(f,result,args)==linear_proto(f,result,args));++checks;
    }
    CHECK(symbols::prototype(empty,0,{})==symbols::no_index);++checks;
    for(uint16_t owner:{uint16_t(0),uint16_t(1),uint16_t(3)})
        for(uint32_t name:{0u,2u,4u})for(uint16_t type:{uint16_t(0),uint16_t(2),uint16_t(4)}){
            MethodReference m{};m.owner=owner;m.name=name;m.type=type;f.method_refs.push_back(m);
            FieldReference field{};field.owner=owner;field.name=name;field.type=type;f.field_refs.push_back(field);
        }
    for(uint32_t owner=0;owner<5;++owner)for(uint32_t name=0;name<6;++name)for(uint32_t type=0;type<6;++type){
        CHECK(symbols::method_ref(f,owner,name,type)==linear_member(f.method_refs,owner,name,type));
        CHECK(symbols::field_ref(f,owner,name,type)==linear_member(f.field_refs,owner,name,type));checks+=2;
    }
    CHECK(symbols::method_ref(empty,0,0,0)==symbols::no_index);
    CHECK(symbols::field_ref(empty,0,0,0)==symbols::no_index);checks+=2;
    std::cout<<"missing-key positions: before="<<before<<", middle="<<middle<<", after="<<after<<", empty-table="<<1<<"\n";
}
int main(int argc,char** argv) {
    try {CHECK(argc==2);unsigned checks=0;uleb_boundaries(checks);dex_unicode(argv[1],checks);synthetic(checks);
        std::cout<<"PASS: "<<checks<<" differential lookups and real DEX UTF-16 identities\n";return 0;
    } catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
