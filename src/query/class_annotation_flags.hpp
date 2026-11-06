#pragma once
#include "format/reader.hpp"
#include "query/reflection_flags.hpp"
#include <algorithm>
#include <cstdint>
#include <memory_resource>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>

// This model only inspects the immutable checked source selected by the caller.
// It does not resolve a runtime class, initialize a class, or authenticate origin.
namespace dexmeguviz::query::class_annotation_flags {
enum class Source : uint32_t { no_directory=0, no_class_set=1, no_system_inner=2, inner_int=3 };
struct Observation {
    std::optional<uint32_t> projected;
    Source source=Source::no_directory;
    uint32_t directory=0,set=0,item=0,value_offset=0,encoded=0;
};
struct Area { uint32_t offset=0;uint64_t end=0;bool present=false; };

template<class Charge>
class CheckedReader {
    std::span<const uint8_t> bytes;
    Charge& charge;
public:
    CheckedReader(std::span<const uint8_t> b,Charge& c):bytes(b),charge(c){}
    void range(uint64_t at,uint64_t amount,uint64_t end) {
        if(end>bytes.size()||at>end||amount>end-at)throw ReadError(ReadCode::corrupt,at,"class annotation range outside section");
    }
    uint8_t u8(uint64_t at,uint64_t end){charge(1);range(at,1,end);return bytes[at];}
    uint16_t u16(uint64_t at,uint64_t end){const auto a=u8(at,end),b=u8(at+1,end);return uint16_t(a)|(uint16_t(b)<<8);}
    uint32_t u32(uint64_t at,uint64_t end){uint32_t v=0;for(unsigned i=0;i<4;++i)v|=uint32_t(u8(at+i,end))<<(8*i);return v;}
    uint32_t uleb(uint64_t& at,uint64_t end){
        const auto start=at;uint32_t v=0;
        for(unsigned i=0;i<5;++i){const auto b=u8(at++,end);if(i==4&&(b&0xf0))throw ReadError(ReadCode::corrupt,start,"class annotation ULEB exceeds 32 bits");v|=uint32_t(b&127)<<(7*i);if(!(b&128))return v;}
        throw ReadError(ReadCode::corrupt,start,"unterminated class annotation ULEB");
    }
};

template<class Charge>
Observation inspect(std::span<const uint8_t> bytes,const Facts& facts,const ClassDefinition& klass,
                    std::pmr::memory_resource* memory,Charge& charge) {
    if(!memory)throw std::invalid_argument("class annotation memory resource required");
    Observation result;result.directory=klass.annotations_offset;
    result.projected=reflection_flags::project(klass.access_flags,reflection_flags::Target::klass,true);
    if(!result.projected||!klass.annotations_offset)return result;
    CheckedReader<Charge> r(bytes,charge);const auto end=uint64_t(bytes.size());
    const uint32_t map=r.u32(52,end),count=r.u32(map,end);if(!count||count>64)throw ReadError(ReadCode::corrupt,map,"invalid class annotation map");
    r.range(uint64_t(map)+4,uint64_t(count)*12,end);
    Area items,sets,dirs;uint32_t previous=0;
    for(uint32_t i=0;i<count;++i){
        const auto at=uint64_t(map)+4+uint64_t(i)*12;const auto type=r.u16(at,end);const auto n=r.u32(at+4,end),off=r.u32(at+8,end);
        if(!n||(i&&off<=previous)||off>=end)throw ReadError(ReadCode::corrupt,at,"invalid class annotation map order");
        const auto next=i+1<count?uint64_t(r.u32(at+20,end)):end;if(next<=off||next>end)throw ReadError(ReadCode::corrupt,at,"invalid class annotation section");
        previous=off;Area* area=type==0x2004?&items:type==0x1003?&sets:type==0x2006?&dirs:nullptr;
        if(area){if(area->present)throw ReadError(ReadCode::corrupt,at,"duplicate class annotation section");*area={off,next,true};}
    }
    const auto within=[&](const Area& area,uint64_t at,uint64_t n){if(!area.present||at<area.offset)throw ReadError(ReadCode::corrupt,at,"class annotation section missing");r.range(at,n,area.end);};
    within(dirs,result.directory,16);const uint32_t set=r.u32(result.directory,dirs.end);result.set=set;
    if(!set){result.source=Source::no_class_set;return result;}
    within(sets,set,4);const uint32_t entries=r.u32(set,sets.end);r.range(uint64_t(set)+4,uint64_t(entries)*4,sets.end);
    uint32_t previous_type=0;bool have_previous=false,seen=false;
    for(uint32_t i=0;i<entries;++i){
        const auto item=r.u32(uint64_t(set)+4+uint64_t(i)*4,sets.end);within(items,item,1);
        uint64_t at=item;const auto visibility=r.u8(at++,items.end);if(visibility>2)throw ReadError(ReadCode::corrupt,item,"invalid annotation visibility");
        const auto type=r.uleb(at,items.end);if(type>=facts.types.size()||facts.types[type]>=facts.strings.size())throw ReadError(ReadCode::corrupt,item,"annotation type outside table");
        if(have_previous&&type<=previous_type)throw ReadError(ReadCode::corrupt,item,"annotation types not strictly ordered");previous_type=type;have_previous=true;
        const auto& type_name=facts.strings[facts.types[type]];charge(30); // bounded comparison with the fixed descriptor
        if(visibility!=2||std::u16string_view(type_name)!=u"Ldalvik/annotation/InnerClass;")continue;
        if(seen)throw ReadError(ReadCode::corrupt,item,"duplicate inner class annotation");seen=true;result.item=item;
        const auto elements=r.uleb(at,items.end);if(elements>1000000u)throw ReadError(ReadCode::budget,at,"annotation element limit");
        struct Frame {uint32_t remaining;bool annotation;uint32_t previous;bool has_previous;};
        std::pmr::vector<Frame> stack(memory);stack.push_back({elements,true,0,false});bool found=false,valid=false;
        while(!stack.empty()){
            auto& frame=stack.back();if(!frame.remaining){stack.pop_back();continue;}
            uint32_t name=UINT32_MAX;if(frame.annotation){name=r.uleb(at,items.end);if(name>=facts.strings.size()||(frame.has_previous&&name<=frame.previous))throw ReadError(ReadCode::corrupt,at,"invalid annotation name");frame.previous=name;frame.has_previous=true;}
            if(stack.size()==1&&name!=UINT32_MAX)charge(11); // bounded fixed-name comparison
            const bool wanted=stack.size()==1&&name!=UINT32_MAX&&std::u16string_view(facts.strings[name])==u"accessFlags";
            --frame.remaining;const auto value_at=at;const auto tag=r.u8(at++,items.end);const unsigned kind=tag&31u,arg=unsigned(tag)>>5;
            if(wanted){if(found)throw ReadError(ReadCode::corrupt,value_at,"duplicate accessFlags");found=true;result.value_offset=static_cast<uint32_t>(value_at);}
            if(kind==0x1c||kind==0x1d){
                if(arg||stack.size()>=1024)throw ReadError(arg?ReadCode::corrupt:ReadCode::budget,value_at,"invalid nested annotation value");
                if(kind==0x1d){const auto nested_type=r.uleb(at,items.end);if(nested_type>=facts.types.size())throw ReadError(ReadCode::corrupt,at,"nested annotation type outside table");}
                const auto n=r.uleb(at,items.end);if(n>1000000u)throw ReadError(ReadCode::budget,at,"nested annotation element limit");stack.push_back({n,kind==0x1d,0,false});continue;
            }
            if(kind==0x1e||kind==0x1f){if((kind==0x1e&&arg)||(kind==0x1f&&arg>1))throw ReadError(ReadCode::corrupt,value_at,"invalid annotation scalar");continue;}
            unsigned max_arg;
            switch(kind){case 0x00:max_arg=0;break;case 0x02:case 0x03:max_arg=1;break;
                case 0x04:case 0x10:case 0x15:case 0x16:case 0x17:case 0x18:case 0x19:case 0x1a:case 0x1b:max_arg=3;break;
                case 0x06:case 0x11:max_arg=7;break;default:throw ReadError(ReadCode::corrupt,value_at,"unknown annotation scalar");}
            if(arg>max_arg)throw ReadError(ReadCode::corrupt,value_at,"invalid annotation scalar width");
            uint32_t bits=0;uint8_t last=0;
            for(unsigned j=0;j<=arg;++j){last=r.u8(at++,items.end);if(j<4)bits|=uint32_t(last)<<(j*8);}
            if(kind>=0x15 && kind<=0x1b){
                if((kind==0x15||kind==0x16)&&facts.dex_version<38)throw ReadError(ReadCode::corrupt,value_at,"method annotation value requires DEX 038");
                uint64_t bound=0;
                switch(kind){case 0x15:bound=facts.prototypes.size();break;case 0x16:bound=facts.method_handle_count;break;
                    case 0x17:bound=facts.strings.size();break;case 0x18:bound=facts.types.size();break;
                    case 0x19:case 0x1b:bound=facts.field_refs.size();break;case 0x1a:bound=facts.method_refs.size();break;}
                if(bits>=bound)throw ReadError(ReadCode::corrupt,value_at,"annotation reference outside table");
            }
            if(wanted&&kind==0x04){if(arg<3&&(last&0x80))bits|=~uint32_t(0)<<((arg+1)*8);result.encoded=bits;valid=true;}
        }
        result.source=Source::inner_int;
        if(!found||!valid){result.projected.reset();return result;}
        constexpr uint32_t inner_allowed=0x761fu;const auto visibility_bits=result.encoded&7u;
        if((result.encoded&~inner_allowed)||(visibility_bits&&(visibility_bits&(visibility_bits-1))))result.projected.reset();
        else result.projected=result.encoded&0xffffu;
    }
    if(!seen)result.source=Source::no_system_inner;
    return result;
}
}
