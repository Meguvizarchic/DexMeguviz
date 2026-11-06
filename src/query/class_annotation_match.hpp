#pragma once
#include "query/ir.hpp"
#include "query/class_annotation_flags.hpp"
#include <cstdint>
#include <span>
#include <string_view>

// Source-local static class annotation query; no runtime/default-value resolution.
namespace dexmeguviz::query::class_annotation_match {
enum class Match { no, yes, unknown };
using class_annotation_flags::Area;
using class_annotation_flags::CheckedReader;
// Owned by one Evaluator, never shared across sources or executions.
struct MapCache {
    const uint8_t* data=nullptr;
    size_t size=0;
    const Facts* facts=nullptr;
    Area items{},sets{},dirs{};
    uint64_t work_units=0;
    bool ready=false;
};

template<class Charge>
uint32_t value(CheckedReader<Charge>& r,uint64_t& at,uint64_t end,const Facts& facts,unsigned depth,uint32_t& actual_kind){
    if(depth>=64)throw Error(ErrorCode::budget,"annotation nesting limit");
    const auto pos=at;const auto tag=r.u8(at++,end);const unsigned kind=tag&31u,arg=tag>>5;actual_kind=kind;
    if(kind==0x1c||kind==0x1d){
        if(arg)throw ReadError(ReadCode::corrupt,pos,"annotation nested value arg");
        if(kind==0x1d&&r.uleb(at,end)>=facts.types.size())throw ReadError(ReadCode::corrupt,pos,"annotation nested type");
        const auto count=r.uleb(at,end);if(count>100000u)throw Error(ErrorCode::budget,"annotation nested value count");
        uint32_t previous=0;bool have=false;
        for(uint32_t i=0;i<count;++i){if(kind==0x1d){const auto name=r.uleb(at,end);if(name>=facts.strings.size()||(have&&name<=previous))throw ReadError(ReadCode::corrupt,at,"annotation nested element name");previous=name;have=true;}uint32_t ignored=0;(void)value(r,at,end,facts,depth+1,ignored);}return 0;
    }
    if(kind==0x1e||kind==0x1f){if((kind==0x1e&&arg)||(kind==0x1f&&arg>1))throw ReadError(ReadCode::corrupt,pos,"annotation simple value arg");return 0;}
    unsigned maximum=0;switch(kind){case 0x00:maximum=0;break;case 0x02:case 0x03:maximum=1;break;
        case 0x04:case 0x10:case 0x15:case 0x16:case 0x17:case 0x18:case 0x19:case 0x1a:case 0x1b:maximum=3;break;
        case 0x06:case 0x11:maximum=7;break;default:throw ReadError(ReadCode::corrupt,pos,"annotation value kind");}
    if(arg>maximum)throw ReadError(ReadCode::corrupt,pos,"annotation value width");uint64_t bits=0;uint8_t last=0;
    for(unsigned i=0;i<=arg;++i){last=r.u8(at++,end);bits|=uint64_t(last)<<(8*i);}
    if(kind>=0x15&&kind<=0x1b){
        if((kind==0x15||kind==0x16)&&facts.dex_version<38)throw ReadError(ReadCode::corrupt,pos,"annotation method constant version");
        uint64_t bound=0;switch(kind){case 0x15:bound=facts.prototypes.size();break;case 0x16:bound=facts.method_handle_count;break;case 0x17:bound=facts.strings.size();break;case 0x18:bound=facts.types.size();break;case 0x19:case 0x1b:bound=facts.field_refs.size();break;case 0x1a:bound=facts.method_refs.size();break;}
        if(bits>=bound)throw ReadError(ReadCode::corrupt,pos,"annotation reference index");
    }
    uint32_t result=static_cast<uint32_t>(bits);if(kind==0x04&&arg<3&&(last&0x80))result|=~uint32_t(0)<<((arg+1)*8);return result;
}

template<class Charge>
Match inspect(std::span<const uint8_t> bytes,const Facts& facts,const ClassDefinition& klass,
              std::u16string_view descriptor,uint32_t visibility,std::u16string_view element,bool has_element,uint32_t expected,Charge& charge,MapCache* cache=nullptr,const std::u16string_view* expected_string=nullptr){
    if(!klass.annotations_offset)return Match::no;
    CheckedReader<Charge> r(bytes,charge);const uint64_t end=bytes.size();
    Area items,sets,dirs;
    if(cache&&cache->ready&&cache->data==bytes.data()&&cache->size==bytes.size()&&cache->facts==&facts){
        // Preserve each original byte charge, including budget failure and
        // cancellation checkpoints. Cached source bytes must remain immutable.
        for(uint64_t i=0;i<cache->work_units;++i)charge(1);
        items=cache->items;sets=cache->sets;dirs=cache->dirs;
    }else{
        const auto map=r.u32(52,end),count=r.u32(map,end);
        if(!count||count>1000)throw ReadError(ReadCode::corrupt,map,"annotation map count");r.range(uint64_t(map)+4,uint64_t(count)*12,end);
        uint32_t previous_offset=0;
        for(uint32_t i=0;i<count;++i){const uint64_t at=uint64_t(map)+4+uint64_t(i)*12;const auto type=r.u16(at,end);const auto offset=r.u32(at+8,end);const auto next=i+1<count?uint64_t(r.u32(at+20,end)):end;
            if((i&&offset<=previous_offset)||next<=offset||next>end)throw ReadError(ReadCode::corrupt,at,"annotation map range");previous_offset=offset;
            Area* a=type==0x2004?&items:type==0x1003?&sets:type==0x2006?&dirs:nullptr;if(a){if(a->present)throw ReadError(ReadCode::corrupt,at,"duplicate annotation section");*a={offset,next,true};}}
        if(cache){cache->data=bytes.data();cache->size=bytes.size();cache->facts=&facts;cache->items=items;cache->sets=sets;cache->dirs=dirs;cache->work_units=4u+uint64_t(count)*10u;cache->ready=true;}
    }
    const auto inside=[&](const Area& a,uint64_t at,uint64_t n){if(!a.present||at<a.offset)throw ReadError(ReadCode::corrupt,at,"annotation section missing");r.range(at,n,a.end);};
    inside(dirs,klass.annotations_offset,16);const auto set=r.u32(klass.annotations_offset,dirs.end);if(!set)return Match::no;
    inside(sets,set,4);const auto n=r.u32(set,sets.end);r.range(uint64_t(set)+4,uint64_t(n)*4,sets.end);
    uint32_t previous=0;bool have=false;Match result=Match::no;
    for(uint32_t i=0;i<n;++i){const auto item=r.u32(uint64_t(set)+4+uint64_t(i)*4,sets.end);inside(items,item,1);uint64_t at=item;
        const auto seen_visibility=r.u8(at++,items.end);if(seen_visibility>2)throw ReadError(ReadCode::corrupt,item,"annotation visibility");
        const auto type=r.uleb(at,items.end);if(type>=facts.types.size()||facts.types[type]>=facts.strings.size()||(have&&type<=previous))throw ReadError(ReadCode::corrupt,item,"annotation type/order");previous=type;have=true;
        const auto& actual_type=facts.strings[facts.types[type]];charge(descriptor.size());
        const bool wanted=std::u16string_view(actual_type)==descriptor&&(!visibility||visibility-1==seen_visibility);
        const auto elements=r.uleb(at,items.end);if(elements>100000u)throw Error(ErrorCode::budget,"annotation element count");
        uint32_t previous_name=0;bool have_name=false,found=false;Match current=has_element?Match::unknown:Match::yes;
        for(uint32_t j=0;j<elements;++j){const auto name=r.uleb(at,items.end);if(name>=facts.strings.size()||(have_name&&name<=previous_name))throw ReadError(ReadCode::corrupt,at,"annotation element name/order");previous_name=name;have_name=true;
            bool selected=false;if(wanted&&has_element){charge(element.size());selected=std::u16string_view(facts.strings[name])==element;}
            uint32_t kind=0;const auto bits=value(r,at,items.end,facts,0,kind);if(selected){found=true;if(!expected_string)current=kind==0x04&&bits==expected?Match::yes:Match::no;
                else if(kind!=0x17)current=Match::no;
                else {const std::u16string_view actual=facts.strings[bits];bool equal=actual.size()==expected_string->size();
                    if(equal)for(size_t unit=0;unit<actual.size();++unit){charge(1);if(actual[unit]!=(*expected_string)[unit]){equal=false;break;}}
                    current=equal?Match::yes:Match::no;}}}
        if(wanted)result=has_element&&!found?Match::unknown:current;
    }
    return result;
}
}
