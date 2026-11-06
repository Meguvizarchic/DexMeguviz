#pragma once
#include "format/reader.hpp"
#include <algorithm>
#include <span>
#include <tuple>

namespace dexmeguviz::symbols {
constexpr uint32_t no_index=UINT32_MAX;
template<class Compare>uint32_t find_string(const Facts& f,Compare&& compare){
    size_t begin=0,end=f.strings.size();
    while(begin<end){const auto middle=begin+(end-begin)/2;if(compare(f.strings[middle])<0)begin=middle+1;else end=middle;}
    return begin<f.strings.size()&&compare(f.strings[begin])==0?static_cast<uint32_t>(begin):no_index;
}
inline uint32_t string(const Facts& f,std::u16string_view text)noexcept{
    return find_string(f,[text](std::u16string_view value)noexcept{return value.compare(text);});
}
// Compare in UTF-16 units and invoke the caller's accounting hook before
// each examined unit. Its exceptions are deliberately propagated.
template<class Charge>uint32_t string_with_work(const Facts& f,std::u16string_view text,Charge&& charge){
    return find_string(f,[&](std::u16string_view value){
        const auto length=std::min(value.size(),text.size());
        for(size_t i=0;i<length;++i){charge();if(value[i]!=text[i])return value[i]<text[i]?-1:1;}
        return value.size()==text.size()?0:value.size()<text.size()?-1:1;
    });
}
inline uint32_t type(const Facts& f,std::u16string_view descriptor)noexcept{
    const auto id=string(f,descriptor);if(id==no_index)return no_index;
    const auto it=std::lower_bound(f.types.begin(),f.types.end(),id);
    return it!=f.types.end()&&*it==id?static_cast<uint32_t>(it-f.types.begin()):no_index;
}
inline uint32_t prototype(const Facts& f,uint32_t return_type,std::span<const uint16_t> parameters)noexcept{
    struct Key{uint32_t result;std::span<const uint16_t> parameters;};
    const Key key{return_type,parameters};
    const auto it=std::lower_bound(f.prototypes.begin(),f.prototypes.end(),key,[](const Prototype& p,const Key& k){
        if(p.return_type!=k.result)return p.return_type<k.result;
        return std::lexicographical_compare(p.parameters.begin(),p.parameters.end(),k.parameters.begin(),k.parameters.end());
    });
    return it!=f.prototypes.end()&&it->return_type==return_type&&it->parameters.size()==parameters.size()&&
        std::equal(it->parameters.begin(),it->parameters.end(),parameters.begin())?static_cast<uint32_t>(it-f.prototypes.begin()):no_index;
}
template<class References>uint32_t member(const References& refs,uint32_t owner,uint32_t name,uint32_t type)noexcept{
    const auto key=std::tuple(owner,name,type);
    const auto it=std::lower_bound(refs.begin(),refs.end(),key,[](const auto& r,const auto& k){return std::tuple(uint32_t(r.owner),r.name,uint32_t(r.type))<k;});
    return it!=refs.end()&&it->owner==owner&&it->name==name&&it->type==type?static_cast<uint32_t>(it-refs.begin()):no_index;
}
inline uint32_t method_ref(const Facts& f,uint32_t owner,uint32_t name,uint32_t proto)noexcept{return member(f.method_refs,owner,name,proto);}
inline uint32_t field_ref(const Facts& f,uint32_t owner,uint32_t name,uint32_t type)noexcept{return member(f.field_refs,owner,name,type);}
inline uint32_t method_definition(const Facts& f,uint32_t reference)noexcept{return reference<f.method_definition_by_ref.size()?f.method_definition_by_ref[reference]:no_index;}
// This is only a classification within this immutable checked Facts object.
// No-local-definition says nothing about other source occurrences or loaders.
enum class MethodRefLocalKind { invalid_reference, invalid_metadata, no_local_definition, local_no_body, local_with_body };
struct MethodRefLocal { MethodRefLocalKind kind; uint32_t definition_ordinal; };
inline MethodRefLocal classify_method_ref(const Facts& f,uint32_t reference)noexcept{
    if(reference>=f.method_refs.size())return {MethodRefLocalKind::invalid_reference,no_index};
    if(reference>=f.method_definition_by_ref.size())return {MethodRefLocalKind::invalid_metadata,no_index};
    const auto definition=f.method_definition_by_ref[reference];
    if(definition==no_index)return {MethodRefLocalKind::no_local_definition,no_index};
    if(definition>=f.methods.size()||f.methods[definition].method_index!=reference)
        return {MethodRefLocalKind::invalid_metadata,no_index};
    return {f.methods[definition].code_offset?MethodRefLocalKind::local_with_body:MethodRefLocalKind::local_no_body,definition};
}
inline uint32_t field_definition(const Facts& f,uint32_t reference)noexcept{return reference<f.field_definition_by_ref.size()?f.field_definition_by_ref[reference]:no_index;}
inline uint32_t class_definition(const Facts& f,uint32_t type)noexcept{return type<f.class_definition_by_type.size()?f.class_definition_by_type[type]:no_index;}
}
