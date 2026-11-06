#pragma once
#include "hierarchy.hpp"
#include <algorithm>
#include <span>

// A scoped static candidate lookup, not a ClassLoader or access-control model.
namespace dexmeguviz::field_declaration {
enum class State { found, absent, unknown };
enum class Edge : uint32_t { root=0, interface_type=1, superclass=2 };
struct Step { uint32_t source, ordinal; Edge edge; uint32_t interface_index; };
struct Result {
    State state=State::unknown;
    std::pmr::vector<Step> path;
    uint32_t field_source=UINT32_MAX, field_ordinal=UINT32_MAX;
    explicit Result(std::pmr::memory_resource* r):path(r){}
};
inline Result lookup(std::span<const hierarchy::Source> sources,std::u16string_view owner,
                     std::u16string_view name,std::u16string_view type,
                     hierarchy::Budget& budget,std::pmr::memory_resource* memory) {
    Result out(memory);
    const auto equal=[&](std::u16string_view a,std::u16string_view b) {
        budget.charge();if(a.size()!=b.size())return false;
        for(size_t i=0;i<a.size();i+=256){const auto n=std::min<size_t>(256,a.size()-i);budget.charge(n);if(a.substr(i,n)!=b.substr(i,n))return false;}
        return true;
    };
    const auto descriptor=[](const Facts& f,uint32_t i)->std::u16string_view {
        if(i>=f.types.size()||f.types[i]>=f.strings.size())throw std::invalid_argument("field resolution invalid type");
        return f.strings[f.types[i]];
    };
    const auto search=[&](auto&& self,std::u16string_view wanted,Edge edge,uint32_t interface_index)->State {
        budget.charge();const hierarchy::Source* selected=nullptr;uint32_t ordinal=UINT32_MAX;
        for(const auto& src:sources){
            if(!src.facts)throw std::invalid_argument("field resolution null source");
            for(uint32_t i=0;i<src.facts->class_definitions.size();++i){
                budget.charge();const auto& cls=src.facts->class_definitions[i];
                if(equal(descriptor(*src.facts,cls.type_id),wanted)){
                    if(selected)return State::unknown;
                    selected=&src;ordinal=i;
                }
            }
        }
        if(!selected)return State::unknown;
        const auto& f=*selected->facts;const auto& cls=f.class_definitions[ordinal];
        if((edge==Edge::interface_type&&!(cls.access_flags&0x200u))||
           (edge==Edge::superclass&&(cls.access_flags&0x200u)))return State::unknown;
        for(const auto& step:out.path){budget.charge();if(step.source==selected->occurrence&&step.ordinal==ordinal)return State::unknown;}
        if(out.path.size()>=256)throw ReadError(ReadCode::budget,0,"field declaration depth limit exceeded");
        budget.bound(out.path.size()+1);out.path.push_back({selected->occurrence,ordinal,edge,interface_index});
        uint32_t found=UINT32_MAX;
        for(uint32_t i=0;i<f.field_definitions.size();++i){
            budget.charge();const auto& d=f.field_definitions[i];if(d.owner_type!=cls.type_id)continue;
            if((cls.access_flags&0x200u) && ((d.access_flags&0x19u)!=0x19u || (d.access_flags&7u)!=1u))return State::unknown;
            if(d.field_ref_index>=f.field_refs.size())throw std::invalid_argument("field definition reference outside table");
            const auto& r=f.field_refs[d.field_ref_index];if(r.name>=f.strings.size())throw std::invalid_argument("field name outside table");
            if(equal(f.strings[r.name],name)&&equal(descriptor(f,r.type),type)){
                if(found!=UINT32_MAX)return State::unknown;found=i;
            }
        }
        if(found!=UINT32_MAX){out.field_source=selected->occurrence;out.field_ordinal=found;return State::found;}
        for(uint32_t i=0;i<cls.interfaces.size();++i){
            budget.charge();const auto result=self(self,descriptor(f,cls.interfaces[i]),Edge::interface_type,i);
            if(result!=State::absent)return result;
        }
        // An interface's DEX superclass does not by itself establish its ART
        // superclass/search behavior. Never turn that edge into a known path.
        if((cls.access_flags&0x200u) && cls.superclass_type!=UINT32_MAX)return State::unknown;
        if(cls.superclass_type!=UINT32_MAX){
            const auto result=self(self,descriptor(f,cls.superclass_type),Edge::superclass,UINT32_MAX);
            if(result!=State::absent)return result;
        }
        out.path.pop_back();return State::absent;
    };
    out.state=search(search,owner,Edge::root,UINT32_MAX);
    return out;
}
}
