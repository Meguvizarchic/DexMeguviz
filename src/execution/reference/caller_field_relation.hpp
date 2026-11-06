#pragma once
#include "hierarchy.hpp"
#include <algorithm>
#include <span>

// Structural relations among selected immutable source occurrences only.
// This does not authenticate a ClassLoader or prove access/ART linkage.
namespace dexmeguviz::caller_field_relation {
enum class Status:uint32_t {self=1,ancestor=2,external=3,unknown=4};
enum class Reason:uint32_t {none=0,missing=1,ambiguous=2,cycle=3,invalid_type=4,interface_superclass=5};
enum class EdgeKind:uint32_t {root=0,interface_type=1,superclass=2};
struct Key {uint32_t source,ordinal;bool operator==(const Key&)const=default;};
struct Node {Key key;uint32_t parent;EdgeKind edge;uint32_t interface_index;};
struct Edge {uint32_t from,to;EdgeKind kind;uint32_t interface_index;};
struct InterfaceObjectCheck {uint32_t interface_node;Key object;};
struct Observation {
    Status status=Status::unknown;Reason reason=Reason::none;
    std::pmr::vector<Node> nodes;std::pmr::vector<Edge> edges;std::pmr::vector<InterfaceObjectCheck> object_checks;
    explicit Observation(std::pmr::memory_resource* r):nodes(r),edges(r),object_checks(r){}
};
inline Observation observe(std::span<const hierarchy::Source> sources,Key caller,Key target,
                           hierarchy::Budget& budget,std::pmr::memory_resource* memory){
    Observation out(memory);
    auto source_for=[&](uint32_t index)->const Facts&{
        for(const auto& x:sources){budget.charge();if(x.occurrence==index&&x.facts)return *x.facts;}
        throw std::invalid_argument("caller field class outside scope");
    };
    auto descriptor=[](const Facts& f,uint32_t t)->std::u16string_view{
        if(t>=f.types.size()||f.types[t]>=f.strings.size())throw std::invalid_argument("caller field invalid type");
        return f.strings[f.types[t]];
    };
    auto same=[&](std::u16string_view a,std::u16string_view z){
        budget.charge();if(a.size()!=z.size())return false;
        for(size_t i=0;i<a.size();i+=256){auto n=std::min<size_t>(256,a.size()-i);budget.charge(n);if(a.substr(i,n)!=z.substr(i,n))return false;}return true;
    };
    const auto& first=source_for(caller.source);const auto& last=source_for(target.source);
    if(caller.ordinal>=first.class_definitions.size()||target.ordinal>=last.class_definitions.size())throw std::invalid_argument("caller field class ordinal outside scope");
    const auto callerDesc=descriptor(first,first.class_definitions[caller.ordinal].type_id);
    const auto targetDesc=descriptor(last,last.class_definitions[target.ordinal].type_id);
    budget.bound(1);out.nodes.push_back({caller,UINT32_MAX,EdgeKind::root,UINT32_MAX});
    if(caller==target){out.status=Status::self;return out;}
    // Equal names in different occurrences cannot establish external identity.
    if(same(callerDesc,targetDesc)){out.nodes.clear();out.reason=Reason::ambiguous;return out;}
    bool uncertain=false;Reason firstReason=Reason::none;
    auto unknown=[&](Reason why){uncertain=true;if(firstReason==Reason::none)firstReason=why;};
    auto lookup=[&](std::u16string_view wanted,Key& found)->Reason{
        bool have=false;
        for(const auto& s:sources){if(!s.facts)throw std::invalid_argument("null caller field source");
            for(uint32_t i=0;i<s.facts->class_definitions.size();++i){budget.charge();const auto& c=s.facts->class_definitions[i];
                if(same(descriptor(*s.facts,c.type_id),wanted)){if(have)return Reason::ambiguous;have=true;found={s.occurrence,i};}
            }
        }
        return have?Reason::none:Reason::missing;
    };
    auto add_edge=[&](uint32_t from,std::u16string_view wanted,EdgeKind kind,uint32_t interfaceIndex)->bool{
        budget.charge();Key k{};const auto state=lookup(wanted,k);if(state!=Reason::none){unknown(state);return false;}
        const auto& f=source_for(k.source);const auto& cls=f.class_definitions[k.ordinal];
        if((kind==EdgeKind::interface_type&&!(cls.access_flags&0x200u))||(kind==EdgeKind::superclass&&(cls.access_flags&0x200u))){unknown(Reason::invalid_type);return false;}
        uint32_t to=UINT32_MAX;for(uint32_t i=0;i<out.nodes.size();++i){budget.charge();if(out.nodes[i].key==k){to=i;break;}}
        if(to==UINT32_MAX){if(out.nodes.size()>=UINT32_MAX)throw std::length_error("too many caller relation nodes");budget.bound(out.nodes.size()+out.edges.size()+out.object_checks.size()+1);to=static_cast<uint32_t>(out.nodes.size());out.nodes.push_back({k,from,kind,interfaceIndex});}
        budget.bound(out.nodes.size()+out.edges.size()+out.object_checks.size()+1);out.edges.push_back({from,to,kind,interfaceIndex});
        return k==target;
    };
    for(uint32_t current=0;current<out.nodes.size();++current){
        budget.charge();const auto n=out.nodes[current];const auto& f=source_for(n.key.source);const auto& cls=f.class_definitions[n.key.ordinal];
        for(uint32_t i=0;i<cls.interfaces.size();++i){if(add_edge(current,descriptor(f,cls.interfaces[i]),EdgeKind::interface_type,i)){out.status=Status::ancestor;goto found;}}
        if(cls.access_flags&0x200u){
            if(cls.superclass_type==UINT32_MAX||!same(descriptor(f,cls.superclass_type),u"Ljava/lang/Object;"))unknown(Reason::interface_superclass);
            else {
                // Object is a required validated interface convention, not an
                // interface ancestry edge. Missing/duplicate/invalid cannot
                // establish a closed graph for External.
                Key object{};const auto objectState=lookup(u"Ljava/lang/Object;",object);
                if(objectState!=Reason::none)unknown(objectState);
                else {
                    const auto& of=source_for(object.source);const auto& oc=of.class_definitions[object.ordinal];
                    if((oc.access_flags&1u)==0||(oc.access_flags&~0x1021u)!=0||oc.superclass_type!=UINT32_MAX||!oc.interfaces.empty())unknown(Reason::invalid_type);
                    else {budget.bound(out.nodes.size()+out.edges.size()+out.object_checks.size()+1);out.object_checks.push_back({current,object});}
                }
            }
        }else if(cls.superclass_type==UINT32_MAX){
            if(!same(descriptor(f,cls.type_id),u"Ljava/lang/Object;"))unknown(Reason::invalid_type);
        }else if(add_edge(current,descriptor(f,cls.superclass_type),EdgeKind::superclass,UINT32_MAX)){out.status=Status::ancestor;goto found;}
    }
    // A BFS spanning tree alone cannot distinguish diamonds from directed cycles.
    // Color the complete observed adjacency graph before proving External.
    {std::pmr::vector<uint8_t> color(out.nodes.size(),0,memory);std::pmr::vector<std::pair<uint32_t,uint32_t>> stack(memory);
     for(uint32_t start=0;start<out.nodes.size();++start){if(color[start])continue;budget.bound(out.nodes.size()+out.edges.size()+out.object_checks.size()+stack.size()+1);stack.push_back({start,0});color[start]=1;
      while(!stack.empty()){
       budget.charge();auto& frame=stack.back();uint32_t e=frame.second;
       while(e<out.edges.size()&&out.edges[e].from!=frame.first){budget.charge();++e;}
       if(e==out.edges.size()){color[frame.first]=2;stack.pop_back();continue;}
       frame.second=e+1;const auto child=out.edges[e].to;
       if(color[child]==1){unknown(Reason::cycle);continue;}
       if(color[child]==0){budget.bound(out.nodes.size()+out.edges.size()+out.object_checks.size()+stack.size()+1);color[child]=1;stack.push_back({child,0});}
      }
     }
    }
    if(uncertain){out.status=Status::unknown;out.reason=firstReason;out.nodes.clear();out.edges.clear();out.object_checks.clear();return out;}
    out.status=Status::external;return out;
found:
    // One path with uniquely resolved edges is asserted, not global path uniqueness or sibling completeness.
    {uint32_t index=UINT32_MAX;for(uint32_t i=0;i<out.nodes.size();++i)if(out.nodes[i].key==target){index=i;break;}
     if(index==UINT32_MAX)throw std::invalid_argument("caller relation target path missing");
     std::pmr::vector<Node> path(memory);for(uint32_t n=index;n!=UINT32_MAX;n=out.nodes[n].parent){budget.charge();budget.bound(path.size()+1);path.push_back(out.nodes[n]);}
     std::reverse(path.begin(),path.end());for(uint32_t i=0;i<path.size();++i)path[i].parent=i?i-1:UINT32_MAX;out.nodes=std::move(path);out.edges.clear();out.object_checks.clear();
    }
    return out;
}
}
