#pragma once
#include "inherited_fields.hpp"
#include "query/ir.hpp"

// Static superclass + superinterface member model. No loader binding,
// reflection, reachability, or Java type-verification is implied.
namespace dexmeguviz::hierarchy {
enum class InterfaceItem:uint32_t {node=1,edge=2,frontier=3,field=4,branch=5};
enum class InterfaceFrontier:uint32_t {missing=1,ambiguous=2,not_interface=3,incomplete=4,cycle=5,access_unknown=6,unsupported_interface_field=7,unsupported_interface_type=8,interface_root_unsupported=9,interface_as_superclass=10};
struct InterfaceEvent {
    InterfaceItem item;
    uint32_t branch,node,aux,detail,source,ordinal;
    query::Relation relation;
};
struct InterfaceFieldResult {
    FieldTruth truth=FieldTruth::unknown;
    std::pmr::vector<InterfaceEvent> events;
    explicit InterfaceFieldResult(std::pmr::memory_resource* r):events(r){}
};

inline InterfaceFieldResult interface_fields(std::span<const Source> sources,const Result& classes,bool scope_complete,
    uint32_t minimum,uint32_t maximum,FieldMatcher matcher,void* matcher_context,Budget& budget,std::pmr::memory_resource* memory){
    if(!memory||!matcher||minimum>maximum||classes.paths.empty())throw std::invalid_argument("invalid interface field request");
    struct Node {ClassKey key;bool is_interface=false;};
    struct Edge {uint32_t from,to,type,kind;};
    struct Member {uint32_t node;FieldKey key;std::u16string_view name;uint32_t flags;};
    InterfaceFieldResult output(memory);bool saw_yes=false,saw_no=false,saw_unknown=false;
    auto emit=[&](InterfaceItem kind,uint32_t branch,uint32_t node,uint32_t aux,uint32_t detail,uint32_t source,query::Relation relation,uint32_t ordinal){
        budget.charge();budget.bound(output.events.size()+1);output.events.push_back({kind,branch,node,aux,detail,source,ordinal,relation});
    };
    auto facts_for=[&](uint32_t occurrence)->const Facts&{
        for(const auto& s:sources){budget.charge();if(s.occurrence==occurrence&&s.facts)return *s.facts;}
        throw std::invalid_argument("interface occurrence outside scope");
    };
    auto name_of=[&](const Facts& f,uint32_t type)->std::u16string_view{
        if(type>=f.types.size()||f.types[type]>=f.strings.size())throw std::invalid_argument("invalid interface type");return f.strings[f.types[type]];
    };
    auto equal=[&](std::u16string_view a,std::u16string_view b){
        budget.charge();if(a.size()!=b.size())return false;
        for(size_t i=0;i<a.size();){const auto n=std::min<size_t>(256,a.size()-i);budget.charge(n);if(a.substr(i,n)!=b.substr(i,n))return false;i+=n;}return true;
    };
    for(uint32_t branch=0;branch<classes.ends.size();++branch){
        budget.charge();const auto end=classes.ends[branch];
        std::pmr::vector<uint32_t> chain(memory);for(uint32_t p=end.path;p!=UINT32_MAX;){
            budget.charge();if(p>=classes.paths.size()||chain.size()>=classes.paths.size())throw std::invalid_argument("invalid superclass branch");chain.push_back(p);p=classes.paths[p].parent;
        }
        if(chain.empty()||chain.back()!=0)throw std::invalid_argument("superclass root mismatch");std::reverse(chain.begin(),chain.end());
        std::pmr::vector<Node> nodes(memory);std::pmr::vector<Edge> edges(memory);bool incomplete=end.reason!=Stop::no_superclass||!scope_complete;
        auto add_node=[&](ClassKey key,bool is_interface){
            for(uint32_t i=0;i<nodes.size();++i){budget.charge();if(nodes[i].key==key)return i;}
            budget.bound(nodes.size()+1);nodes.push_back({key,is_interface});return static_cast<uint32_t>(nodes.size()-1);
        };
        auto add_edge=[&](uint32_t from,uint32_t to,uint32_t type,uint32_t kind){budget.charge();budget.bound(edges.size()+1);edges.push_back({from,to,type,kind});};
        for(size_t i=0;i<chain.size();++i){const auto key=classes.paths[chain[i]].key;const auto& f=facts_for(key.occurrence);
            if(key.ordinal>=f.class_definitions.size())throw std::invalid_argument("invalid hierarchy class");
            const auto id=add_node(key,(f.class_definitions[key.ordinal].access_flags&0x200u)!=0);
            if(id!=i){incomplete=true;break;}
            if(nodes[id].is_interface){incomplete=true;if(i)emit(InterfaceItem::frontier,branch,id,0,static_cast<uint32_t>(InterfaceFrontier::interface_as_superclass),key.occurrence,query::Relation::class_defs,key.ordinal);}
            if(i){const auto& child=facts_for(nodes[i-1].key.occurrence).class_definitions[nodes[i-1].key.ordinal];add_edge(static_cast<uint32_t>(i-1),id,child.superclass_type,0);}
        }
        if(nodes.empty())throw std::invalid_argument("empty interface branch");
        if(nodes[0].is_interface){incomplete=true;emit(InterfaceItem::frontier,branch,0,0,static_cast<uint32_t>(InterfaceFrontier::interface_root_unsupported),nodes[0].key.occurrence,query::Relation::class_defs,nodes[0].key.ordinal);}
        for(uint32_t from=0;from<nodes.size();++from){
            budget.charge();const auto key=nodes[from].key;const auto& f=facts_for(key.occurrence);const auto& cls=f.class_definitions[key.ordinal];
            for(const auto type:cls.interfaces){
                budget.charge();const auto wanted=name_of(f,type);std::pmr::vector<ClassKey> found(memory);
                for(const auto& source:sources)for(uint32_t i=0;i<source.facts->class_definitions.size();++i){
                    budget.charge();if(equal(wanted,name_of(*source.facts,source.facts->class_definitions[i].type_id))){budget.bound(found.size()+1);found.push_back({source.occurrence,i});}
                }
                if(found.size()!=1){incomplete=true;emit(InterfaceItem::frontier,branch,from,static_cast<uint32_t>(found.size()),static_cast<uint32_t>(found.empty()?InterfaceFrontier::missing:InterfaceFrontier::ambiguous),key.occurrence,query::Relation::type_refs,type);continue;}
                const auto target=found[0];const auto& tf=facts_for(target.occurrence);const auto& definition=tf.class_definitions[target.ordinal];
                if(!(definition.access_flags&0x200u)){incomplete=true;emit(InterfaceItem::frontier,branch,from,1,static_cast<uint32_t>(InterfaceFrontier::not_interface),key.occurrence,query::Relation::type_refs,type);continue;}
                // Public abstract interfaces, including annotation/synthetic
                // variants, are the statically supported type form. A
                // package-visible or otherwise unusual form may be valid in
                // some contexts, but its accessibility is not established.
                if((definition.access_flags&0x601u)!=0x601u||(definition.access_flags&~0x3601u)!=0){
                    incomplete=true;emit(InterfaceItem::frontier,branch,from,1,static_cast<uint32_t>(InterfaceFrontier::unsupported_interface_type),key.occurrence,query::Relation::type_refs,type);
                }
                const auto to=add_node(target,true);add_edge(from,to,type,1);
            }
        }
        for(uint32_t i=0;i<nodes.size();++i)emit(InterfaceItem::node,branch,i,UINT32_MAX,nodes[i].is_interface?1u:0u,nodes[i].key.occurrence,query::Relation::class_defs,nodes[i].key.ordinal);
        for(const auto& e:edges)emit(InterfaceItem::edge,branch,e.from,e.to,e.kind,nodes[e.from].key.occurrence,query::Relation::type_refs,e.type);
        if(end.reason!=Stop::no_superclass||!scope_complete)emit(InterfaceItem::frontier,branch,0,0,static_cast<uint32_t>(InterfaceFrontier::incomplete),nodes[0].key.occurrence,query::Relation::class_defs,nodes[0].key.ordinal);
        std::pmr::vector<uint8_t> done(nodes.size(),0,memory);std::pmr::vector<Member> members(memory);size_t completed=0;
        while(completed<nodes.size()){
            bool advanced=false;
            for(uint32_t i=0;i<nodes.size();++i){
                budget.charge();if(done[i])continue;bool ready=true;for(const auto& edge:edges){budget.charge();if(edge.from==i&&!done[edge.to]){ready=false;break;}}
                if(!ready)continue;const auto key=nodes[i].key;const auto& f=facts_for(key.occurrence);const auto& cls=f.class_definitions[key.ordinal];
                std::pmr::vector<Member> own(memory);for(uint32_t field_index=0;field_index<f.field_definitions.size();++field_index){
                    budget.charge();if(budget.field_observed)budget.field_observed(budget.external_context);const auto& field=f.field_definitions[field_index];if(field.owner_type!=cls.type_id)continue;
                    if(field.field_ref_index>=f.field_refs.size())throw std::invalid_argument("invalid interface field ref");const auto& ref=f.field_refs[field.field_ref_index];
                    if(ref.name>=f.strings.size())throw std::invalid_argument("invalid interface field name");
                    // The v8 static model recognizes public static final fields,
                    // optionally synthetic. Other interface-field forms remain
                    // Unknown rather than being treated as Java declarations.
                    if(nodes[i].is_interface&&((field.access_flags&0x19u)!=0x19u||(field.access_flags&~0x1019u)!=0)){
                        incomplete=true;emit(InterfaceItem::frontier,branch,i,field_index,static_cast<uint32_t>(InterfaceFrontier::unsupported_interface_field),key.occurrence,query::Relation::field_defs,field_index);
                    }
                    budget.bound(own.size()+1);own.push_back({i,{key.occurrence,field_index},f.strings[ref.name],field.access_flags});
                }
                for(const auto& edge:edges){budget.charge();if(edge.from!=i)continue;
                    const size_t existing_members=members.size();for(size_t mi=0;mi<existing_members;++mi){budget.charge();const auto member=members[mi];if(member.node!=edge.to)continue;
                        const auto visibility=member.flags&7u;if(visibility==2u)continue;
                        bool hidden=false;for(const auto& declaration:own)if(equal(member.name,declaration.name)){hidden=true;break;}if(hidden)continue;
                        if(visibility!=1u&&visibility!=4u){incomplete=true;emit(InterfaceItem::frontier,branch,i,0,static_cast<uint32_t>(InterfaceFrontier::access_unknown),key.occurrence,query::Relation::class_defs,key.ordinal);continue;}
                        bool duplicate=false;for(const auto& prior:members){budget.charge();if(prior.node==i&&prior.key==member.key){duplicate=true;break;}}
                        if(!duplicate){budget.bound(members.size()+1);members.push_back({i,member.key,member.name,member.flags});}
                    }
                }
                for(const auto& member:own){budget.bound(members.size()+1);members.push_back(member);}
                done[i]=1;++completed;advanced=true;
            }
            if(!advanced){incomplete=true;emit(InterfaceItem::frontier,branch,0,0,static_cast<uint32_t>(InterfaceFrontier::cycle),nodes[0].key.occurrence,query::Relation::class_defs,nodes[0].key.ordinal);break;}
        }
        uint32_t count=0;
        if(done[0])for(const auto& member:members){
            budget.charge();if(member.node!=0||(member.key.occurrence==nodes[0].key.occurrence&&facts_for(member.key.occurrence).field_definitions[member.key.ordinal].owner_type==facts_for(nodes[0].key.occurrence).class_definitions[nodes[0].key.ordinal].type_id))continue;
            const auto& f=facts_for(member.key.occurrence);const auto& field=f.field_definitions[member.key.ordinal];if(!matcher(matcher_context,f,field))continue;
            if(count==UINT32_MAX)throw std::length_error("too many interface fields");++count;
            uint32_t owner_node=UINT32_MAX;for(uint32_t i=0;i<nodes.size();++i){budget.charge();if(nodes[i].key.occurrence==member.key.occurrence&&f.class_definitions[nodes[i].key.ordinal].type_id==field.owner_type){owner_node=i;break;}}
            emit(InterfaceItem::field,branch,owner_node,UINT32_MAX,0,member.key.occurrence,query::Relation::field_defs,member.key.ordinal);
        }
        FieldTruth value=FieldTruth::unknown;
        if(minimum==0&&maximum==UINT32_MAX)value=FieldTruth::yes;
        else if(!incomplete)value=count>=minimum&&count<=maximum?FieldTruth::yes:FieldTruth::no;
        emit(InterfaceItem::branch,branch,0,count,(static_cast<uint32_t>(value)<<1)|(incomplete?1u:0u),nodes[0].key.occurrence,query::Relation::class_defs,nodes[0].key.ordinal);
        saw_yes|=value==FieldTruth::yes;saw_no|=value==FieldTruth::no;saw_unknown|=value==FieldTruth::unknown;
    }
    if(!output.events.empty()&&!saw_unknown&&saw_yes!=saw_no)output.truth=saw_yes?FieldTruth::yes:FieldTruth::no;
    return output;
}
}
