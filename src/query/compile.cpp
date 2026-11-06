#include "ir.hpp"
#include "numeric_match.hpp"
#include "format/dex_names.hpp"
#include "json.hpp"
#include "facts/use_relations/use_scan.hpp"
#include "source/sha256.hpp"
#include <algorithm>
#include <charconv>
#include <limits>

namespace dexmeguviz::query {
namespace {
using json::Json;
[[noreturn]] void invalid(const char* m){throw Error(ErrorCode::invalid,m);}
[[noreturn]] void unsupported(const char* m){throw Error(ErrorCode::unsupported,m);}
void object(const Json& j){if(j.kind!=Json::Kind::object)invalid("expected query object");}
void keys(const Json& j,std::initializer_list<std::u16string_view> allowed){
    object(j);for(const auto& [key,value]:j.object){(void)value;if(std::find(allowed.begin(),allowed.end(),std::u16string_view(key))==allowed.end())unsupported("unsupported QueryIR field");}
}
const Json* optional(const Json& j,std::u16string_view key){object(j);const auto it=j.object.find(key);return it==j.object.end()?nullptr:&it->second;}
const Json& required(const Json& j,std::u16string_view key){if(const auto* p=optional(j,key))return *p;invalid("missing required QueryIR field");}
std::u16string_view text(const Json& j){if(j.kind!=Json::Kind::string)invalid("expected query string");return j.string;}
uint64_t integer64(const Json& j){
    if(j.kind!=Json::Kind::number||j.number.empty())invalid("expected unsigned integer");
    uint64_t v=0;for(char c:j.number){if(c<'0'||c>'9')invalid("expected unsigned integer");const auto digit=uint64_t(c-'0');if(v>(UINT64_MAX-digit)/10)invalid("integer overflow");v=v*10+digit;}return v;
}
uint32_t integer(const Json& j){const auto v=integer64(j);if(v>UINT32_MAX)invalid("integer exceeds uint32");return static_cast<uint32_t>(v);}
bool boolean(const Json& j){if(j.kind!=Json::Kind::boolean)invalid("expected boolean");return j.boolean;}
const auto& array(const Json& j){if(j.kind!=Json::Kind::array)invalid("expected query array");return j.array;}
void limits(const Json& j,uint32_t& minimum,uint32_t& maximum){
    if(j.kind==Json::Kind::number){minimum=maximum=integer(j);return;}
    keys(j,{u"min",u"max"});if(auto p=optional(j,u"min"))minimum=integer(*p);if(auto p=optional(j,u"max"))maximum=integer(*p);
    if(minimum>maximum)invalid("inverted range");
}
char16_t fold(char16_t c)noexcept{return c>=u'A'&&c<=u'Z'?static_cast<char16_t>(c+32):c;}
void prepare_text(TextMatcher& t){
    if(t.ascii_fold)for(auto& c:t.text)c=fold(c);
    if(t.op==TextOp::contains){t.prefix.resize(t.text.size());for(size_t i=1,j=0;i<t.text.size();++i){while(j&&t.text[i]!=t.text[j])j=t.prefix[j-1];if(t.text[i]==t.text[j])++j;t.prefix[i]=static_cast<uint32_t>(j);}}
}
std::pmr::string utf8(std::u16string_view input,std::pmr::memory_resource* r){
    std::pmr::string out(r);
    for(size_t i=0;i<input.size();++i){uint32_t cp=input[i];if(!cp)invalid("scope slot contains NUL");
        if(cp>=0xd800&&cp<=0xdbff){if(i+1==input.size()||input[i+1]<0xdc00||input[i+1]>0xdfff)invalid("scope slot has an unpaired surrogate");cp=0x10000+((cp-0xd800)<<10)+(input[++i]-0xdc00);}
        else if(cp>=0xdc00&&cp<=0xdfff)invalid("scope slot has an unpaired surrogate");
        if(cp<0x80)out.push_back(static_cast<char>(cp));
        else if(cp<0x800){out.push_back(static_cast<char>(0xc0|(cp>>6)));out.push_back(static_cast<char>(0x80|(cp&63)));}
        else if(cp<0x10000){out.push_back(static_cast<char>(0xe0|(cp>>12)));out.push_back(static_cast<char>(0x80|((cp>>6)&63)));out.push_back(static_cast<char>(0x80|(cp&63)));}
        else{out.push_back(static_cast<char>(0xf0|(cp>>18)));out.push_back(static_cast<char>(0x80|((cp>>12)&63)));out.push_back(static_cast<char>(0x80|((cp>>6)&63)));out.push_back(static_cast<char>(0x80|(cp&63)));}
    }return out;
}
void u32(std::pmr::string& s,uint32_t value){for(unsigned i=0;i<4;++i)s.push_back(static_cast<char>(value>>(8*i)));}
void u64(std::pmr::string& s,uint64_t value){for(unsigned i=0;i<8;++i)s.push_back(static_cast<char>(value>>(8*i)));}
void bytes(std::pmr::string& s,std::string_view value){u64(s,value.size());s.append(value);}
void units(std::pmr::string& s,std::u16string_view value){u64(s,value.size());for(auto c:value){s.push_back(static_cast<char>(c&255));s.push_back(static_cast<char>(c>>8));}}
bool binary_less(std::string_view a,std::string_view b){return std::lexicographical_compare(a.begin(),a.end(),b.begin(),b.end(),[](char x,char y){return static_cast<unsigned char>(x)<static_cast<unsigned char>(y);});}
bool use_relation(Relation relation){return is_use_relation(relation);}
Relation relation_type(const Json& value){
    const auto name=text(value);
    if(name==u"method_defs")return Relation::method_defs;if(name==u"class_defs")return Relation::class_defs;if(name==u"field_defs")return Relation::field_defs;
    if(name==u"method_refs")return Relation::method_refs;if(name==u"field_refs")return Relation::field_refs;if(name==u"string_values")return Relation::string_values;if(name==u"type_refs")return Relation::type_refs;
    if(name==u"string_uses")return Relation::string_uses;if(name==u"invoke_sites")return Relation::invoke_sites;if(name==u"field_uses")return Relation::field_uses;if(name==u"type_uses")return Relation::type_uses;
    unsupported("unsupported entity relation");
}
Identity identity(const Json& value){const auto name=text(value);if(name==u"entity")return Identity::entity;if(name==u"tuple")return Identity::tuple;unsupported("unsupported row identity");}
JoinKey join_key(const Json& value){
    const auto name=text(value);
    if(name==u"same_entity")return JoinKey::same_entity;
    if(name==u"local_definition")return JoinKey::local_definition;
    if(name==u"local_owner")return JoinKey::local_owner;
    if(name==u"symbol")return JoinKey::symbol;
    if(name==u"caller")return JoinKey::caller;
    if(name==u"target_ref")return JoinKey::target_ref;
    if(name==u"target_symbol")return JoinKey::target_symbol;
    unsupported("unsupported join key");
}
bool join_compatible(JoinKey key,Relation left,Relation right){
    const auto method=[](Relation type){return type==Relation::method_defs||type==Relation::method_refs;};
    const auto field=[](Relation type){return type==Relation::field_defs||type==Relation::field_refs;};
    const auto type=[](Relation relation){return relation==Relation::class_defs||relation==Relation::type_refs;};
    const auto definition=[](Relation relation){return relation==Relation::method_defs||relation==Relation::field_defs||relation==Relation::class_defs;};
    const auto pair=[&](Relation a,Relation b){return (left==a&&right==b)||(left==b&&right==a);};
    switch(key){
    case JoinKey::same_entity:return left==right;
    case JoinKey::local_definition:return definition(left)!=definition(right)&&
        ((method(left)&&method(right))||(field(left)&&field(right))||(type(left)&&type(right)));
    case JoinKey::local_owner:return (method(left)||field(left))&&right==Relation::class_defs;
    case JoinKey::symbol:return (method(left)&&method(right))||(field(left)&&field(right))||(type(left)&&type(right))||
        (left==Relation::string_values&&right==Relation::string_values);
    case JoinKey::caller:return (left==Relation::method_defs&&use_relation(right))||(right==Relation::method_defs&&use_relation(left));
    case JoinKey::target_ref:return pair(Relation::string_uses,Relation::string_values)||pair(Relation::field_uses,Relation::field_refs)||pair(Relation::invoke_sites,Relation::method_refs)||pair(Relation::type_uses,Relation::type_refs);
    case JoinKey::target_symbol:return pair(Relation::string_uses,Relation::string_values)||pair(Relation::field_uses,Relation::field_refs)||pair(Relation::field_uses,Relation::field_defs)||pair(Relation::invoke_sites,Relation::method_refs)||pair(Relation::invoke_sites,Relation::method_defs);
    }
    return false;
}
bool bag_semantics(const Json& value){const auto name=text(value);if(name==u"bag")return true;if(name==u"set")return false;unsupported("unsupported collection semantics");}
void scope(const Json& value,std::pmr::vector<std::pmr::string>& slots,std::pmr::memory_resource* memory){
    keys(value,{u"slots"});const auto& values=array(required(value,u"slots"));
    if(values.size()>64)throw Error(ErrorCode::budget,"scope exceeds 64 input slots");
    for(const auto& slot:values){auto encoded=utf8(text(slot),memory);if(encoded.empty()||encoded.size()>4096)invalid("scope slot length outside range");slots.push_back(std::move(encoded));}
    std::sort(slots.begin(),slots.end(),[](const auto& a,const auto& b){return binary_less(a,b);});
    if(std::adjacent_find(slots.begin(),slots.end())!=slots.end())invalid("duplicate scope slot");
}
void encode_text(const Plan& p,std::pmr::string& out,uint32_t index){
    u32(out,index==none?0:1);if(index==none)return;const auto& t=p.texts[index];u32(out,static_cast<uint32_t>(t.op));u32(out,t.ascii_fold?1:0);units(out,t.text);
}
void encode_symbol(const Plan& p,std::pmr::string& out,const SymbolMatcher& s){
    encode_text(p,out,s.owner);encode_text(p,out,s.name);encode_text(p,out,s.prototype);encode_text(p,out,s.returned);
    u32(out,s.minimum_parameters);u32(out,s.maximum_parameters);u32(out,static_cast<uint32_t>(s.invoke_kind));u32(out,static_cast<uint32_t>(s.parameters.size()));
    for(auto v:s.parameters){u32(out,v.index);encode_text(p,out,v.text);}
}
void encode_node(const Plan& p,std::pmr::string& out,uint32_t index){
    const auto& n=p.nodes[index];u32(out,static_cast<uint32_t>(n.kind));encode_text(p,out,n.text);u32(out,n.argument);u32(out,n.minimum);u32(out,n.maximum);
    if(n.kind==Kind::class_annotation){encode_text(p,out,n.symbol);}
    else if(n.kind==Kind::class_annotation_string){encode_text(p,out,n.symbol);encode_text(p,out,static_cast<uint32_t>(n.annotation_value_text));}
    else if(n.kind==Kind::numeric_bits){u32(out,n.minimum);u32(out,n.argument);u64(out,n.numeric_value);}
    else if(n.kind==Kind::invoke)encode_symbol(p,out,p.symbols[n.symbol]);
    else if(n.kind==Kind::target_field_declaration||n.kind==Kind::field_access||n.kind==Kind::declared_field_count||n.kind==Kind::inherited_field_count||n.kind==Kind::inherited_interface_count||n.kind==Kind::inherited_interface_resolved_count){const auto& f=p.fields[n.symbol];encode_text(p,out,f.owner);encode_text(p,out,f.name);encode_text(p,out,f.type);u32(out,f.flags);u32(out,f.access);}
    std::pmr::vector<std::pmr::string> children(p.memory);
    for(auto child:n.children){children.emplace_back();encode_node(p,children.back(),child);}
    if(n.kind==Kind::all||n.kind==Kind::any)std::sort(children.begin(),children.end(),[](const auto& a,const auto& b){return binary_less(a,b);});
    u32(out,static_cast<uint32_t>(children.size()));for(const auto& c:children)bytes(out,c);
}
void encode_relation(const Plan& p,std::pmr::string& out,uint32_t index){
    const auto& n=p.relations[index];u32(out,static_cast<uint32_t>(n.op));u32(out,static_cast<uint32_t>(n.relation));
    u32(out,n.predicate==none?0:1);if(n.predicate!=none){std::pmr::string encoded(p.memory);encode_node(p,encoded,n.predicate);bytes(out,encoded);}
    u32(out,n.label==none?0:1);if(n.label!=none)bytes(out,p.labels[n.label]);
    u32(out,n.minimum);u32(out,n.maximum);u32(out,static_cast<uint32_t>(n.identity));u32(out,n.bag?1:0);u32(out,n.explicit_scope?1:0);u32(out,n.distinct_roles?1:0);
    if(n.op==RelOp::join||n.op==RelOp::semi_join)u32(out,static_cast<uint32_t>(n.join_key));
    if(n.op==RelOp::bounded_expand){
        u32(out,static_cast<uint32_t>(n.expand_direction));u32(out,static_cast<uint32_t>(n.expand_output));
        u32(out,0);u32(out,0);u32(out,0); // Fixed invoke_method_ref, all_definitions, bounded_walk.
        u32(out,n.expand_min_depth);u32(out,n.expand_max_depth);
        u64(out,n.expand_max_visited);u64(out,n.expand_max_edges);u64(out,n.expand_max_paths);
        for(auto predicate:{n.expand_walk_predicate,n.expand_emit_predicate}){
            u32(out,predicate==none?0:1);if(predicate!=none){std::pmr::string encoded(p.memory);encode_node(p,encoded,predicate);bytes(out,encoded);}
        }
    }
    u32(out,static_cast<uint32_t>(n.scope_slots.size()));for(const auto& slot:n.scope_slots)bytes(out,slot);
    u32(out,static_cast<uint32_t>(n.required_roles.size()));for(auto role:n.required_roles)bytes(out,p.labels[role]);
    u32(out,static_cast<uint32_t>(n.children.size()));for(auto child:n.children){std::pmr::string encoded(p.memory);encode_relation(p,encoded,child);bytes(out,encoded);}
}
void finish(Plan& p,bool method_type_syntax=false){
    p.demand_mask=0;p.contains_uses=false;p.contains_expand=false;
    const bool inherited_explicit=(p.required_capabilities&16384u)!=0;
    const bool v6_predicate=std::any_of(p.nodes.begin(),p.nodes.end(),[](const auto& node){return node.kind==Kind::inherited_field_count;});
    const bool v8_predicate=std::any_of(p.nodes.begin(),p.nodes.end(),[](const auto& node){return node.kind==Kind::inherited_interface_count;});
    const bool v11_predicate=std::any_of(p.nodes.begin(),p.nodes.end(),[](const auto& node){return node.kind==Kind::inherited_interface_resolved_count;});
    p.has_inherited_predicate=v6_predicate||v8_predicate||v11_predicate;
    p.contains_inherited=(p.required_capabilities&16384u)!=0||v6_predicate;
    p.contains_interface_fields=(p.required_capabilities&65536u)!=0||v8_predicate;
    p.contains_interface_resolved=(p.required_capabilities&524288u)!=0||v11_predicate;
    if(p.contains_interface_resolved)p.required_capabilities|=524288u;
    if(p.contains_inherited)p.required_capabilities|=16384u;
    if(p.contains_interface_fields)p.required_capabilities|=65536u;
    auto demands=[&](auto&& self,uint32_t index)->uint32_t{
        auto& n=p.nodes[index];uint32_t mask=n.kind==Kind::using_string?1u:n.kind==Kind::invoke?2u:n.kind==Kind::field_access?4u:n.kind==Kind::numeric_bits?8u:n.kind==Kind::using_type?256u:n.kind==Kind::opcode_sequence?512u:0u;
        for(auto c:n.children)mask|=self(self,c);n.demand_mask=mask;return mask;
    };p.demand_mask=demands(demands,p.root);
    p.required_capabilities|=2u|(p.relation==Relation::method_defs?1u:use_relation(p.relation)?0u:256u)|(p.explicit_scope?8u:0u)|((!p.order.empty()||p.intent==Intent::top_n)?16u:0u);
    const bool relational=p.relation_root!=none;
    const bool annotation_present=std::any_of(p.nodes.begin(),p.nodes.end(),[](const auto& node){return node.kind==Kind::class_annotation||node.kind==Kind::class_annotation_string;});
    const bool annotation_string_present=std::any_of(p.nodes.begin(),p.nodes.end(),[](const auto& node){return node.kind==Kind::class_annotation_string;});
    if(annotation_present!=p.class_annotation_requested)unsupported("class annotation requires its explicit capability and predicate");
    if(annotation_string_present!=p.class_annotation_string_requested|| (p.class_annotation_string_requested&&!p.class_annotation_requested))unsupported("class annotation string requires both capabilities and a string predicate");
    if(p.class_annotation_requested){
        constexpr uint32_t allowed=2u|4u|8u|256u;
        if(relational||p.relation!=Relation::class_defs||!p.order.empty()||p.intent==Intent::top_n||(p.required_capabilities&~allowed)||p.demand_mask)
            unsupported("class annotation supports unordered direct class definitions without advanced profiles");
    }

    const auto declaration_count=std::count_if(p.nodes.begin(),p.nodes.end(),[](const auto& n){return n.kind==Kind::target_field_declaration;});
    p.field_declaration_resolution=declaration_count!=0;
    const bool declaration_requested=(p.required_capabilities&134217728u)!=0;
    if(declaration_requested!=p.field_declaration_resolution)unsupported("field declaration requires its explicit capability and predicate");
    if((p.required_capabilities&268435456u)&&!declaration_requested)unsupported("caller field relation requires field declaration capability");
    if(declaration_requested){
        if(declaration_count!=1||!relational||!p.explicit_scope||p.scope_slots.empty()||p.relation_root>=p.relations.size()||!p.order.empty()||p.intent==Intent::top_n)
            unsupported("field declaration requires a supported scoped graph");
        const auto& root=p.relations[p.relation_root];
        const bool single=p.relations.size()==1&&root.op==RelOp::scan&&root.relation==Relation::field_uses&&!root.explicit_scope;
        bool caller=false;
        if(p.relations.size()==3&&(root.op==RelOp::join||root.op==RelOp::semi_join)&&root.join_key==JoinKey::caller&&root.children.size()==2){
            const auto& left=p.relations[root.children[0]];const auto& right=p.relations[root.children[1]];
            caller=left.op==RelOp::scan&&left.relation==Relation::method_defs&&!left.explicit_scope&&
                   right.op==RelOp::scan&&right.relation==Relation::field_uses&&!right.explicit_scope;
            if(caller){
                const auto metadata_only=[&](auto&& self,uint32_t i)->bool{
                    const auto& node=p.nodes[i];if(node.kind==Kind::using_string||node.kind==Kind::invoke||node.kind==Kind::field_access||node.kind==Kind::numeric_bits||
                       node.kind==Kind::inherited_field_count||node.kind==Kind::inherited_interface_count||node.kind==Kind::inherited_interface_resolved_count||node.kind==Kind::target_field_declaration)return false;
                    for(auto child:node.children)if(!self(self,child))return false;return true;
                };
                caller=left.predicate!=none&&metadata_only(metadata_only,left.predicate);
            }
        }
        if(!single&&!caller)unsupported("field declaration supports only scoped scan or caller join/semi_join");
        if((p.required_capabilities&268435456u)&&!caller)unsupported("caller field relation observation requires caller join/semi_join");
        for(const auto& n:p.nodes)if(n.kind==Kind::negate)unsupported("field declaration does not support not");
        const auto contains_declaration=[&](auto&& self,uint32_t i)->bool{
            if(p.nodes[i].kind==Kind::target_field_declaration)return true;
            for(auto child:p.nodes[i].children)if(self(self,child))return true;return false;
        };
        for(const auto& n:p.nodes)if(n.kind==Kind::any)for(auto child:n.children)
            if(contains_declaration(contains_declaration,child))unsupported("field declaration cannot occur under any");
        const uint32_t allowed=1u|2u|4u|8u|128u|512u|4096u|134217728u|(caller?(2048u|268435456u):0u);
        if(p.required_capabilities&~allowed)unsupported("field declaration cannot mix advanced profiles");
    }
    const bool reflection=std::any_of(p.nodes.begin(),p.nodes.end(),[](const auto& node){
        return (node.kind==Kind::flags_contains||node.kind==Kind::flags_exact||node.kind==Kind::flags_any)&&(node.argument&2u);
    });
    const bool target_symbol=std::any_of(p.relations.begin(),p.relations.end(),[](const auto& n){return (n.op==RelOp::join||n.op==RelOp::semi_join)&&n.join_key==JoinKey::target_symbol;});
    const bool target_symbol_requested=(p.required_capabilities&16777216u)!=0;
    if(target_symbol!=target_symbol_requested)unsupported("target_symbol requires its explicit capability and a matching join");
    const bool type_uses_requested=(p.required_capabilities&1073741824u)!=0;
    const bool type_uses_present=std::any_of(p.relations.begin(),p.relations.end(),[](const auto& n){return n.op==RelOp::scan&&n.relation==Relation::type_uses;});
    const bool method_type_present=std::any_of(p.nodes.begin(),p.nodes.end(),[](const auto& n){return n.kind==Kind::using_type;});
    if((method_type_present&&!method_type_syntax)||type_uses_requested!=(type_uses_present||method_type_syntax)||(type_uses_present&&method_type_syntax))unsupported("type uses require explicit capability and exactly one supported shape");
    p.method_type_query=method_type_syntax;
    if(type_uses_requested){
        if(reflection||(p.required_capabilities&(16384u|32768u|65536u|131072u|262144u|524288u|1048576u|16777216u|33554432u|67108864u|134217728u|268435456u|536870912u)))unsupported("type uses cannot mix with advanced profiles");
        if(method_type_syntax){if(relational||p.relation!=Relation::method_defs||!p.order.empty()||p.intent==Intent::top_n)unsupported("method type predicates require an unordered direct method query");}
        else{if(!relational)unsupported("type use scan requires a relation");for(const auto& n:p.relations)if(n.op==RelOp::scan&&use_relation(n.relation)&&n.relation!=Relation::type_uses)unsupported("type use profile cannot mix use families");}
    }
    const bool opcode_requested=(p.required_capabilities&0x80000000u)!=0;
    const bool opcode_present=std::any_of(p.nodes.begin(),p.nodes.end(),[](const auto& node){return node.kind==Kind::opcode_sequence;});
    if(opcode_requested!=opcode_present)unsupported("opcode sequence requires its explicit capability and predicate");
    const bool reflection_requested=(p.required_capabilities&2097152u)!=0;
    if(reflection!=reflection_requested)unsupported("static reflection flags require an explicit capability and predicate");
    const bool class_annotations=(p.required_capabilities&536870912u)!=0;
    if(class_annotations&&!reflection_requested)unsupported("class annotation flags require static reflection flags");
    const bool reflection_relational=(p.required_capabilities&4194304u)!=0;
    const bool reflection_method_uses=(p.required_capabilities&8388608u)!=0;
    const bool reflection_body_relational=(p.required_capabilities&33554432u)!=0;
    const bool inherited_target_symbol=(p.required_capabilities&67108864u)!=0;
    if(reflection_relational&&(!reflection||!relational))unsupported("reflection_relational requires a relational expression and reflection predicate");
    if(relational){
        p.required_capabilities|=512;
        for(const auto& relation:p.relations){
            p.required_capabilities|=relation.relation==Relation::method_defs?1u:use_relation(relation.relation)?0u:256u;
            if(relation.op==RelOp::scan&&use_relation(relation.relation)){
                p.contains_uses=true;p.required_capabilities|=4096u;
                p.demand_mask|=relation.relation==Relation::string_uses?1u:relation.relation==Relation::invoke_sites?2u:relation.relation==Relation::field_uses?4u:256u;
            }
            if(relation.explicit_scope)p.required_capabilities|=8;
            if(relation.op==RelOp::group_by_owner)p.required_capabilities|=1024;
            if(relation.op==RelOp::join||relation.op==RelOp::semi_join)p.required_capabilities|=2048;
            if(relation.op==RelOp::bounded_expand){
                p.contains_expand=true;p.required_capabilities|=8192u;p.demand_mask|=2u;
                if(relation.expand_walk_predicate!=none)p.demand_mask|=demands(demands,relation.expand_walk_predicate);
                if(relation.expand_emit_predicate!=none)p.demand_mask|=demands(demands,relation.expand_emit_predicate);
            }
            if(relation.predicate!=none)p.demand_mask|=demands(demands,relation.predicate);
        }
    }
    if(p.demand_mask&1)p.required_capabilities|=32;if(p.demand_mask&2)p.required_capabilities|=64;if(p.demand_mask&4)p.required_capabilities|=128;
    if(p.demand_mask&8)p.required_capabilities|=32768;p.contains_numeric=(p.required_capabilities&32768)!=0;
    if(type_uses_requested){
        const uint32_t allowed=p.method_type_query?(1u|2u|4u|8u|32u|64u|128u|1073741824u):(1u|2u|4u|8u|16u|256u|512u|1024u|2048u|4096u|1073741824u);
        if((p.method_type_query?((p.demand_mask&~(256u|1u|2u|4u))!=0):p.demand_mask!=256u)||(p.required_capabilities&~allowed))unsupported("type use profile cannot mix unsupported demands or capabilities");
    }
    if(opcode_requested){
        constexpr uint32_t allowed=1u|2u|4u|8u|32u|64u|128u|0x80000000u;
        if(relational||p.relation!=Relation::method_defs||!p.order.empty()||p.intent==Intent::top_n||
           (p.required_capabilities&~allowed)||(p.demand_mask&~(512u|1u|2u|4u)))
            unsupported("opcode sequences require unordered direct method queries without advanced profiles");
    }
    p.unique_one_stream=(p.required_capabilities&1048576u)!=0;
    if(p.unique_one_stream)p.required_capabilities|=131072u;
    p.use_streaming=(p.required_capabilities&131072u)!=0;
    if(p.contains_inherited&&p.contains_interface_fields)
        unsupported("superclass-only and interface-inclusive inheritance require a future combined profile");
    if(p.use_streaming&&!p.contains_uses)unsupported("use streaming requires a use relation");
    const auto advanced=unsigned(p.contains_inherited)+unsigned(p.contains_numeric)+unsigned(p.contains_interface_fields)+unsigned(p.use_streaming);
    if(p.contains_interface_resolved&&(advanced!=0||(p.required_capabilities&262144u)!=0))unsupported("interface resolved cannot mix with v6-v10 capabilities");
    if(inherited_target_symbol&&(!relational||!target_symbol||!v6_predicate||!inherited_explicit||
       !p.contains_uses||advanced!=1||!p.contains_inherited||p.contains_interface_resolved||reflection||
       (p.required_capabilities&(262144u|1048576u))))
        unsupported("inherited_target_symbol requires an explicit inherited predicate and target symbol join only");
    if(target_symbol&&(advanced||p.contains_interface_resolved||reflection||(p.required_capabilities&(262144u|1048576u)))&&!inherited_target_symbol)
        unsupported("target_symbol cannot mix with advanced profiles without inherited_target_symbol");
    const bool composite=(p.required_capabilities&262144u)!=0||advanced>1;
    if(composite)p.required_capabilities|=262144u;
    constexpr uint32_t unsupported_reflection_caps=32u|64u|128u|4096u|16384u|32768u|65536u|131072u|262144u|524288u|1048576u;
    if(reflection_body_relational&&(!reflection||!reflection_relational||!relational||reflection_method_uses||
       !(p.demand_mask&7u)||(p.demand_mask&~7u)||p.contains_uses||target_symbol||
       (p.required_capabilities&(unsupported_reflection_caps&~(32u|64u|128u)))))
        unsupported("reflection_body_relational requires reflection relational with method body predicates only");
    if(reflection_method_uses&&(!reflection||reflection_relational||relational||p.relation!=Relation::method_defs||
       !(p.demand_mask&7u)||(p.demand_mask&~7u)||!p.order.empty()||p.intent==Intent::top_n||
       (p.required_capabilities&(unsupported_reflection_caps&~(32u|64u|128u)))))
        unsupported("reflection_method_uses requires an unordered direct method query with static reflection and method use predicates only");
    if(reflection&&(!reflection_relational&&(relational||!p.order.empty()||p.intent==Intent::top_n||
                                            (p.required_capabilities&(16u|512u|1024u|2048u)))))
        unsupported("static reflection flags support direct unordered metadata queries only");
    if(reflection&&!reflection_method_uses&&!reflection_body_relational&&(p.demand_mask||(p.required_capabilities&unsupported_reflection_caps)))
        unsupported("static reflection flags cannot mix with use or advanced capabilities");
    if(p.unique_one_stream){
        if(composite||p.contains_interface_resolved||p.intent!=Intent::unique||p.max_results!=1||!p.order.empty()||
           p.unique_identity!=Identity::entity||p.relation_root>=p.relations.size()||p.relations.size()!=1||
           p.relations[p.relation_root].op!=RelOp::scan||!use_relation(p.relations[p.relation_root].relation)||
           !p.relations[p.relation_root].children.empty()||(p.required_capabilities&(16u|1024u|2048u)))
            unsupported("unique_one_stream supports only unordered Unique/1 root use scan");
        const auto root=p.relations[p.relation_root].relation;
        const uint32_t expected=root==Relation::string_uses?32u:root==Relation::invoke_sites?64u:128u;
        if((p.required_capabilities&(32u|64u|128u))!=expected)
            unsupported("unique_one_stream rejects cross-kind use requirements");
    }
    const bool requires_expand=p.contains_expand||(p.required_capabilities&8192u)!=0;
    if(requires_expand&&!p.contains_expand)unsupported("bounded_expand capability requires an expand relation");
    constexpr uint32_t unsupported_expand_caps=0xffffc000u;
    if(requires_expand&&(p.required_capabilities&unsupported_expand_caps))
        unsupported("bounded_expand cannot mix with advanced profile capabilities");
    if(requires_expand&&use_relation(p.relation))
        unsupported("bounded_expand use-event main output requires a tagged endpoint ABI");
    auto number_nodes=[&](auto&& self,uint32_t index)->void{
        auto& n=p.nodes[index];if(n.stable_id!=none)return;n.stable_id=static_cast<uint32_t>(p.stable_order.size());p.stable_order.push_back(index);
        if(n.kind==Kind::all||n.kind==Kind::any||n.kind==Kind::negate)p.required_capabilities|=4;
        std::pmr::vector<std::pair<std::pmr::string,uint32_t>> children(p.memory);
        for(auto child:n.children){std::pmr::string key(p.memory);encode_node(p,key,child);children.emplace_back(std::move(key),child);}
        if(n.kind==Kind::all||n.kind==Kind::any){
            std::sort(children.begin(),children.end(),[](const auto& a,const auto& b){return binary_less(a.first,b.first);});
            n.children.clear();for(const auto& child:children)n.children.push_back(child.second);
        }
        for(const auto& child:children)self(self,child.second);
    };number_nodes(number_nodes,p.root);
    if(relational){uint32_t next=0;auto number_relations=[&](auto&& self,uint32_t index,unsigned depth)->void{
        if(depth>=32)throw Error(ErrorCode::budget,"relation depth exceeds 32");
        auto& relation=p.relations[index];if(relation.stable_id!=none)return;relation.stable_id=next++;
        if(relation.predicate!=none)number_nodes(number_nodes,relation.predicate);
        if(relation.expand_walk_predicate!=none)number_nodes(number_nodes,relation.expand_walk_predicate);
        if(relation.expand_emit_predicate!=none)number_nodes(number_nodes,relation.expand_emit_predicate);
        for(auto child:relation.children)self(self,child,depth+1);
    };number_relations(number_relations,p.relation_root,0);}
    const bool legacy=!requires_expand&&!reflection&&!p.contains_interface_resolved&&!composite&&!p.use_streaming&&!p.contains_inherited&&!p.contains_numeric&&!p.contains_interface_fields&&!relational&&p.relation==Relation::method_defs&&std::none_of(p.nodes.begin(),p.nodes.end(),[](const auto& n){return n.kind>=Kind::descriptor;})&&std::none_of(p.order.begin(),p.order.end(),[](const auto& k){return k.field>=SortField::descriptor;});
    std::pmr::string canonical(p.class_annotation_string_requested?"DexMeguviz:QueryIR:class-annotation-string-static-v25":p.class_annotation_requested?"DexMeguviz:QueryIR:class-annotation-static-v24":opcode_requested?"DexMeguviz:QueryIR:opcode-sequence-v23":requires_expand?"DexMeguviz:QueryIR:expand-v5":p.method_type_query?"DexMeguviz:QueryIR:method-type-uses-v22":type_uses_requested?"DexMeguviz:QueryIR:type-uses-v21":class_annotations?"DexMeguviz:QueryIR:reflection-class-annotations-v20":p.field_declaration_resolution?"DexMeguviz:QueryIR:field-declaration-v19":inherited_target_symbol?"DexMeguviz:QueryIR:inherited-target-symbol-v18":reflection_body_relational?"DexMeguviz:QueryIR:reflection-body-relational-v17":target_symbol?"DexMeguviz:QueryIR:use-target-symbol-v16":reflection_method_uses?"DexMeguviz:QueryIR:reflection-method-uses-v15":reflection_relational?"DexMeguviz:QueryIR:reflection-relational-v14":reflection?"DexMeguviz:QueryIR:reflection-flags-v13":p.unique_one_stream?"DexMeguviz:QueryIR:unique-one-v12":p.contains_interface_resolved?"DexMeguviz:QueryIR:interface-resolved-v11":composite?"DexMeguviz:QueryIR:composite-v10":p.use_streaming?"DexMeguviz:QueryIR:use-stream-v9":p.contains_interface_fields?"DexMeguviz:QueryIR:interface-v8":p.contains_inherited?"DexMeguviz:QueryIR:inherited-v6":p.contains_numeric?"DexMeguviz:QueryIR:numeric-v7":p.contains_uses?"DexMeguviz:QueryIR:use-v4":relational?"DexMeguviz:QueryIR:relational-v3":legacy?"DexMeguviz:QueryIR:method-v1":"DexMeguviz:QueryIR:entity-v2",p.memory);
    if(!legacy)u32(canonical,static_cast<uint32_t>(p.relation));
    u32(canonical,static_cast<uint32_t>(p.intent));u32(canonical,p.max_results);u64(canonical,p.max_work);u32(canonical,p.projection);u32(canonical,p.bag?1:0);u32(canonical,p.explicit_scope?1:0);u32(canonical,p.required_capabilities);
    if(relational){u32(canonical,static_cast<uint32_t>(p.unique_identity));u32(canonical,p.max_intermediate_rows);}
    u32(canonical,static_cast<uint32_t>(p.scope_slots.size()));for(const auto& slot:p.scope_slots)bytes(canonical,slot);
    u32(canonical,static_cast<uint32_t>(p.order.size()));for(auto key:p.order){u32(canonical,static_cast<uint32_t>(key.field));u32(canonical,key.descending?1:0);}
    if(relational)encode_relation(p,canonical,p.relation_root);else encode_node(p,canonical,p.root);
    p.id=p.class_annotation_string_requested?"query:v25:":p.class_annotation_requested?"query:v24:":opcode_requested?"query:v23:":requires_expand?"query:v5:":p.method_type_query?"query:v22:":type_uses_requested?"query:v21:":class_annotations?"query:v20:":p.field_declaration_resolution?"query:v19:":inherited_target_symbol?"query:v18:":reflection_body_relational?"query:v17:":target_symbol?"query:v16:":reflection_method_uses?"query:v15:":reflection_relational?"query:v14:":reflection?"query:v13:":p.unique_one_stream?"query:v12:":p.contains_interface_resolved?"query:v11:":composite?"query:v10:":p.use_streaming?"query:v9:":p.contains_interface_fields?"query:v8:":p.contains_inherited?"query:v6:":p.contains_numeric?"query:v7:":p.contains_uses?"query:v4:":relational?"query:v3:":legacy?"query:v1:":"query:v2:";p.id+=sha256<std::pmr::string>({reinterpret_cast<const uint8_t*>(canonical.data()),canonical.size()},p.memory);
}
class Compiler {
public:
    explicit Compiler(std::pmr::memory_resource* resource):plan(resource){}
    Plan run(const Json& input){
        keys(input,{u"schema_version",u"relation",u"where",u"intent",u"max_results",u"scope",u"semantics",u"order_by",u"projection",u"max_work",u"required_capabilities",u"evidence_profile",u"unique_by",u"max_intermediate_rows"});
        if(integer(required(input,u"schema_version"))!=1)unsupported("unsupported QueryIR version");
        const auto& relation=required(input,u"relation");const bool relational=relation.kind==Json::Kind::object;
        if(relational){plan.bag=true;plan.relation_root=expression(relation,0);plan.relation=plan.relations[plan.relation_root].relation;}
        else{
            if(optional(input,u"unique_by")||optional(input,u"max_intermediate_rows"))unsupported("relational options require an expression root");
            plan.relation=relation_type(relation);
            if(use_relation(plan.relation))unsupported("use relations require an object scan");
        }
        if(auto v=optional(input,u"unique_by"))plan.unique_identity=identity(*v);
        else if(relational&&std::any_of(plan.relations.begin(),plan.relations.end(),[](const RelNode& node){
            return node.op==RelOp::bounded_expand&&node.expand_output==ExpandOutput::paths;
        }))plan.unique_identity=Identity::tuple;
        if(auto v=optional(input,u"max_intermediate_rows"))plan.max_intermediate_rows=integer(*v);
        if(!plan.max_intermediate_rows||plan.max_intermediate_rows>1000000)invalid("max_intermediate_rows must be in 1..1000000");
        plan.projection=allowed_projection();
        if(auto v=optional(input,u"intent")){const auto label=text(*v);if(label==u"enumerate")plan.intent=Intent::enumerate;else if(label==u"exists")plan.intent=Intent::exists;else if(label==u"unique")plan.intent=Intent::unique;else if(label==u"top_n")plan.intent=Intent::top_n;else unsupported("unsupported result intent");}
        if(auto v=optional(input,u"max_results"))plan.max_results=integer(*v);
        if(!plan.max_results||plan.max_results>100000)invalid("max_results must be in 1..100000");
        if(auto v=optional(input,u"max_work"))plan.max_work=integer64(*v);
        if(!plan.max_work)invalid("max_work must be nonzero");
        if(auto v=optional(input,u"semantics"))plan.bag=bag_semantics(*v);
        if(auto v=optional(input,u"evidence_profile"))if(text(*v)!=u"minimal")unsupported("unsupported evidence profile");
        if(auto v=optional(input,u"required_capabilities"))for(const auto& capability:array(*v)){
            const auto label=text(capability);if(label==u"class_annotation_string_static")plan.class_annotation_string_requested=true;else if(label==u"class_annotation_static")plan.class_annotation_requested=true;else if(label==u"method_defs")plan.required_capabilities|=1;else if(label==u"metadata")plan.required_capabilities|=2;else if(label==u"booleans")plan.required_capabilities|=4;else if(label==u"source_scope")plan.required_capabilities|=8;else if(label==u"order")plan.required_capabilities|=16;else if(label==u"string_uses")plan.required_capabilities|=32;else if(label==u"invoke_sites")plan.required_capabilities|=64;else if(label==u"field_uses")plan.required_capabilities|=128;else if(label==u"entity_roots")plan.required_capabilities|=256;else if(label==u"relational")plan.required_capabilities|=512;else if(label==u"owner_groups")plan.required_capabilities|=1024;else if(label==u"join")plan.required_capabilities|=2048;else if(label==u"use_relations")plan.required_capabilities|=4096;else if(label==u"bounded_expand")plan.required_capabilities|=8192;else if(label==u"inherited_fields")plan.required_capabilities|=16384;else if(label==u"numeric_literals")plan.required_capabilities|=32768;else if(label==u"interface_fields")plan.required_capabilities|=65536;else if(label==u"use_streaming")plan.required_capabilities|=131072;else if(label==u"unique_one_stream")plan.required_capabilities|=1048576;else if(label==u"reflection_flags_static")plan.required_capabilities|=2097152;else if(label==u"reflection_relational")plan.required_capabilities|=4194304;else if(label==u"reflection_method_uses")plan.required_capabilities|=8388608;else if(label==u"use_target_symbol")plan.required_capabilities|=16777216u;else if(label==u"reflection_body_relational")plan.required_capabilities|=33554432u;else if(label==u"inherited_target_symbol")plan.required_capabilities|=67108864u;else if(label==u"field_declaration_static")plan.required_capabilities|=134217728u;else if(label==u"caller_field_relation_observation")plan.required_capabilities|=268435456u;else if(label==u"reflection_class_annotations_static")plan.required_capabilities|=536870912u;else if(label==u"type_uses")plan.required_capabilities|=1073741824u;else if(label==u"opcode_sequence")plan.required_capabilities|=0x80000000u;else if(label==u"interface_resolved")plan.required_capabilities|=524288;else if(label==u"composite")plan.required_capabilities|=262144;else unsupported("unknown required capability");
        }
        if(auto v=optional(input,u"scope")){
            plan.explicit_scope=true;scope(*v,plan.scope_slots,plan.memory);
        }
        if(auto v=optional(input,u"projection")){
            plan.projection=0;
            for(const auto& column:array(*v)){auto name=text(column);if(name==u"owner")plan.projection|=project_owner;else if(name==u"name")plan.projection|=project_name;else if(name==u"prototype")plan.projection|=project_prototype;else if(name==u"descriptor"||name==u"type")plan.projection|=project_type;else if(name==u"value")plan.projection|=project_value;else if(name!=u"identity"&&name!=u"evidence")unsupported("unsupported projection column");}
            if(plan.projection&~allowed_projection())unsupported("projection column does not apply to relation");
        }
        if(auto v=optional(input,u"order_by")){
            if(array(*v).size()>6)invalid("too many order keys");
            for(const auto& key:array(*v)){keys(key,{u"field",u"direction"});SortKey s{};auto label=text(required(key,u"field"));
                if(label==u"owner")s.field=SortField::owner;else if(label==u"name")s.field=SortField::name;else if(label==u"prototype")s.field=SortField::prototype;else if(label==u"flags")s.field=SortField::flags;else if(label==u"source_index")s.field=SortField::source_index;else if(label==u"method_index")s.field=SortField::method_index;else if(label==u"descriptor"||label==u"type")s.field=SortField::descriptor;else if(label==u"value")s.field=SortField::value;else if(label==u"local_index")s.field=SortField::local_index;else if(label==u"pc")s.field=SortField::use_pc;else if(label==u"opcode")s.field=SortField::use_opcode;else if(label==u"target_index")s.field=SortField::use_target_index;else unsupported("unsupported order field");
                if((s.field==SortField::owner||s.field==SortField::name)&&!member_relation()&&!use_relation(plan.relation))unsupported("order field requires member or use relation");
                if(s.field==SortField::prototype&&!method_relation()&&!use_relation(plan.relation))unsupported("prototype order requires method or use relation");
                if(s.field==SortField::method_index&&!method_relation())unsupported("method_index order requires method relation");
                if(s.field==SortField::descriptor&&!(allowed_projection()&project_type))unsupported("order field requires a type descriptor");
                if(s.field==SortField::value&&plan.relation!=Relation::string_values)unsupported("value order requires string_values");
                if(plan.relation==Relation::string_values&&s.field!=SortField::value&&s.field!=SortField::local_index&&s.field!=SortField::source_index)unsupported("order field does not apply to string_values");
                if((s.field==SortField::use_pc||s.field==SortField::use_opcode||s.field==SortField::use_target_index)&&!use_relation(plan.relation))unsupported("use order field requires a use relation");
                if(use_relation(plan.relation)&&s.field==SortField::flags)unsupported("flags order does not apply to use relation");
                if(auto d=optional(key,u"direction")){if(text(*d)==u"desc")s.descending=true;else if(text(*d)!=u"asc")invalid("invalid order direction");}plan.order.push_back(s);
            }
        }
        plan.root=optional(input,u"where")?predicate(*optional(input,u"where"),0):add(Kind::yes);
        if(relational){
            if(optional(input,u"where")){RelNode filter(plan.memory);filter.op=RelOp::filter;filter.relation=plan.relation;filter.predicate=plan.root;filter.children.push_back(plan.relation_root);plan.relation_root=add_relation(std::move(filter));}
            if(!plan.bag){RelNode distinct(plan.memory);distinct.op=RelOp::distinct;distinct.relation=plan.relation;distinct.children.push_back(plan.relation_root);plan.relation_root=add_relation(std::move(distinct));}
            const auto expand_count=std::count_if(plan.relations.begin(),plan.relations.end(),[](const RelNode& node){return node.op==RelOp::bounded_expand;});
            if(expand_count>1)
                unsupported("multiple or nested bounded_expand nodes are not supported");
        }
        finish(plan,using_type_syntax);return std::move(plan);
    }
    Plan plan;
    bool using_type_syntax=false;
    uint32_t add(Kind kind){if(plan.nodes.size()>=1024)throw Error(ErrorCode::budget,"predicate graph exceeds 1024 nodes");plan.nodes.emplace_back(plan.memory);plan.nodes.back().kind=kind;return static_cast<uint32_t>(plan.nodes.size()-1);}
    uint32_t pattern(const Json& value){
        if(plan.texts.size()>=256)throw Error(ErrorCode::budget,"text matcher count exceeds 256");
        TextMatcher t(plan.memory);
        if(value.kind==Json::Kind::string)t.text=value.string;
        else{
            keys(value,{u"op",u"value",u"u16",u"ascii_case_insensitive"});
            if(auto v=optional(value,u"op")){auto op=text(*v);if(op==u"exact")t.op=TextOp::exact;else if(op==u"contains")t.op=TextOp::contains;else if(op==u"prefix")t.op=TextOp::prefix;else unsupported("unsupported text operation");}
            const auto* normal=optional(value,u"value");const auto* raw=optional(value,u"u16");if((normal==nullptr)==(raw==nullptr))invalid("text needs exactly one value or u16");
            if(normal)t.text=text(*normal);else for(const auto& v:array(*raw)){const auto c=integer(v);if(c>65535)invalid("u16 value exceeds 65535");t.text.push_back(static_cast<char16_t>(c));}
            if(auto v=optional(value,u"ascii_case_insensitive"))t.ascii_fold=boolean(*v);
        }
        if(t.text.size()>65536)throw Error(ErrorCode::budget,"text matcher too long");prepare_text(t);
        plan.texts.push_back(std::move(t));return static_cast<uint32_t>(plan.texts.size()-1);
    }
private:
    uint32_t add_relation(RelNode node){
        if(plan.relations.size()>=128)throw Error(ErrorCode::budget,"relation graph exceeds 128 nodes");
        plan.relations.push_back(std::move(node));return static_cast<uint32_t>(plan.relations.size()-1);
    }
    uint32_t label_id(const Json& value){
        const auto name=text(value);if(name.empty()||name.size()>64)invalid("label length must be in 1..64");
        std::pmr::string encoded(plan.memory);for(auto c:name){
            if(!((c>=u'A'&&c<=u'Z')||(c>=u'a'&&c<=u'z')||(c>=u'0'&&c<=u'9')||c==u'_'||c==u'.'||c==u'-'))invalid("label must be an ASCII identifier");
            encoded.push_back(static_cast<char>(c));
        }
        const auto found=std::find(plan.labels.begin(),plan.labels.end(),encoded);
        if(found!=plan.labels.end())return static_cast<uint32_t>(found-plan.labels.begin());
        plan.labels.push_back(std::move(encoded));return static_cast<uint32_t>(plan.labels.size()-1);
    }
    uint32_t predicate_for(const Json& value,Relation relation){
        const auto previous=plan.relation;plan.relation=relation;const auto result=predicate(value,0);plan.relation=previous;return result;
    }
    uint32_t expression(const Json& value,unsigned depth){
        if(depth>=32)throw Error(ErrorCode::budget,"relation depth exceeds 32");
        object(value);const auto operation=text(required(value,u"op"));RelNode node(plan.memory);
        if(operation==u"scan"){
            keys(value,{u"op",u"relation",u"where",u"scope"});node.relation=relation_type(required(value,u"relation"));
            node.predicate=optional(value,u"where")?predicate_for(*optional(value,u"where"),node.relation):add(Kind::yes);
            if(auto v=optional(value,u"scope")){node.explicit_scope=true;scope(*v,node.scope_slots,plan.memory);}
        }else if(operation==u"filter"){
            keys(value,{u"op",u"input",u"where"});node.op=RelOp::filter;
            const auto child=expression(required(value,u"input"),depth+1);node.children.push_back(child);node.relation=plan.relations[child].relation;
            node.predicate=predicate_for(required(value,u"where"),node.relation);
        }else if(operation==u"bounded_expand"){
            keys(value,{u"op",u"input",u"edge",u"direction",u"resolution",u"scope",u"min_depth",u"max_depth",u"cycle",u"output",u"walk_where",u"emit_where",u"max_visited",u"max_edges",u"max_paths"});
            node.op=RelOp::bounded_expand;
            const auto child=expression(required(value,u"input"),depth+1);
            if(plan.relations[child].relation!=Relation::method_defs)unsupported("bounded_expand requires method definitions");
            node.children.push_back(child);node.relation=Relation::method_defs;
            if(auto v=optional(value,u"edge"))if(text(*v)!=u"invoke_method_ref")unsupported("unsupported expand edge");
            if(auto v=optional(value,u"resolution"))if(text(*v)!=u"all_definitions")unsupported("unsupported expand resolution");
            if(auto v=optional(value,u"cycle"))if(text(*v)!=u"bounded_walk")unsupported("unsupported expand cycle policy");
            if(auto v=optional(value,u"direction")){const auto name=text(*v);if(name==u"incoming")node.expand_direction=ExpandDirection::incoming;else if(name!=u"outgoing")unsupported("unsupported expand direction");}
            if(auto v=optional(value,u"output")){const auto name=text(*v);if(name==u"endpoints")node.expand_output=ExpandOutput::endpoints;else if(name!=u"paths")unsupported("unsupported expand output");}
            node.expand_max_depth=integer(required(value,u"max_depth"));
            if(auto v=optional(value,u"min_depth"))node.expand_min_depth=integer(*v);
            if(node.expand_min_depth>node.expand_max_depth)invalid("inverted expand depth range");
            if(auto v=optional(value,u"max_visited"))node.expand_max_visited=integer64(*v);
            if(auto v=optional(value,u"max_edges"))node.expand_max_edges=integer64(*v);
            if(auto v=optional(value,u"max_paths"))node.expand_max_paths=integer64(*v);
            if(!node.expand_max_visited||!node.expand_max_edges||!node.expand_max_paths)invalid("expand budgets must be nonzero");
            if(auto v=optional(value,u"scope")){node.explicit_scope=true;scope(*v,node.scope_slots,plan.memory);}
            if(auto v=optional(value,u"walk_where"))node.expand_walk_predicate=predicate_for(*v,Relation::method_defs);
            if(auto v=optional(value,u"emit_where"))node.expand_emit_predicate=predicate_for(*v,Relation::method_defs);
        }else if(operation==u"join"||operation==u"semi_join"){
            keys(value,{u"op",u"left",u"right",u"on"});
            node.op=operation==u"join"?RelOp::join:RelOp::semi_join;
            node.join_key=join_key(required(value,u"on"));
            const auto left=expression(required(value,u"left"),depth+1);
            const auto right=expression(required(value,u"right"),depth+1);
            node.relation=plan.relations[left].relation;
            if(!join_compatible(node.join_key,node.relation,plan.relations[right].relation))unsupported("join key does not apply to input relation types");
            node.children.push_back(left);node.children.push_back(right);
        }else if(operation==u"union"||operation==u"group_by_owner"){
            const bool group=operation==u"group_by_owner";node.op=group?RelOp::group_by_owner:RelOp::union_rows;
            if(group)keys(value,{u"op",u"inputs",u"min",u"max",u"required_roles",u"role_policy"});
            else keys(value,{u"op",u"inputs",u"semantics",u"identity"});
            if(!group){node.bag=bag_semantics(required(value,u"semantics"));if(auto v=optional(value,u"identity"))node.identity=identity(*v);}
            const auto& inputs=array(required(value,u"inputs"));if(inputs.empty())invalid("relation inputs must not be empty");
            for(const auto& input:inputs){
                const auto child=expression(input,depth+1);const auto type=plan.relations[child].relation;
                if(group){if(type!=Relation::method_defs&&type!=Relation::field_defs)unsupported("group_by_owner requires member definitions");}
                else if(!node.children.empty()&&node.relation!=type)unsupported("union inputs must have the same relation type");
                if(node.children.empty())node.relation=type;node.children.push_back(child);
            }
            if(group){
                node.relation=Relation::class_defs;
                if(auto v=optional(value,u"min"))node.minimum=integer(*v);if(auto v=optional(value,u"max"))node.maximum=integer(*v);
                if(node.minimum>node.maximum)invalid("inverted group member range");
                if(auto v=optional(value,u"role_policy")){const auto policy=text(*v);if(policy==u"distinct")node.distinct_roles=true;else if(policy!=u"shared")unsupported("unsupported group role policy");}
                if(auto v=optional(value,u"required_roles"))for(const auto& role:array(*v)){
                    const auto id=label_id(role);if(std::find(node.required_roles.begin(),node.required_roles.end(),id)!=node.required_roles.end())invalid("duplicate required group role");
                    node.required_roles.push_back(id);
                }
            }
        }else if(operation==u"distinct"||operation==u"label"){
            const bool labeled=operation==u"label";node.op=labeled?RelOp::label:RelOp::distinct;
            if(labeled)keys(value,{u"op",u"input",u"label"});else keys(value,{u"op",u"input",u"identity"});
            const auto child=expression(required(value,u"input"),depth+1);node.children.push_back(child);node.relation=plan.relations[child].relation;
            if(labeled)node.label=label_id(required(value,u"label"));else if(auto v=optional(value,u"identity"))node.identity=identity(*v);
        }else unsupported("unsupported relation operation");
        return add_relation(std::move(node));
    }
    bool method_relation()const{return plan.relation==Relation::method_defs||plan.relation==Relation::method_refs;}
    bool member_relation()const{return method_relation()||plan.relation==Relation::field_defs||plan.relation==Relation::field_refs;}
    uint32_t allowed_projection()const{return (method_relation()||use_relation(plan.relation))?project_all:member_relation()?project_owner|project_name|project_type:plan.relation==Relation::string_values?project_value:project_type;}
    void check_predicate(std::u16string_view name)const{
        if(name==u"all"||name==u"any"||name==u"not")return;
        if(use_relation(plan.relation)){
            if(name==u"target_field_declaration"&&plan.relation==Relation::field_uses)return;
            if(name==u"target_descriptor"){if(plan.relation!=Relation::type_uses)unsupported("target descriptor requires type uses");return;}
        if(name==u"caller_name"||name==u"caller_owner"||name==u"pc"||name==u"opcode"||name==u"target_index"||name==u"target_domain")return;
            unsupported("predicate does not apply to use relation");
        }
        if(name==u"annotation"){if(plan.relation!=Relation::class_defs)unsupported("annotation requires class_defs");return;}
        if(name==u"target_descriptor")unsupported("target descriptor requires type uses");
        if(name==u"target_field_declaration")unsupported("field declaration requires field_uses");
        if(name==u"caller_name"||name==u"caller_owner"||name==u"pc"||name==u"opcode"||name==u"target_index"||name==u"target_domain")unsupported("use predicate requires use relation");
        if(name==u"value"){if(plan.relation!=Relation::string_values)unsupported("value requires string_values");return;}
        if(plan.relation==Relation::string_values)unsupported("predicate does not apply to string_values");
        if(name==u"using_strings"||name==u"invokes"||name==u"field_access"||name==u"using_types"||name==u"numeric_bits"||name==u"opcodes"){if(plan.relation!=Relation::method_defs)unsupported("body predicate requires method_defs");return;}
        if(name==u"prototype"||name==u"return_type"||name==u"param_count"||name==u"parameters"||name==u"parameter"||name==u"kind"){if(!method_relation())unsupported("predicate requires method relation");return;}
        if(name==u"name"||name==u"owner"||name==u"owner_flags"){if(!member_relation())unsupported("predicate requires member relation");return;}
        if(name==u"descriptor"){if(plan.relation!=Relation::class_defs&&plan.relation!=Relation::type_refs)unsupported("descriptor requires class_defs or type_refs");return;}
        if(name==u"type"&&plan.relation!=Relation::field_defs&&plan.relation!=Relation::field_refs)unsupported("type requires field relation");
    }
    uint32_t use_domain(const Json& value)const{
        using Domain=facts::TargetDomain;const auto name=text(value);
        if(plan.relation==Relation::string_uses&&name==u"string_value")return static_cast<uint32_t>(Domain::string_value);
        if(plan.relation==Relation::field_uses&&name==u"field_ref")return static_cast<uint32_t>(Domain::field_ref);
        if(plan.relation==Relation::type_uses&&name==u"type_ref")return static_cast<uint32_t>(Domain::type_ref);
        if(plan.relation==Relation::invoke_sites){
            if(name==u"method_ref")return static_cast<uint32_t>(Domain::method_ref);
            if(name==u"method_and_proto")return static_cast<uint32_t>(Domain::method_and_proto);
            if(name==u"call_site")return static_cast<uint32_t>(Domain::call_site);
        }
        unsupported("target domain does not apply to use relation");
    }
    uint32_t text_node(Kind kind,const Json& value){const auto id=add(kind);plan.nodes[id].text=pattern(value);return id;}
    uint32_t combine(Kind kind,std::span<const uint32_t> children){
        if(children.empty())return add(kind==Kind::all?Kind::yes:Kind::no);if(children.size()==1)return children[0];
        const auto id=add(kind);plan.nodes[id].children.assign(children.begin(),children.end());return id;
    }
    uint32_t flags(const Json& value,bool owner){
        keys(value,{u"mode",u"value",u"domain"});bool reflection=false;
        if(auto d=optional(value,u"domain")){const auto domain=text(*d);if(domain==u"reflection")reflection=true;else if(domain!=u"dex")unsupported("unknown flag domain");}
        Kind kind=Kind::flags_contains;if(auto mode=optional(value,u"mode")){auto name=text(*mode);if(name==u"exact")kind=Kind::flags_exact;else if(name==u"any")kind=Kind::flags_any;else if(name!=u"contains")unsupported("unsupported flags operation");}
        const auto id=add(kind);plan.nodes[id].minimum=integer(required(value,u"value"));plan.nodes[id].argument=(owner?1u:0u)|(reflection?2u:0u);return id;
    }
    uint32_t symbol(const Json& value){
        keys(value,{u"owner",u"name",u"prototype",u"return_type",u"param_count",u"parameters",u"reference_kind"});
        SymbolMatcher s(plan.memory);if(auto v=optional(value,u"owner"))s.owner=pattern(*v);if(auto v=optional(value,u"name"))s.name=pattern(*v);
        if(auto v=optional(value,u"prototype"))s.prototype=pattern(*v);if(auto v=optional(value,u"return_type"))s.returned=pattern(*v);
        if(auto v=optional(value,u"param_count"))limits(*v,s.minimum_parameters,s.maximum_parameters);
        if(auto v=optional(value,u"parameters")){const auto& parameters=array(*v);if(parameters.size()>256)throw Error(ErrorCode::budget,"parameter matcher count exceeds 256");
            const auto size=static_cast<uint32_t>(parameters.size());s.minimum_parameters=std::max(s.minimum_parameters,size);s.maximum_parameters=std::min(s.maximum_parameters,size);
            for(uint32_t i=0;i<size;++i)s.parameters.push_back({i,pattern(parameters[i])});}
        if(auto v=optional(value,u"reference_kind")){auto name=text(*v);if(name==u"method")s.invoke_kind=InvokeKind::normal;else if(name==u"method_and_proto")s.invoke_kind=InvokeKind::polymorphic;else if(name==u"call_site")s.invoke_kind=InvokeKind::call_site;else if(name!=u"method_like")unsupported("unsupported invoke reference kind");}
        if(s.invoke_kind==InvokeKind::call_site&&(s.owner!=none||s.name!=none||s.prototype!=none||s.returned!=none||!s.parameters.empty()||s.minimum_parameters||s.maximum_parameters!=UINT32_MAX))unsupported("call-site bootstrap symbol predicates are not implemented");
        plan.symbols.push_back(std::move(s));return static_cast<uint32_t>(plan.symbols.size()-1);
    }
    uint32_t field(const Json& value,bool declaration){
        if(declaration)keys(value,{u"owner",u"name",u"type",u"flags_contains"});else keys(value,{u"owner",u"name",u"type",u"access"});
        FieldMatcher f;if(auto v=optional(value,u"owner"))f.owner=pattern(*v);if(auto v=optional(value,u"name"))f.name=pattern(*v);if(auto v=optional(value,u"type"))f.type=pattern(*v);
        if(auto v=optional(value,u"flags_contains"))f.flags=integer(*v);
        if(auto v=optional(value,u"access")){auto access=text(*v);if(access==u"read")f.access=1;else if(access==u"write")f.access=2;else if(access!=u"any")unsupported("unsupported field access kind");}
        plan.fields.push_back(f);return static_cast<uint32_t>(plan.fields.size()-1);
    }
    template<class Leaf>uint32_t quantified(const Json& value,Leaf leaf){
        keys(value,{u"all",u"any"});const auto* all=optional(value,u"all");const auto* any=optional(value,u"any");if((all==nullptr)==(any==nullptr))invalid("quantified matcher needs exactly one all or any");
        std::pmr::vector<uint32_t> children(plan.memory);for(const auto& v:array(all?*all:*any))children.push_back(leaf(v));return combine(all?Kind::all:Kind::any,children);
    }
    uint32_t predicate(const Json& value,unsigned depth){
        if(depth>32)throw Error(ErrorCode::budget,"predicate depth exceeds 32");
        if(value.kind==Json::Kind::boolean)return add(value.boolean?Kind::yes:Kind::no);
        keys(value,{u"all",u"any",u"not",u"name",u"owner",u"prototype",u"return_type",u"param_count",u"parameter",u"parameters",u"flags",u"flags_contains",u"flags_exact",u"flags_any",u"owner_flags",u"using_strings",u"invokes",u"field_access",u"numeric_bits",u"declares_fields",u"superclass",u"direct_interface",u"kind",u"descriptor",u"type",u"value",u"has_local_definition",u"caller_name",u"caller_owner",u"pc",u"opcode",u"target_index",u"target_domain",u"target_field_declaration",u"target_descriptor",u"using_types",u"opcodes",u"annotation"});
        std::pmr::vector<uint32_t> children(plan.memory);
        for(const auto& [key,v]:value.object){const auto name=std::u16string_view(key);uint32_t id=none;
            check_predicate(name);
            if(name==u"all"||name==u"any"){
                std::pmr::vector<uint32_t> nested(plan.memory);for(const auto& child:array(v))nested.push_back(predicate(child,depth+1));id=combine(name==u"all"?Kind::all:Kind::any,nested);
            }else if(name==u"not"){const auto child=predicate(v,depth+1);id=add(Kind::negate);plan.nodes[id].children.push_back(child);}
            else if(name==u"name")id=text_node(Kind::name,v);else if(name==u"owner")id=text_node(Kind::owner,v);
            else if(name==u"annotation"){
                keys(v,{u"type",u"visibility",u"element"});const auto descriptor=text(required(v,u"type"));
                if(!dex_names::class_descriptor(descriptor,40))invalid("annotation type must be a valid class descriptor");
                const auto type_index=pattern(required(v,u"type"));uint32_t visibility=0,element_index=none,int_bits=0,string_index=none;
                if(auto value=optional(v,u"visibility")){const auto x=integer(*value);if(x>2)invalid("invalid annotation visibility");visibility=x+1;}
                if(auto element=optional(v,u"element")){
                    keys(*element,{u"name",u"int",u"string"});const auto name_text=text(required(*element,u"name"));if(!dex_names::member_name(name_text,40))invalid("annotation element name invalid");
                    element_index=pattern(required(*element,u"name"));const auto* integer_value=optional(*element,u"int");const auto* string_value=optional(*element,u"string");
                    if((integer_value==nullptr)==(string_value==nullptr))invalid("annotation element requires exactly one int or string");
                    if(integer_value){const auto& number=*integer_value;if(number.kind!=Json::Kind::number||number.number.empty())invalid("annotation int must be int32");int32_t parsed=0;
                        const auto first=number.number.data(),last=first+number.number.size();const auto result=std::from_chars(first,last,parsed);
                        if(result.ec!=std::errc{}||result.ptr!=last)invalid("annotation int must be int32");int_bits=static_cast<uint32_t>(parsed);
                    }else{(void)text(*string_value);string_index=pattern(*string_value);}
                }
                id=add(string_index==none?Kind::class_annotation:Kind::class_annotation_string);auto& node=plan.nodes[id];node.text=type_index;node.symbol=element_index;node.argument=visibility;node.minimum=int_bits;if(string_index!=none)node.annotation_value_text=string_index;
            }
            else if(name==u"target_field_declaration"){
                keys(v,{u"scope",u"owner",u"name",u"type",u"flags_contains"});
                FieldMatcher f;if(auto x=optional(v,u"owner"))f.owner=pattern(*x);if(auto x=optional(v,u"name"))f.name=pattern(*x);if(auto x=optional(v,u"type"))f.type=pattern(*x);if(auto x=optional(v,u"flags_contains"))f.flags=integer(*x);
                plan.fields.push_back(f);id=add(Kind::target_field_declaration);auto& n=plan.nodes[id];n.symbol=static_cast<uint32_t>(plan.fields.size()-1);
                const auto scope=text(required(v,u"scope"));if(scope==u"declared")n.argument=0;else if(scope==u"inherited")n.argument=1;else if(scope==u"any")n.argument=2;else unsupported("unknown field declaration scope");
            }else if(name==u"caller_name")id=text_node(Kind::use_caller_name,v);else if(name==u"caller_owner")id=text_node(Kind::use_caller_owner,v);
            else if(name==u"pc"||name==u"opcode"||name==u"target_index"){
                id=add(name==u"pc"?Kind::use_pc:name==u"opcode"?Kind::use_opcode:Kind::use_target_index);limits(v,plan.nodes[id].minimum,plan.nodes[id].maximum);
            }else if(name==u"target_domain"){id=add(Kind::use_domain);plan.nodes[id].argument=use_domain(v);}
            else if(name==u"target_descriptor")id=text_node(Kind::use_target_descriptor,v);
            else if(name==u"descriptor"||name==u"type")id=text_node(Kind::descriptor,v);else if(name==u"value")id=text_node(Kind::value,v);
            else if(name==u"has_local_definition"){id=add(Kind::has_local_definition);plan.nodes[id].argument=boolean(v)?1u:0u;}
            else if(name==u"prototype")id=text_node(Kind::prototype,v);else if(name==u"return_type")id=text_node(Kind::return_type,v);
            else if(name==u"superclass")id=text_node(Kind::superclass,v);else if(name==u"direct_interface")id=text_node(Kind::interface_type,v);
            else if(name==u"flags"||name==u"owner_flags")id=flags(v,name==u"owner_flags");
            else if(name==u"flags_contains"||name==u"flags_exact"||name==u"flags_any"){id=add(name==u"flags_contains"?Kind::flags_contains:name==u"flags_exact"?Kind::flags_exact:Kind::flags_any);plan.nodes[id].minimum=integer(v);}
            else if(name==u"param_count"){id=add(Kind::parameter_count);limits(v,plan.nodes[id].minimum,plan.nodes[id].maximum);}
            else if(name==u"parameter"){keys(v,{u"index",u"type"});id=text_node(Kind::parameter_type,required(v,u"type"));plan.nodes[id].argument=integer(required(v,u"index"));}
            else if(name==u"parameters"){
                const auto& parameters=array(v);if(parameters.size()>256)throw Error(ErrorCode::budget,"parameter matcher count exceeds 256");
                std::pmr::vector<uint32_t> nested(plan.memory);const auto count=add(Kind::parameter_count);plan.nodes[count].minimum=plan.nodes[count].maximum=static_cast<uint32_t>(parameters.size());nested.push_back(count);
                for(uint32_t i=0;i<parameters.size();++i){const auto part=text_node(Kind::parameter_type,parameters[i]);plan.nodes[part].argument=i;nested.push_back(part);}id=combine(Kind::all,nested);
            }else if(name==u"using_types"){using_type_syntax=true;id=quantified(v,[&](const Json& target){
                keys(target,{u"descriptor",u"opcode"});const auto leaf=text_node(Kind::using_type,required(target,u"descriptor"));plan.nodes[leaf].argument=UINT32_MAX;
                if(const auto op=optional(target,u"opcode")){const auto value=integer(*op);if(value!=0x1c&&value!=0x1f&&value!=0x20&&value!=0x22&&value!=0x23&&value!=0x24&&value!=0x25)unsupported("unsupported type-use opcode");plan.nodes[leaf].argument=value;}return leaf;
            });}
            else if(name==u"using_strings")id=quantified(v,[&](const Json& pattern){return text_node(Kind::using_string,pattern);});
            else if(name==u"invokes")id=quantified(v,[&](const Json& target){const auto s=symbol(target);const auto leaf=add(Kind::invoke);plan.nodes[leaf].symbol=s;return leaf;});
            else if(name==u"field_access")id=quantified(v,[&](const Json& target){const auto f=field(target,false);const auto leaf=add(Kind::field_access);plan.nodes[leaf].symbol=f;return leaf;});
            else if(name==u"opcodes"){
                keys(v,{u"mode",u"values",u"count",u"negative_wildcards",u"signed16_coercion"});
                const bool allow_wildcards=optional(v,u"negative_wildcards")?boolean(*optional(v,u"negative_wildcards")):false;
                const bool signed16_coercion=optional(v,u"signed16_coercion")?boolean(*optional(v,u"signed16_coercion")):false;
                if(plan.texts.size()>=256)throw Error(ErrorCode::budget,"matcher count exceeds 256");
                TextMatcher pattern(plan.memory);const auto mode=text(required(v,u"mode"));OpcodeMode match_mode;
                if(mode==u"contains")match_mode=OpcodeMode::contains;else if(mode==u"starts_with")match_mode=OpcodeMode::starts_with;
                else if(mode==u"ends_with")match_mode=OpcodeMode::ends_with;else if(mode==u"equals")match_mode=OpcodeMode::equals;
                else unsupported("unsupported opcode sequence mode");
                const auto& values=array(required(v,u"values"));if(values.size()>4096)throw Error(ErrorCode::budget,"opcode sequence exceeds 4096 entries");
                bool wildcard=false;
                for(const auto& item:values){
                    if(item.kind!=Json::Kind::number||item.number.empty())invalid("opcode must be an int32");
                    int32_t number=0;const auto* begin=item.number.data();const auto* end=begin+item.number.size();
                    const auto parsed=std::from_chars(begin,end,number);if(parsed.ec!=std::errc{}||parsed.ptr!=end)invalid("opcode integer outside int32");
                    if(signed16_coercion){
                        const auto encoded=static_cast<uint32_t>(number)&0xffffu;
                        if(encoded&0x8000u){if(!allow_wildcards)unsupported("signed-int16 negative opcode requires explicit wildcard opt-in");pattern.text.push_back(char16_t{256});wildcard=true;}
                        else pattern.text.push_back(static_cast<char16_t>(encoded&255u));
                    }else if(number<0){if(!allow_wildcards)unsupported("negative opcode wildcard requires explicit opt-in");pattern.text.push_back(char16_t{256});wildcard=true;}
                    else{if(number>255)unsupported("opcode outside byte range requires explicit signed16 coercion");pattern.text.push_back(static_cast<char16_t>(number));}
                }
                if(wildcard&&match_mode==OpcodeMode::contains){
                    const auto words=(pattern.text.size()+31u)/32u;pattern.prefix.resize(words*257u);
                    for(size_t i=0;i<pattern.text.size();++i){const auto code=static_cast<uint32_t>(pattern.text[i]);pattern.prefix[size_t(code)*words+i/32u]|=uint32_t{1}<<(i%32u);}
                }else if(!wildcard&&match_mode==OpcodeMode::contains){
                    pattern.prefix.resize(pattern.text.size());
                    for(size_t i=1,j=0;i<pattern.text.size();++i){while(j&&pattern.text[i]!=pattern.text[j])j=pattern.prefix[j-1];if(pattern.text[i]==pattern.text[j])++j;pattern.prefix[i]=static_cast<uint32_t>(j);}
                }
                plan.texts.push_back(std::move(pattern));id=add(Kind::opcode_sequence);auto& node=plan.nodes[id];
                node.text=static_cast<uint32_t>(plan.texts.size()-1);node.argument=static_cast<uint32_t>(match_mode)|(wildcard?4u:0u)|(signed16_coercion?8u:0u);
                if(auto count=optional(v,u"count"))limits(*count,node.minimum,node.maximum);
            }
            else if(name==u"numeric_bits"){
                keys(v,{u"width",u"bits",u"kind"});numeric::Pattern pattern;
                if(!numeric::parse(integer(required(v,u"width")),text(required(v,u"bits")),text(required(v,u"kind")),pattern))invalid("invalid numeric bit pattern");
                id=add(Kind::numeric_bits);plan.nodes[id].minimum=pattern.width;plan.nodes[id].argument=static_cast<uint32_t>(pattern.kind);plan.nodes[id].numeric_value=pattern.bits;
            }
            else if(name==u"declares_fields"){
                keys(v,{u"where",u"min",u"max",u"scope"});const auto f=field(required(v,u"where"),true);auto kind=Kind::declared_field_count;
                if(const auto scope_value=optional(v,u"scope")){const auto scope_name=text(*scope_value);if(scope_name==u"inherited")kind=Kind::inherited_field_count;else if(scope_name==u"inherited_interfaces")kind=Kind::inherited_interface_count;else if(scope_name==u"inherited_interfaces_resolved")kind=Kind::inherited_interface_resolved_count;else if(scope_name!=u"declared")unsupported("unsupported field declaration scope");}
                id=add(kind);plan.nodes[id].symbol=f;
                if(auto minimum=optional(v,u"min"))plan.nodes[id].minimum=integer(*minimum);if(auto maximum=optional(v,u"max"))plan.nodes[id].maximum=integer(*maximum);if(plan.nodes[id].minimum>plan.nodes[id].maximum)invalid("inverted declared-field range");
            }else if(name==u"kind"){
                const auto kind=text(v);if(kind!=u"constructor"&&kind!=u"clinit"&&kind!=u"normal")unsupported("unsupported method kind");
                auto special=[&](std::u16string_view label){Json j(plan.memory);j.kind=Json::Kind::string;j.string=label;return text_node(Kind::name,j);};
                if(kind==u"constructor")id=special(u"<init>");else if(kind==u"clinit")id=special(u"<clinit>");else{uint32_t names[]={special(u"<init>"),special(u"<clinit>")};auto any=combine(Kind::any,names);id=add(Kind::negate);plan.nodes[id].children.push_back(any);}
            }
            children.push_back(id);
        }return combine(Kind::all,children);
    }
};
}
Plan compile(std::string_view input,std::pmr::memory_resource* plan_memory,std::pmr::memory_resource* temporary_memory){
    if(input.size()>65536)throw Error(ErrorCode::budget,"QueryIR JSON exceeds 64 KiB");
    try{const auto parsed=json::JsonReader(input,temporary_memory).parse();return Compiler(plan_memory).run(parsed);}
    catch(const json::JsonError&){throw Error(ErrorCode::invalid,"invalid or oversized QueryIR JSON");}
}
Plan compile_simple(const SimpleQuery& q,std::pmr::memory_resource* memory){
    Compiler compiler(memory);auto& p=compiler.plan;p.intent=q.intent;p.max_results=q.max_results;
    std::pmr::vector<uint32_t> children(memory);
    auto text_node=[&](Kind kind,std::u16string_view value,TextOp op){TextMatcher t(memory);t.text=value;t.op=op;prepare_text(t);p.texts.push_back(std::move(t));const auto id=compiler.add(kind);p.nodes[id].text=static_cast<uint32_t>(p.texts.size()-1);children.push_back(id);};
    if(q.name_enabled)text_node(Kind::name,q.name,q.name_op);if(q.owner_enabled)text_node(Kind::owner,q.owner,TextOp::exact);
    if(q.flags){const auto id=compiler.add(Kind::flags_contains);p.nodes[id].minimum=q.flags;children.push_back(id);}
    if(children.empty())p.root=compiler.add(Kind::yes);else if(children.size()==1)p.root=children[0];else{p.root=compiler.add(Kind::all);p.nodes[p.root].children=std::move(children);}
    finish(p);return std::move(p);
}
}
