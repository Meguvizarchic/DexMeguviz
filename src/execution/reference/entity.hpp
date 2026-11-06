#pragma once
#include "query/ir.hpp"
#include "format/reader.hpp"
#include "facts/symbols.hpp"
#include <span>

namespace dexmeguviz::reference {
struct SourceView {uint32_t source_index,input_index;const Facts* facts;std::span<const uint8_t> bytes;};
struct EntityView {
    query::Relation kind=query::Relation::method_defs;
    uint32_t source_index=0,ordinal=0,reference_index=UINT32_MAX,record_offset=UINT32_MAX;
    uint32_t definition_offset=0,access_flags=0,code_offset=0,owner_type=UINT32_MAX;
    bool definition_known=false,flags_known=false,code_known=false;
    std::u16string_view owner,name,prototype,type_descriptor,value;
    const Method* method=nullptr;
    const Prototype* proto=nullptr;
    const ClassDefinition* owner_class=nullptr;
};
inline void validate_entity_relation(query::Relation kind){
    switch(kind){
    case query::Relation::method_defs:case query::Relation::class_defs:case query::Relation::field_defs:
    case query::Relation::method_refs:case query::Relation::field_refs:case query::Relation::string_values:case query::Relation::type_refs:return;
    }
    throw query::Error(query::ErrorCode::unsupported,"unsupported entity relation");
}
inline uint32_t relation_size(const Facts& f,query::Relation kind){
    switch(kind){case query::Relation::method_defs:return static_cast<uint32_t>(f.methods.size());case query::Relation::class_defs:return static_cast<uint32_t>(f.class_definitions.size());
    case query::Relation::field_defs:return static_cast<uint32_t>(f.field_definitions.size());case query::Relation::method_refs:return static_cast<uint32_t>(f.method_refs.size());
    case query::Relation::field_refs:return static_cast<uint32_t>(f.field_refs.size());case query::Relation::string_values:return static_cast<uint32_t>(f.strings.size());case query::Relation::type_refs:return static_cast<uint32_t>(f.types.size());}
    throw query::Error(query::ErrorCode::unsupported,"unsupported entity relation");
}
inline EntityView entity(const SourceView& source,query::Relation kind,uint32_t ordinal){
    validate_entity_relation(kind);
    if(!source.facts)throw query::Error(query::ErrorCode::invalid,"entity source has no metadata");
    const auto& f=*source.facts;if(ordinal>=relation_size(f,kind))throw query::Error(query::ErrorCode::invalid,"entity ordinal outside its relation");
    EntityView out;out.kind=kind;out.source_index=source.source_index;out.ordinal=ordinal;
    auto type=[&](uint32_t i)->std::u16string_view{return f.strings[f.types[i]];};
    auto table=[&](uint32_t field,uint32_t width,uint32_t index){
        const uint64_t header_field=uint64_t(f.header_offset)+field;
        if(header_field>source.bytes.size()||4>source.bytes.size()-header_field)throw query::Error(query::ErrorCode::invalid,"entity source has no checked header");
        const auto* p=source.bytes.data()+header_field;const uint64_t start=uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24);
        const uint64_t at=start+uint64_t(width)*index;if(at>source.bytes.size()||width>source.bytes.size()-at||at>UINT32_MAX)throw query::Error(query::ErrorCode::invalid,"entity record outside checked source");return static_cast<uint32_t>(at);
    };
    if(kind==query::Relation::method_defs||kind==query::Relation::method_refs){
        out.reference_index=kind==query::Relation::method_defs?f.methods[ordinal].method_index:ordinal;
        const auto& ref=f.method_refs[out.reference_index];out.owner_type=ref.owner;out.owner=type(ref.owner);out.name=f.strings[ref.name];out.proto=&f.prototypes[ref.type];out.prototype=out.proto->descriptor;
        auto definition=ordinal;
        if(kind==query::Relation::method_refs){
            const auto local=symbols::classify_method_ref(f,out.reference_index);
            if(local.kind==symbols::MethodRefLocalKind::invalid_reference||local.kind==symbols::MethodRefLocalKind::invalid_metadata)
                throw query::Error(query::ErrorCode::invalid,"invalid local method reference metadata");
            definition=local.definition_ordinal;
        }
        out.record_offset=kind==query::Relation::method_defs?f.methods[ordinal].declaration_offset:table(92,8,ordinal);
        if(definition!=UINT32_MAX){const auto& m=f.methods[definition];out.definition_known=true;out.flags_known=true;out.definition_offset=m.declaration_offset;out.access_flags=m.access_flags;
            if(kind==query::Relation::method_defs){out.method=&m;out.code_known=true;out.code_offset=m.code_offset;}}
    }else if(kind==query::Relation::field_defs||kind==query::Relation::field_refs){
        out.reference_index=kind==query::Relation::field_defs?f.field_definitions[ordinal].field_ref_index:ordinal;
        const auto& ref=f.field_refs[out.reference_index];out.owner_type=ref.owner;out.owner=type(ref.owner);out.name=f.strings[ref.name];out.type_descriptor=type(ref.type);
        const auto definition=kind==query::Relation::field_defs?ordinal:f.field_definition_by_ref[out.reference_index];
        out.record_offset=kind==query::Relation::field_defs?f.field_definitions[ordinal].declaration_offset:table(84,8,ordinal);
        if(definition!=UINT32_MAX){const auto& d=f.field_definitions[definition];out.definition_known=true;out.flags_known=true;out.definition_offset=d.declaration_offset;out.access_flags=d.access_flags;}
    }else if(kind==query::Relation::class_defs||kind==query::Relation::type_refs){
        out.reference_index=kind==query::Relation::class_defs?f.class_definitions[ordinal].type_id:ordinal;out.owner_type=out.reference_index;out.type_descriptor=type(out.reference_index);
        const auto definition=kind==query::Relation::class_defs?ordinal:f.class_definition_by_type[out.reference_index];
        out.record_offset=kind==query::Relation::class_defs?f.class_definitions[ordinal].definition_offset:table(68,4,ordinal);
        if(definition!=UINT32_MAX){const auto& c=f.class_definitions[definition];out.definition_known=true;out.flags_known=true;out.definition_offset=c.definition_offset;out.access_flags=c.access_flags;out.owner_class=&c;}
    }else if(kind==query::Relation::string_values){
        out.reference_index=ordinal;out.record_offset=table(60,4,ordinal);out.value=f.strings[ordinal];
    }else throw query::Error(query::ErrorCode::unsupported,"unsupported entity relation");
    if(!out.owner_class&&out.owner_type!=UINT32_MAX&&out.owner_type<f.class_definition_by_type.size()){
        const auto owner=f.class_definition_by_type[out.owner_type];if(owner!=UINT32_MAX)out.owner_class=&f.class_definitions[owner];
    }
    return out;
}
}
