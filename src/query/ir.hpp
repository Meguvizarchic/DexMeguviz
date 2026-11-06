#pragma once
#include <cstdint>
#include <exception>
#include <memory_resource>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace dexmeguviz::query {
enum class ErrorCode { invalid, unsupported, budget, cancelled, source_mismatch };
struct Error final:std::exception {
    ErrorCode code;const char* message;
    Error(ErrorCode c,const char* m)noexcept:code(c),message(m){}
    const char* what()const noexcept override{return message;}
};
constexpr uint32_t none=UINT32_MAX;
enum class Relation:uint32_t {method_defs,class_defs,field_defs,method_refs,field_refs,string_values,type_refs,string_uses,invoke_sites,field_uses,type_uses};
constexpr bool is_use_relation(Relation r)noexcept{return r==Relation::string_uses||r==Relation::invoke_sites||r==Relation::field_uses||r==Relation::type_uses;}
enum class TextOp:uint32_t { exact,contains,prefix };
struct TextMatcher {
    TextOp op=TextOp::exact;
    bool ascii_fold=false;
    std::pmr::u16string text;
    std::pmr::vector<uint32_t> prefix;
    explicit TextMatcher(std::pmr::memory_resource* r):text(r),prefix(r){}
};
enum class Kind:uint32_t { yes,no,all,any,negate,name,owner,prototype,return_type,
    parameter_count,parameter_type,flags_contains,flags_exact,flags_any,
    using_string,invoke,field_access,declared_field_count,superclass,interface_type,
    descriptor,value,has_local_definition,use_pc,use_opcode,use_target_index,use_domain,use_caller_name,use_caller_owner,inherited_field_count=29,numeric_bits=30,inherited_interface_count=31,inherited_interface_resolved_count=32, target_field_declaration=33, use_target_descriptor=34, using_type=35, opcode_sequence=36, class_annotation=37, class_annotation_string=38 };
struct Node {
    Kind kind=Kind::yes;
    uint32_t text=none,argument=0,minimum=0,maximum=UINT32_MAX,symbol=none,demand_mask=0,stable_id=none;
    // The alternative index is used only for the v25 string-annotation leaf.
    union {uint64_t numeric_value=0;uint64_t annotation_value_text;};
    std::pmr::vector<uint32_t> children;
    explicit Node(std::pmr::memory_resource* r):children(r){}
};
enum class OpcodeMode:uint32_t { contains, starts_with, ends_with, equals };
struct Parameter {uint32_t index,text;};
enum class InvokeKind:uint32_t { method_like,normal,polymorphic,call_site };
struct SymbolMatcher {
    uint32_t owner=none,name=none,prototype=none,returned=none;
    uint32_t minimum_parameters=0,maximum_parameters=UINT32_MAX;
    InvokeKind invoke_kind=InvokeKind::method_like;
    std::pmr::vector<Parameter> parameters;
    explicit SymbolMatcher(std::pmr::memory_resource* r):parameters(r){}
};
struct FieldMatcher {uint32_t owner=none,name=none,type=none,flags=0;uint32_t access=0;};
enum class SortField:uint32_t {owner,name,prototype,flags,source_index,method_index,descriptor,value,local_index,use_pc,use_opcode,use_target_index};
struct SortKey {SortField field;bool descending=false;};
enum class Intent:uint32_t { enumerate,exists,unique,top_n };
enum Projection:uint32_t { project_owner=1,project_name=2,project_prototype=4,project_type=8,project_value=16,project_all=7 };
enum class RelOp:uint32_t {scan,filter,union_rows,distinct,label,group_by_owner,join,semi_join,bounded_expand};
enum class JoinKey:uint32_t {same_entity,local_definition,local_owner,symbol,caller,target_ref,target_symbol};
enum class Identity:uint32_t {entity,tuple};
enum class ExpandDirection:uint32_t {outgoing,incoming};
enum class ExpandOutput:uint32_t {paths,endpoints};
struct RelNode {
    RelOp op=RelOp::scan;
    Relation relation=Relation::method_defs;
    uint32_t predicate=none,label=none,minimum=1,maximum=UINT32_MAX,stable_id=none;
    Identity identity=Identity::tuple;
    JoinKey join_key=JoinKey::same_entity;
    ExpandDirection expand_direction=ExpandDirection::outgoing;
    ExpandOutput expand_output=ExpandOutput::paths;
    uint32_t expand_min_depth=1,expand_max_depth=0,expand_walk_predicate=none,expand_emit_predicate=none;
    uint64_t expand_max_visited=100000,expand_max_edges=100000,expand_max_paths=100000;
    bool bag=false,explicit_scope=false,distinct_roles=false;
    std::pmr::vector<uint32_t> children,required_roles;
    std::pmr::vector<std::pmr::string> scope_slots;
    explicit RelNode(std::pmr::memory_resource* r):children(r),required_roles(r),scope_slots(r){}
};
struct Plan {
    std::pmr::memory_resource* memory;
    std::pmr::vector<Node> nodes;
    std::pmr::vector<TextMatcher> texts;
    std::pmr::vector<SymbolMatcher> symbols;
    std::pmr::vector<FieldMatcher> fields;
    std::pmr::vector<std::pmr::string> scope_slots;
    std::pmr::vector<SortKey> order;
    std::pmr::vector<uint32_t> stable_order;
    std::pmr::vector<RelNode> relations;
    std::pmr::vector<std::pmr::string> labels;
    std::pmr::string id;
    uint32_t root=0,demand_mask=0,max_results=4096,projection=project_all,required_capabilities=0;
    uint64_t max_work=100'000'000;
    Intent intent=Intent::enumerate;
    Relation relation=Relation::method_defs;
    uint32_t relation_root=none,max_intermediate_rows=100000;
    Identity unique_identity=Identity::entity;
    bool field_declaration_resolution=false;
    bool explicit_scope=false,bag=false,contains_uses=false,contains_inherited=false,has_inherited_predicate=false,contains_numeric=false,contains_interface_fields=false,contains_interface_resolved=false,use_streaming=false,contains_expand=false;
    // Draft-only capability; this branch is not yet approved for release.
    bool unique_one_stream=false,method_type_query=false,class_annotation_requested=false,class_annotation_string_requested=false;
    explicit Plan(std::pmr::memory_resource* r):memory(r),nodes(r),texts(r),symbols(r),fields(r),scope_slots(r),order(r),stable_order(r),relations(r),labels(r),id(r){}
    Plan(const Plan&)=delete;Plan& operator=(const Plan&)=delete;
    Plan(Plan&&)noexcept=default;Plan& operator=(Plan&&)=delete;
};
struct SimpleQuery {
    bool name_enabled=false,owner_enabled=false;
    TextOp name_op=TextOp::exact;
    std::u16string_view name,owner;
    uint32_t flags=0,max_results=4096;
    Intent intent=Intent::enumerate;
};
Plan compile(std::string_view json,std::pmr::memory_resource* plan_memory,std::pmr::memory_resource* temporary_memory);
Plan compile_simple(const SimpleQuery& query,std::pmr::memory_resource* memory);
}
