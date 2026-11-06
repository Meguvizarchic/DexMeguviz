#pragma once
#include "query/ir.hpp"
#include "format/reader.hpp"
#include "entity.hpp"
#include "facts/use_relations/use_scan.hpp"
#include "facts/use_relations/reverse_index.hpp"
#include <span>
#include <optional>
#include <array>
#include <unordered_map>
#include <exception>

namespace dexmeguviz::reference {
// Internal opt-in: runtime creates the context from the exact Dataset it owns.
struct ReverseTargetJoin {
    facts::ReverseRegistry* registry=nullptr;
    facts::ReverseLimits limits{};
    uint64_t max_adapter_work=0,adapter_work=0;
    uint32_t max_page_calls=0,page_calls=0;
    query::Relation use_relation=query::Relation::invoke_sites;
    bool intersection_only=false;
};
struct DatasetView {std::span<const SourceView> sources;std::span<const std::string_view> input_slots;bool scope_complete=true;ReverseTargetJoin* reverse_target_join=nullptr;};
struct Cancel {bool(*requested)(void*)noexcept=nullptr;void* context=nullptr;};
enum class WitnessKind:uint32_t {metadata=1,string_use=2,invoke=3,field_use=4,instruction_scope=5,no_body=6,string_pool_absence=7,inherited=8,numeric_literal=9,interface_inherited=10,interface_resolved=11, field_declaration=12, caller_field_relation=13, class_annotation_flags=14,type_use=15};
struct Witness {
    WitnessKind kind=WitnessKind::metadata;
    uint32_t node=0,matched=0,dex_pc=UINT32_MAX,opcode=0,reference_index=UINT32_MAX,reference_kind=0,extra_proto=UINT32_MAX,code_units=0;
    uint32_t relation_node=UINT32_MAX,source_index=UINT32_MAX,entity_ordinal=UINT32_MAX;
    query::Relation entity_relation=query::Relation::method_defs;
    uint32_t entity_pc=UINT32_MAX;
    uint64_t numeric_bits=0;uint32_t numeric_width=0,numeric_kind=0;
    // Only used by kind=inherited; all indices are within the matching leaf.
    uint32_t inherited_item=0,inherited_path=UINT32_MAX,inherited_aux=UINT32_MAX,inherited_branch=UINT32_MAX,inherited_detail=0;
};
struct EntityKey {
    uint32_t source_index=0,ordinal=0;
    query::Relation relation=query::Relation::method_defs;
    uint32_t dex_pc=UINT32_MAX;
    bool operator==(const EntityKey&)const=default;
};
struct Binding {
    uint32_t label=query::none;EntityKey entity;
    std::array<uint8_t,32> path{};uint32_t path_length=0;
    bool operator==(const Binding&)const=default;
};
struct JoinLink {uint32_t node=0;query::JoinKey key=query::JoinKey::same_entity;EntityKey left,right;};
struct ProofBinding {uint32_t node=0;Binding binding;};
struct ExpandHop {
    EntityKey caller,resolved;
    uint32_t dex_pc=UINT32_MAX,code_offset=0,opcode=0,target_method_ref=UINT32_MAX,candidate_count=0;
    bool resolution_complete=false;
    bool operator==(const ExpandHop&)const=default;
};
struct ExpandPath {
    uint32_t node=0;EntityKey seed,endpoint;bool uncertain=false;
    std::pmr::vector<Binding> seed_bindings;
    std::pmr::vector<JoinLink> seed_links;
    std::pmr::vector<ProofBinding> seed_proof_bindings;
    std::pmr::vector<Witness> seed_witnesses,walk_witnesses,emit_witnesses;
    std::pmr::vector<ExpandHop> hops;
    explicit ExpandPath(std::pmr::memory_resource* r):seed_bindings(r),seed_links(r),seed_proof_bindings(r),seed_witnesses(r),walk_witnesses(r),emit_witnesses(r),hops(r){}
};
enum class FrontierReason:uint32_t {unresolved,incomplete,unknown_walk,unknown_emit};
struct ExpandFrontier {
    uint32_t node=0,depth=0;EntityKey seed,current,caller;
    uint32_t dex_pc=UINT32_MAX,target_method_ref=UINT32_MAX;
    FrontierReason reason=FrontierReason::unresolved;
    std::pmr::vector<Binding> seed_bindings;
    std::pmr::vector<JoinLink> seed_links;
    std::pmr::vector<ProofBinding> seed_proof_bindings;
    std::pmr::vector<Witness> seed_witnesses,walk_witnesses,emit_witnesses;
    std::pmr::vector<ExpandHop> prefix;
    explicit ExpandFrontier(std::pmr::memory_resource* r):seed_bindings(r),seed_links(r),seed_proof_bindings(r),seed_witnesses(r),walk_witnesses(r),emit_witnesses(r),prefix(r){}
};
struct ExpandProfile {
    uint32_t node=0;
    uint64_t visited=0,edges=0,paths=0,decoded_methods=0,unresolved=0,unknown=0;
    uint64_t reverse_builds=0,reverse_reuses=0;
};
struct Candidate {
    uint32_t source_index=0,method_ordinal=0;
    query::Relation relation=query::Relation::method_defs;
    uint32_t dex_pc=UINT32_MAX;
    bool uncertain=false;
    std::pmr::vector<Binding> bindings;
    std::pmr::vector<JoinLink> links;
    std::pmr::vector<ProofBinding> proof_bindings;
    std::pmr::vector<Witness> witnesses;
    std::pmr::vector<ExpandPath> expand_paths;
    bool expand_path_identity=false;
    Candidate(uint32_t source,uint32_t method,std::pmr::memory_resource* r,query::Relation kind=query::Relation::method_defs,uint32_t pc=UINT32_MAX):source_index(source),method_ordinal(method),relation(kind),dex_pc(pc),bindings(r),links(r),proof_bindings(r),witnesses(r),expand_paths(r){}
    EntityKey key()const{return {source_index,method_ordinal,relation,dex_pc};}
};
enum class ScanDomain:uint32_t {none,entity_records,method_defs};
struct OperatorProfile {
    uint32_t node=0;query::RelOp op=query::RelOp::scan;
    uint64_t input_rows=0,output_rows=0,unknown_rows=0,visited_rows=0,total_rows=0;
    ScanDomain scan_domain=ScanDomain::none;
    uint64_t attempted_methods=0,no_body_methods=0,decoded_methods=0,emitted_events=0,code_units=0;
    bool complete=false;
};
struct GraphProgress {
    uint32_t identity_count=0,root_node=0;
    uint64_t entity_total=0,entity_visited=0,method_total=0,method_visited=0,events_collected=0;
    std::pmr::vector<OperatorProfile> nodes;
    std::pmr::vector<ExpandProfile> expands;
    explicit GraphProgress(std::pmr::memory_resource* r):nodes(r),expands(r){}
};
struct Profile {
    uint64_t work_units=0,fact_requests=0,methods_decoded=0,code_units=0;
    uint64_t string_pool_lookups=0,invoke_sites=0,field_uses=0,declared_fields=0;
    uint64_t matches_seen=0,sort_comparisons=0;
    uint64_t unknown_rows=0;
};
struct Progress {
    uint32_t visited=0,total=0,scope_source_count=0;
    bool scope_complete=false,order_verified=false;
    bool scope_derived_unknown=false;
    Profile profile;
    std::optional<GraphProgress> graph;
};
struct Result {
    std::pmr::vector<Candidate> rows;
    std::pmr::vector<uint32_t> scope_sources;
    struct UseHash {
        size_t operator()(const facts::UseKey& key)const noexcept {
            size_t value=key.source_index;
            value=(value*size_t(16777619))^key.caller_ordinal;
            value=(value*size_t(16777619))^key.dex_pc;
            return (value*size_t(16777619))^static_cast<uint32_t>(key.kind);
        }
    };
    std::pmr::unordered_map<facts::UseKey,facts::UseRecord,UseHash> uses;
    std::pmr::vector<ExpandFrontier> frontiers;
    bool result_limit=false;
    // v12: tentative until the caller commits it; not part of the public Result.
    bool unique_one_limit_pending=false;
    explicit Result(std::pmr::memory_resource* r):rows(r),scope_sources(r),uses(r),frontiers(r){}
};
// Internal provisional-row sink. It is invoked for unordered Exists/Unique
// plans only after a complete known-true root candidate has been formed.
// The callback may throw; no external callback is invoked under an engine lock.
struct CandidateSink {
    void (*accept)(void*,const Result&,const Candidate&,const Progress&)=nullptr;
    void* context=nullptr;
};
// True only when root candidates can be emitted without a new logical
// identity comparison or a change to the evaluator's max_work trajectory.
bool can_stream(const query::Plan& plan) noexcept;
bool unique_one_stream_shape(const query::Plan& plan) noexcept;
facts::UseKind use_kind(query::Relation relation);
facts::UseKey use_key(const EntityKey& key);
const facts::UseRecord& use_record(const Result& result,const EntityKey& key);
class FactsCache;
// Experimental direct method enumeration. Unsupported shapes return false
// before touching lanes; each admitted lane retains its own result and error.
struct FusedMethodLane {
    const query::Plan* plan=nullptr;
    Progress* progress=nullptr;
    Result* result=nullptr;
    std::pmr::memory_resource* memory=nullptr;
    std::exception_ptr error;
};
bool execute_fused_methods(const DatasetView& dataset,std::span<FusedMethodLane> lanes,FactsCache* shared_facts=nullptr);
Result execute(const DatasetView& dataset,const query::Plan& plan,Progress& progress,
    std::pmr::memory_resource* memory,Cancel cancel={},CandidateSink sink={},FactsCache* shared_facts=nullptr);
}
