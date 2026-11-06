#pragma once
#include "dexmeguviz/dexmeguviz.h"
#include "execution/budget/account.hpp"
#include "format/reader.hpp"
#include "facts/use_relations/reverse_index.hpp"
#include "source/archive/archive.hpp"
#include "format/instructions/decoder.hpp"
#include "query/ir.hpp"
#include "execution/reference/evaluate.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <thread>
#include <utility>

namespace dexmeguviz::runtime {
static_assert(static_cast<uint32_t>(facts::TargetDomain::string_value)==DMG_TARGET_STRING_VALUE&&
              static_cast<uint32_t>(facts::TargetDomain::field_ref)==DMG_TARGET_FIELD_REF&&
              static_cast<uint32_t>(facts::TargetDomain::method_ref)==DMG_TARGET_METHOD_REF&&
              static_cast<uint32_t>(facts::TargetDomain::method_and_proto)==DMG_TARGET_METHOD_AND_PROTO&&
              static_cast<uint32_t>(facts::TargetDomain::call_site)==DMG_TARGET_CALL_SITE&&
              static_cast<uint32_t>(facts::TargetDomain::type_ref)==DMG_TARGET_TYPE_REF);
static_assert(static_cast<uint32_t>(reference::ScanDomain::none)==DMG_SCAN_DOMAIN_NONE&&
              static_cast<uint32_t>(reference::ScanDomain::entity_records)==DMG_SCAN_DOMAIN_ENTITY_RECORDS&&
              static_cast<uint32_t>(reference::ScanDomain::method_defs)==DMG_SCAN_DOMAIN_METHOD_DEFS);
struct JobState;
struct EngineState {
    Account account;
    AccountResource source_resource,fact_resource,scratch_resource,query_resource,result_resource,control_resource;
    uint64_t max_source_bytes;
    uint32_t max_jobs;
    std::mutex admission;
    bool closed=false;
    uint32_t active_jobs=0;
    std::array<std::weak_ptr<JobState>,64> jobs;
    explicit EngineState(const dmg_engine_options& o):account(o.owned_bytes_limit,o.borrowed_bytes_limit),
        source_resource(account,MemoryKind::source),fact_resource(account,MemoryKind::facts),
        scratch_resource(account,MemoryKind::scratch),query_resource(account,MemoryKind::query),
        result_resource(account,MemoryKind::result),control_resource(account,MemoryKind::control),
        max_source_bytes(o.max_source_bytes),max_jobs(o.max_jobs){}
};
template<class T> struct StateAllocator {
    using value_type=T;
    std::shared_ptr<EngineState> owner;
    explicit StateAllocator(std::shared_ptr<EngineState> e):owner(std::move(e)){}
    template<class U>StateAllocator(const StateAllocator<U>& other):owner(other.owner){}
    T* allocate(size_t n){
        if(n>SIZE_MAX/sizeof(T))throw BudgetExceeded();
        return static_cast<T*>(owner->control_resource.allocate(n*sizeof(T),alignof(T)));
    }
    void deallocate(T* p,size_t n)noexcept{owner->control_resource.deallocate(p,n*sizeof(T),alignof(T));}
    template<class U>bool operator==(const StateAllocator<U>& other)const noexcept{return owner==other.owner;}
};
template<class T,class...Args>std::shared_ptr<T> state(const std::shared_ptr<EngineState>& e,Args&&...args){
    return std::allocate_shared<T>(StateAllocator<T>(e),e,std::forward<Args>(args)...);
}
struct Source {
    std::shared_ptr<EngineState> engine;
    std::pmr::vector<uint8_t> bytes;
    std::shared_ptr<const Source> physical_owner;
    Facts facts;
    std::pmr::string digest,content,occurrence,snapshot,slot_key,role,logical,archive_digest,entry_name;
    uint32_t input_index=0,entry_index=UINT32_MAX;
    bool crc_verified=false,header_verified=false,expected_verified=false;
    const uint8_t* borrowed=nullptr;
    uint64_t borrowed_size=0;
    dmg_buffer_lease lease{};
    explicit Source(std::shared_ptr<EngineState> e):engine(std::move(e)),bytes(&engine->source_resource),
        facts(&engine->fact_resource),digest(&engine->source_resource),content(&engine->source_resource),
        occurrence(&engine->source_resource),snapshot(&engine->source_resource),slot_key(&engine->source_resource),
        role(&engine->source_resource),logical(&engine->source_resource),archive_digest(&engine->source_resource),entry_name(&engine->source_resource){}
    ~Source(){if(lease.release){engine->account.release_borrowed(borrowed_size);lease.release(lease.context);}}
    std::span<const uint8_t> view()const noexcept{return physical_owner?physical_owner->view():lease.release?std::span<const uint8_t>(borrowed,static_cast<size_t>(borrowed_size)):std::span<const uint8_t>(bytes);}
};
struct InputRecord {
    uint32_t format=DMG_INPUT_RAW_DEX,source_count=0;
    bool allow_no_dex=false,expected_verified=false,container_checked=false;
    uint64_t bytes=0;
    std::pmr::string slot,role,digest,content;
    explicit InputRecord(std::pmr::memory_resource* r):slot(r),role(r),digest(r),content(r){}
};
struct Dataset {
    std::shared_ptr<EngineState> engine;
    std::pmr::vector<std::shared_ptr<const Source>> sources;
    std::pmr::vector<InputRecord> inputs;
    std::pmr::string namespace_key,snapshot_id;
    bool scope_complete=true;
    uint64_t input_bytes=0,dex_bytes=0,strings=0,types=0,classes=0,method_refs=0,methods=0;
    mutable facts::ReverseRegistry reverse;
    explicit Dataset(std::shared_ptr<EngineState> e):engine(std::move(e)),sources(&engine->source_resource),
        inputs(&engine->source_resource),namespace_key(&engine->source_resource),snapshot_id(&engine->source_resource),
        reverse(&engine->fact_resource,&engine->scratch_resource){}
};
struct QueryState {
    std::shared_ptr<EngineState> engine;
    dmg_method_query options{};
    std::optional<query::Plan> plan;
    explicit QueryState(std::shared_ptr<EngineState> e):engine(std::move(e)){}
};
struct Control;
struct EntityData {
    uint32_t method_index,flags,declaration,code,source_index,ordinal,record_offset;
    query::Relation relation;bool definition_known,flags_known,code_known;
    std::pmr::vector<uint16_t> owner,name,prototype,type_descriptor,value;
    std::optional<facts::UseRecord> use;
    EntityData(const reference::EntityView& m,std::pmr::memory_resource* resource,const Control& control,
        uint32_t projection=query::project_all);
    EntityData(const reference::EntityView& caller,const facts::UseRecord& record,query::Relation event_relation,
        std::pmr::memory_resource* resource,const Control& control,uint32_t projection);
};
struct BoundRow {
    uint32_t label;EntityData entity;
    std::array<uint8_t,32> path{};uint32_t path_length=0;
    BoundRow(const reference::Binding& binding,EntityData&& value):
        label(binding.label),entity(std::move(value)),path(binding.path),path_length(binding.path_length){
        if(path_length>path.size())throw query::Error(query::ErrorCode::invalid,"binding path length exceeds its storage");
    }
};
struct ProofBoundRow {
    uint32_t node;BoundRow binding;
    ProofBoundRow(uint32_t node,const reference::Binding& value,EntityData&& entity):
        node(node),binding(value,std::move(entity)){}
};
struct ExpandHopData {
    reference::ExpandHop hop;
    EntityData target;
    ExpandHopData(const reference::ExpandHop& value,EntityData&& symbol):hop(value),target(std::move(symbol)){}
};
struct ExpandPathData {
    uint32_t node;reference::EntityKey seed,endpoint;bool uncertain;
    std::pmr::vector<BoundRow> bindings;std::pmr::vector<ExpandHopData> hops;
    std::pmr::vector<reference::JoinLink> seed_links;std::pmr::vector<ProofBoundRow> seed_proofs;
    std::pmr::vector<reference::Witness> seed_witnesses,walk_witnesses,emit_witnesses;
    ExpandPathData(const reference::ExpandPath& value,std::pmr::memory_resource* r):
        node(value.node),seed(value.seed),endpoint(value.endpoint),uncertain(value.uncertain),bindings(r),hops(r),seed_links(r),seed_proofs(r),seed_witnesses(r),walk_witnesses(r),emit_witnesses(r){}
};
struct ExpandFrontierData {
    uint32_t node,depth,dex_pc,target_method_ref;reference::EntityKey seed,current,caller;
    reference::FrontierReason reason;
    std::optional<EntityData> target;
    std::pmr::vector<BoundRow> bindings;std::pmr::vector<ExpandHopData> prefix;
    std::pmr::vector<reference::JoinLink> seed_links;std::pmr::vector<ProofBoundRow> seed_proofs;
    std::pmr::vector<reference::Witness> seed_witnesses,walk_witnesses,emit_witnesses;
    ExpandFrontierData(const reference::ExpandFrontier& value,std::pmr::memory_resource* r):
        node(value.node),depth(value.depth),dex_pc(value.dex_pc),target_method_ref(value.target_method_ref),
        seed(value.seed),current(value.current),caller(value.caller),reason(value.reason),bindings(r),prefix(r),seed_links(r),seed_proofs(r),seed_witnesses(r),walk_witnesses(r),emit_witnesses(r){}
};
struct Row:EntityData {
    std::pmr::vector<reference::Witness> witnesses;
    std::pmr::vector<BoundRow> bindings;
    std::pmr::vector<reference::JoinLink> links;
    std::pmr::vector<ProofBoundRow> proof_bindings;
    std::pmr::vector<ExpandPathData> expand_paths;
    Row(EntityData&& value,std::pmr::memory_resource* r,std::span<const reference::Witness> evidence={}):
        EntityData(std::move(value)),witnesses(evidence.begin(),evidence.end(),r),bindings(r),links(r),proof_bindings(r),expand_paths(r){}
};
struct GraphState {
    dmg_graph_info info{};
    uint64_t entity_total=0,entity_visited=0,method_total=0,method_visited=0,events_collected=0;
    std::pmr::vector<reference::OperatorProfile> nodes;
    std::pmr::vector<reference::ExpandProfile> expands;
    explicit GraphState(std::pmr::memory_resource* r):nodes(r),expands(r){}
};
inline void initialize_graph(GraphState& state,const QueryState& query){
    const auto& plan=*query.plan;if(plan.relation_root==query::none)return;
    state.info={plan.relations[plan.relation_root].stable_id,static_cast<uint32_t>(plan.unique_identity),0,static_cast<uint32_t>(plan.relations.size())};
    state.nodes.resize(plan.relations.size());for(size_t i=0;i<plan.relations.size();++i){
        const auto& relation=plan.relations[i];auto& node=state.nodes[i];node.node=relation.stable_id;node.op=relation.op;
        if(relation.op==query::RelOp::scan)node.scan_domain=query::is_use_relation(relation.relation)?reference::ScanDomain::method_defs:reference::ScanDomain::entity_records;
        if(relation.op==query::RelOp::bounded_expand){reference::ExpandProfile profile{};profile.node=relation.stable_id;state.expands.push_back(profile);}
    }
}
inline void copy_graph(const reference::Progress& progress,GraphState& state){
    if(!progress.graph)return;const auto& graph=*progress.graph;state.info.identity_count=graph.identity_count;
    state.entity_total=graph.entity_total;state.entity_visited=graph.entity_visited;state.method_total=graph.method_total;state.method_visited=graph.method_visited;state.events_collected=graph.events_collected;
    const auto count=std::min(state.nodes.size(),graph.nodes.size());
    for(auto& output:state.expands)for(const auto& input:graph.expands)if(output.node==input.node){output=input;break;}
    for(size_t i=0;i<count;++i){const auto& input=graph.nodes[i];auto& output=state.nodes[i];
        if(input.node!=output.node||input.op!=output.op||
           (output.op==query::RelOp::scan&&input.scan_domain!=output.scan_domain))continue;
        output.input_rows=input.input_rows;output.output_rows=input.output_rows;output.unknown_rows=input.unknown_rows;
        output.visited_rows=input.visited_rows;output.total_rows=input.total_rows;output.attempted_methods=input.attempted_methods;
        output.no_body_methods=input.no_body_methods;output.decoded_methods=input.decoded_methods;output.emitted_events=input.emitted_events;output.code_units=input.code_units;output.complete=input.complete;
    }
}
struct Stop { dmg_status status; };
#ifdef DMG_TEST_ALLOC_FAILURES
using TestExpandTerminalHook=void(*)()noexcept;
inline std::atomic<int64_t> test_expand_fail_materialization_after{-1};
inline std::atomic<TestExpandTerminalHook> test_expand_after_terminal_hook{nullptr};
// Both stages run without admission/job locks: 0 before evaluation (the Job
// already owns its baseline state), 1 after materialization and before commit.
inline std::atomic<void(*)(uint32_t)> test_expand_commit_hook{nullptr};
#endif
struct Control {
    const std::atomic<bool>* cancelled=nullptr;
    std::chrono::steady_clock::time_point deadline=std::chrono::steady_clock::time_point::max();
    void check()const{
        if(cancelled&&cancelled->load(std::memory_order_acquire))throw Stop{DMG_CANCELLED};
        if(std::chrono::steady_clock::now()>=deadline)throw Stop{DMG_DEADLINE_EXCEEDED};
    }
};
inline std::span<const reference::Witness> row_evidence(const query::Plan& plan,const reference::Candidate& row)noexcept{
    return plan.contains_expand?std::span<const reference::Witness>{}:std::span<const reference::Witness>{row.witnesses};
}
inline EntityData::EntityData(const reference::EntityView& m,std::pmr::memory_resource* resource,const Control& control,uint32_t projection):
    method_index(m.reference_index),flags(m.access_flags),declaration(m.definition_offset),code(m.code_offset),source_index(m.source_index),ordinal(m.ordinal),record_offset(m.record_offset),
    relation(m.kind),definition_known(m.definition_known),flags_known(m.flags_known),code_known(m.code_known),
    owner(resource),name(resource),prototype(resource),type_descriptor(resource),value(resource){
    control.check();
    const auto copy=[&](std::pmr::vector<uint16_t>& target,std::u16string_view text){
        control.check();target.reserve(text.size());
        for(size_t i=0;i<text.size();++i){if((i&1023)==0)control.check();target.push_back(static_cast<uint16_t>(text[i]));}
    };
    if(projection&query::project_owner)copy(owner,m.owner);
    if(projection&query::project_name)copy(name,m.name);
    if(projection&query::project_prototype)copy(prototype,m.prototype);
    if(projection&query::project_type)copy(type_descriptor,m.type_descriptor);
    if(projection&query::project_value)copy(value,m.value);
}
inline EntityData::EntityData(const reference::EntityView& caller,const facts::UseRecord& record,query::Relation event_relation,
    std::pmr::memory_resource* resource,const Control& control,uint32_t projection):EntityData(caller,resource,control,projection){
    relation=event_relation;use=record;
}
inline void message(dmg_error* error,uint64_t offset,const char* text)noexcept{
    if(!error)return;error->offset=offset;size_t n=0;
    while(n<sizeof(error->message)-1&&text[n])++n;
    std::memcpy(error->message,text,n);error->message[n]=0;
}
template<class F>dmg_status guard(F&& f,dmg_error* error=nullptr)noexcept{
    if(error)*error={};
    try{return f();}
    catch(const BudgetExceeded& e){message(error,0,e.what());return DMG_BUDGET_EXCEEDED;}
    catch(const ReadError& e){message(error,e.offset,e.what());return e.code==ReadCode::corrupt?DMG_CORRUPT_INPUT:e.code==ReadCode::unsupported?DMG_UNSUPPORTED:DMG_BUDGET_EXCEEDED;}
    catch(const instructions::DecodeError& e){message(error,e.dex_offset,e.what());switch(e.code){case instructions::DecodeCode::corrupt:return DMG_CORRUPT_INPUT;case instructions::DecodeCode::unsupported:return DMG_UNSUPPORTED;case instructions::DecodeCode::cancelled:return DMG_CANCELLED;default:return DMG_BUDGET_EXCEEDED;}}
    catch(const facts::UseScanError& e){message(error,0,e.what());switch(e.code){case facts::UseScanError::Code::invalid:return DMG_INVALID_ARGUMENT;case facts::UseScanError::Code::unsupported:return DMG_UNSUPPORTED;case facts::UseScanError::Code::budget:return DMG_BUDGET_EXCEEDED;case facts::UseScanError::Code::cancelled:return DMG_CANCELLED;default:return DMG_INTERNAL_ERROR;}}
    catch(const query::Error& e){message(error,0,e.what());switch(e.code){case query::ErrorCode::invalid:return DMG_INVALID_ARGUMENT;case query::ErrorCode::unsupported:return DMG_UNSUPPORTED;case query::ErrorCode::budget:return DMG_BUDGET_EXCEEDED;case query::ErrorCode::cancelled:return DMG_CANCELLED;default:return DMG_SOURCE_MISMATCH;}}
    catch(const archive::Error& e){message(error,e.offset,e.what());switch(e.status){case archive::Status::corrupt_input:return DMG_CORRUPT_INPUT;case archive::Status::unsupported:return DMG_UNSUPPORTED;case archive::Status::budget_exceeded:return DMG_BUDGET_EXCEEDED;case archive::Status::cancelled:return DMG_CANCELLED;default:return DMG_INTERNAL_ERROR;}}
    catch(const Stop& e){message(error,0,dmg_status_name(e.status));return e.status;}
    catch(const std::bad_alloc&){message(error,0,"allocation failed");return DMG_OUT_OF_MEMORY;}
    catch(...){message(error,0,"unexpected internal failure");return DMG_INTERNAL_ERROR;}
}
inline void initial(dmg_result_info& info,const Dataset& s,const QueryState& q){
    info={};info.total_methods=q.plan->relation_root==query::none&&q.plan->relation==query::Relation::method_defs?static_cast<uint32_t>(s.methods):0;
    info.coverage=DMG_COVERAGE_PARTIAL;info.decision=q.options.intent==DMG_ENUMERATE?DMG_NOT_APPLICABLE:DMG_UNDETERMINED;
}
inline void finalize(dmg_result_info& info,const QueryState& q,bool scope_complete,uint64_t unknown_rows=0,bool scope_derived_unknown=false){
    info.coverage=scope_complete&&!unknown_rows&&info.execution_status==DMG_OK&&info.visited_methods==info.total_methods?DMG_COVERAGE_COMPLETE:DMG_COVERAGE_PARTIAL;
    if(unknown_rows&&info.execution_status==DMG_OK)info.reason=scope_derived_unknown&&!scope_complete?DMG_SOURCE_SCOPE_INCOMPLETE:DMG_UNKNOWN_ATTRIBUTE;
    if(q.options.intent==DMG_ENUMERATE)return;
    if(q.options.intent==DMG_TOP_N){info.decision=info.coverage==DMG_COVERAGE_COMPLETE?DMG_PROVEN_TRUE:DMG_UNDETERMINED;if(!scope_complete&&!unknown_rows&&info.execution_status==DMG_OK)info.reason=DMG_SOURCE_SCOPE_INCOMPLETE;return;}
    if(q.options.intent==DMG_EXISTS&&info.candidates_count){info.decision=DMG_PROVEN_TRUE;info.reason=DMG_WITNESS;}
    else if(q.options.intent==DMG_UNIQUE&&info.candidates_count>=2){info.decision=DMG_PROVEN_FALSE;info.reason=DMG_AMBIGUOUS;}
    else if(info.coverage==DMG_COVERAGE_COMPLETE){info.decision=info.candidates_count?DMG_PROVEN_TRUE:DMG_PROVEN_FALSE;info.reason=info.candidates_count?DMG_REASON_NONE:DMG_NO_MATCH;}
    else if(!scope_complete&&!unknown_rows&&info.execution_status==DMG_OK&&info.visited_methods==info.total_methods&&info.decision==DMG_UNDETERMINED)info.reason=DMG_SOURCE_SCOPE_INCOMPLETE;
}
inline dmg_relation_info relation_info(const dmg_result_info& info,const QueryState& q,uint64_t unknown_rows){
    return {static_cast<uint32_t>(q.plan->relation),info.execution_status,info.coverage,info.decision,info.reason,info.candidates_count,info.visited_methods,info.total_methods,unknown_rows};
}
inline EntityData materialize_value(const Dataset& data,const reference::Result& evaluated,const reference::EntityKey& key,
    std::pmr::memory_resource* memory,const Control& control,uint32_t projection){
    control.check();if(key.source_index>=data.sources.size())throw query::Error(query::ErrorCode::invalid,"value source index outside snapshot");
    const auto& source=*data.sources[key.source_index];const reference::SourceView view{key.source_index,source.input_index,&source.facts,source.view()};
    if(query::is_use_relation(key.relation)){
        if(key.dex_pc==UINT32_MAX)throw query::Error(query::ErrorCode::invalid,"use identity requires a DEX PC");
        const auto& record=reference::use_record(evaluated,key);
        const auto caller=reference::entity(view,query::Relation::method_defs,key.ordinal);
        if(record.key.source_index!=key.source_index||record.key.caller_ordinal!=key.ordinal||record.key.dex_pc!=key.dex_pc||
           record.key.kind!=reference::use_kind(key.relation)||!caller.method||record.caller_method_ref!=caller.reference_index||record.code_offset!=caller.code_offset)
            throw query::Error(query::ErrorCode::invalid,"use record identity does not match caller");
        EntityData value(caller,record,key.relation,memory,control,projection);
        if(key.relation==query::Relation::type_uses){
            if(record.target_domain!=facts::TargetDomain::type_ref||record.target_index>=source.facts.types.size()||source.facts.types[record.target_index]>=source.facts.strings.size())throw query::Error(query::ErrorCode::invalid,"type use target outside source");
            const auto& text=source.facts.strings[source.facts.types[record.target_index]];value.type_descriptor.reserve(text.size());
            for(size_t i=0;i<text.size();++i){if((i&1023u)==0)control.check();value.type_descriptor.push_back(static_cast<uint16_t>(text[i]));}
        }
        return value;
    }
    if(key.dex_pc!=UINT32_MAX)throw query::Error(query::ErrorCode::invalid,"entity identity cannot contain a DEX PC");
    return EntityData(reference::entity(view,key.relation,key.ordinal),memory,control,projection);
}
inline void materialize_bindings(Row& row,const Dataset& dataset,const reference::Result& evaluated,const reference::Candidate& candidate,std::pmr::memory_resource* memory,const Control& control){
    if(candidate.bindings.size()>UINT32_MAX||candidate.links.size()>UINT32_MAX||candidate.proof_bindings.size()>UINT32_MAX)throw BudgetExceeded();
    row.bindings.reserve(candidate.bindings.size());
    for(const auto& binding:candidate.bindings){control.check();
        row.bindings.emplace_back(binding,materialize_value(dataset,evaluated,binding.entity,memory,control,31));
    }
    row.links.reserve(candidate.links.size());
    for(const auto& link:candidate.links){control.check();row.links.push_back(link);}
    row.proof_bindings.reserve(candidate.proof_bindings.size());
    for(const auto& proof:candidate.proof_bindings){control.check();
        row.proof_bindings.emplace_back(proof.node,proof.binding,materialize_value(dataset,evaluated,proof.binding.entity,memory,control,31));
    }
}
inline void expand_bindings(std::pmr::vector<BoundRow>& out,std::span<const reference::Binding> input,const Dataset& dataset,
    const reference::Result& evaluated,std::pmr::memory_resource* memory,const Control& control){
    if(input.size()>UINT32_MAX)throw BudgetExceeded();control.check();out.reserve(input.size());control.check();
    for(const auto& binding:input){control.check();out.emplace_back(binding,materialize_value(dataset,evaluated,binding.entity,memory,control,31));}
}
inline void expand_hops(std::pmr::vector<ExpandHopData>& out,std::span<const reference::ExpandHop> input,const Dataset& dataset,
    const reference::Result& evaluated,std::pmr::memory_resource* memory,const Control& control){
    if(input.size()>UINT32_MAX)throw BudgetExceeded();control.check();out.reserve(input.size());control.check();
    for(const auto& hop:input){control.check();
        reference::EntityKey ref{hop.caller.source_index,hop.target_method_ref,query::Relation::method_refs,UINT32_MAX};
        out.emplace_back(hop,materialize_value(dataset,evaluated,ref,memory,control,31));
    }
}
template<class T>inline void copy_expand_evidence(std::pmr::vector<T>& out,const std::pmr::vector<T>& input,const Control& control){
    control.check();out.clear();out.reserve(input.size());control.check();
    constexpr size_t quantum=1024;
    for(size_t offset=0;offset<input.size();){
        control.check();const auto count=std::min(quantum,input.size()-offset);
        out.insert(out.end(),input.begin()+static_cast<ptrdiff_t>(offset),input.begin()+static_cast<ptrdiff_t>(offset+count));offset+=count;
    }
    control.check();
}
template<class Output,class Input>inline void expand_evidence(Output& out,const Input& input,const Dataset& dataset,
    const reference::Result& evaluated,std::pmr::memory_resource* memory,const Control& control){
    if(input.seed_links.size()>UINT32_MAX||input.seed_proof_bindings.size()>UINT32_MAX||input.seed_witnesses.size()>UINT32_MAX||
       input.walk_witnesses.size()>UINT32_MAX||input.emit_witnesses.size()>UINT32_MAX)throw BudgetExceeded();
    copy_expand_evidence(out.seed_links,input.seed_links,control);control.check();out.seed_proofs.reserve(input.seed_proof_bindings.size());control.check();
    for(const auto& proof:input.seed_proof_bindings){control.check();out.seed_proofs.emplace_back(proof.node,proof.binding,materialize_value(dataset,evaluated,proof.binding.entity,memory,control,31));}
    copy_expand_evidence(out.seed_witnesses,input.seed_witnesses,control);
    copy_expand_evidence(out.walk_witnesses,input.walk_witnesses,control);copy_expand_evidence(out.emit_witnesses,input.emit_witnesses,control);
}
inline void materialize_expand_paths(Row& row,const Dataset& dataset,const reference::Result& evaluated,
    const reference::Candidate& candidate,std::pmr::memory_resource* memory,const Control& control){
    if(candidate.expand_paths.size()>UINT32_MAX)throw BudgetExceeded();control.check();row.expand_paths.reserve(candidate.expand_paths.size());control.check();
    for(const auto& path:candidate.expand_paths){control.check();row.expand_paths.emplace_back(path,memory);auto& value=row.expand_paths.back();
        expand_bindings(value.bindings,path.seed_bindings,dataset,evaluated,memory,control);
        expand_hops(value.hops,path.hops,dataset,evaluated,memory,control);
        expand_evidence(value,path,dataset,evaluated,memory,control);
    }
}
inline void materialize_expand_frontiers(std::pmr::vector<ExpandFrontierData>& out,const Dataset& dataset,
    const reference::Result& evaluated,std::pmr::memory_resource* memory,const Control& control){
    if(evaluated.frontiers.size()>UINT32_MAX)throw BudgetExceeded();control.check();out.reserve(evaluated.frontiers.size());control.check();
    for(const auto& frontier:evaluated.frontiers){control.check();out.emplace_back(frontier,memory);auto& value=out.back();
        if(frontier.caller.source_index!=UINT32_MAX && frontier.target_method_ref!=UINT32_MAX){
            reference::EntityKey ref{frontier.caller.source_index,frontier.target_method_ref,query::Relation::method_refs,UINT32_MAX};
            value.target.emplace(materialize_value(dataset,evaluated,ref,memory,control,31));
        }
        expand_bindings(value.bindings,frontier.seed_bindings,dataset,evaluated,memory,control);
        expand_hops(value.prefix,frontier.prefix,dataset,evaluated,memory,control);
        expand_evidence(value,frontier,dataset,evaluated,memory,control);
    }
}
inline void fill_entity(const EntityData& r,dmg_entity_row* out)noexcept{
    *out={static_cast<uint32_t>(r.relation),r.source_index,r.ordinal,r.method_index,r.record_offset,
        r.definition_known?1u:0u,r.declaration,r.flags_known?1u:0u,r.flags,r.code_known?1u:0u,r.code,
        r.owner.data(),r.owner.size(),r.name.data(),r.name.size(),r.prototype.data(),r.prototype.size(),
        r.type_descriptor.data(),r.type_descriptor.size(),r.value.data(),r.value.size()};
}
inline void fill_value(const EntityData& r,dmg_value_row_v2* out)noexcept{
    *out={};if(!r.use){out->kind=DMG_VALUE_ENTITY;fill_entity(r,&out->entity);return;}
    const auto& use=*r.use;out->kind=DMG_VALUE_USE;
    out->use={static_cast<uint32_t>(r.relation),use.key.source_index,use.key.caller_ordinal,use.caller_method_ref,use.key.dex_pc,
        use.opcode,use.code_offset,static_cast<uint32_t>(use.target_domain),use.target_index,use.extra_proto,
        r.owner.data(),r.owner.size(),r.name.data(),r.name.size(),r.prototype.data(),r.prototype.size()};
}
inline void fill_value_v3(const EntityData& r,dmg_value_row_v3* out)noexcept{
    *out={};fill_value(r,&out->value);if(r.use&&r.relation==query::Relation::type_uses){out->target_descriptor=r.type_descriptor.data();out->target_descriptor_length=r.type_descriptor.size();}
}
inline dmg_value_identity_v2 identity_v2(const reference::EntityKey& key)noexcept{
    return {static_cast<uint32_t>(key.relation),key.source_index,key.ordinal,key.dex_pc};
}
inline dmg_relation_info_v2 relation_info_v2(const dmg_result_info& info,const QueryState& q,uint64_t unknown_rows,const GraphState& graph)noexcept{
    return {static_cast<uint32_t>(q.plan->relation),info.execution_status,info.coverage,info.decision,info.reason,info.candidates_count,
        graph.entity_visited,graph.entity_total,graph.method_visited,graph.method_total,graph.events_collected,unknown_rows};
}
inline void fill_operator_v2(const reference::OperatorProfile& p,dmg_operator_profile_v2* out)noexcept{
    *out={p.node,static_cast<uint32_t>(p.op),static_cast<uint32_t>(p.scan_domain),p.complete?1u:0u,
        p.input_rows,p.output_rows,p.unknown_rows,p.visited_rows,p.total_rows,p.attempted_methods,p.no_body_methods,p.decoded_methods,p.emitted_events,p.code_units};
}
inline void fill_operator(const reference::OperatorProfile& p,dmg_operator_profile* out)noexcept{
    *out={p.node,static_cast<uint32_t>(p.op),p.input_rows,p.output_rows,p.unknown_rows,p.visited_rows,p.total_rows,p.complete?1u:0u};
}
std::shared_ptr<QueryState> compile(const std::shared_ptr<EngineState>& engine,const dmg_method_query& input);
void fill_info(const Source& source,dmg_snapshot_info* out,const char* snapshot_id=nullptr)noexcept;
void fill_overview(const Dataset& dataset,dmg_snapshot_overview* out)noexcept;
dmg_status fill_input(const Dataset& dataset,uint32_t index,dmg_input_info* out)noexcept;
dmg_status fill_source(const Dataset& dataset,uint32_t index,dmg_source_info* out)noexcept;
std::shared_ptr<Dataset> single_source(const std::shared_ptr<Source>& source,const char* source_namespace);
std::shared_ptr<EngineState> make_engine(const dmg_engine_options* options=nullptr);
void admit(const std::shared_ptr<EngineState>& engine);
void fill_query_info(const QueryState& query,dmg_query_info* out)noexcept;
void fill_query_profile(const reference::Progress& progress,uint32_t scope_sources,dmg_query_profile* out)noexcept;
reference::Result evaluate_query(const Dataset& dataset,const QueryState& query,reference::Progress& progress,const Control& control,std::pmr::memory_resource* memory,reference::CandidateSink sink={},reference::ReverseTargetJoin* reverse_join=nullptr);
dmg_status execute_query(dmg_snapshot* snapshot,const std::shared_ptr<const QueryState>& query,dmg_result** out,dmg_error* error);
}

struct dmg_engine {std::atomic<uint32_t> references{1};std::shared_ptr<dexmeguviz::runtime::EngineState> owner;explicit dmg_engine(std::shared_ptr<dexmeguviz::runtime::EngineState> e):owner(std::move(e)){} };
struct dmg_snapshot {
    std::atomic<uint32_t> references{1};std::atomic<bool> closed{false};
    std::shared_ptr<dexmeguviz::runtime::EngineState> owner;
    std::shared_ptr<const dexmeguviz::runtime::Dataset> dataset;
    dmg_snapshot(std::shared_ptr<dexmeguviz::runtime::EngineState> e,std::shared_ptr<const dexmeguviz::runtime::Dataset> s):owner(std::move(e)),dataset(std::move(s)){}
};
struct dmg_query {
    std::atomic<uint32_t> references{1};std::shared_ptr<dexmeguviz::runtime::EngineState> owner;
    std::shared_ptr<const dexmeguviz::runtime::QueryState> query;
    dmg_query(std::shared_ptr<dexmeguviz::runtime::EngineState> e,std::shared_ptr<const dexmeguviz::runtime::QueryState> q):owner(std::move(e)),query(std::move(q)){}
};
struct dmg_result {
    std::atomic<uint32_t> references{1};std::shared_ptr<dexmeguviz::runtime::EngineState> owner;
    std::shared_ptr<const dexmeguviz::runtime::Dataset> dataset;
    std::shared_ptr<const dexmeguviz::runtime::QueryState> query;
    std::pmr::vector<dexmeguviz::runtime::Row> rows;
    std::pmr::vector<dexmeguviz::runtime::ExpandFrontierData> expand_frontiers;
    std::pmr::vector<uint32_t> scope_sources;
    dmg_query_profile profile{};
    uint64_t unknown_rows=0;
    dexmeguviz::runtime::GraphState graph;
    dmg_result_info info{};
    dmg_result* parent=nullptr;uint32_t view_offset=0,view_count=0;
    dmg_result(std::shared_ptr<dexmeguviz::runtime::EngineState> e,std::shared_ptr<const dexmeguviz::runtime::Dataset> s,std::shared_ptr<const dexmeguviz::runtime::QueryState> q):owner(std::move(e)),dataset(std::move(s)),query(std::move(q)),rows(&owner->result_resource),expand_frontiers(&owner->result_resource),scope_sources(&owner->result_resource),graph(&owner->result_resource){dexmeguviz::runtime::initialize_graph(graph,*query);}
    ~dmg_result(){if(parent)dmg_result_release(parent);}
};
namespace dexmeguviz::runtime {
inline const dmg_result& expand_root(const dmg_result& result)noexcept{return result.parent?*result.parent:result;}
inline uint32_t expand_rows(const dmg_result& result)noexcept{return result.parent?result.view_count:static_cast<uint32_t>(result.rows.size());}
inline const Row& expand_row(const dmg_result& result,uint32_t index){
    const auto& root=expand_root(result);return root.rows[(result.parent?result.view_offset:0)+index];
}
inline dmg_expand_info expand_info(const dmg_result& view)noexcept{
    const auto& root=expand_root(view);auto outcome=relation_info_v2(root.info,*root.query,root.unknown_rows,root.graph);
    outcome.candidates_count=expand_rows(view);
    return {outcome,root.profile,root.graph.info,static_cast<uint32_t>(root.expand_frontiers.size()),static_cast<uint32_t>(root.rows.size()),static_cast<uint32_t>(root.graph.expands.size())};
}
inline void fill_expand_binding(const BoundRow& value,const QueryState& query,dmg_expand_binding* out)noexcept{
    dmg_expand_binding item{};item.label=value.label==query::none?nullptr:query.plan->labels[value.label].c_str();
    fill_value(value.entity,&item.value);item.path={value.path.data(),value.path_length};*out=item;
}
inline void fill_expand_hop(const ExpandHopData& value,dmg_expand_hop* out)noexcept{
    const auto& h=value.hop;dmg_expand_hop item{};
    item.caller=identity_v2(h.caller);item.resolved=identity_v2(h.resolved);item.dex_pc=h.dex_pc;item.code_offset=h.code_offset;
    item.opcode=h.opcode;item.target_method_ref=h.target_method_ref;item.candidate_count=h.candidate_count;item.resolution_complete=h.resolution_complete?1u:0u;
    fill_entity(value.target,&item.target_symbol);*out=item;
}
inline void fill_expand_frontier(const ExpandFrontierData& value,dmg_expand_frontier* out)noexcept{
    dmg_expand_frontier item{};item.node_id=value.node;item.depth=value.depth;item.reason=static_cast<uint32_t>(value.reason);
    item.dex_pc=value.dex_pc;item.target_method_ref=value.target_method_ref;item.has_target_symbol=value.target?1u:0u;
    item.seed_binding_count=static_cast<uint32_t>(value.bindings.size());item.prefix_count=static_cast<uint32_t>(value.prefix.size());
    item.seed_link_count=static_cast<uint32_t>(value.seed_links.size());item.seed_proof_count=static_cast<uint32_t>(value.seed_proofs.size());
    item.seed_witness_count=static_cast<uint32_t>(value.seed_witnesses.size());item.walk_witness_count=static_cast<uint32_t>(value.walk_witnesses.size());item.emit_witness_count=static_cast<uint32_t>(value.emit_witnesses.size());
    item.seed=identity_v2(value.seed);item.current=identity_v2(value.current);item.caller=identity_v2(value.caller);
    if(value.target)fill_entity(*value.target,&item.target_symbol);*out=item;
}
inline void fill_expand_link(const reference::JoinLink& link,dmg_relation_link_v2* out)noexcept{
    *out={link.node,static_cast<uint32_t>(link.key),identity_v2(link.left),identity_v2(link.right)};
}
inline void fill_expand_proof(const ProofBoundRow& proof,const QueryState& query,dmg_expand_proof* out)noexcept{
    dmg_expand_proof item{};item.operator_node=proof.node;fill_expand_binding(proof.binding,query,&item.binding);*out=item;
}
inline void fill_expand_witness(const reference::Witness& w,dmg_relation_witness_v2* out)noexcept{
    *out={{static_cast<uint32_t>(w.kind),w.node,w.matched,w.dex_pc,w.opcode,w.reference_index,w.reference_kind,w.extra_proto,w.code_units},
        w.relation_node,identity_v2({w.source_index,w.entity_ordinal,w.entity_relation,w.entity_pc})};
}
template<class T>inline const std::pmr::vector<reference::Witness>* expand_witnesses(const T& item,uint32_t which)noexcept{
    if(which==DMG_EXPAND_SEED_WITNESS)return &item.seed_witnesses;
    if(which==DMG_EXPAND_WALK_WITNESS)return &item.walk_witnesses;
    if(which==DMG_EXPAND_EMIT_WITNESS)return &item.emit_witnesses;return nullptr;
}
template<class T,class...Args>T* handle(const std::shared_ptr<EngineState>& e,Args&&...args){
    void* p=e->control_resource.allocate(sizeof(T),alignof(T));
    try{return ::new(p)T(e,std::forward<Args>(args)...);}
    catch(...){e->control_resource.deallocate(p,sizeof(T),alignof(T));throw;}
}
template<class T>void destroy(T* p)noexcept{auto owner=p->owner;p->~T();owner->control_resource.deallocate(p,sizeof(T),alignof(T));}
struct ResultDelete {void operator()(dmg_result* p)const noexcept{if(p)dmg_result_release(p);}};
using ResultOwner=std::unique_ptr<dmg_result,ResultDelete>;
// Internal only: materialize a completed, unpublished reference result using
// the same path as the synchronous C API. The caller retains all inputs.
ResultOwner materialize_evaluated(const std::shared_ptr<EngineState>& owner,
    const std::shared_ptr<const Dataset>& dataset,const std::shared_ptr<const QueryState>& query,
    const reference::Result& evaluated,const reference::Progress& progress,const Control& control);
struct JobState {
    std::shared_ptr<EngineState> engine;
    std::shared_ptr<const Dataset> dataset;
    std::shared_ptr<const QueryState> query;
    std::atomic<bool> cancelled{false};
    std::mutex mutex;
    std::condition_variable changed;
    std::pmr::deque<ResultOwner> queue;
    ResultOwner committed_expand;
    uint32_t expand_cursor=0;
    dmg_job_status status{};
    dmg_job_options options{};
    dmg_query_profile profile{};
    uint64_t unknown_rows=0;
    // Present only after scoped class-annotation evaluation resolves its actual
    // sources. Terminal access still requires successful committed status.
    std::optional<std::pmr::vector<uint32_t>> terminal_scope_sources;
    dexmeguviz::runtime::GraphState graph;
    Control control;
    JobState(std::shared_ptr<EngineState> e,std::shared_ptr<const Dataset> s,std::shared_ptr<const QueryState> q,const dmg_job_options& o):
        engine(std::move(e)),dataset(std::move(s)),query(std::move(q)),queue(&engine->control_resource),options(o),graph(&engine->control_resource){
        initialize_graph(graph,*query);
        control.cancelled=&cancelled;
        if(o.deadline_after_ms)control.deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(o.deadline_after_ms);
        initial(status.outcome,*dataset,*query);
    }
};
}
struct dmg_job {
    std::atomic<uint32_t> references{1};std::shared_ptr<dexmeguviz::runtime::EngineState> owner;
    std::shared_ptr<dexmeguviz::runtime::JobState> state;
    std::thread worker;
    dmg_job(std::shared_ptr<dexmeguviz::runtime::EngineState> e,std::shared_ptr<dexmeguviz::runtime::JobState> s):owner(std::move(e)),state(std::move(s)){}
};
