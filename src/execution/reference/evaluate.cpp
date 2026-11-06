#include "evaluate.hpp"
#include "facts_cache.hpp"
#include "query/numeric_match.hpp"
#include "query/reflection_flags.hpp"
#include "query/class_annotation_flags.hpp"
#include "query/class_annotation_match.hpp"
#include "facts/method_facts.hpp"
#include "facts/symbols.hpp"
#include "inherited_fields.hpp"
#include "field_declaration.hpp"
#include "caller_field_relation.hpp"
#include "interface_fields.hpp"
#include "interface_fields_v11.hpp"
#include <algorithm>
#include <deque>
#include <memory>
#include <optional>
#include <tuple>
#if defined(DMG_TEST_JOB_COMMIT_BARRIER) || defined(DMG_TEST_TARGET_SYMBOL_BARRIER) || defined(DMG_TEST_REVERSE_JOIN_BARRIER)
#include <atomic>
#endif

namespace dexmeguviz::reference {
#ifdef DMG_TEST_REVERSE_JOIN_BARRIER
std::atomic<void(*)()> test_reverse_join_page_barrier{nullptr};
#endif
#ifdef DMG_TEST_TARGET_SYMBOL_BARRIER
std::atomic<void(*)(uint64_t)> test_target_symbol_barrier{nullptr};
#endif
#ifdef DMG_TEST_JOB_COMMIT_BARRIER
std::atomic<void(*)()> test_result_limit_barrier{nullptr};
std::atomic<void(*)()> test_type_use_method_barrier{nullptr};
std::atomic<void(*)(uint32_t,uint64_t)> test_graph_reduce_barrier{nullptr};
#endif
namespace {
// Limit v9 early publication to the relation shapes explicitly covered by
// sync/Job proof and budget tests. Other v9 plans retain atomic delivery.
bool v9_stream_shape(const query::Plan& p)noexcept{
    using O=query::RelOp;using R=query::Relation;using K=query::JoinKey;
    auto node=[&](uint32_t i)->const query::RelNode*{return i<p.relations.size()?&p.relations[i]:nullptr;};
    auto scan=[&](uint32_t i,R r){const auto* n=node(i);return n&&n->op==O::scan&&n->relation==r;};
    auto use_scan=[&](uint32_t i){const auto* n=node(i);return n&&n->op==O::scan&&query::is_use_relation(n->relation);};
    auto filter_scan=[&](uint32_t i){const auto* n=node(i);return n&&n->op==O::filter&&n->children.size()==1&&scan(n->children[0],R::invoke_sites);};
    auto caller=[&](uint32_t i){const auto* n=node(i);return n&&(n->op==O::join||n->op==O::semi_join)&&n->join_key==K::caller&&n->children.size()==2&&scan(n->children[0],R::method_defs)&&scan(n->children[1],R::invoke_sites);};
    auto target=[&](uint32_t i){const auto* n=node(i);return n&&n->op==O::join&&n->join_key==K::target_ref&&n->children.size()==2&&scan(n->children[0],R::invoke_sites)&&scan(n->children[1],R::method_refs);};
    auto two_use_scans=[&](uint32_t i){const auto* n=node(i);return n&&n->op==O::union_rows&&n->children.size()==2&&scan(n->children[0],R::invoke_sites)&&scan(n->children[1],R::invoke_sites);};
    const auto* root=node(p.relation_root);if(!root)return false;
    if(use_scan(p.relation_root)||filter_scan(p.relation_root))return true;
    if(root->op==O::label&&root->children.size()==1&&filter_scan(root->children[0]))return true;
    if(p.intent!=query::Intent::exists)return false;
    if(caller(p.relation_root)||target(p.relation_root)||two_use_scans(p.relation_root))return true;
    if(root->op==O::distinct&&root->children.size()==1){const auto* input=node(root->children[0]);return input&&input->bag&&two_use_scans(root->children[0]);}
    if(root->op==O::group_by_owner&&root->children.size()==1){const auto* input=node(root->children[0]);return input&&input->op==O::join&&caller(root->children[0]);}
    return false;
}
}
bool unique_one_stream_shape(const query::Plan& p) noexcept {
    if(!p.unique_one_stream||(p.required_capabilities&1048576u)==0||!p.use_streaming||!p.contains_uses||p.intent!=query::Intent::unique||
       p.max_results!=1||!p.order.empty()||(p.required_capabilities&(16u|1024u|2048u|16384u|32768u|65536u|262144u|524288u))||
       p.unique_identity!=query::Identity::entity||p.relations.size()!=1||p.relation_root>=p.relations.size())return false;
    const auto& root=p.relations[p.relation_root];
    if(root.op!=query::RelOp::scan||!root.children.empty()||!query::is_use_relation(root.relation))return false;
    const uint32_t expected=root.relation==query::Relation::string_uses?32u:root.relation==query::Relation::invoke_sites?64u:128u;
    return (p.required_capabilities&(32u|64u|128u))==expected;
}
bool can_stream(const query::Plan& plan) noexcept {
    if(plan.method_type_query||(plan.required_capabilities&0x80000000u)||plan.contains_expand)return false;
    if(!plan.order.empty()||(plan.intent!=query::Intent::exists&&plan.intent!=query::Intent::unique))return false;
    // Composite plans retain v9's method-by-method accounting, but their
    // mixed proof and failure paths have not yet established early delivery.
    if(plan.required_capabilities&262144u)return false;
    // With a one-row Unique limit, final materialization may itself exhaust
    // work after the limit is observed. Keep v9 synchronous and Job failure
    // status/reason aligned by using the same atomic path for this shape.
    if(plan.use_streaming&&plan.intent==query::Intent::unique&&plan.max_results==1){
        return unique_one_stream_shape(plan);
    }
    if(plan.relation_root==query::none)return true;
    // Legacy use profiles retain their original source-atomic work order.
    // Explicit v9 uses one checked-method accounting order in both paths.
    if(plan.contains_uses&&!plan.use_streaming)return false;
    if(plan.relation_root>=plan.relations.size())return false;
    if(plan.contains_uses)return v9_stream_shape(plan);
    if(plan.intent==query::Intent::exists)return true;
    // Scan emits each source/entity/PC key at most once. Filter and label
    // preserve that key; all other Unique roots may duplicate it.
    auto index=plan.relation_root;
    for(size_t remaining=plan.relations.size();remaining;--remaining){
        if(index>=plan.relations.size())return false;
        const auto& node=plan.relations[index];
        if(node.op==query::RelOp::scan)return true;
        if((node.op!=query::RelOp::filter&&node.op!=query::RelOp::label)||node.children.size()!=1)return false;
        index=node.children[0];
    }
    return false;
}
facts::UseKind use_kind(query::Relation relation){
    switch(relation){
    case query::Relation::string_uses:return facts::UseKind::string_use;
    case query::Relation::invoke_sites:return facts::UseKind::invoke_site;
    case query::Relation::field_uses:return facts::UseKind::field_use;
    case query::Relation::type_uses:return facts::UseKind::type_use;
    default:throw query::Error(query::ErrorCode::unsupported,"relation is not a use kind");
    }
}
facts::UseKey use_key(const EntityKey& key){
    if(key.dex_pc==UINT32_MAX)throw query::Error(query::ErrorCode::invalid,"use key has no dex PC");
    return {key.source_index,key.ordinal,key.dex_pc,use_kind(key.relation)};
}
const facts::UseRecord& use_record(const Result& result,const EntityKey& key){
    const auto wanted=use_key(key);const auto found=result.uses.find(wanted);
    if(found==result.uses.end())throw query::Error(query::ErrorCode::invalid,"use key is absent from result registry");
    if(!(found->second.key==wanted))throw query::Error(query::ErrorCode::invalid,"use registry key differs from its payload");
    return found->second;
}
namespace {
using query::Kind;
enum class Truth:uint32_t {no=0,yes=1,unknown=2};
Truth truth(bool value){return value?Truth::yes:Truth::no;}
struct Work {
    const query::Plan& plan;Progress& progress;Cancel cancel;
    void check()const{if(cancel.requested&&cancel.requested(cancel.context))throw query::Error(query::ErrorCode::cancelled,"query cancelled or deadline reached");}
    void charge(uint64_t amount=1){
        if(amount>plan.max_work-progress.profile.work_units)throw query::Error(query::ErrorCode::budget,"query work limit exceeded");
        const auto before=progress.profile.work_units;progress.profile.work_units+=amount;
        if((before>>10)!=(progress.profile.work_units>>10)||before==0)check();
    }
};
// Prepare the selected hierarchy sources only when an inherited predicate is
// actually evaluated. A failed or cancelled preparation is never published.
struct InheritanceScope {
    const DatasetView& dataset;
    std::span<const uint32_t> selected;
    Work& work;
    std::pmr::memory_resource* memory;
    std::pmr::vector<hierarchy::Source> sources;
    bool ready=false;
    void (*select)(void*,std::pmr::vector<uint32_t>&)=nullptr;
    void* select_context=nullptr;
    InheritanceScope(const DatasetView& data,std::span<const uint32_t> indices,Work& w,std::pmr::memory_resource* r,
                     void (*choose)(void*,std::pmr::vector<uint32_t>&)=nullptr,void* context=nullptr):
        dataset(data),selected(indices),work(w),memory(r),sources(r),select(choose),select_context(context){}
    std::span<const hierarchy::Source> get(){
        if(!ready){
            std::pmr::vector<hierarchy::Source> prepared(memory);
            std::pmr::vector<uint32_t> indices(memory);
            if(select)select(select_context,indices);
            const std::span<const uint32_t> chosen=select?std::span<const uint32_t>(indices):selected;
            for(auto index:chosen){work.charge();prepared.push_back({index,dataset.sources[index].facts});}
            sources=std::move(prepared);ready=true;
        }
        return sources;
    }
};
char16_t fold(char16_t c)noexcept{return c>=u'A'&&c<=u'Z'?static_cast<char16_t>(c+32):c;}
bool text_match(const query::TextMatcher& matcher,std::u16string_view value,Work& work){
    auto unit=[&](char16_t c){return matcher.ascii_fold?fold(c):c;};
    if(matcher.op==query::TextOp::exact&&value.size()!=matcher.text.size())return false;
    if(matcher.op==query::TextOp::prefix&&value.size()<matcher.text.size())return false;
    if(matcher.op==query::TextOp::exact||matcher.op==query::TextOp::prefix){
        for(size_t i=0;i<matcher.text.size();++i){work.charge();if(unit(value[i])!=matcher.text[i])return false;}return true;
    }
    if(matcher.text.empty())return true;
    for(size_t i=0,j=0;i<value.size();++i){work.charge();while(j&&unit(value[i])!=matcher.text[j]){work.charge();j=matcher.prefix[j-1];}if(unit(value[i])==matcher.text[j])++j;if(j==matcher.text.size())return true;}return false;
}
std::u16string_view type_name(const Facts& facts,uint32_t type){return facts.strings[facts.types[type]];}
class Evaluator {
public:
    Evaluator(const SourceView& source,const query::Plan& plan,Work& work,std::pmr::memory_resource* memory,
        InheritanceScope* inheritance=nullptr,bool inheritance_complete=false,FactsCache* shared_facts=nullptr,const query::RelNode* graph_scope=nullptr):
        proof(memory),source(source),facts(*source.facts),plan(plan),work(work),memory(memory),inheritance(inheritance),inheritance_complete(inheritance_complete),cache(shared_facts),cache_graph_scope(graph_scope),exact_ids(plan.texts.size(),-2,memory),opcode_body(memory){}
    ~Evaluator(){reset_body();}
    Truth run(uint32_t ordinal){
        return run(ordinal,plan.root,plan.relation);
    }
    Truth run(uint32_t ordinal,uint32_t predicate,query::Relation relation,uint32_t operation=query::none){
        current=ordinal;row=entity(source,relation,ordinal);current_use=nullptr;current_relation=relation;relation_node=operation;reset_body();proof.clear();work.check();return evaluate(predicate);
    }
    Truth run_use(const facts::UseRecord& use,uint32_t predicate,query::Relation relation,uint32_t operation){
        if(use.key.source_index!=source.source_index||use.key.kind!=use_kind(relation)||use.key.dex_pc==UINT32_MAX)
            throw query::Error(query::ErrorCode::invalid,"use record identity differs from its scan");
        current=use.key.caller_ordinal;row=entity(source,query::Relation::method_defs,current);
        if(!row.method||row.method->method_index!=use.caller_method_ref||row.method->code_offset!=use.code_offset||!use.code_offset)
            throw query::Error(query::ErrorCode::invalid,"use record differs from its caller definition");
        using D=facts::TargetDomain;
        uint64_t bound=0;
        if(relation==query::Relation::string_uses&&use.target_domain==D::string_value){bound=facts.strings.size();if(use.extra_proto!=UINT32_MAX)throw query::Error(query::ErrorCode::invalid,"string use has extra prototype");}
        else if(relation==query::Relation::field_uses&&use.target_domain==D::field_ref){bound=facts.field_refs.size();if(use.extra_proto!=UINT32_MAX)throw query::Error(query::ErrorCode::invalid,"field use has extra prototype");}
        else if(relation==query::Relation::type_uses&&use.target_domain==D::type_ref){bound=facts.types.size();if(use.extra_proto!=UINT32_MAX)throw query::Error(query::ErrorCode::invalid,"type use has extra prototype");}
        else if(relation==query::Relation::invoke_sites){
            if(use.target_domain==D::method_ref){bound=facts.method_refs.size();if(use.extra_proto!=UINT32_MAX)throw query::Error(query::ErrorCode::invalid,"ordinary invoke has extra prototype");}
            else if(use.target_domain==D::method_and_proto){bound=facts.method_refs.size();if(use.extra_proto>=facts.prototypes.size())throw query::Error(query::ErrorCode::invalid,"polymorphic invoke prototype is outside its table");}
            else if(use.target_domain==D::call_site){bound=facts.call_site_count;if(use.extra_proto!=UINT32_MAX)throw query::Error(query::ErrorCode::invalid,"custom invoke has extra prototype");}
            else throw query::Error(query::ErrorCode::invalid,"invoke has an invalid target domain");
        }else throw query::Error(query::ErrorCode::invalid,"use has an invalid target domain");
        if(use.target_index>=bound)throw query::Error(query::ErrorCode::invalid,"use target index is outside its table");
        const uint64_t header=uint64_t(use.code_offset)+12;
        if(header>source.bytes.size()||source.bytes.size()-header<4)throw query::Error(query::ErrorCode::invalid,"use caller code header is outside source");
        const auto* p=source.bytes.data()+header;const auto units=uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24);
        if(use.key.dex_pc>=units)throw query::Error(query::ErrorCode::invalid,"use PC exceeds caller code units");
        current_use=&use;current_relation=relation;relation_node=operation;reset_body();proof.clear();work.check();
        const auto kind=relation==query::Relation::string_uses?WitnessKind::string_use:relation==query::Relation::invoke_sites?WitnessKind::invoke:relation==query::Relation::field_uses?WitnessKind::field_use:WitnessKind::type_use;
        const auto ref_kind=use.target_domain==facts::TargetDomain::call_site?1u:use.target_domain==facts::TargetDomain::method_and_proto?2u:0u;
        witness(kind,predicate,Truth::yes,use.key.dex_pc,use.opcode,use.target_index,ref_kind,use.extra_proto);
        proof.back().code_units=units;
        return evaluate(predicate);
    }
    std::pmr::vector<Witness> proof;
private:
    const SourceView& source;const Facts& facts;const query::Plan& plan;Work& work;std::pmr::memory_resource* memory;
    InheritanceScope* inheritance;bool inheritance_complete;FactsCache* cache;const query::RelNode* cache_graph_scope;
    query::class_annotation_match::MapCache annotation_map;
    std::pmr::vector<int64_t> exact_ids;
    std::pmr::vector<instructions::Instruction> opcode_body;
    uint32_t current=0,relation_node=query::none;EntityView row;
    query::Relation current_relation=query::Relation::method_defs;
    const facts::UseRecord* current_use=nullptr;
    // Recorder lifetime must exceed the vectors allocated through it.
    std::optional<RecordingResource> recorder;
    std::optional<dexmeguviz::facts::MethodFacts> owned_body;
    const dexmeguviz::facts::MethodFacts* body=nullptr;
    bool replayed=false;
    void reset_body()noexcept{
        body=nullptr;owned_body.reset();recorder.reset();
        // Release prior method instructions before the next checked decode.
        // Both vectors use the same resource; swap is non-throwing and avoids
        // charging two large instruction buffers at the same time.
        if(plan.demand_mask&instructions::opcode_list){std::pmr::vector<instructions::Instruction> empty(memory);opcode_body.swap(empty);}
        if(replayed){cache->replay.clear();replayed=false;}
    }
    const Method& method()const{return *row.method;}
    const Prototype& prototype()const{return *row.proto;}
    bool matches(uint32_t matcher,std::u16string_view value){return matcher==query::none||text_match(plan.texts[matcher],value,work);}
    void witness(WitnessKind kind,uint32_t node,Truth matched,uint32_t pc=UINT32_MAX,uint32_t opcode=0,uint32_t index=UINT32_MAX,uint32_t reference_kind=0,uint32_t proto=UINT32_MAX){
        proof.push_back({kind,plan.nodes[node].stable_id,static_cast<uint32_t>(matched),pc,opcode,index,reference_kind,proto,body?body->decoded_code_units:0});
        auto& w=proof.back();w.relation_node=relation_node;w.source_index=source.source_index;w.entity_ordinal=current;w.entity_relation=current_relation;w.entity_pc=current_use?current_use->key.dex_pc:UINT32_MAX;
    }
    void retain_last_proof(size_t base,size_t last){
        if(base==last)return;const auto count=proof.size()-last;
        std::move(proof.begin()+static_cast<ptrdiff_t>(last),proof.end(),proof.begin()+static_cast<ptrdiff_t>(base));proof.resize(base+count);
    }
    int64_t exact_id(uint32_t index){
        auto& stored=exact_ids[index];if(stored!=-2)return stored;
        ++work.progress.profile.string_pool_lookups;const auto& pattern=plan.texts[index].text;
        const auto found=symbols::string_with_work(facts,pattern,[&]{work.charge();});
        stored=found==symbols::no_index?-1:static_cast<int64_t>(found);return stored;
    }
    void ensure_body(){
        if(body)return;++work.progress.profile.fact_requests;work.check();
        const auto remaining=plan.max_work-work.progress.profile.work_units;
        const bool opcode_requested=(plan.demand_mask&instructions::opcode_list)!=0;
        if(cache&&!opcode_requested){body=cache->find(source,current,plan,remaining,memory,cache_graph_scope,inheritance_complete);if(body)replayed=true;}
        try{if(!body){
            auto* decoder_memory=memory;
            const bool recording=cache&&!opcode_requested&&cache->can_record(source,plan,cache_graph_scope);
            if(cache&&(!cache->method_provider()||opcode_requested))++cache->profile_stats.physical_collects;
            if(recording){cache->begin_recording();recorder.emplace(memory,&cache->recording);decoder_memory=&*recorder;}
            if(opcode_requested)owned_body.emplace(dexmeguviz::facts::collect_method_with_instructions(source.bytes,facts,current,plan.demand_mask,opcode_body,decoder_memory,work.cancel.requested,work.cancel.context,remaining));
            else if(cache&&cache->method_provider())owned_body.emplace(dexmeguviz::cache::collect_method(cache->method_provider(),source.bytes,facts,current,plan.demand_mask,decoder_memory,work.cancel.requested,work.cancel.context,remaining));
            else owned_body.emplace(dexmeguviz::facts::collect_method(source.bytes,facts,current,plan.demand_mask,decoder_memory,work.cancel.requested,work.cancel.context,remaining));
            body=&*owned_body;
            if(recording){cache->publish(source,current,plan,*body,cache_graph_scope,inheritance_complete);cache->recording.enabled=false;}
        }}
        catch(const instructions::DecodeError& failure){
            if(cache&&recorder)cache->discard_recording();
            const auto detail=std::string("source ")+std::to_string(source.source_index)+" method_ref "+std::to_string(method().method_index)+" pc "+std::to_string(failure.dex_pc)+": "+failure.what();
            throw instructions::DecodeError(failure.code,failure.dex_offset,failure.dex_pc,detail.c_str());
        }
        catch(...){if(cache&&recorder)cache->discard_recording();throw;}
        if((plan.demand_mask && body->has_body && !body->instruction_checked) || (body->requested_mask & plan.demand_mask)!=plan.demand_mask)
            throw query::Error(query::ErrorCode::unsupported,"method facts lack requested columns");
#ifdef DMG_TEST_JOB_COMMIT_BARRIER
        if(plan.method_type_query)if(const auto hook=test_type_use_method_barrier.load(std::memory_order_acquire))hook();
#endif
        if(body->instruction_checked){++work.progress.profile.methods_decoded;work.progress.profile.code_units+=body->decoded_code_units;work.charge(body->validation_work);}
    }
    bool symbol_match(const query::SymbolMatcher& s,const instructions::InvokeSite& site){
        using IK=instructions::ReferenceKind;
        if(s.invoke_kind==query::InvokeKind::call_site)return site.reference_kind==IK::call_site;
        if(site.reference_kind==IK::call_site)return false;
        if(s.invoke_kind==query::InvokeKind::normal&&site.reference_kind!=IK::method)return false;
        if(s.invoke_kind==query::InvokeKind::polymorphic&&site.reference_kind!=IK::method_and_proto)return false;
        const auto& ref=facts.method_refs[site.index];const auto& proto=facts.prototypes[ref.type];
        if(proto.parameters.size()<s.minimum_parameters||proto.parameters.size()>s.maximum_parameters)return false;
        if(!matches(s.owner,type_name(facts,ref.owner))||!matches(s.name,facts.strings[ref.name])||!matches(s.prototype,proto.descriptor)||!matches(s.returned,type_name(facts,proto.return_type)))return false;
        for(auto p:s.parameters)if(p.index>=proto.parameters.size()||!matches(p.text,type_name(facts,proto.parameters[p.index])))return false;
        return true;
    }
    bool field_match(const query::FieldMatcher& f,const FieldReference& ref){return matches(f.owner,type_name(facts,ref.owner))&&matches(f.name,facts.strings[ref.name])&&matches(f.type,type_name(facts,ref.type));}
    Truth inherited(uint32_t index){
        const auto& n=plan.nodes[index];
        const bool resolved=n.kind==Kind::inherited_interface_resolved_count;
        const bool include_interfaces=n.kind==Kind::inherited_interface_count||resolved;
        const auto proof_kind=resolved?WitnessKind::interface_resolved:include_interfaces?WitnessKind::interface_inherited:WitnessKind::inherited;
        if(!row.owner_class){witness(proof_kind,index,Truth::unknown);return Truth::unknown;}
        if(row.owner_type>=facts.class_definition_by_type.size())throw query::Error(query::ErrorCode::invalid,"inherited owner type is outside source");
        const auto owner=facts.class_definition_by_type[row.owner_type];
        if(owner==UINT32_MAX)throw query::Error(query::ErrorCode::invalid,"inherited owner identity is inconsistent");
        if(!inheritance)throw query::Error(query::ErrorCode::invalid,"inherited source scope is unavailable");
        const auto inheritance_sources=inheritance->get();
        hierarchy::Budget budget{UINT64_MAX};
        budget.charge_external=[](void* ctx,uint64_t amount){auto& work=*static_cast<Work*>(ctx);work.charge(amount);work.check();};
        budget.external_context=&work;budget.max_nodes=plan.max_intermediate_rows;
        budget.field_observed=[](void* ctx){++static_cast<Work*>(ctx)->progress.profile.declared_fields;};
        auto graph=[&](){
            if(resolved&&(row.owner_class->access_flags&0x200u)){
                hierarchy::Result g(memory);budget.charge();budget.bound(1);g.paths.push_back({{source.source_index,owner},UINT32_MAX,hierarchy::Link::root});g.ends.push_back({0,hierarchy::Stop::no_superclass});return g;
            }
            return hierarchy::resolve(inheritance_sources,{source.source_index,owner},inheritance_complete,budget,memory);
        }();
        struct MatcherContext {Evaluator* self;const query::FieldMatcher* matcher;};
        MatcherContext matcher_context{this,&plan.fields[n.symbol]};
        const auto matcher=[](void* ctx,const Facts& facts,const FieldDefinition& field){
            auto& m=*static_cast<MatcherContext*>(ctx);const auto& f=*m.matcher;const auto& ref=facts.field_refs[field.field_ref_index];
            return (field.access_flags&f.flags)==f.flags&&m.self->matches(f.owner,type_name(facts,ref.owner))&&
                m.self->matches(f.name,facts.strings[ref.name])&&m.self->matches(f.type,type_name(facts,ref.type));
        };
        if(resolved){
            const auto observed=hierarchy::v11::interface_fields(inheritance_sources,graph,inheritance_complete,n.minimum,n.maximum,matcher,&matcher_context,budget,memory);
            const auto value=observed.truth==hierarchy::FieldTruth::yes?Truth::yes:observed.truth==hierarchy::FieldTruth::no?Truth::no:Truth::unknown;
            if(value==Truth::unknown&&!inheritance_complete)work.progress.scope_derived_unknown=true;
            for(const auto& item:observed.events){work.charge();budget.bound(proof.size()+1);witness(proof_kind,index,value);auto& w=proof.back();
                w.source_index=item.source;w.entity_ordinal=item.ordinal;w.entity_relation=item.relation;w.entity_pc=UINT32_MAX;
                w.inherited_item=static_cast<uint32_t>(item.item);w.inherited_path=item.node;w.inherited_aux=item.aux;w.inherited_branch=item.branch;w.inherited_detail=item.detail;}
            return value;
        }
        if(include_interfaces){
            const auto observed=hierarchy::interface_fields(inheritance_sources,graph,inheritance_complete,n.minimum,n.maximum,matcher,&matcher_context,budget,memory);
            const auto value=observed.truth==hierarchy::FieldTruth::yes?Truth::yes:observed.truth==hierarchy::FieldTruth::no?Truth::no:Truth::unknown;
            if(value==Truth::unknown&&!inheritance_complete)work.progress.scope_derived_unknown=true;
            for(const auto& item:observed.events){
                work.charge();budget.bound(proof.size()+1);witness(proof_kind,index,value);auto& w=proof.back();
                w.source_index=item.source;w.entity_ordinal=item.ordinal;w.entity_relation=item.relation;w.entity_pc=UINT32_MAX;
                w.inherited_item=static_cast<uint32_t>(item.item);w.inherited_path=item.node;w.inherited_aux=item.aux;w.inherited_branch=item.branch;w.inherited_detail=item.detail;
            }
            return value;
        }
        const auto fields=hierarchy::inherited_fields(inheritance_sources,graph,n.minimum,n.maximum,matcher,&matcher_context,budget,memory);
        const auto value=fields.truth==hierarchy::FieldTruth::yes?Truth::yes:fields.truth==hierarchy::FieldTruth::no?Truth::no:Truth::unknown;
        if(value==Truth::unknown&&!inheritance_complete)work.progress.scope_derived_unknown=true;
        auto event=[&](uint32_t item,uint32_t source_index,uint32_t ordinal,query::Relation relation,uint32_t path,uint32_t aux,uint32_t branch,uint32_t detail){
            work.charge();budget.bound(proof.size()+1);witness(WitnessKind::inherited,index,value);auto& w=proof.back();
            w.source_index=source_index;w.entity_ordinal=ordinal;w.entity_relation=relation;w.entity_pc=UINT32_MAX;
            w.inherited_item=item;w.inherited_path=path;w.inherited_aux=aux;w.inherited_branch=branch;w.inherited_detail=detail;
        };
        for(uint32_t i=0;i<graph.paths.size();++i){const auto& p=graph.paths[i];event(1,p.key.occurrence,p.key.ordinal,query::Relation::class_defs,i,p.parent,UINT32_MAX,static_cast<uint32_t>(p.link));}
        for(uint32_t i=0;i<graph.ends.size();++i){const auto& e=graph.ends[i];const auto& p=graph.paths[e.path];event(2,p.key.occurrence,p.key.ordinal,query::Relation::class_defs,e.path,static_cast<uint32_t>(e.reason),i,0);}
        for(const auto& b:fields.branches){const auto& e=graph.ends[b.end_index];const auto& p=graph.paths[e.path];
            event(3,p.key.occurrence,p.key.ordinal,query::Relation::class_defs,e.path,b.known_matches,b.end_index,(b.incomplete?1u:0u)|(static_cast<uint32_t>(b.truth)<<1));}
        for(const auto& w:fields.witnesses)event(4,w.field.occurrence,w.field.ordinal,query::Relation::field_defs,w.path_index,UINT32_MAX,w.end_index,0);
        return value;
    }
    Truth field_declaration(uint32_t index){
        const auto& n=plan.nodes[index];
        if(!current_use||current_relation!=query::Relation::field_uses||!inheritance||!inheritance_complete)
            throw query::Error(query::ErrorCode::invalid,"field declaration scope unavailable");
        const auto& ref=facts.field_refs[current_use->target_index];
        if(ref.name>=facts.strings.size())throw query::Error(query::ErrorCode::invalid,"field reference name outside table");
        hierarchy::Budget budget{UINT64_MAX};
        budget.charge_external=[](void* ctx,uint64_t amount){auto& w=*static_cast<Work*>(ctx);w.charge(amount);w.check();};
        budget.external_context=&work;budget.max_nodes=plan.max_intermediate_rows;
        const auto sources=inheritance->get();
        const auto resolved=field_declaration::lookup(sources,type_name(facts,ref.owner),facts.strings[ref.name],type_name(facts,ref.type),budget,memory);
        if(resolved.state!=field_declaration::State::found)return Truth::unknown;
        const Facts* definition_facts=nullptr;
        for(const auto& s:sources){work.charge();if(s.occurrence==resolved.field_source){definition_facts=s.facts;break;}}
        if(!definition_facts||resolved.field_ordinal>=definition_facts->field_definitions.size()||resolved.path.empty())
            throw query::Error(query::ErrorCode::invalid,"field declaration identity outside scope");
        const auto& def=definition_facts->field_definitions[resolved.field_ordinal];
        const auto visibility=def.access_flags&7u;
        constexpr uint32_t field_flag_mask=0x50dfu; // DEX field flags only.
        if((def.access_flags&~field_flag_mask)!=0 || ((def.access_flags&0x50u)==0x50u) ||
           (visibility!=0&&visibility!=1&&visibility!=2&&visibility!=4))return Truth::unknown;
        const bool opcode_static=current_use->opcode>=0x60&&current_use->opcode<=0x6d;
        const bool opcode_instance=current_use->opcode>=0x52&&current_use->opcode<=0x5f;
        if((!opcode_static&&!opcode_instance)||opcode_static!=((def.access_flags&8u)!=0))return Truth::unknown;
        const auto& last=resolved.path.back();
        if(last.source!=resolved.field_source)throw query::Error(query::ErrorCode::invalid,"field declaration path source mismatch");
        if(last.ordinal>=definition_facts->class_definitions.size())throw query::Error(query::ErrorCode::invalid,"field declaration path class outside scope");
        const auto& cls=definition_facts->class_definitions[last.ordinal];
        if(def.owner_type!=cls.type_id)return Truth::unknown;
        if((cls.access_flags&0x200u)&&!(def.access_flags&8u))return Truth::unknown;
        const bool declared=resolved.path.size()==1;
        if((n.argument==0&&!declared)||(n.argument==1&&declared))return Truth::no;
        const auto& match=plan.fields[n.symbol];const auto& actual=definition_facts->field_refs[def.field_ref_index];
        if(!matches(match.owner,type_name(*definition_facts,def.owner_type))||!matches(match.name,definition_facts->strings[actual.name])||
           !matches(match.type,type_name(*definition_facts,actual.type))||(def.access_flags&match.flags)!=match.flags)return Truth::no;
        budget.bound(proof.size()+resolved.path.size()+1);
        for(uint32_t i=0;i<resolved.path.size();++i){
            work.charge();const auto& step=resolved.path[i];witness(WitnessKind::field_declaration,index,Truth::yes);
            auto& w=proof.back();w.source_index=step.source;w.entity_ordinal=step.ordinal;w.entity_relation=query::Relation::class_defs;w.entity_pc=UINT32_MAX;
            w.inherited_item=0;w.inherited_path=i;w.inherited_aux=static_cast<uint32_t>(step.edge);w.inherited_branch=step.interface_index;w.inherited_detail=0;
        }
        witness(WitnessKind::field_declaration,index,Truth::yes);auto& w=proof.back();
        w.source_index=resolved.field_source;w.entity_ordinal=resolved.field_ordinal;w.entity_relation=query::Relation::field_defs;w.entity_pc=UINT32_MAX;
        w.inherited_item=1;w.inherited_path=static_cast<uint32_t>(resolved.path.size()-1);w.inherited_aux=UINT32_MAX;w.inherited_branch=UINT32_MAX;w.inherited_detail=def.access_flags;
        return Truth::yes;
    }
    Truth metadata(const query::Node& n,uint32_t node_index){
        switch(n.kind){
        case Kind::yes:return Truth::yes;case Kind::no:return Truth::no;
        case Kind::class_annotation:case Kind::class_annotation_string:{
            if(current_relation!=query::Relation::class_defs||!row.owner_class)throw query::Error(query::ErrorCode::unsupported,"class annotation requires local class definition");
            if(facts.dex_version==41)throw query::Error(query::ErrorCode::unsupported,"class annotations do not support DEX 041");
            auto charge=[&](uint64_t n){work.charge(n);};const auto& type=plan.texts[n.text].text;
            const std::u16string_view name=n.symbol==query::none?std::u16string_view{}:std::u16string_view(plan.texts[n.symbol].text);
            const std::u16string_view expected=n.kind==Kind::class_annotation_string?std::u16string_view(plan.texts[static_cast<uint32_t>(n.annotation_value_text)].text):std::u16string_view{};
            const auto value=query::class_annotation_match::inspect(source.bytes,facts,*row.owner_class,type,n.argument,name,n.symbol!=query::none,n.minimum,charge,&annotation_map,n.kind==Kind::class_annotation_string?&expected:nullptr);
            return value==query::class_annotation_match::Match::yes?Truth::yes:value==query::class_annotation_match::Match::no?Truth::no:Truth::unknown;
        }

        case Kind::name:return truth(matches(n.text,row.name));case Kind::owner:return truth(matches(n.text,row.owner));case Kind::prototype:return truth(matches(n.text,row.prototype));
        case Kind::descriptor:return truth(matches(n.text,row.type_descriptor));case Kind::value:return truth(matches(n.text,row.value));
        case Kind::has_local_definition:return truth(row.definition_known==(n.argument!=0));
        case Kind::use_caller_name:case Kind::use_caller_owner:
            if(!current_use)throw query::Error(query::ErrorCode::invalid,"use predicate on non-use row");
            return truth(matches(n.text,n.kind==Kind::use_caller_name?row.name:row.owner));
        case Kind::use_pc:case Kind::use_opcode:case Kind::use_target_index:{
            if(!current_use)throw query::Error(query::ErrorCode::invalid,"use predicate on non-use row");
            const auto value=n.kind==Kind::use_pc?current_use->key.dex_pc:n.kind==Kind::use_opcode?uint32_t(current_use->opcode):current_use->target_index;
            return truth(value>=n.minimum&&value<=n.maximum);
        }
        case Kind::use_target_descriptor:
            if(!current_use||current_use->target_domain!=facts::TargetDomain::type_ref||current_use->target_index>=facts.types.size()||facts.types[current_use->target_index]>=facts.strings.size())throw query::Error(query::ErrorCode::invalid,"type use descriptor outside table");
            return truth(matches(n.text,facts.strings[facts.types[current_use->target_index]]));
        case Kind::use_domain:
            if(!current_use)throw query::Error(query::ErrorCode::invalid,"use predicate on non-use row");
            return truth(static_cast<uint32_t>(current_use->target_domain)==n.argument);
        case Kind::return_type:return truth(matches(n.text,type_name(facts,prototype().return_type)));
        case Kind::parameter_count:return truth(prototype().parameters.size()>=n.minimum&&prototype().parameters.size()<=n.maximum);
        case Kind::parameter_type:return truth(n.argument<prototype().parameters.size()&&matches(n.text,type_name(facts,prototype().parameters[n.argument])));
        case Kind::flags_contains:case Kind::flags_exact:case Kind::flags_any:{
            const bool owner=(n.argument&1u)!=0;
            if(owner?!row.owner_class:!row.flags_known)return Truth::unknown;
            auto value=owner?row.owner_class->access_flags:row.access_flags;
            std::optional<query::class_annotation_flags::Observation> annotation;
            if(n.argument&2u){
                using Target=query::reflection_flags::Target;
                const bool klass=owner||row.kind==query::Relation::class_defs||row.kind==query::Relation::type_refs;
                const bool method=row.kind==query::Relation::method_defs||row.kind==query::Relation::method_refs;
                const auto target=klass?Target::klass:method?Target::method:Target::field;
                std::optional<uint32_t> normalized;
                if(klass&&(plan.required_capabilities&536870912u)){
                    if(!row.owner_class)return Truth::unknown;
                    auto charge=[&](uint64_t units){work.charge(units);};
                    annotation=query::class_annotation_flags::inspect(source.bytes,facts,*row.owner_class,memory,charge);
                    normalized=annotation->projected;
                }else normalized=query::reflection_flags::project(value,target,klass&&row.owner_class&&row.owner_class->annotations_offset==0);
                if(!normalized)return Truth::unknown;
                value=*normalized;
            }
            const auto matched=n.kind==Kind::flags_exact?truth(value==n.minimum):n.kind==Kind::flags_any?truth((value&n.minimum)!=0):truth((value&n.minimum)==n.minimum);
            if(annotation){
                if(row.owner_type>=facts.class_definition_by_type.size())throw query::Error(query::ErrorCode::invalid,"class annotation owner type outside table");
                const auto class_ordinal=facts.class_definition_by_type[row.owner_type];
                if(class_ordinal>=facts.class_definitions.size())throw query::Error(query::ErrorCode::invalid,"class annotation owner outside definitions");
                witness(WitnessKind::class_annotation_flags,node_index,matched);auto& proof_row=proof.back();
                proof_row.source_index=source.source_index;proof_row.entity_relation=query::Relation::class_defs;proof_row.entity_ordinal=class_ordinal;proof_row.entity_pc=UINT32_MAX;
                proof_row.inherited_item=static_cast<uint32_t>(annotation->source);proof_row.inherited_path=annotation->directory;
                proof_row.inherited_aux=annotation->set;proof_row.inherited_branch=annotation->item;proof_row.inherited_detail=annotation->value_offset;
                proof_row.numeric_bits=annotation->encoded;proof_row.numeric_width=value;proof_row.numeric_kind=row.owner_class->access_flags;
            }
            return matched;
        }
        case Kind::superclass:{if(!row.owner_class)return Truth::unknown;auto parent=row.owner_class->superclass_type;return truth(parent!=UINT32_MAX&&matches(n.text,type_name(facts,parent)));}
        case Kind::interface_type:if(!row.owner_class)return Truth::unknown;for(auto type:row.owner_class->interfaces)if(matches(n.text,type_name(facts,type)))return Truth::yes;return Truth::no;
        case Kind::declared_field_count:{
            if(!row.owner_class)return Truth::unknown;
            uint32_t count=0;const auto& match=plan.fields[n.symbol];
            for(const auto& field:facts.field_definitions){work.charge();++work.progress.profile.declared_fields;if(field.owner_type==row.owner_type&&(field.access_flags&match.flags)==match.flags&&field_match(match,facts.field_refs[field.field_ref_index]))++count;}
            return truth(count>=n.minimum&&count<=n.maximum);
        }
        default:throw query::Error(query::ErrorCode::invalid,"invalid metadata node");
        }
    }
    Truth evaluate(uint32_t index){
        work.charge();const auto& n=plan.nodes[index];
        if(n.kind==Kind::all||n.kind==Kind::any){
            const auto base=proof.size();bool unknown=false;
            // Pure metadata constraints are evaluated first, without demanding a method body.
            for(unsigned body_pass=0;body_pass<2;++body_pass)for(auto child:n.children){
                if((plan.nodes[child].demand_mask!=0)!=(body_pass!=0))continue;const auto last=proof.size();const auto value=evaluate(child);unknown|=value==Truth::unknown;
                if((n.kind==Kind::all&&value==Truth::no)||(n.kind==Kind::any&&value==Truth::yes)){retain_last_proof(base,last);return value;}
            }
            return unknown?Truth::unknown:truth(n.kind==Kind::all);
        }
        if(n.kind==Kind::negate){const auto value=evaluate(n.children[0]);return value==Truth::unknown?value:value==Truth::yes?Truth::no:Truth::yes;}
        if(n.kind==Kind::using_string){
            const auto& pattern=plan.texts[n.text];int64_t id=-2;
            if(pattern.op==query::TextOp::exact&&!pattern.ascii_fold){id=exact_id(n.text);if(id==-1){witness(WitnessKind::string_pool_absence,index,Truth::no);return Truth::no;}}
            ensure_body();for(const auto& use:body->string_uses){work.charge();if(id>=0?use.string_index==static_cast<uint32_t>(id):matches(n.text,facts.strings[use.string_index])){witness(WitnessKind::string_use,index,Truth::yes,use.pc,use.opcode,use.string_index);return Truth::yes;}}
        }else if(n.kind==Kind::using_type){
            ensure_body();for(const auto& use:body->type_uses){work.charge();if(use.type_index>=facts.types.size()||facts.types[use.type_index]>=facts.strings.size())throw query::Error(query::ErrorCode::invalid,"type use outside source table");
                if((n.argument==UINT32_MAX||n.argument==use.opcode)&&matches(n.text,facts.strings[facts.types[use.type_index]])){witness(WitnessKind::type_use,index,Truth::yes,use.pc,use.opcode,use.type_index);return Truth::yes;}}
        }else if(n.kind==Kind::invoke){
            ensure_body();for(const auto& site:body->invoke_sites){work.charge();++work.progress.profile.invoke_sites;if(symbol_match(plan.symbols[n.symbol],site)){witness(WitnessKind::invoke,index,Truth::yes,site.pc,site.opcode,site.index,static_cast<uint32_t>(site.reference_kind),site.extra_proto);return Truth::yes;}}
        }else if(n.kind==Kind::opcode_sequence){
            ensure_body();const auto& pattern=plan.texts[n.text];const size_t count=opcode_body.size(),wanted=pattern.text.size();
            const auto mode=static_cast<query::OpcodeMode>(n.argument&3u);const bool wildcard=(n.argument&4u)!=0;
            work.charge(count);bool matched=false;
            if(count>=n.minimum&&count<=n.maximum){
                // Empty lists impose no sequence condition, including on bodyless methods.
                if(wanted==0)matched=true;
                else if(wanted<=count){
                    if(mode==query::OpcodeMode::contains){
                        if(wildcard){
                            const auto words=(wanted+31u)/32u;if(pattern.prefix.size()!=words*257u)throw query::Error(query::ErrorCode::invalid,"invalid opcode bitset");
                            std::pmr::vector<uint32_t> state(words,uint32_t{0},memory);
                            for(const auto& instruction:opcode_body){
                                uint32_t carry=1;const auto offset=size_t(instruction.opcode)*words,wild=256u*words;
                                for(size_t w=0;w<words;++w){work.charge();const auto old=state[w];const auto shifted=(old<<1u)|carry;carry=old>>31u;
                                    state[w]=shifted&(pattern.prefix[wild+w]|pattern.prefix[offset+w]);}
                                if(state[(wanted-1u)/32u]&(uint32_t{1}<<((wanted-1u)%32u))){matched=true;break;}
                            }
                        }else{
                            if(pattern.prefix.size()!=wanted)throw query::Error(query::ErrorCode::invalid,"invalid opcode prefix table");
                            size_t j=0;for(const auto& instruction:opcode_body){
                                work.charge();while(j&&instruction.opcode!=pattern.text[j]){work.charge();j=pattern.prefix[j-1];}
                                if(instruction.opcode==pattern.text[j])++j;
                                if(j==wanted){matched=true;break;}
                            }
                        }
                    }else if(mode!=query::OpcodeMode::equals||wanted==count){
                        const size_t offset=mode==query::OpcodeMode::ends_with?count-wanted:0;matched=true;
                        for(size_t i=0;i<wanted;++i){work.charge();if(pattern.text[i]!=char16_t{256}&&opcode_body[offset+i].opcode!=pattern.text[i]){matched=false;break;}}
                    }
                }
            }
            if(matched){witness(body->has_body?WitnessKind::instruction_scope:WitnessKind::no_body,index,Truth::yes);return Truth::yes;}
        }else if(n.kind==Kind::numeric_bits){
            ensure_body();const query::numeric::Pattern pattern{n.numeric_value,n.minimum,static_cast<query::numeric::Kind>(n.argument)};
            for(const auto& literal:body->numeric_literals){work.charge();if(query::numeric::matches(pattern,literal)){
                witness(WitnessKind::numeric_literal,index,Truth::yes,literal.pc,literal.opcode);auto& proof_row=proof.back();
                proof_row.numeric_bits=literal.bits;proof_row.numeric_width=literal.width_bits;proof_row.numeric_kind=static_cast<uint32_t>(literal.kind);return Truth::yes;}}
        }else if(n.kind==Kind::field_access){
            ensure_body();const auto& f=plan.fields[n.symbol];for(const auto& use:body->field_uses){work.charge();++work.progress.profile.field_uses;
                const bool read=(use.opcode>=0x52&&use.opcode<=0x58)||(use.opcode>=0x60&&use.opcode<=0x66);
                if((f.access==0||(f.access==1&&read)||(f.access==2&&!read))&&field_match(f,facts.field_refs[use.field_index])){witness(WitnessKind::field_use,index,Truth::yes,use.pc,use.opcode,use.field_index);return Truth::yes;}}
        }else if(n.kind==Kind::target_field_declaration){return field_declaration(index);
        }else if(n.kind==Kind::inherited_field_count||n.kind==Kind::inherited_interface_count||n.kind==Kind::inherited_interface_resolved_count){return inherited(index);
        }else{const auto value=metadata(n,index);witness(WitnessKind::metadata,index,value);return value;}
        witness(body->has_body?WitnessKind::instruction_scope:WitnessKind::no_body,index,Truth::no);return Truth::no;
    }
};
int compare_text(std::u16string_view a,std::u16string_view b,Work& work){
    const auto length=std::min(a.size(),b.size());for(size_t i=0;i<length;++i){work.charge();if(a[i]!=b[i])return a[i]<b[i]?-1:1;}return a.size()==b.size()?0:a.size()<b.size()?-1:1;
}
#include "relational.inc"
}
Result execute(const DatasetView& dataset,const query::Plan& plan,Progress& progress,std::pmr::memory_resource* memory,Cancel cancel,CandidateSink sink,FactsCache* shared_facts){
    // Experimental container admission is centralized across sync, Job and multi execution.
    for(const auto& source:dataset.sources)if(source.facts&&source.facts->dex_version==41){
        constexpr uint32_t admitted=16383u|1073741824u;
        if(plan.required_capabilities&~admitted)throw query::Error(query::ErrorCode::unsupported,"041 profile combination not admitted");
    }

    progress={};Work work{plan,progress,cancel};work.check();Result result(memory);
    if(dataset.reverse_target_join){
        auto& option=*dataset.reverse_target_join;option.adapter_work=0;option.page_calls=0;
        using O=query::RelOp;using R=query::Relation;using K=query::JoinKey;
        if(!option.registry||!option.limits.max_work||!option.limits.max_index_bytes||!option.limits.max_records||
           !option.max_adapter_work||!option.max_page_calls)throw query::Error(query::ErrorCode::invalid,"invalid reverse join limits");
        if(sink.accept||plan.use_streaming||(plan.required_capabilities&~8191u)||plan.relation_root==query::none||plan.relation_root>=plan.relations.size())
            throw query::Error(query::ErrorCode::unsupported,"reverse target join requires a synchronous v4 direct graph");
        const auto& node=plan.relations[plan.relation_root];
        if(node.op!=O::join||node.join_key!=K::target_ref||node.children.size()!=2||node.children[0]>=plan.relations.size()||node.children[1]>=plan.relations.size())
            throw query::Error(query::ErrorCode::unsupported,"reverse target join shape unsupported");
        const auto& left=plan.relations[node.children[0]];const auto& right=plan.relations[node.children[1]];
        const auto use=option.use_relation;
        if(use!=R::invoke_sites&&use!=R::field_uses&&use!=R::string_uses)throw query::Error(option.intersection_only?query::ErrorCode::unsupported:query::ErrorCode::invalid,"invalid reverse join domain");
        const auto target=use==R::invoke_sites?R::method_refs:use==R::field_uses?R::field_refs:R::string_values;
        if(left.op!=O::scan||left.relation!=use||right.op!=O::scan||right.relation!=target)
            throw query::Error(query::ErrorCode::unsupported,use==R::invoke_sites?
                "reverse target join requires direct invoke and method reference scans":use==R::field_uses?
                "reverse field target join requires direct field use and field reference scans":
                "reverse string target join requires direct string use and string value scans");
    }
    if(query::is_use_relation(plan.relation))(void)use_kind(plan.relation);else validate_entity_relation(plan.relation);
    if(plan.relation_root!=query::none){
        if(plan.relation_root>=plan.relations.size())throw query::Error(query::ErrorCode::invalid,"relation root outside plan");
        if(query::is_use_relation(plan.relations[plan.relation_root].relation))(void)use_kind(plan.relations[plan.relation_root].relation);else validate_entity_relation(plan.relations[plan.relation_root].relation);
        if(plan.relations[plan.relation_root].relation!=plan.relation)throw query::Error(query::ErrorCode::invalid,"relation root type differs from plan");
    }
    if(plan.unique_one_stream&&!unique_one_stream_shape(plan))
        throw query::Error(query::ErrorCode::unsupported,"invalid unique_one_stream shape");
    if(sink.accept&&!can_stream(plan))
        throw query::Error(query::ErrorCode::invalid,"candidate sink requires a streamable unordered Exists/Unique plan");
    if(plan.relation_root!=query::none)return GraphExecutor(dataset,plan,progress,work,memory,sink,cancel.requested?nullptr:shared_facts).run();
    if(query::is_use_relation(plan.relation))throw query::Error(query::ErrorCode::unsupported,"use scans require a relation expression");
    auto same_slot=[&](std::string_view a,std::string_view b){work.charge();if(a.size()!=b.size())return false;for(size_t i=0;i<a.size();++i){work.charge();if(a[i]!=b[i])return false;}return true;};
    if(plan.explicit_scope)for(const auto& slot:plan.scope_slots)if(std::none_of(dataset.input_slots.begin(),dataset.input_slots.end(),[&](auto candidate){return same_slot(candidate,slot);}))throw query::Error(query::ErrorCode::source_mismatch,"requested source slot is absent");
    uint64_t total=0;
    for(size_t position=0;position<dataset.sources.size();++position){const auto& source=dataset.sources[position];
        if(!source.facts||source.input_index>=dataset.input_slots.size()||source.source_index!=position)throw query::Error(query::ErrorCode::invalid,"source view identity is inconsistent");
        if(plan.explicit_scope&&std::none_of(plan.scope_slots.begin(),plan.scope_slots.end(),[&](const auto& slot){return same_slot(slot,dataset.input_slots[source.input_index]);}))continue;
        if(plan.class_annotation_requested&&source.facts->dex_version==41)throw query::Error(query::ErrorCode::unsupported,"class annotations do not support DEX 041");
        result.scope_sources.push_back(source.source_index);total+=relation_size(*source.facts,plan.relation);if(total>UINT32_MAX)throw query::Error(query::ErrorCode::budget,"query scope exceeds counter range");
    }
    progress.total=static_cast<uint32_t>(total);progress.scope_complete=plan.explicit_scope||dataset.scope_complete;
    progress.scope_source_count=static_cast<uint32_t>(result.scope_sources.size());
    auto less=[&](const Candidate& a,const Candidate& b){
        work.charge();++progress.profile.sort_comparisons;
        const auto ma=entity(dataset.sources[a.source_index],a.relation,a.method_ordinal);const auto mb=entity(dataset.sources[b.source_index],b.relation,b.method_ordinal);
        for(auto key:plan.order){work.charge();int comparison=0;
            switch(key.field){
            case query::SortField::owner:comparison=compare_text(ma.owner,mb.owner,work);break;
            case query::SortField::name:comparison=compare_text(ma.name,mb.name,work);break;
            case query::SortField::prototype:comparison=compare_text(ma.prototype,mb.prototype,work);break;
            case query::SortField::flags:comparison=ma.flags_known!=mb.flags_known?(ma.flags_known?1:-1):!ma.flags_known?0:ma.access_flags==mb.access_flags?0:ma.access_flags<mb.access_flags?-1:1;break;
            case query::SortField::source_index:comparison=a.source_index==b.source_index?0:a.source_index<b.source_index?-1:1;break;
            case query::SortField::method_index:comparison=ma.reference_index==mb.reference_index?0:ma.reference_index<mb.reference_index?-1:1;break;
            case query::SortField::descriptor:comparison=compare_text(ma.type_descriptor,mb.type_descriptor,work);break;
            case query::SortField::value:comparison=compare_text(ma.value,mb.value,work);break;
            case query::SortField::local_index:comparison=ma.ordinal==mb.ordinal?0:ma.ordinal<mb.ordinal?-1:1;break;
            case query::SortField::use_pc:case query::SortField::use_opcode:case query::SortField::use_target_index:throw query::Error(query::ErrorCode::unsupported,"use order requires relation expression");
            }
            if(comparison)return key.descending?comparison>0:comparison<0;
        }
        return a.source_index!=b.source_index?a.source_index<b.source_index:a.method_ordinal<b.method_ordinal;
    };
    InheritanceScope inheritance(dataset,result.scope_sources,work,memory);
    bool stop=false;
    for(auto index:result.scope_sources){
        Evaluator evaluator(dataset.sources[index],plan,work,memory,plan.has_inherited_predicate?&inheritance:nullptr,progress.scope_complete,cancel.requested?nullptr:shared_facts);
        for(uint32_t ordinal=0;ordinal<relation_size(*dataset.sources[index].facts,plan.relation);++ordinal){
            work.charge();++progress.visited;const auto match=evaluator.run(ordinal);if(match==Truth::unknown)++progress.profile.unknown_rows;if(match!=Truth::yes)continue;++progress.profile.matches_seen;
            if(plan.intent!=query::Intent::top_n&&result.rows.size()==plan.max_results){result.result_limit=true;
#ifdef DMG_TEST_JOB_COMMIT_BARRIER
                if(const auto barrier=test_result_limit_barrier.load(std::memory_order_acquire))barrier();
#endif
                stop=true;break;}
            Candidate candidate(index,ordinal,memory,plan.relation);candidate.witnesses=std::move(evaluator.proof);
            if(plan.intent==query::Intent::top_n){
                if(result.rows.size()<plan.max_results){result.rows.push_back(std::move(candidate));std::push_heap(result.rows.begin(),result.rows.end(),less);}
                else if(less(candidate,result.rows.front())){std::pop_heap(result.rows.begin(),result.rows.end(),less);result.rows.back()=std::move(candidate);std::push_heap(result.rows.begin(),result.rows.end(),less);}
            }else result.rows.push_back(std::move(candidate));
            if(sink.accept)sink.accept(sink.context,result,result.rows.back(),progress);
            if(plan.intent==query::Intent::exists||(plan.intent==query::Intent::unique&&result.rows.size()==2)){stop=true;break;}
        }
        if(stop)break;
    }
    if(plan.intent==query::Intent::top_n)std::sort_heap(result.rows.begin(),result.rows.end(),less);
    else if(!plan.order.empty())std::sort(result.rows.begin(),result.rows.end(),less);
    progress.order_verified=!result.result_limit&&progress.scope_complete&&progress.visited==progress.total&&!progress.profile.unknown_rows;
    if(!(result.result_limit&&sink.accept))work.check();return result;
}

bool execute_fused_methods(const DatasetView& dataset,std::span<FusedMethodLane> lanes,FactsCache* shared_facts){
    // This first slice is intentionally limited to the direct v1 enumeration
    // shape. Other plans are left untouched for the scalar executor.
    if(lanes.empty()||lanes.size()>32||dataset.reverse_target_join)return false;
    for(const auto& lane:lanes){
        if(!lane.plan||!lane.progress||!lane.result||!lane.memory||lane.error||!lane.result->rows.empty()||
           !lane.result->scope_sources.empty()||!lane.plan->id.starts_with("query:v1:")||
           lane.plan->relation!=query::Relation::method_defs||lane.plan->relation_root!=query::none||
           lane.plan->intent!=query::Intent::enumerate||lane.plan->explicit_scope||!lane.plan->order.empty()||
           lane.plan->has_inherited_predicate||lane.plan->contains_expand||lane.plan->class_annotation_requested||
           lane.plan->method_type_query)return false;
    }
    uint64_t total=0;
    for(size_t i=0;i<dataset.sources.size();++i){const auto& source=dataset.sources[i];
        if(!source.facts||source.facts->dex_version==41||source.input_index>=dataset.input_slots.size()||source.source_index!=i)return false;
        total+=relation_size(*source.facts,query::Relation::method_defs);if(total>UINT32_MAX)return false;
    }
    struct WorkDelete {std::pmr::memory_resource* memory=nullptr;void operator()(Work* p)const{if(p){std::destroy_at(p);memory->deallocate(p,sizeof(Work),alignof(Work));}}};
    struct EvalDelete {std::pmr::memory_resource* memory=nullptr;void operator()(Evaluator* p)const{if(p){std::destroy_at(p);memory->deallocate(p,sizeof(Evaluator),alignof(Evaluator));}}};
    using WorkPtr=std::unique_ptr<Work,WorkDelete>;
    using EvalPtr=std::unique_ptr<Evaluator,EvalDelete>;
    struct State {
        WorkPtr work;
        EvalPtr evaluator;
        bool stopped=false;
        State():work(nullptr,WorkDelete{}),evaluator(nullptr,EvalDelete{}){}
    };
    std::pmr::vector<State> states(lanes[0].memory);states.reserve(lanes.size());
    for(size_t i=0;i<lanes.size();++i)states.emplace_back();
    for(size_t i=0;i<lanes.size();++i){auto& lane=lanes[i];
        try {
            *lane.progress={};auto* storage=lane.memory->allocate(sizeof(Work),alignof(Work));
            try{states[i].work=WorkPtr(new(storage) Work{*lane.plan,*lane.progress,{}},WorkDelete{lane.memory});}
            catch(...){lane.memory->deallocate(storage,sizeof(Work),alignof(Work));throw;}
            states[i].work->check();
            for(const auto& source:dataset.sources)lane.result->scope_sources.push_back(source.source_index);
            lane.progress->total=static_cast<uint32_t>(total);lane.progress->scope_complete=dataset.scope_complete;
            lane.progress->scope_source_count=static_cast<uint32_t>(lane.result->scope_sources.size());
        }catch(...){lane.error=std::current_exception();states[i].stopped=true;}
    }
    for(const auto& source:dataset.sources){
        for(size_t i=0;i<lanes.size();++i)if(!states[i].stopped){
            try {auto* storage=lanes[i].memory->allocate(sizeof(Evaluator),alignof(Evaluator));
                try{states[i].evaluator=EvalPtr(new(storage) Evaluator(source,*lanes[i].plan,*states[i].work,lanes[i].memory,nullptr,false,shared_facts),EvalDelete{lanes[i].memory});}
                catch(...){lanes[i].memory->deallocate(storage,sizeof(Evaluator),alignof(Evaluator));throw;}}
            catch(...){lanes[i].error=std::current_exception();states[i].stopped=true;}
        }
        for(uint32_t ordinal=0;ordinal<relation_size(*source.facts,query::Relation::method_defs);++ordinal){
            bool live=false;
            for(size_t i=0;i<lanes.size();++i)if(!states[i].stopped){auto& lane=lanes[i];auto& state=states[i];live=true;
                try {
                    state.work->charge();++lane.progress->visited;const auto match=state.evaluator->run(ordinal);
                    if(match==Truth::unknown)++lane.progress->profile.unknown_rows;
                    if(match!=Truth::yes)continue;
                    ++lane.progress->profile.matches_seen;
                    if(lane.result->rows.size()==lane.plan->max_results){lane.result->result_limit=true;state.stopped=true;state.evaluator.reset();continue;}
                    Candidate candidate(source.source_index,ordinal,lane.memory,query::Relation::method_defs);
                    candidate.witnesses=std::move(state.evaluator->proof);lane.result->rows.push_back(std::move(candidate));
                }catch(...){lane.error=std::current_exception();state.stopped=true;state.evaluator.reset();}
            }
            if(!live)break;
        }
        for(auto& state:states)state.evaluator.reset();
    }
    for(size_t i=0;i<lanes.size();++i)if(!lanes[i].error){auto& lane=lanes[i];
        lane.progress->order_verified=!lane.result->result_limit&&lane.progress->scope_complete&&
            lane.progress->visited==lane.progress->total&&!lane.progress->profile.unknown_rows;
        try{states[i].work->check();}catch(...){lane.error=std::current_exception();}
    }
    return true;
}
}
