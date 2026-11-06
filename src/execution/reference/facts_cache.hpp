#pragma once
#include "entity.hpp"
#include "facts/method_facts.hpp"
#include "cache/method_provider.hpp"
#include <array>
#include <list>
#include <memory_resource>
#include <span>
#include <stdexcept>
#include <string_view>

namespace dexmeguviz::reference {
// Bounded allocation trace for replay against each rule's own PMR resource.
// Overflow disables caching; it never changes the original allocation result.
struct AllocationTrace {
    struct Event { size_t size=0,alignment=0;uint32_t id=0;bool allocate=false; };
    struct Live {void* pointer=nullptr;};
    static constexpr size_t max_events=1024,max_allocations=256;
    std::array<Event,max_events> events{};
    std::array<Live,max_allocations> allocations{};
    uint32_t count=0,allocated=0;bool enabled=false,overflow=false;
    uint64_t* work_left=nullptr;uint64_t* work_charged=nullptr;
    void reset(uint64_t* left,uint64_t* charged)noexcept{count=0;allocated=0;enabled=true;overflow=false;work_left=left;work_charged=charged;}
    bool spend()noexcept{
        if(!enabled)return false;
        if(!*work_left){enabled=false;return false;}
        --*work_left;++*work_charged;return true;
    }
    void allocated_pointer(void* pointer,size_t size,size_t alignment)noexcept{
        if(!spend())return;
        if(count==max_events||allocated==max_allocations){enabled=false;overflow=true;return;}
        const auto id=allocated++;allocations[id].pointer=pointer;events[count++]={size,alignment,id,true};
    }
    void deallocated_pointer(void* pointer,size_t size,size_t alignment)noexcept{
        if(!enabled)return;
        uint32_t id=0;
        while(id<allocated){if(!spend())return;if(allocations[id].pointer==pointer)break;++id;}
        if(!spend())return;
        if(id==allocated||count==max_events){enabled=false;overflow=true;return;}
        allocations[id].pointer=nullptr;events[count++]={size,alignment,id,false};
    }
};

class RecordingResource final:public std::pmr::memory_resource {
    std::pmr::memory_resource* upstream;AllocationTrace* trace;
    void* do_allocate(size_t n,size_t alignment)override{
        void* p=upstream->allocate(n,alignment);trace->allocated_pointer(p,n,alignment);return p;
    }
    void do_deallocate(void* p,size_t n,size_t alignment)override{
        trace->deallocated_pointer(p,n,alignment);upstream->deallocate(p,n,alignment);
    }
    bool do_is_equal(const std::pmr::memory_resource& other)const noexcept override{return this==&other;}
public:
    RecordingResource(std::pmr::memory_resource* resource,AllocationTrace* log):upstream(resource),trace(log){}
};

struct ReplayState {
    struct Live {void* pointer=nullptr;size_t size=0,alignment=0;};
    std::array<Live,AllocationTrace::max_allocations> allocations{};
    std::array<uint32_t,4> release_ids{};uint32_t release_count=0;
    std::pmr::memory_resource* resource=nullptr;
    void clear()noexcept{
        if(resource){
            for(uint32_t i=0;i<release_count;++i){auto& slot=allocations[release_ids[i]];if(slot.pointer){resource->deallocate(slot.pointer,slot.size,slot.alignment);slot.pointer=nullptr;}}
            for(auto& slot:allocations)if(slot.pointer){resource->deallocate(slot.pointer,slot.size,slot.alignment);slot.pointer=nullptr;}
        }
        release_count=0;resource=nullptr;
    }
    ~ReplayState(){clear();}
    void replay(std::span<const AllocationTrace::Event> events,std::span<const uint32_t> releases,std::pmr::memory_resource* target){
        clear();resource=target;release_count=static_cast<uint32_t>(releases.size());
        for(uint32_t i=0;i<release_count;++i)release_ids[i]=releases[i];
        try{for(const auto& e:events){auto& slot=allocations[e.id];
            if(e.allocate){if(slot.pointer)throw std::logic_error("duplicate allocation replay");slot={resource->allocate(e.size,e.alignment),e.size,e.alignment};}
            else{if(!slot.pointer||slot.size!=e.size||slot.alignment!=e.alignment)throw std::logic_error("invalid allocation replay");resource->deallocate(slot.pointer,slot.size,slot.alignment);slot.pointer=nullptr;}
        }}catch(...){clear();throw;}
    }
};

struct SharedFactsProfile {uint64_t physical_collects=0,cache_hits=0,cache_builds=0,trace_overflows=0,cache_rejections=0,replay_failures=0,cache_work_charged=0;};
// Bound to one immutable DatasetView invocation. A separate bounded arena is
// explicitly reserved by the caller; never use the rule scratch resource as
// the cache arena. This type is internal, not a public or persistent cache.
class FactsCache {
    struct Entry {
        uint32_t source=0,method=0,demand=0,capabilities=0;
        bool explicit_scope=false,graph=false,graph_explicit_scope=false,scope_complete=false;
        std::string_view profile;
        std::pmr::vector<std::string_view> slots,graph_slots;
        std::pmr::vector<AllocationTrace::Event> trace;
        std::array<uint32_t,4> release_ids{};uint32_t release_count=0;
        facts::MethodFacts facts;
        explicit Entry(std::pmr::memory_resource* r):slots(r),graph_slots(r),trace(r),facts(r){}
    };
    std::span<const SourceView> sources;
    std::pmr::memory_resource* arena;
    std::pmr::list<Entry> entries;
    uint64_t cache_work_left;
    cache::MethodProvider* persistent_provider=nullptr;
    bool spend(uint64_t amount)noexcept{
        if(amount>cache_work_left){cache_work_left=0;return false;}
        cache_work_left-=amount;profile_stats.cache_work_charged+=amount;return true;
    }
    static std::string_view profile(const query::Plan& p)noexcept{
        const auto id=std::string_view(p.id);
        for(auto prefix:{std::string_view("query:v1:"),std::string_view("query:v2:"),std::string_view("query:v3:"),std::string_view("query:v4:"),std::string_view("query:v6:"),std::string_view("query:v7:"),std::string_view("query:v17:")})if(id.starts_with(prefix))return prefix;
        return {};
    }
    bool key_valid(const SourceView& source,const query::Plan& plan,const query::RelNode* graph_scope)noexcept{
        constexpr uint32_t copied_demands = instructions::Demand::strings | instructions::Demand::invokes |
            instructions::Demand::fields | instructions::Demand::numeric;
        const auto prof=profile(plan);
        if(source.source_index>=sources.size()||prof.empty()||(plan.demand_mask & ~copied_demands))return false;
        if(plan.relation_root==query::none){if(graph_scope||prof=="query:v17:")return false;}
        else if((prof!="query:v3:"&&prof!="query:v17:")||!graph_scope||graph_scan_scope(plan)!=graph_scope)return false;
        const auto& bound=sources[source.source_index];
        return bound.facts==source.facts&&bound.input_index==source.input_index&&bound.source_index==source.source_index&&
               bound.bytes.data()==source.bytes.data()&&bound.bytes.size()==source.bytes.size();
    }
    bool same(const Entry& e,const SourceView& source,uint32_t method,const query::Plan& p,const query::RelNode* graph_scope,bool complete)noexcept{
        if(!spend(1))return false;
        if(e.source!=source.source_index||e.method!=method||e.demand!=p.demand_mask||e.capabilities!=p.required_capabilities||
           e.explicit_scope!=p.explicit_scope||e.profile!=profile(p)||e.slots.size()!=p.scope_slots.size()||
           e.graph!=(graph_scope!=nullptr)||e.scope_complete!=complete)return false;
        if(graph_scope&&(e.graph_explicit_scope!=graph_scope->explicit_scope||e.graph_slots.size()!=graph_scope->scope_slots.size()))return false;
        for(size_t i=0;i<e.slots.size();++i){const auto& a=e.slots[i];const auto& b=p.scope_slots[i];
            if(!spend(1)||a.size()!=b.size())return false;
            for(size_t at=0;at<a.size();++at)if(!spend(1)||a[at]!=b[at])return false;
        }
        if(graph_scope)for(size_t i=0;i<e.graph_slots.size();++i){const auto& a=e.graph_slots[i];const auto& b=graph_scope->scope_slots[i];
            if(!spend(1)||a.size()!=b.size())return false;
            for(size_t at=0;at<a.size();++at)if(!spend(1)||a[at]!=b[at])return false;
        }
        return true;
    }
public:
    // A single Scan with zero or more Filter/Label ancestors has one effective
    // scope at every evaluation point. All other graph shapes fall back.
    static const query::RelNode* single_scan_scope(const query::Plan& p)noexcept{
        if(p.relation_root==query::none||p.contains_uses||p.relation!=query::Relation::method_defs)return nullptr;
        uint32_t at=p.relation_root;size_t seen=0;
        while(at<p.relations.size()&&seen<p.relations.size()){
            const auto& node=p.relations[at];++seen;
            if(node.relation!=query::Relation::method_defs)return nullptr;
            if(node.op==query::RelOp::scan)return node.children.empty()&&seen==p.relations.size()?&node:nullptr;
            if((node.op!=query::RelOp::filter&&node.op!=query::RelOp::label)||node.children.size()!=1||node.explicit_scope||!node.scope_slots.empty())return nullptr;
            at=node.children[0];
        }
        return nullptr;
    }
    // Multiple scans are safe only when every evaluation subtree observes the
    // same declared scan scope. GroupByOwner may combine method definitions;
    // group roles, decisions and result rows are never cached.
    const query::RelNode* graph_scan_scope(const query::Plan& p)noexcept{
        if(!spend(p.relations.size()))return nullptr;
        if(const auto* one=single_scan_scope(p))return one;
        constexpr size_t max_nodes=128;
        if(p.relation_root==query::none||p.contains_uses||
           (p.relation!=query::Relation::method_defs&&p.relation!=query::Relation::class_defs)||
           p.relations.empty()||p.relations.size()>max_nodes||p.relation_root>=p.relations.size())return nullptr;
        std::array<uint32_t,max_nodes> pending{};std::array<bool,max_nodes> seen{};
        size_t count=0,visited=0;pending[count++]=p.relation_root;const query::RelNode* scope=nullptr;
        while(count){
            if(!spend(1))return nullptr;
            const auto index=pending[--count];if(index>=p.relations.size()||seen[index])return nullptr;
            seen[index]=true;++visited;const auto& node=p.relations[index];
            if(node.relation!=query::Relation::method_defs&&node.relation!=query::Relation::class_defs)return nullptr;
            if(node.op==query::RelOp::scan){
                // Restrict all leaves to method definitions: other source
                // types and mixed member groups keep the scalar path.
                if(node.relation!=query::Relation::method_defs||!node.children.empty())return nullptr;
                if(!scope)scope=&node;
                else {
                    if(scope->explicit_scope!=node.explicit_scope||scope->scope_slots.size()!=node.scope_slots.size())return nullptr;
                    for(size_t i=0;i<scope->scope_slots.size();++i){
                        const auto& a=scope->scope_slots[i];const auto& b=node.scope_slots[i];
                        if(!spend(1)||a.size()!=b.size())return nullptr;
                        for(size_t j=0;j<a.size();++j)if(!spend(1)||a[j]!=b[j])return nullptr;
                    }
                }
                continue;
            }
            if(node.explicit_scope||!node.scope_slots.empty())return nullptr;
            if(node.op==query::RelOp::union_rows){if(node.children.empty())return nullptr;}
            else if(node.op==query::RelOp::group_by_owner){
                if(node.relation!=query::Relation::class_defs||node.children.empty())return nullptr;
                for(const auto child:node.children)
                    if(child>=p.relations.size()||p.relations[child].relation!=query::Relation::method_defs)return nullptr;
            }
            else if(node.op==query::RelOp::filter||node.op==query::RelOp::label||node.op==query::RelOp::distinct){
                if(node.children.size()!=1)return nullptr;
            }else return nullptr;
            if(node.children.size()>max_nodes-count)return nullptr;
            for(const auto child:node.children)pending[count++]=child;
        }
        return visited==p.relations.size()?scope:nullptr;
    }
    const query::RelNode* admit_graph(const query::Plan& plan)noexcept{
        return graph_scan_scope(plan);
    }
    AllocationTrace recording;
    ReplayState replay;
    SharedFactsProfile profile_stats;
    FactsCache(std::span<const SourceView> snapshot_sources,std::pmr::memory_resource* cache_arena,uint64_t max_cache_work,cache::MethodProvider* persistent=nullptr):sources(snapshot_sources),arena(cache_arena),entries(cache_arena),cache_work_left(max_cache_work),persistent_provider(persistent){}
    cache::MethodProvider* method_provider()const noexcept{return persistent_provider;}
    const facts::MethodFacts* find(const SourceView& source,uint32_t method,const query::Plan& plan,uint64_t remaining,std::pmr::memory_resource* rule_memory,const query::RelNode* graph_scope=nullptr,bool complete=false){
        if(persistent_provider||!key_valid(source,plan,graph_scope)||!cache_work_left)return nullptr;
        for(const auto& e:entries){if(!cache_work_left)break;if(same(e,source,method,plan,graph_scope,complete)){
            // With insufficient logical work, rerun the decoder so its exact
            // budget/error ordering and offset remain the scalar behavior.
            if(e.facts.validation_work>remaining){++profile_stats.cache_rejections;return nullptr;}
            // Reserve a conservative bound for the replay loop and all
            // possible cleanup slots, including allocation-failure unwind.
            if(!spend(uint64_t(e.trace.size())+AllocationTrace::max_allocations+4)){++profile_stats.cache_rejections;return nullptr;}
            try{replay.replay(e.trace,std::span(e.release_ids).first(e.release_count),rule_memory);}
            catch(...){++profile_stats.replay_failures;throw;}
            ++profile_stats.cache_hits;return &e.facts;
        }}
        return nullptr;
    }
    bool can_record(const SourceView& source,const query::Plan& plan,const query::RelNode* graph_scope=nullptr)noexcept{
        return !persistent_provider&&key_valid(source,plan,graph_scope)&&plan.demand_mask&&cache_work_left&&entries.size()<256;
    }
    void begin_recording()noexcept{recording.reset(&cache_work_left,&profile_stats.cache_work_charged);}
    void discard_recording()noexcept{
        recording.enabled=false;
    }
    void publish(const SourceView& source,uint32_t method,const query::Plan& plan,const facts::MethodFacts& value,const query::RelNode* graph_scope=nullptr,bool complete=false)noexcept{
        if(!key_valid(source,plan,graph_scope))return;
        if(!recording.enabled){if(recording.overflow)++profile_stats.trace_overflows;else ++profile_stats.cache_rejections;return;}
        if(!cache_work_left){++profile_stats.cache_rejections;return;}
        if(entries.size()>=256){++profile_stats.cache_rejections;return;}
        std::array<uint32_t,4> release_ids{};uint32_t release_count=0;
        auto release=[&](const void* pointer,size_t capacity){
            if(!capacity)return true;
            for(uint32_t i=0;i<recording.allocated;++i){if(!spend(1))return false;if(recording.allocations[i].pointer==pointer){release_ids[release_count++]=i;return true;}}
            return false;
        };
        // MethodFacts destroys its PMR vectors in reverse declaration order.
        if(!release(value.numeric_literals.data(),value.numeric_literals.capacity())||!release(value.field_uses.data(),value.field_uses.capacity())||
           !release(value.invoke_sites.data(),value.invoke_sites.capacity())||!release(value.string_uses.data(),value.string_uses.capacity())){++profile_stats.cache_rejections;return;}
        uint32_t active=0;for(uint32_t i=0;i<recording.allocated;++i){if(!spend(1)){++profile_stats.cache_rejections;return;}if(recording.allocations[i].pointer)++active;}
        if(active!=release_count){++profile_stats.cache_rejections;return;}
        uint64_t copy_work=uint64_t(recording.count)+16;
        for(const auto amount:{plan.scope_slots.size(),graph_scope?graph_scope->scope_slots.size():size_t(0),value.string_uses.size(),value.invoke_sites.size(),value.field_uses.size(),value.numeric_literals.size()}){
            if(amount>UINT64_MAX-copy_work){++profile_stats.cache_rejections;return;}copy_work+=amount;
        }
        if(!spend(copy_work)){++profile_stats.cache_rejections;return;}
        try{
            entries.emplace_back(arena);auto& e=entries.back();
            try{
                e.source=source.source_index;e.method=method;e.demand=plan.demand_mask;e.capabilities=plan.required_capabilities;
                e.explicit_scope=plan.explicit_scope;e.profile=profile(plan);e.graph=graph_scope!=nullptr;e.scope_complete=complete;
                if(graph_scope)e.graph_explicit_scope=graph_scope->explicit_scope;
                e.slots.reserve(plan.scope_slots.size());for(const auto& slot:plan.scope_slots)e.slots.push_back(slot);
                if(graph_scope){e.graph_slots.reserve(graph_scope->scope_slots.size());for(const auto& slot:graph_scope->scope_slots)e.graph_slots.push_back(slot);}
                e.trace.assign(recording.events.begin(),recording.events.begin()+recording.count);e.release_ids=release_ids;e.release_count=release_count;
                e.facts.method_index=value.method_index;e.facts.code_offset=value.code_offset;e.facts.has_body=value.has_body;
                e.facts.instruction_checked=value.instruction_checked;e.facts.decoded_code_units=value.decoded_code_units;e.facts.validation_work=value.validation_work;e.facts.requested_mask=value.requested_mask;
                e.facts.string_uses.assign(value.string_uses.begin(),value.string_uses.end());e.facts.invoke_sites.assign(value.invoke_sites.begin(),value.invoke_sites.end());
                e.facts.field_uses.assign(value.field_uses.begin(),value.field_uses.end());e.facts.numeric_literals.assign(value.numeric_literals.begin(),value.numeric_literals.end());
            }catch(...){entries.pop_back();throw;}
            ++profile_stats.cache_builds;
        }catch(...){++profile_stats.cache_rejections;}
    }
};
}
