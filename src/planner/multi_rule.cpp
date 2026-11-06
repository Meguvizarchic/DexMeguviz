#include "multi_rule.hpp"
#include "execution/budget/account.hpp"
#include <algorithm>
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace dexmeguviz::planner {
namespace {
bool overlaps(std::span<std::byte> cache,const void* pointer,size_t length){
    if(cache.empty()||length==0)return false;
    if(!cache.data()||!pointer)throw std::invalid_argument("null nonempty range");
    const auto a=reinterpret_cast<uintptr_t>(cache.data()),b=reinterpret_cast<uintptr_t>(pointer);
    const auto limit=std::numeric_limits<uintptr_t>::max();
    if(cache.size()>limit-a||length>limit-b)throw std::invalid_argument("address range overflow");
    return a<b+length&&b<a+cache.size();
}
template<class T> void reject_overlap(std::span<std::byte> cache,const T* pointer,size_t count){
    if(count>std::numeric_limits<size_t>::max()/sizeof(T))throw std::invalid_argument("range length overflow");
    if(overlaps(cache,pointer,count*sizeof(T)))throw std::invalid_argument("cache overlaps protected input");
}
OutcomeCode query_status(query::ErrorCode code)noexcept{
    switch(code){case query::ErrorCode::invalid:return OutcomeCode::invalid;case query::ErrorCode::unsupported:return OutcomeCode::unsupported;
    case query::ErrorCode::budget:return OutcomeCode::budget;case query::ErrorCode::cancelled:return OutcomeCode::cancelled;case query::ErrorCode::source_mismatch:return OutcomeCode::source_mismatch;}
    return OutcomeCode::internal;
}
OutcomeCode decoder_status(instructions::DecodeCode code)noexcept{
    switch(code){case instructions::DecodeCode::corrupt:return OutcomeCode::corrupt;case instructions::DecodeCode::unsupported:return OutcomeCode::unsupported;
    case instructions::DecodeCode::budget:return OutcomeCode::budget;case instructions::DecodeCode::cancelled:return OutcomeCode::cancelled;}
    return OutcomeCode::internal;
}
}
MultiResult execute(const reference::DatasetView& dataset,std::span<const Rule> rules,
    std::pmr::memory_resource* coordinator,std::span<std::byte> reserved_cache,uint64_t max_cache_work,bool fused_methods){
    if(!coordinator||rules.size()>256)throw std::invalid_argument("invalid multi-rule request");
    reject_overlap(reserved_cache,dataset.sources.data(),dataset.sources.size());
    reject_overlap(reserved_cache,dataset.input_slots.data(),dataset.input_slots.size());
    reject_overlap(reserved_cache,rules.data(),rules.size());
    for(const auto& source:dataset.sources){
        reject_overlap(reserved_cache,source.bytes.data(),source.bytes.size());
        if(source.facts)reject_overlap(reserved_cache,source.facts,1);
    }
    for(const auto slot:dataset.input_slots)reject_overlap(reserved_cache,slot.data(),slot.size());
    for(size_t i=0;i<rules.size();++i){
        const auto& r=rules[i];if(!r.plan||!r.memory||r.rule_id.empty()||r.rule_id.size()>256)throw std::invalid_argument("invalid multi-rule entry");
        reject_overlap(reserved_cache,r.rule_id.data(),r.rule_id.size());
        reject_overlap(reserved_cache,r.plan,1);
        reject_overlap(reserved_cache,r.plan->id.data(),r.plan->id.size());
        reject_overlap(reserved_cache,r.memory,1);
        for(size_t j=0;j<i;++j)if(rules[j].rule_id==r.rule_id)throw std::invalid_argument("duplicate rule id");
    }
    MultiResult out(coordinator);
    if(rules.empty())return out;
    out.rules.reserve(rules.size());
    for(const auto& r:rules){out.rules.emplace_back(coordinator);out.rules.back().rule_id.assign(r.rule_id);}
    std::pmr::monotonic_buffer_resource arena(reserved_cache.data(),reserved_cache.size(),std::pmr::null_memory_resource());
    const bool enabled=!reserved_cache.empty()&&max_cache_work!=0;
    std::optional<reference::FactsCache> cache;
    if(enabled)try{cache.emplace(dataset.sources,&arena,max_cache_work);}catch(const std::bad_alloc&){}
    if(fused_methods&&std::all_of(rules.begin(),rules.end(),[](const auto& r){return !r.cancel.requested&&r.allocation_replay_safe;})){
        std::pmr::vector<reference::FusedMethodLane> lanes(coordinator);lanes.reserve(rules.size());
        for(size_t i=0;i<rules.size();++i){out.rules[i].result.emplace(rules[i].memory);lanes.push_back({rules[i].plan,&out.rules[i].progress,&*out.rules[i].result,rules[i].memory,{}});}
        if(reference::execute_fused_methods(dataset,lanes,cache?&*cache:nullptr)){
            out.fused_methods_used=true;
            for(size_t i=0;i<lanes.size();++i){auto& dst=out.rules[i];
                if(!lanes[i].error){dst.code=OutcomeCode::result_available;continue;}
                dst.result.reset();
                try{std::rethrow_exception(lanes[i].error);}
                catch(const query::Error& e){dst.code=query_status(e.code);}
                catch(const instructions::DecodeError& e){dst.code=decoder_status(e.code);dst.error_offset=e.dex_offset;dst.error_pc=e.dex_pc;}
                catch(const ReadError& e){dst.error_offset=e.offset;dst.code=e.code==ReadCode::budget?OutcomeCode::budget:e.code==ReadCode::unsupported?OutcomeCode::unsupported:OutcomeCode::corrupt;}
                catch(const facts::UseScanError& e){switch(e.code){case facts::UseScanError::Code::invalid:dst.code=OutcomeCode::invalid;break;case facts::UseScanError::Code::unsupported:dst.code=OutcomeCode::unsupported;break;case facts::UseScanError::Code::budget:dst.code=OutcomeCode::budget;break;case facts::UseScanError::Code::cancelled:dst.code=OutcomeCode::cancelled;break;}}
                catch(const BudgetExceeded&){dst.code=OutcomeCode::budget;}
                catch(const std::bad_alloc&){dst.code=OutcomeCode::out_of_memory;}
                catch(...){dst.code=OutcomeCode::internal;}
            }
            if(cache)out.shared=cache->profile_stats;return out;
        }
        for(auto& lane:out.rules)lane.result.reset();
    }
    for(size_t i=0;i<rules.size();++i){
        const auto& r=rules[i];auto& dst=out.rules[i];
        try{
            auto result=reference::execute(dataset,*r.plan,dst.progress,r.memory,r.cancel,{},cache&&r.allocation_replay_safe?&*cache:nullptr);
            dst.result.emplace(std::move(result));dst.code=OutcomeCode::result_available;
        }catch(const query::Error& e){dst.code=query_status(e.code);}
         catch(const instructions::DecodeError& e){dst.code=decoder_status(e.code);dst.error_offset=e.dex_offset;dst.error_pc=e.dex_pc;}
         catch(const ReadError& e){dst.error_offset=e.offset;dst.code=e.code==ReadCode::budget?OutcomeCode::budget:e.code==ReadCode::unsupported?OutcomeCode::unsupported:OutcomeCode::corrupt;}
         catch(const facts::UseScanError& e){switch(e.code){case facts::UseScanError::Code::invalid:dst.code=OutcomeCode::invalid;break;case facts::UseScanError::Code::unsupported:dst.code=OutcomeCode::unsupported;break;case facts::UseScanError::Code::budget:dst.code=OutcomeCode::budget;break;case facts::UseScanError::Code::cancelled:dst.code=OutcomeCode::cancelled;break;}}
         catch(const BudgetExceeded&){dst.code=OutcomeCode::budget;}
         catch(const std::bad_alloc&){dst.code=OutcomeCode::out_of_memory;}
         catch(...){dst.code=OutcomeCode::internal;}
    }
    if(cache)out.shared=cache->profile_stats;return out;
}
}
