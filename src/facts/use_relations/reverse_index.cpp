#include "reverse_index.hpp"
#include <algorithm>
#include <chrono>
#include <limits>
#include <tuple>

namespace dexmeguviz::facts {
namespace {
void checked(UseScanCancel c){if(c.requested&&c.requested(c.context))throw UseScanError(UseScanError::Code::cancelled,"reverse lookup cancelled");}
void increment(uint64_t& v)noexcept{if(v!=std::numeric_limits<uint64_t>::max())++v;}
void charge(uint64_t& work,uint64_t limit){if(work>=limit)throw UseScanError(UseScanError::Code::budget,"reverse work limit exceeded");++work;}
auto key(const UseRecord& r){return std::tuple{static_cast<uint32_t>(r.target_domain),r.target_index,r.extra_proto};}
auto key(ReverseKey k){return std::tuple{static_cast<uint32_t>(k.domain),k.target_index,k.extra_proto};}
ReversePage select_rows(const std::pmr::vector<UseRecord>& rows,ReverseKey target,uint64_t offset,uint32_t capacity,
    bool include_page,uint64_t& work,uint64_t limit,UseScanCancel cancel,std::pmr::memory_resource* scratch){
    checked(cancel);const auto targetKey=key(target);
    auto first=std::lower_bound(rows.begin(),rows.end(),targetKey,[&](const UseRecord& x,const auto& y){charge(work,limit);checked(cancel);return key(x)<y;});
    auto last=std::upper_bound(first,rows.end(),targetKey,[&](const auto& x,const UseRecord& y){charge(work,limit);checked(cancel);return x<key(y);});
    ReversePage result(scratch);result.total=static_cast<uint64_t>(last-first);
    if(include_page){
        if(offset>result.total)throw UseScanError(UseScanError::Code::invalid,"reverse page offset exceeds result count");
        const auto available=result.total-offset;
        const auto count=static_cast<uint32_t>(std::min<uint64_t>(available,capacity));
        result.rows.reserve(count);
        auto pos=first+static_cast<std::ptrdiff_t>(offset);
        for(uint32_t i=0;i<count;++i,++pos){
            charge(work,limit);checked(cancel);const auto& r=*pos;
            result.rows.push_back({r.key.source_index,static_cast<uint32_t>(r.key.kind),r.key.caller_ordinal,r.caller_method_ref,
                r.key.dex_pc,r.opcode,r.code_offset,static_cast<uint32_t>(r.target_domain),r.target_index,r.extra_proto});
        }
    }
    checked(cancel);return result;
}
}
ReverseStats ReverseRegistry::profile(){std::lock_guard lock(mutex_);return stats_;}
ReversePage ReverseRegistry::select(std::span<const uint8_t> bytes,const Facts& metadata,uint32_t source_index,UseKind kind,
    ReverseKey target,uint64_t offset,uint32_t capacity,bool include_page,ReverseLimits limits,UseScanCancel cancel,cache::MethodProvider* provider){
    if((include_page&&capacity>4096)||!limits.max_work||!limits.max_records||!limits.max_index_bytes||limits.max_work>100'000'000||limits.max_records>100'000)
        throw UseScanError(UseScanError::Code::invalid,"invalid reverse limits");
    checked(cancel);std::unique_lock<std::timed_mutex> lock(mutex_,std::defer_lock);
    while(!lock.try_lock_for(std::chrono::milliseconds(5)))checked(cancel);
    checked(cancel);
    uint64_t lookup_work=0;auto found=entries_.end();
    for(auto it=entries_.begin();it!=entries_.end();++it){
        charge(lookup_work,limits.max_work);checked(cancel);
        if(it->source_index==source_index&&it->kind==kind){found=it;break;}
    }
    if(found!=entries_.end()){
        const uint64_t bytes_required=static_cast<uint64_t>(found->rows.size())*sizeof(UseRecord);
        if(found->rows.size()>limits.max_records||bytes_required>limits.max_index_bytes||found->work>limits.max_work-lookup_work)
            throw UseScanError(UseScanError::Code::budget,"cached reverse index exceeds request limits");
        auto work=lookup_work+found->work;auto answer=select_rows(found->rows,target,offset,capacity,include_page,work,limits.max_work,cancel,scratch_);
        increment(stats_.reuses);return answer;
    }
    if(lookup_work>=limits.max_work)throw UseScanError(UseScanError::Code::budget,"reverse registry work limit exceeded");
    increment(stats_.attempts);
    try{
        UseScanProgress progress{};auto result=collect_uses(bytes,metadata,source_index,kind,progress,scratch_,{limits.max_work-lookup_work,limits.max_records},cancel,{},provider);
        const uint64_t bytes_required=static_cast<uint64_t>(result.rows.size())*sizeof(UseRecord);
        if(bytes_required>limits.max_index_bytes)throw UseScanError(UseScanError::Code::budget,"reverse index byte limit exceeded");
        Entry candidate(source_index,kind,facts_);candidate.rows.reserve(result.rows.size());uint64_t work=lookup_work+progress.work_units;
        for(const auto& row:result.rows){charge(work,limits.max_work);checked(cancel);candidate.rows.push_back(row);}
        std::sort(candidate.rows.begin(),candidate.rows.end(),[&](const UseRecord& a,const UseRecord& b){
            charge(work,limits.max_work);checked(cancel);
            return std::tuple{key(a),a.key.caller_ordinal,a.key.dex_pc,a.opcode,a.caller_method_ref,a.code_offset}
                 < std::tuple{key(b),b.key.caller_ordinal,b.key.dex_pc,b.opcode,b.caller_method_ref,b.code_offset};
        });
        // The current request pays registry probing, target lookup and page
        // copying, but those request-specific costs must not contaminate the
        // reusable construction cost paid by later lookups.
        const auto construction_work=work-lookup_work;
        auto answer=select_rows(candidate.rows,target,offset,capacity,include_page,work,limits.max_work,cancel,scratch_);
        charge(work,limits.max_work);checked(cancel);candidate.work=construction_work+1;
        entries_.push_back(std::move(candidate));increment(stats_.builds);increment(stats_.published);
        const auto total=static_cast<uint64_t>(entries_.back().rows.size());
        stats_.records=total>std::numeric_limits<uint64_t>::max()-stats_.records?std::numeric_limits<uint64_t>::max():stats_.records+total;
        return answer;
    }catch(...){increment(stats_.failures);throw;}
}
uint64_t ReverseRegistry::lookup(std::span<const uint8_t> bytes,const Facts& metadata,uint32_t source_index,UseKind kind,
    ReverseKey target,ReverseLimits limits,UseScanCancel cancel,cache::MethodProvider* provider){
    return select(bytes,metadata,source_index,kind,target,0,0,false,limits,cancel,provider).total;
}
ReversePage ReverseRegistry::page(std::span<const uint8_t> bytes,const Facts& metadata,uint32_t source_index,UseKind kind,
    ReverseKey target,uint64_t offset,uint32_t capacity,ReverseLimits limits,UseScanCancel cancel,cache::MethodProvider* provider){
    return select(bytes,metadata,source_index,kind,target,offset,capacity,true,limits,cancel,provider);
}
}
