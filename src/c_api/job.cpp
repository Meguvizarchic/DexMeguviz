#include "runtime.hpp"
#ifdef DMG_TEST_JOB_COMMIT_BARRIER
#include <system_error>
#endif
using namespace dexmeguviz;
using namespace dexmeguviz::runtime;
#ifdef DMG_TEST_JOB_COMMIT_BARRIER
namespace dexmeguviz::runtime {
std::atomic<void(*)(uint32_t)> test_job_commit_barrier{nullptr};
std::atomic<bool> test_job_cancel_lock_failure{false};
std::atomic<void(*)()> test_job_queue_wait_barrier{nullptr};
std::atomic<void(*)(uint32_t)> test_job_scan_barrier{nullptr};
#ifdef DMG_TEST_UNIQUE_ONE_STREAM
std::atomic<void(*)(uint32_t)> test_unique_one_publish_barrier{nullptr};
std::atomic<bool> test_unique_one_queue_allocation_failed{false};
std::atomic<bool> test_unique_one_binding_allocation_failed{false};
std::atomic<void(*)()> test_unique_one_terminal_locked{nullptr};
std::atomic<void(*)()> test_unique_one_cancel_enter{nullptr};
#endif
}
#endif
namespace {
void expand_worker(std::shared_ptr<JobState> job,size_t slot)noexcept{
    dmg_result_info info{};initial(info,*job->dataset,*job->query);dmg_error error{};
    reference::Progress progress;ResultOwner pending;bool result_limit=false;
    auto status=guard([&]()->dmg_status{
        {std::lock_guard lock(job->mutex);job->status.lifecycle=DMG_JOB_RUNNING;}job->changed.notify_all();
#ifdef DMG_TEST_ALLOC_FAILURES
        if(const auto hook=test_expand_commit_hook.load(std::memory_order_acquire))hook(0);
#endif
        job->control.check();
        auto evaluated=evaluate_query(*job->dataset,*job->query,progress,job->control,&job->engine->scratch_resource);
        result_limit=evaluated.result_limit;
        pending.reset(handle<dmg_result>(job->engine,job->dataset,job->query));
#ifdef DMG_TEST_ALLOC_FAILURES
        const auto fail_at=test_expand_fail_materialization_after.load(std::memory_order_acquire);
        if(fail_at>=0)test_fail_allocation_after(fail_at);
#endif
        pending->scope_sources.assign(evaluated.scope_sources.begin(),evaluated.scope_sources.end());
        for(const auto& candidate:evaluated.rows){job->control.check();
            auto value=materialize_value(*job->dataset,evaluated,candidate.key(),&job->engine->result_resource,job->control,job->query->plan->projection);
            pending->rows.emplace_back(std::move(value),&job->engine->result_resource,row_evidence(*job->query->plan,candidate));
            materialize_bindings(pending->rows.back(),*job->dataset,evaluated,candidate,&job->engine->result_resource,job->control);
            materialize_expand_paths(pending->rows.back(),*job->dataset,evaluated,candidate,&job->engine->result_resource,job->control);
        }
        materialize_expand_frontiers(pending->expand_frontiers,*job->dataset,evaluated,&job->engine->result_resource,job->control);
        copy_graph(progress,pending->graph);pending->unknown_rows=progress.profile.unknown_rows;
        fill_query_profile(progress,progress.scope_source_count,&pending->profile);job->control.check();return DMG_OK;
    },&error);
#ifdef DMG_TEST_ALLOC_FAILURES
    test_fail_allocation_after(-1);
    if(const auto hook=test_expand_commit_hook.load(std::memory_order_acquire))hook(1);
#endif
    // Admission protects engine shutdown from racing the final cancellation
    // check and the atomic success/aggregate commit. No batch is visible yet.
    {std::lock_guard admission(job->engine->admission);std::lock_guard lock(job->mutex);
        if(status==DMG_OK)status=guard([&]()->dmg_status{job->control.check();return DMG_OK;},&error);
        info.total_methods=progress.total;info.visited_methods=progress.visited;info.execution_status=status==DMG_OK&&result_limit?DMG_BUDGET_EXCEEDED:status;
        if(status==DMG_OK&&result_limit)info.reason=DMG_RESULT_LIMIT;
        info.candidates_count=status==DMG_OK?static_cast<uint32_t>(pending->rows.size()):0;
        finalize(info,*job->query,progress.scope_complete,progress.profile.unknown_rows,progress.scope_derived_unknown);
        fill_query_profile(progress,progress.scope_source_count,&job->profile);job->unknown_rows=progress.profile.unknown_rows;copy_graph(progress,job->graph);
        if(status!=DMG_OK)pending.reset();
        progress.graph.reset();
        if(status==DMG_OK){pending->info=info;job->committed_expand=std::move(pending);}
        job->status.lifecycle=status==DMG_OK?DMG_JOB_COMPLETED:(status==DMG_CANCELLED?DMG_JOB_CANCELLED:DMG_JOB_FAILED);
        job->status.terminal=1;job->status.outcome=info;job->status.error=error;
        job->engine->jobs[slot].reset();--job->engine->active_jobs;
    }
    job->changed.notify_all();
#ifdef DMG_TEST_ALLOC_FAILURES
    if(const auto hook=test_expand_after_terminal_hook.load(std::memory_order_acquire))hook();
#endif
}
void publish(const std::shared_ptr<JobState>& job,ResultOwner& batch,dmg_result_info& info,const reference::Progress* progress=nullptr){
    if(!batch||batch->rows.empty())return;
    std::unique_lock lock(job->mutex);
    while(job->queue.size()>=job->options.max_queued_batches){
        job->control.check();
#ifdef DMG_TEST_JOB_COMMIT_BARRIER
        if(const auto barrier=test_job_queue_wait_barrier.load(std::memory_order_acquire))barrier();
#endif
        // shutdown and the exceptional cancel fallback can notify without
        // this mutex; periodically recheck in case that notification is lost.
        using Clock=std::chrono::steady_clock;
        const auto quantum=std::chrono::duration_cast<Clock::duration>(std::chrono::milliseconds(50));
        const auto now=Clock::now();
        const auto next=now>Clock::time_point::max()-quantum?Clock::time_point::max():now+quantum;
        job->changed.wait_until(lock,std::min(next,job->control.deadline));
    }
    job->control.check();
    batch->info=info;batch->info.coverage=DMG_COVERAGE_PARTIAL;batch->info.decision=DMG_NOT_APPLICABLE;
    batch->info.candidates_count=static_cast<uint32_t>(batch->rows.size());
    const auto count=batch->info.candidates_count;
#if defined(DMG_TEST_UNIQUE_ONE_STREAM) && defined(DMG_TEST_JOB_COMMIT_BARRIER)
    if(reference::unique_one_stream_shape(*job->query->plan))if(const auto hook=test_unique_one_publish_barrier.load(std::memory_order_acquire))hook(4);
#endif
    try{job->queue.push_back(std::move(batch));}
    catch(const std::bad_alloc&){
#if defined(DMG_TEST_UNIQUE_ONE_STREAM) && defined(DMG_TEST_JOB_COMMIT_BARRIER)
        test_unique_one_queue_allocation_failed.store(true,std::memory_order_release);
#endif
        throw;
    }
    info.candidates_count+=count;job->status.outcome=info;
    if(progress){fill_query_profile(*progress,progress->scope_source_count,&job->profile);job->unknown_rows=progress->profile.unknown_rows;copy_graph(*progress,job->graph);}
    lock.unlock();job->changed.notify_all();
}
void worker(std::shared_ptr<JobState> job,size_t slot)noexcept{
    if(job->query->plan->contains_expand){expand_worker(std::move(job),slot);return;}
    dmg_result_info info{};initial(info,*job->dataset,*job->query);dmg_error error{};
    reference::Progress progress;
    bool pending_unique_one_limit=false;
    auto status=guard([&]()->dmg_status{
        {std::lock_guard lock(job->mutex);job->status.lifecycle=DMG_JOB_RUNNING;}
        job->changed.notify_all();job->control.check();ResultOwner batch;
        const auto deliver=[&](const reference::Result& evaluated,const reference::Candidate& candidate,const reference::Progress& current){
#if defined(DMG_TEST_UNIQUE_ONE_STREAM) && defined(DMG_TEST_JOB_COMMIT_BARRIER)
            if(reference::unique_one_stream_shape(*job->query->plan))if(const auto hook=test_unique_one_publish_barrier.load(std::memory_order_acquire))hook(1);
#endif
            job->control.check();auto value=materialize_value(*job->dataset,evaluated,candidate.key(),&job->engine->result_resource,job->control,job->query->plan->projection);
#if defined(DMG_TEST_UNIQUE_ONE_STREAM) && defined(DMG_TEST_JOB_COMMIT_BARRIER)
            if(reference::unique_one_stream_shape(*job->query->plan))if(const auto hook=test_unique_one_publish_barrier.load(std::memory_order_acquire))hook(2);
#endif
            if(!batch){batch.reset(handle<dmg_result>(job->engine,job->dataset,job->query));batch->scope_sources.assign(evaluated.scope_sources.begin(),evaluated.scope_sources.end());fill_query_profile(current,current.scope_source_count,&batch->profile);batch->unknown_rows=current.profile.unknown_rows;copy_graph(current,batch->graph);}
#if defined(DMG_TEST_UNIQUE_ONE_STREAM) && defined(DMG_TEST_JOB_COMMIT_BARRIER)
            if(reference::unique_one_stream_shape(*job->query->plan))if(const auto hook=test_unique_one_publish_barrier.load(std::memory_order_acquire))hook(3);
#endif
            batch->rows.emplace_back(std::move(value),&job->engine->result_resource,candidate.witnesses);
#if defined(DMG_TEST_UNIQUE_ONE_STREAM) && defined(DMG_TEST_JOB_COMMIT_BARRIER)
            if(const auto hook=test_unique_one_publish_barrier.load(std::memory_order_acquire))hook(5);
#endif
#if defined(DMG_TEST_UNIQUE_ONE_STREAM) && defined(DMG_TEST_JOB_COMMIT_BARRIER)
            try{materialize_bindings(batch->rows.back(),*job->dataset,evaluated,candidate,&job->engine->result_resource,job->control);}
            catch(const std::bad_alloc&){if(!candidate.bindings.empty())test_unique_one_binding_allocation_failed.store(true,std::memory_order_release);throw;}
#else
            materialize_bindings(batch->rows.back(),*job->dataset,evaluated,candidate,&job->engine->result_resource,job->control);
#endif
            if(batch->rows.size()>=job->options.batch_size){info.total_methods=current.total;info.visited_methods=current.visited;publish(job,batch,info,&current);}
        };
        const auto& plan=*job->query->plan;
        const bool streaming=reference::can_stream(plan);
        // Exists/Unique need each completed witness immediately, even when
        // the configured maximum batch size is larger than one.
        const auto stream_delivery=[&](const reference::Result& r,const reference::Candidate& c,const reference::Progress& p){
            info.total_methods=p.total;info.visited_methods=p.visited;deliver(r,c,p);publish(job,batch,info,&p);
#ifdef DMG_TEST_JOB_COMMIT_BARRIER
            if(const auto barrier=test_job_scan_barrier.load(std::memory_order_acquire))barrier(info.candidates_count);
#endif
        };
        reference::CandidateSink sink{};
        if(streaming){sink.context=const_cast<void*>(static_cast<const void*>(&stream_delivery));
            sink.accept=[](void* context,const reference::Result& r,const reference::Candidate& c,const reference::Progress& p){(*static_cast<decltype(stream_delivery)*>(context))(r,c,p);};}
        auto evaluated=evaluate_query(*job->dataset,*job->query,progress,job->control,&job->engine->scratch_resource,sink);
        // Retain the actual selected occurrence list for successful scoped
        // annotation Jobs, including zero-result and zero-source runs.
        if(job->query->plan->class_annotation_requested&&job->query->plan->explicit_scope){
            if(!progress.scope_complete||evaluated.scope_sources.size()!=progress.scope_source_count)
                throw query::Error(query::ErrorCode::invalid,"scoped annotation source count mismatch");
            std::pmr::vector<uint32_t> selected(&job->engine->control_resource);
            selected.assign(evaluated.scope_sources.begin(),evaluated.scope_sources.end());
            job->control.check();
            std::lock_guard lock(job->mutex);job->terminal_scope_sources.emplace(std::move(selected));
        }
        info.total_methods=progress.total;info.visited_methods=progress.visited;
        {std::lock_guard lock(job->mutex);fill_query_profile(progress,progress.scope_source_count,&job->profile);job->unknown_rows=progress.profile.unknown_rows;copy_graph(progress,job->graph);}
        if(!streaming)for(const auto& candidate:evaluated.rows)deliver(evaluated,candidate,progress);
        publish(job,batch,info);
        pending_unique_one_limit=evaluated.unique_one_limit_pending;
        if(evaluated.result_limit){info.reason=DMG_RESULT_LIMIT;return DMG_BUDGET_EXCEEDED;}return DMG_OK;
    },&error);
#ifdef DMG_TEST_JOB_COMMIT_BARRIER
    if(const auto barrier=test_job_commit_barrier.load(std::memory_order_acquire))barrier(info.candidates_count);
#endif
    // Admission and job mutex jointly linearize shutdown/cancel against the
    // terminal commit. Previously published batches remain provisional.
    {std::lock_guard admission(job->engine->admission);std::lock_guard lock(job->mutex);
        if(status==DMG_OK)status=guard([&]()->dmg_status{job->control.check();return DMG_OK;},&error);
        // Until this lock-protected point the tentative limit is not a final
        // outcome; an observed cancellation/deadline wins before commitment.
        if(status==DMG_OK&&pending_unique_one_limit){
#if defined(DMG_TEST_UNIQUE_ONE_STREAM) && defined(DMG_TEST_JOB_COMMIT_BARRIER)
            if(const auto hook=test_unique_one_terminal_locked.load(std::memory_order_acquire))hook();
#endif
            status=DMG_BUDGET_EXCEEDED;info.reason=DMG_RESULT_LIMIT;
        }
        info.total_methods=progress.total;info.visited_methods=progress.visited;
        info.execution_status=status;finalize(info,*job->query,progress.scope_complete,progress.profile.unknown_rows,progress.scope_derived_unknown);
        job->status.lifecycle=status==DMG_OK?DMG_JOB_COMPLETED:(status==DMG_CANCELLED?DMG_JOB_CANCELLED:DMG_JOB_FAILED);
        job->status.terminal=1;job->status.outcome=info;job->status.error=error;
        fill_query_profile(progress,progress.scope_source_count,&job->profile);job->unknown_rows=progress.profile.unknown_rows;copy_graph(progress,job->graph);
        // Reset weak control-block ownership before dropping the worker reference.
        job->engine->jobs[slot].reset();--job->engine->active_jobs;
    }
    job->changed.notify_all();
}
}
extern "C" {
dmg_status dmg_job_start(dmg_snapshot* snapshot,dmg_query* query,const dmg_job_options* options,dmg_job** out,dmg_error* error){
    if(out)*out=nullptr;
    return guard([&]()->dmg_status{
        if(!snapshot||!query||!out||snapshot->owner!=query->owner)return DMG_INVALID_ARGUMENT;
        if(query->query->plan->required_capabilities&268435456u)return DMG_UNSUPPORTED;
        const dmg_job_options fallback{sizeof(dmg_job_options),DMG_ABI_VERSION,64,2,0};const auto& o=options?*options:fallback;
        if(o.struct_size!=sizeof(o)||o.abi_version!=DMG_ABI_VERSION||!o.batch_size||o.batch_size>4096||!o.max_queued_batches||o.max_queued_batches>16||o.deadline_after_ms>86400000)return DMG_INVALID_ARGUMENT;
        const auto e=snapshot->owner;std::lock_guard lock(e->admission);
        if(e->closed||snapshot->closed.load(std::memory_order_acquire))return DMG_CLOSED;
        if(e->active_jobs>=e->max_jobs)return DMG_BUDGET_EXCEEDED;
        size_t slot=0;while(slot<e->jobs.size()&&!e->jobs[slot].expired())++slot;
        if(slot==e->jobs.size())return DMG_INTERNAL_ERROR;
        auto state=runtime::state<JobState>(e,snapshot->dataset,query->query,o);
        auto result=handle<dmg_job>(e,state);
        e->jobs[slot]=state;++e->active_jobs;
        try{result->worker=std::thread(worker,state,slot);}
        catch(...){e->jobs[slot].reset();--e->active_jobs;destroy(result);throw;}
        *out=result;return DMG_OK;
    },error);
}
void dmg_job_retain(dmg_job* job){if(job)job->references.fetch_add(1,std::memory_order_relaxed);}
void dmg_job_cancel(dmg_job* job){if(job){
    try{
#ifdef DMG_TEST_JOB_COMMIT_BARRIER
        if(test_job_cancel_lock_failure.exchange(false,std::memory_order_acq_rel))throw std::system_error(std::make_error_code(std::errc::operation_not_permitted));
#ifdef DMG_TEST_UNIQUE_ONE_STREAM
        if(const auto hook=test_unique_one_cancel_enter.load(std::memory_order_acquire))hook();
#endif
#endif
        std::lock_guard lock(job->state->mutex);
        if(!job->state->status.terminal)job->state->cancelled.store(true,std::memory_order_release);
    }catch(...){
        // The void C ABI cannot report a locking error. Preserve the request
        // as best effort; a previously committed terminal result stays intact.
        job->state->cancelled.store(true,std::memory_order_release);
    }
    job->state->changed.notify_all();
}}
void dmg_job_release(dmg_job* job){
    if(job&&job->references.fetch_sub(1,std::memory_order_acq_rel)==1){dmg_job_cancel(job);if(job->worker.joinable())job->worker.join();destroy(job);}
}
dmg_status dmg_job_get_status(const dmg_job* job,dmg_job_status* out){return guard([&]()->dmg_status{
    if(!job||!out)return DMG_INVALID_ARGUMENT;if((job->state->query->plan->relation!=query::Relation::method_defs||job->state->query->plan->relation_root!=query::none))return DMG_UNSUPPORTED;std::lock_guard lock(job->state->mutex);*out=job->state->status;return DMG_OK;
});}
dmg_status dmg_job_wait(dmg_job* job,uint32_t timeout,dmg_job_status* out){return guard([&]()->dmg_status{
    if(!job||!out)return DMG_INVALID_ARGUMENT;if((job->state->query->plan->relation!=query::Relation::method_defs||job->state->query->plan->relation_root!=query::none))return DMG_UNSUPPORTED;auto& s=*job->state;std::unique_lock lock(s.mutex);
    const bool ready=s.changed.wait_for(lock,std::chrono::milliseconds(timeout),[&]{return s.status.terminal!=0;});
    *out=s.status;return ready?DMG_OK:DMG_NOT_READY;
});}
dmg_status dmg_job_next(dmg_job* job,uint32_t timeout,dmg_batch** out,dmg_error* error){
    if(out)*out=nullptr;return guard([&]()->dmg_status{
        if(!job||!out)return DMG_INVALID_ARGUMENT;auto& s=*job->state;std::unique_lock lock(s.mutex);
        if(!s.changed.wait_for(lock,std::chrono::milliseconds(timeout),[&]{return !s.queue.empty()||s.status.terminal;}))return DMG_NOT_READY;
        if(s.query->plan->contains_expand){
            if(!s.committed_expand||s.expand_cursor>=s.committed_expand->rows.size())return DMG_END_OF_STREAM;
            ResultOwner view(handle<dmg_result>(s.engine,s.dataset,s.query));
            const auto remaining=static_cast<uint32_t>(s.committed_expand->rows.size()-s.expand_cursor);
            view->view_offset=s.expand_cursor;view->view_count=std::min(s.options.batch_size,remaining);
            view->parent=s.committed_expand.get();dmg_result_retain(view->parent);
            s.expand_cursor+=view->view_count;*out=view.release();return DMG_OK;
        }
        if(s.queue.empty())return DMG_END_OF_STREAM;
        *out=s.queue.front().release();s.queue.pop_front();lock.unlock();s.changed.notify_all();return DMG_OK;
    },error);
}
}
