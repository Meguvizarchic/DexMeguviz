// Included inside the reference evaluator's anonymous namespace.
int key_compare(const EntityKey& a,const EntityKey& b){
    if(a.source_index!=b.source_index)return a.source_index<b.source_index?-1:1;
    if(a.relation!=b.relation)return a.relation<b.relation?-1:1;
    if(a.ordinal!=b.ordinal)return a.ordinal<b.ordinal?-1:1;
    return a.dex_pc==b.dex_pc?0:a.dex_pc<b.dex_pc?-1:1;
}
class GraphExecutor {
    using Rows=std::pmr::vector<Candidate>;
    struct Stage {
        Rows rows;bool source_complete=true;
        // Unrepresented possible rows from a traversal frontier are distinct
        // from the caller-declared source scope and from uncertain row values.
        bool opaque_unknown=false;
        explicit Stage(std::pmr::memory_resource* r):rows(r){}
    };
    const DatasetView& data;const query::Plan& plan;Progress& progress;Work& work;
    std::pmr::memory_resource* memory;Result result;CandidateSink sink;FactsCache* cache;const query::RelNode* cache_scope;
    // Eligibility proves Unique root keys cannot repeat; Exists needs no
    // deduplication. No additional identity comparisons affect max_work.
    size_t offered=0;
    void offer(const Candidate& candidate){
        if(!sink.accept)return;
        auto& metric=progress.graph->nodes[plan.relation_root];++metric.output_rows;
        if(candidate.uncertain){
            ++metric.unknown_rows;
            // Unique streaming is permitted only for scan/filter/label
            // chains with distinct root identities; Exists counts root rows.
            ++progress.profile.unknown_rows;
            return;
        }
        const size_t limit=plan.intent==query::Intent::exists?1:std::min(2u,plan.max_results);
        if(offered>=limit)return;
        ++offered;
        progress.graph->identity_count=static_cast<uint32_t>(offered);
        ++progress.profile.matches_seen;
        sink.accept(sink.context,result,candidate,progress);
    }
    uint64_t expand_unknown_frontiers=0;
    void bounded(size_t n){if(n>plan.max_intermediate_rows)throw query::Error(query::ErrorCode::budget,"intermediate relation row limit exceeded");}
    bool same_slot(std::string_view a,std::string_view b){work.charge();if(a.size()!=b.size())return false;for(size_t i=0;i<a.size();++i){work.charge();if(a[i]!=b[i])return false;}return true;}
    void validate_slots(std::span<const std::pmr::string> slots){
        for(const auto& wanted:slots)if(std::none_of(data.input_slots.begin(),data.input_slots.end(),[&](auto slot){return same_slot(wanted,slot);}))throw query::Error(query::ErrorCode::source_mismatch,"requested relation source slot is absent");
    }
    bool selected(const SourceView& s,const query::RelNode& node){
        const auto slot=data.input_slots[s.input_index];
        return (!plan.explicit_scope||std::any_of(plan.scope_slots.begin(),plan.scope_slots.end(),[&](const auto& key){return same_slot(key,slot);}))&&
               (!node.explicit_scope||std::any_of(node.scope_slots.begin(),node.scope_slots.end(),[&](const auto& key){return same_slot(key,slot);}));
    }
    bool source_complete(uint32_t index){
        const auto& n=plan.relations[index];if(n.op==query::RelOp::scan)return plan.explicit_scope||n.explicit_scope||data.scope_complete;
        if(n.op==query::RelOp::bounded_expand&&!(plan.explicit_scope||n.explicit_scope||data.scope_complete))return false;
        for(auto child:n.children)if(!source_complete(child))return false;return true;
    }
    // A predicate resolves inherited definitions only within the scans of its
    // own input subtree, not unrelated scans elsewhere in the relation graph.
    void inheritance_sources(uint32_t root,std::pmr::vector<uint32_t>& output){
        std::pmr::vector<uint8_t> selected_bits(data.sources.size(),0,memory);
        const auto visit=[&](auto&& self,uint32_t index)->void{
            work.charge();const auto& node=plan.relations[index];
            if(node.op==query::RelOp::scan){
                for(const auto& source:data.sources){work.charge();if(selected(source,node))selected_bits[source.source_index]=1;}
            }else for(auto child:node.children)self(self,child);
        };
        visit(visit,root);
        for(uint32_t index=0;index<selected_bits.size();++index){work.charge();if(selected_bits[index])output.push_back(index);}
    }
    int label_compare(uint32_t a,uint32_t b){
        if(a==b)return 0;if(a==query::none)return -1;if(b==query::none)return 1;
        const auto& x=plan.labels[a];const auto& y=plan.labels[b];const auto n=std::min(x.size(),y.size());
        for(size_t i=0;i<n;++i){work.charge();if(x[i]!=y[i])return x[i]<y[i]?-1:1;}return x.size()==y.size()?0:x.size()<y.size()?-1:1;
    }
    int binding_compare(const Binding& a,const Binding& b){
        work.charge();const auto count=std::min(a.path_length,b.path_length);
        for(uint32_t i=0;i<count;++i){work.charge();if(a.path[i]!=b.path[i])return a.path[i]<b.path[i]?-1:1;}
        if(a.path_length!=b.path_length)return a.path_length<b.path_length?-1:1;
        const auto label=label_compare(a.label,b.label);return label?label:key_compare(a.entity,b.entity);
    }
    void normalize(Candidate& row){
        std::sort(row.bindings.begin(),row.bindings.end(),[&](const auto& a,const auto& b){return binding_compare(a,b)<0;});
        auto end=std::unique(row.bindings.begin(),row.bindings.end(),[&](const auto& a,const auto& b){work.charge();return a==b;});row.bindings.erase(end,row.bindings.end());
    }
    int identity_compare(const Candidate& a,const Candidate& b,query::Identity identity){
        work.charge();auto primary=key_compare(a.key(),b.key());if(primary||identity==query::Identity::entity)return primary;
        const auto count=std::min(a.bindings.size(),b.bindings.size());
        for(size_t i=0;i<count;++i){auto c=binding_compare(a.bindings[i],b.bindings[i]);if(c)return c;}
        if(a.bindings.size()!=b.bindings.size())return a.bindings.size()<b.bindings.size()?-1:1;
        if(a.expand_path_identity!=b.expand_path_identity)return a.expand_path_identity?1:-1;
        if(!a.expand_path_identity)return 0;
        const auto path_count=std::min(a.expand_paths.size(),b.expand_paths.size());
        for(size_t i=0;i<path_count;++i){const auto& x=a.expand_paths[i];const auto& y=b.expand_paths[i];
            if(x.node!=y.node)return x.node<y.node?-1:1;
            const auto seed=key_compare(x.seed,y.seed);if(seed)return seed;
            const auto n=std::min(x.seed_bindings.size(),y.seed_bindings.size());
            for(size_t j=0;j<n;++j){const auto c=binding_compare(x.seed_bindings[j],y.seed_bindings[j]);if(c)return c;}
            if(x.seed_bindings.size()!=y.seed_bindings.size())return x.seed_bindings.size()<y.seed_bindings.size()?-1:1;
            const auto hops=std::min(x.hops.size(),y.hops.size());
            for(size_t j=0;j<hops;++j){work.charge();const auto& l=x.hops[j];const auto& r=y.hops[j];
                auto c=key_compare(l.caller,r.caller);if(c)return c;
                if(l.dex_pc!=r.dex_pc)return l.dex_pc<r.dex_pc?-1:1;
                if(l.target_method_ref!=r.target_method_ref)return l.target_method_ref<r.target_method_ref?-1:1;
                c=key_compare(l.resolved,r.resolved);if(c)return c;
            }
            if(x.hops.size()!=y.hops.size())return x.hops.size()<y.hops.size()?-1:1;
        }
        return a.expand_paths.size()==b.expand_paths.size()?0:a.expand_paths.size()<b.expand_paths.size()?-1:1;
    }
    void append_expand_paths(Candidate& target,const Candidate& source){
        for(const auto& path:source.expand_paths){work.charge();ExpandPath copy(memory);copy.node=path.node;copy.seed=path.seed;copy.endpoint=path.endpoint;copy.uncertain=path.uncertain;
            work.charge(path.seed_bindings.size()+path.seed_links.size()+path.seed_proof_bindings.size()+path.seed_witnesses.size()+path.walk_witnesses.size()+path.emit_witnesses.size()+path.hops.size());
            copy.seed_bindings.assign(path.seed_bindings.begin(),path.seed_bindings.end());copy.seed_links.assign(path.seed_links.begin(),path.seed_links.end());
            copy.seed_proof_bindings.assign(path.seed_proof_bindings.begin(),path.seed_proof_bindings.end());copy.seed_witnesses.assign(path.seed_witnesses.begin(),path.seed_witnesses.end());
            copy.walk_witnesses.assign(path.walk_witnesses.begin(),path.walk_witnesses.end());copy.emit_witnesses.assign(path.emit_witnesses.begin(),path.emit_witnesses.end());
            copy.hops.assign(path.hops.begin(),path.hops.end());target.expand_paths.push_back(std::move(copy));}
    }
    void distinct(Rows& rows,query::Identity identity){
        struct Kept {uint32_t position,representative;};
        std::pmr::vector<uint32_t> order(memory);std::pmr::vector<Kept> kept(memory);order.reserve(rows.size());
        for(uint32_t i=0;i<rows.size();++i){work.charge();order.push_back(i);}
        std::sort(order.begin(),order.end(),[&](auto a,auto b){const auto c=identity_compare(rows[a],rows[b],identity);return c?c<0:a<b;});
        for(size_t begin=0;begin<order.size();){size_t end=begin+1;auto representative=order[begin];
            while(end<order.size()&&identity_compare(rows[order[begin]],rows[order[end]],identity)==0){work.charge();if(rows[representative].uncertain&&!rows[order[end]].uncertain)representative=order[end];++end;}
            if(identity==query::Identity::entity||(plan.contains_expand&&!rows[representative].expand_path_identity)){
                Candidate paths(rows[representative].source_index,rows[representative].method_ordinal,memory,rows[representative].relation,rows[representative].dex_pc);
                for(size_t k=begin;k<end;++k)append_expand_paths(paths,rows[order[k]]);
                rows[representative].expand_paths=std::move(paths.expand_paths);
                // Entity/set identity collapses traversal paths, but keeps their
                // grouped proofs. Later tuple identity must not undo that set.
                if(identity==query::Identity::entity)rows[representative].expand_path_identity=false;
            }
            const auto position=rows[representative].expand_paths.empty()?representative:order[begin];
            kept.push_back({position,representative});begin=end;
        }
        std::sort(kept.begin(),kept.end(),[&](const auto& a,const auto& b){work.charge();return a.position<b.position;});Rows unique(memory);unique.reserve(kept.size());
        for(auto item:kept){work.charge();unique.push_back(std::move(rows[item.representative]));}rows=std::move(unique);
    }
    void append(Rows& target,Rows& source){
        bounded(target.size()+source.size());for(auto& row:source){work.charge();target.push_back(std::move(row));}
    }
    void add_evidence(Candidate& target,std::span<const Witness> proof){
        for(const auto& w:proof){work.charge();target.witnesses.push_back(w);}
    }
    Binding with_side(Binding binding,uint8_t side){
        if(binding.path_length>=binding.path.size())throw query::Error(query::ErrorCode::budget,"binding path exceeds relation depth");
        work.charge(binding.path_length+1);for(uint32_t i=binding.path_length;i>0;--i)binding.path[i]=binding.path[i-1];
        binding.path[0]=side;++binding.path_length;return binding;
    }
    void add_links(Candidate& target,std::span<const JoinLink> links){for(const auto& link:links){work.charge();target.links.push_back(link);}}
    void add_proofs(Candidate& target,std::span<const ProofBinding> bindings,int side=-1){
        for(auto proof:bindings){work.charge();if(side>=0)proof.binding=with_side(proof.binding,static_cast<uint8_t>(side));target.proof_bindings.push_back(proof);}
    }
    void merge_scan(OperatorProfile& metric,const facts::UseScanProgress& scan,query::Relation relation){
        if(progress.profile.work_units>plan.max_work||scan.work_units>plan.max_work-progress.profile.work_units)
            throw query::Error(query::ErrorCode::budget,"use scan work accounting exceeds query limit");
        progress.profile.work_units+=scan.work_units;
        progress.visited+=scan.visited_methods;
        progress.graph->method_visited+=scan.visited_methods;
        progress.graph->events_collected+=scan.emitted_events;
        metric.input_rows+=scan.attempted_methods;metric.visited_rows+=scan.visited_methods;
        metric.attempted_methods+=scan.attempted_methods;metric.no_body_methods+=scan.no_body_methods;
        metric.decoded_methods+=scan.decoded_methods;metric.emitted_events+=scan.emitted_events;metric.code_units+=scan.code_units;
        progress.profile.fact_requests+=scan.attempted_methods;
        progress.profile.methods_decoded+=scan.decoded_methods;progress.profile.code_units+=scan.code_units;
        if(relation==query::Relation::invoke_sites)progress.profile.invoke_sites+=scan.emitted_events;
        if(relation==query::Relation::field_uses)progress.profile.field_uses+=scan.emitted_events;
    }
    const facts::UseRecord& register_use(const facts::UseRecord& record,query::Relation relation,uint32_t source){
        work.charge();
        if(record.key.source_index!=source||record.key.kind!=use_kind(relation)||record.key.dex_pc==UINT32_MAX)
            throw query::Error(query::ErrorCode::invalid,"scanned use identity is inconsistent");
        const auto inserted=result.uses.try_emplace(record.key,record);const auto& stored=inserted.first->second;
        if(!inserted.second&&(stored.caller_method_ref!=record.caller_method_ref||stored.code_offset!=record.code_offset||
            stored.target_index!=record.target_index||stored.extra_proto!=record.extra_proto||stored.opcode!=record.opcode||stored.target_domain!=record.target_domain))
            throw query::Error(query::ErrorCode::invalid,"same use key has conflicting payload");
        return stored;
    }
    void scan_uses(const SourceView& source,const query::RelNode& node,OperatorProfile& metric,Rows& rows,bool root){
        work.check();
        struct FieldScopeContext { GraphExecutor* executor; uint32_t node; };
        FieldScopeContext field_scope_context{this,static_cast<uint32_t>(&node-plan.relations.data())};
        const auto field_scope=[](void* raw,std::pmr::vector<uint32_t>& indices){const auto& c=*static_cast<FieldScopeContext*>(raw);c.executor->inheritance_sources(c.node,indices);};
        InheritanceScope field_inheritance(data,{},work,memory,field_scope,&field_scope_context);
        if(progress.profile.work_units>=plan.max_work)throw query::Error(query::ErrorCode::budget,"use scan has no remaining work");
        const auto remaining=plan.max_work-progress.profile.work_units;
        facts::UseScanProgress scanned_progress;bool merged=false;
        const bool type_use=node.relation==query::Relation::type_uses;
        if(plan.use_streaming||type_use){
            facts::UseScanProgress accounted{};
            auto merge_pending=[&]{
                facts::UseScanProgress delta{};
                delta.attempted_methods=scanned_progress.attempted_methods-accounted.attempted_methods;
                delta.visited_methods=scanned_progress.visited_methods-accounted.visited_methods;
                delta.no_body_methods=scanned_progress.no_body_methods-accounted.no_body_methods;
                delta.decoded_methods=scanned_progress.decoded_methods-accounted.decoded_methods;
                delta.emitted_events=scanned_progress.emitted_events-accounted.emitted_events;
                delta.code_units=scanned_progress.code_units-accounted.code_units;
                delta.validation_work=scanned_progress.validation_work-accounted.validation_work;
                delta.work_units=scanned_progress.work_units-accounted.work_units;
                merge_scan(metric,delta,node.relation);accounted=scanned_progress;
            };
            auto remaining_shared=[&]()noexcept->uint64_t{
                if(scanned_progress.work_units<accounted.work_units||progress.profile.work_units>plan.max_work)return 0;
                const auto pending=scanned_progress.work_units-accounted.work_units;
                return pending>plan.max_work-progress.profile.work_units?0:plan.max_work-progress.profile.work_units-pending;
            };
            std::optional<Evaluator> evaluator;
            auto completed=[&](std::span<const facts::UseRecord> records,const facts::UseScanProgress&){
#ifdef DMG_TEST_JOB_COMMIT_BARRIER
                if(type_use)if(const auto barrier=test_type_use_method_barrier.load(std::memory_order_acquire))barrier();
#endif
                // The whole method and all its records are checked and
                // accounted before any of its events can reach a sink.
                merge_pending();
                if(!records.empty()&&!evaluator)evaluator.emplace(source,plan,work,memory);
                for(const auto& item:records){
                    if(type_use){
                        const auto value=evaluator->run_use(item,node.predicate,node.relation,node.stable_id);if(value==Truth::no)continue;
                        const auto& record=register_use(item,node.relation,source.source_index);
                        bounded(rows.size()+1);Candidate row(source.source_index,record.key.caller_ordinal,memory,node.relation,record.key.dex_pc);
                        row.uncertain=value==Truth::unknown;row.witnesses=std::move(evaluator->proof);rows.push_back(std::move(row));
                        continue;
                    }
                    const auto& record=register_use(item,node.relation,source.source_index);
                    const auto value=evaluator->run_use(record,node.predicate,node.relation,node.stable_id);if(value==Truth::no)continue;
                    bounded(rows.size()+1);Candidate row(source.source_index,record.key.caller_ordinal,memory,node.relation,record.key.dex_pc);
                    row.uncertain=value==Truth::unknown;row.witnesses=std::move(evaluator->proof);rows.push_back(std::move(row));
                    if(root)offer(rows.back());
                }
            };
            struct Context {decltype(remaining_shared)* remaining_fn;decltype(completed)* completed_fn;};
            Context context{&remaining_shared,&completed};facts::UseScanHooks hooks{};hooks.context=&context;
            hooks.remaining=[](void* p)noexcept{return (*static_cast<Context*>(p)->remaining_fn)();};
            hooks.method_complete=[](void* p,std::span<const facts::UseRecord> records,const facts::UseScanProgress& state){(*static_cast<Context*>(p)->completed_fn)(records,state);};
            hooks.discard_after_callback=type_use;
            try{
                const auto scanned=facts::collect_uses(source.bytes,*source.facts,source.source_index,use_kind(node.relation),scanned_progress,memory,
                    {remaining,type_use?1'048'576u:plan.max_intermediate_rows},{work.cancel.requested,work.cancel.context},hooks,cache?cache->method_provider():nullptr);
                merge_pending();
                if(!type_use&&scanned.rows.size()!=scanned_progress.emitted_events)throw query::Error(query::ErrorCode::invalid,"use scan rows differ from completed event count");
            }catch(...){merge_pending();throw;}
            return;
        }
        try{
            const auto scanned=facts::collect_uses(source.bytes,*source.facts,source.source_index,use_kind(node.relation),scanned_progress,memory,
                {remaining,plan.max_intermediate_rows},{work.cancel.requested,work.cancel.context},{},cache?cache->method_provider():nullptr);
            merge_scan(metric,scanned_progress,node.relation);merged=true;
            if(scanned.rows.size()!=scanned_progress.emitted_events)throw query::Error(query::ErrorCode::invalid,"use scan rows differ from completed event count");
            Evaluator evaluator(source,plan,work,memory,plan.field_declaration_resolution?&field_inheritance:nullptr,source_complete(static_cast<uint32_t>(&node-plan.relations.data())));
            for(const auto& item:scanned.rows){
                const auto& record=register_use(item,node.relation,source.source_index);
                const auto value=evaluator.run_use(record,node.predicate,node.relation,node.stable_id);if(value==Truth::no)continue;
                bounded(rows.size()+1);Candidate row(source.source_index,record.key.caller_ordinal,memory,node.relation,record.key.dex_pc);
                row.uncertain=value==Truth::unknown;row.witnesses=std::move(evaluator.proof);rows.push_back(std::move(row));
            }
        }catch(...){if(!merged)merge_scan(metric,scanned_progress,node.relation);throw;}
    }
    bool join_key(const Candidate& left,const Candidate& right,query::JoinKey key){
        work.charge();if(key==query::JoinKey::same_entity)return left.key()==right.key();
        if(key==query::JoinKey::caller||key==query::JoinKey::target_ref||key==query::JoinKey::target_symbol){
            const bool left_use=query::is_use_relation(left.relation),right_use=query::is_use_relation(right.relation);
            if(left_use==right_use)throw query::Error(query::ErrorCode::unsupported,"use join needs exactly one use endpoint");
            const auto& use=left_use?left:right;const auto& other=left_use?right:left;
            const auto& event=use_record(result,use.key());
            if(other.dex_pc!=UINT32_MAX)throw query::Error(query::ErrorCode::invalid,"ordinary join endpoint unexpectedly has a dex PC");
            if(key==query::JoinKey::caller){
                if(other.relation!=query::Relation::method_defs)throw query::Error(query::ErrorCode::unsupported,"caller join needs a method definition");
                return use.source_index==other.source_index&&use.method_ordinal==other.method_ordinal;
            }
            using R=query::Relation;using D=facts::TargetDomain;
            if(key==query::JoinKey::target_symbol){
                if(use.relation==R::invoke_sites&&event.target_domain==D::call_site)return false;
                const bool is_string=use.relation==R::string_uses&&other.relation==R::string_values&&event.target_domain==D::string_value;
                const bool is_field=use.relation==R::field_uses&&(other.relation==R::field_defs||other.relation==R::field_refs)&&event.target_domain==D::field_ref;
                const bool is_method=use.relation==R::invoke_sites&&(other.relation==R::method_defs||other.relation==R::method_refs)&&(event.target_domain==D::method_ref||event.target_domain==D::method_and_proto);
                if(!is_string&&!is_field&&!is_method)throw query::Error(query::ErrorCode::unsupported,"target symbol join has incompatible endpoint domains");
#ifdef DMG_TEST_TARGET_SYMBOL_BARRIER
                if(const auto barrier=test_target_symbol_barrier.load(std::memory_order_acquire))barrier(progress.profile.work_units);
#endif
                const auto ref_relation=is_string?R::string_values:is_field?R::field_refs:R::method_refs;
                const auto a=entity(data.sources[use.source_index],ref_relation,event.target_index);
                const auto b=entity(data.sources[other.source_index],other.relation,other.method_ordinal);
                const auto same=[&](std::u16string_view x,std::u16string_view y){return compare_text(x,y,work)==0;};
                if(is_string)return same(a.value,b.value);
                return same(a.owner,b.owner)&&same(a.name,b.name)&&(is_method?same(a.prototype,b.prototype):same(a.type_descriptor,b.type_descriptor));
            }
            const bool compatible=(use.relation==R::string_uses&&other.relation==R::string_values&&event.target_domain==D::string_value)||
                (use.relation==R::field_uses&&other.relation==R::field_refs&&event.target_domain==D::field_ref)||
                (use.relation==R::type_uses&&other.relation==R::type_refs&&event.target_domain==D::type_ref)||
                (use.relation==R::invoke_sites&&other.relation==R::method_refs&&(event.target_domain==D::method_ref||event.target_domain==D::method_and_proto));
            if(use.relation==R::invoke_sites&&other.relation==R::method_refs&&event.target_domain==D::call_site)return false;
            if(!compatible)throw query::Error(query::ErrorCode::unsupported,"target reference join has incompatible endpoint domains");
            return use.source_index==other.source_index&&event.target_index==other.method_ordinal;
        }
        if(query::is_use_relation(left.relation)||query::is_use_relation(right.relation))throw query::Error(query::ErrorCode::unsupported,"join key does not support use endpoints");
        const auto a=entity(data.sources[left.source_index],left.relation,left.method_ordinal);
        const auto b=entity(data.sources[right.source_index],right.relation,right.method_ordinal);
        if(key==query::JoinKey::local_definition)return a.source_index==b.source_index&&a.reference_index==b.reference_index;
        if(key==query::JoinKey::local_owner)return a.source_index==b.source_index&&a.owner_type==b.reference_index;
        if(key!=query::JoinKey::symbol)throw query::Error(query::ErrorCode::unsupported,"unsupported join key");
        const auto same=[&](std::u16string_view x,std::u16string_view y){return compare_text(x,y,work)==0;};
        if(left.relation==query::Relation::string_values)return same(a.value,b.value);
        if(left.relation==query::Relation::class_defs||left.relation==query::Relation::type_refs)return same(a.type_descriptor,b.type_descriptor);
        if(!same(a.owner,b.owner)||!same(a.name,b.name))return false;
        if(left.relation==query::Relation::method_defs||left.relation==query::Relation::method_refs)return same(a.prototype,b.prototype);
        return same(a.type_descriptor,b.type_descriptor);
    }
    Candidate pair(const Candidate& left,const Candidate& right,const query::RelNode& node){
        Candidate out(left.source_index,left.method_ordinal,memory,left.relation,left.dex_pc);out.uncertain=left.uncertain||right.uncertain;
        out.bindings.push_back(with_side({query::none,left.key()},0));
        for(const auto& binding:left.bindings){work.charge();out.bindings.push_back(with_side(binding,0));}
        out.bindings.push_back(with_side({query::none,right.key()},1));
        for(const auto& binding:right.bindings){work.charge();out.bindings.push_back(with_side(binding,1));}
        normalize(out);add_links(out,left.links);add_links(out,right.links);out.links.push_back({node.stable_id,node.join_key,left.key(),right.key()});
        add_proofs(out,left.proof_bindings,0);add_proofs(out,right.proof_bindings,1);
        add_evidence(out,left.witnesses);add_evidence(out,right.witnesses);
        out.expand_path_identity=left.expand_path_identity||right.expand_path_identity;
        append_expand_paths(out,left);append_expand_paths(out,right);return out;
    }
    bool roles_match(const Candidate& group,const query::RelNode& node,std::span<const EntityKey> members){
        if(node.required_roles.empty())return true;
        std::pmr::vector<int32_t> matched(members.size(),-1,memory);std::pmr::vector<uint8_t> seen(members.size(),0,memory);
        auto augment=[&](auto&& self,uint32_t role)->bool{
            for(const auto& binding:group.bindings){work.charge();if(binding.label!=node.required_roles[role])continue;
                auto it=std::lower_bound(members.begin(),members.end(),binding.entity,[&](const auto& a,const auto& b){work.charge();return key_compare(a,b)<0;});
                if(it==members.end()||*it!=binding.entity)continue;const auto index=static_cast<size_t>(it-members.begin());
                if(seen[index])continue;seen[index]=1;
                if(matched[index]<0||self(self,static_cast<uint32_t>(matched[index]))){matched[index]=static_cast<int32_t>(role);return true;}
            }return false;
        };
        for(uint32_t role=0;role<node.required_roles.size();++role){
            if(!node.distinct_roles){bool found=false;for(const auto& b:group.bindings){work.charge();if(b.label!=node.required_roles[role])continue;
                auto it=std::lower_bound(members.begin(),members.end(),b.entity,[&](const auto& a,const auto& value){work.charge();return key_compare(a,value)<0;});
                if(it!=members.end()&&*it==b.entity){found=true;break;}}
                if(!found)return false;}
            else{work.charge(seen.size());std::fill(seen.begin(),seen.end(),uint8_t{0});if(!augment(augment,role))return false;}
        }return true;
    }
    Rows group(Rows& inputs,const query::RelNode& node,bool source_complete){
        distinct(inputs,query::Identity::tuple);
        struct Member {EntityKey owner;uint32_t input;};std::pmr::vector<Member> members(memory);members.reserve(inputs.size());
        for(uint32_t i=0;i<inputs.size();++i){work.charge();const auto& c=inputs[i];const auto& s=data.sources[c.source_index];const auto e=entity(s,c.relation,c.method_ordinal);
            if(!e.owner_class||(c.relation!=query::Relation::method_defs&&c.relation!=query::Relation::field_defs))throw query::Error(query::ErrorCode::invalid,"owner grouping requires member definitions");
            members.push_back({{c.source_index,s.facts->class_definition_by_type[e.owner_type],query::Relation::class_defs},i});
        }
        std::sort(members.begin(),members.end(),[&](const auto& a,const auto& b){work.charge();const auto c=key_compare(a.owner,b.owner);return c?c<0:a.input<b.input;});
        Rows groups(memory);
        for(size_t begin=0;begin<members.size();){
            size_t end=begin+1;while(end<members.size()&&key_compare(members[begin].owner,members[end].owner)==0){work.charge();++end;}
            const auto owner=members[begin].owner;Candidate candidate(owner.source_index,owner.ordinal,memory,owner.relation);
            std::pmr::vector<EntityKey> known(memory),possible(memory);bool uncertain=false;
            for(size_t i=begin;i<end;++i){work.charge();const auto& row=inputs[members[i].input];possible.push_back(row.key());if(!row.uncertain)known.push_back(row.key());uncertain|=row.uncertain;
                candidate.bindings.push_back({query::none,row.key()});for(auto b:row.bindings){work.charge();candidate.bindings.push_back(b);}
                add_links(candidate,row.links);add_proofs(candidate,row.proof_bindings);add_evidence(candidate,row.witnesses);
                // A class group has member identity; every contributing path
                // remains a separate explanation with its original endpoint.
                append_expand_paths(candidate,row);
            }
            auto sort_keys=[&](auto& keys){std::sort(keys.begin(),keys.end(),[&](const auto& a,const auto& b){work.charge();return key_compare(a,b)<0;});keys.erase(std::unique(keys.begin(),keys.end(),[&](const auto& a,const auto& b){work.charge();return a==b;}),keys.end());};
            sort_keys(known);sort_keys(possible);normalize(candidate);
            if(known.size()<=node.maximum&&possible.size()>=node.minimum&&roles_match(candidate,node,possible)){
                candidate.uncertain=uncertain||!source_complete;
                if(!source_complete)progress.scope_derived_unknown=true;
                bounded(groups.size()+1);groups.push_back(std::move(candidate));
            }begin=end;
        }return groups;
    }
    void reverse_join(Rows& left,Rows& right,const query::RelNode& node,Rows& output){
        auto& opt=*data.reverse_target_join;
        const bool field=opt.use_relation==query::Relation::field_uses;
        const bool string=opt.use_relation==query::Relation::string_uses;
        const auto use_kind=field?facts::UseKind::field_use:string?facts::UseKind::string_use:facts::UseKind::invoke_site;
        if(!opt.intersection_only&&(left.size()>4096||right.size()>4096))throw query::Error(query::ErrorCode::unsupported,"reverse join input exceeds experimental shape bound");
        auto charge_extra=[&]{
            if(opt.adapter_work>=opt.max_adapter_work)throw query::Error(query::ErrorCode::budget,"reverse join adapter work exhausted");
            ++opt.adapter_work;if((opt.adapter_work&1023)==1)work.check();
        };
        struct UsePosition {uint32_t source,caller,pc;size_t position;};
        struct RefPosition {uint64_t key;size_t position;};
        std::pmr::vector<UsePosition> uses(memory);std::pmr::vector<RefPosition> refs(memory);
        std::pmr::vector<size_t> match(left.size(),std::numeric_limits<size_t>::max(),memory);
        uses.reserve(left.size());refs.reserve(right.size());
        for(size_t i=0;i<left.size();++i){charge_extra();uses.push_back({left[i].source_index,left[i].method_ordinal,left[i].dex_pc,i});}
        for(size_t i=0;i<right.size();++i){charge_extra();refs.push_back({(uint64_t(right[i].source_index)<<32)|right[i].method_ordinal,i});}
        auto use_key=[](const UsePosition& x){return std::tuple{x.source,x.caller,x.pc};};
        std::sort(uses.begin(),uses.end(),[&](const auto& a,const auto& b){charge_extra();return use_key(a)<use_key(b);});
        std::sort(refs.begin(),refs.end(),[&](const auto& a,const auto& b){charge_extra();return a.key<b.key;});
        for(size_t i=1;i<uses.size();++i){charge_extra();if(use_key(uses[i-1])==use_key(uses[i]))throw query::Error(query::ErrorCode::unsupported,"duplicate use identity in direct scan");}
        for(size_t i=1;i<refs.size();++i){charge_extra();if(refs[i-1].key==refs[i].key)throw query::Error(query::ErrorCode::unsupported,"duplicate reference identity in direct scan");}
        const auto no_match=std::numeric_limits<size_t>::max();
        const auto fetch=[&](size_t r,facts::TargetDomain domain,uint32_t proto){
            const auto& target=right[r];const auto& source=data.sources[target.source_index];
                uint64_t offset=0;
                do {
                    charge_extra();if(opt.page_calls>=opt.max_page_calls)throw query::Error(query::ErrorCode::budget,"reverse join page call limit exhausted");
                    ++opt.page_calls;
#ifdef DMG_TEST_REVERSE_JOIN_BARRIER
                    if(const auto hook=test_reverse_join_page_barrier.load(std::memory_order_acquire))hook();
#endif
                    auto page=opt.registry->page(source.bytes,*source.facts,source.source_index,use_kind,
                        {domain,target.method_ordinal,proto},offset,4096,opt.limits,{work.cancel.requested,work.cancel.context},cache?cache->method_provider():nullptr);
                    for(const auto& event:page.rows){
                        charge_extra();
                        if(event.source_index!=source.source_index||event.use_kind!=static_cast<uint32_t>(use_kind)||
                           event.target_domain!=static_cast<uint32_t>(domain)||event.target_index!=target.method_ordinal||event.extra_proto!=proto)
                            throw query::Error(query::ErrorCode::invalid,"reverse page key mismatch");
                        const auto wanted=std::tuple{event.source_index,event.caller_ordinal,event.dex_pc};
                        auto it=std::lower_bound(uses.begin(),uses.end(),wanted,[&](const UsePosition& a,const auto& b){charge_extra();return use_key(a)<b;});
                        if(it==uses.end()||use_key(*it)!=wanted)continue; // filtered scan row
                        const auto& raw=use_record(result,left[it->position].key());
                        if(raw.caller_method_ref!=event.caller_method_ref||raw.code_offset!=event.code_offset||raw.opcode!=event.opcode||
                           raw.target_index!=event.target_index||static_cast<uint32_t>(raw.target_domain)!=event.target_domain||raw.extra_proto!=event.extra_proto)
                            throw query::Error(query::ErrorCode::invalid,"reverse event differs from checked forward scan");
                        if(match[it->position]!=no_match)throw query::Error(query::ErrorCode::invalid,"duplicate reverse event identity");
                        match[it->position]=r;
                    }
                    if(page.rows.empty()&&offset<page.total)throw query::Error(query::ErrorCode::invalid,"reverse page did not advance");
                    offset+=page.rows.size();if(offset>=page.total)break;
                }while(true);
            };
        if(!opt.intersection_only){
            if(!left.empty())for(size_t r=0;r<right.size();++r){
                const auto& source=data.sources[right[r].source_index];
                if(field)fetch(r,facts::TargetDomain::field_ref,UINT32_MAX);
                else if(string)fetch(r,facts::TargetDomain::string_value,UINT32_MAX);
                else {
                    fetch(r,facts::TargetDomain::method_ref,UINT32_MAX);
                    if(source.facts->prototypes.size()>UINT32_MAX)throw query::Error(query::ErrorCode::unsupported,"too many prototypes for reverse join");
                    for(uint32_t proto=0;proto<source.facts->prototypes.size();++proto)fetch(r,facts::TargetDomain::method_and_proto,proto);
                }
            }
        }else{
            struct Request {size_t r;facts::TargetDomain domain;uint32_t proto;};
            std::pmr::vector<Request> requests(memory);requests.reserve(left.size());
            for(const auto& row:left){
                charge_extra();const auto& event=use_record(result,row.key());
                const bool eligible=field?event.target_domain==facts::TargetDomain::field_ref:
                    string?event.target_domain==facts::TargetDomain::string_value:
                    event.target_domain==facts::TargetDomain::method_ref||event.target_domain==facts::TargetDomain::method_and_proto;
                if(!eligible)continue;
                const auto k=(uint64_t(row.source_index)<<32)|event.target_index;
                const auto ref=std::lower_bound(refs.begin(),refs.end(),k,[&](const RefPosition& a,uint64_t b){charge_extra();return a.key<b;});
                if(ref!=refs.end()&&ref->key==k)requests.push_back({ref->position,event.target_domain,event.extra_proto});
            }
            auto key=[](const Request& r){return std::tuple{r.r,static_cast<uint32_t>(r.domain),r.proto};};
            std::sort(requests.begin(),requests.end(),[&](const auto& a,const auto& b){charge_extra();return key(a)<key(b);});
            for(size_t i=0;i<requests.size();++i){
                charge_extra();if(i&&key(requests[i])==key(requests[i-1]))continue;
                fetch(requests[i].r,requests[i].domain,requests[i].proto);
            }
        }
        // Verify missing as well as present index events against the immutable
        // forward facts and independently selected reference identities.
        for(size_t i=0;i<left.size();++i){
            charge_extra();const auto& event=use_record(result,left[i].key());
            const bool eligible=field?event.target_domain==facts::TargetDomain::field_ref:
                string?event.target_domain==facts::TargetDomain::string_value:
                event.target_domain==facts::TargetDomain::method_ref||event.target_domain==facts::TargetDomain::method_and_proto;
            const auto k=(uint64_t(left[i].source_index)<<32)|event.target_index;
            const auto ref=std::lower_bound(refs.begin(),refs.end(),k,[&](const RefPosition& a,uint64_t b){charge_extra();return a.key<b;});
            const size_t expected=eligible&&ref!=refs.end()&&ref->key==k?ref->position:no_match;
            if(match[i]!=expected)throw query::Error(query::ErrorCode::invalid,"reverse index omitted or invented a target match");
        }
        // Preserve original per-pair logical work and its 1024-unit checks,
        // while skipping the physical nested comparison of unmatched pairs.
        auto skip=[&](size_t amount){
            while(amount){
                const auto before=progress.profile.work_units;
                if(before==0){work.charge();--amount;continue;}
                const auto remaining=plan.max_work-before;if(!remaining){work.charge();}
                const auto boundary=uint64_t(1024)-(before&1023);
                const auto step=std::min<uint64_t>({static_cast<uint64_t>(amount),remaining,boundary});
                work.charge(step);amount-=static_cast<size_t>(step);
            }
        };
        for(size_t i=0;i<left.size();++i){
            const auto r=match[i];if(r==no_match){skip(right.size());continue;}
            skip(r);work.charge();bounded(output.size()+1);output.push_back(pair(left[i],right[r],node));
            skip(right.size()-r-1);
        }
    }
    void annotate_caller_field(Candidate& row){
        using K=query::Relation;using namespace caller_field_relation;
        if(row.relation!=K::method_defs||row.links.size()!=1||row.links[0].key!=query::JoinKey::caller||
           row.links[0].left!=row.key()||row.links[0].right.relation!=K::field_uses||row.links[0].right.source_index!=row.source_index||row.links[0].right.ordinal!=row.method_ordinal)
            throw query::Error(query::ErrorCode::invalid,"caller relation requires one consistent caller link");
        const auto event=row.links[0].right;const auto& source=data.sources[row.source_index];const auto& facts=*source.facts;
        if(row.method_ordinal>=facts.methods.size())throw query::Error(query::ErrorCode::invalid,"caller relation method ordinal outside source");
        const auto methodRef=facts.methods[row.method_ordinal].method_index;
        if(methodRef>=facts.method_refs.size())throw query::Error(query::ErrorCode::invalid,"caller relation method reference outside source");
        const auto callerType=facts.method_refs[methodRef].owner;
        if(callerType>=facts.class_definition_by_type.size()||facts.class_definition_by_type[callerType]==UINT32_MAX)
            throw query::Error(query::ErrorCode::invalid,"caller relation declaring class missing");
        const Key caller{row.source_index,facts.class_definition_by_type[callerType]};
        const Witness* terminal=nullptr;
        for(const auto& w:row.witnesses){work.charge();if(w.kind==WitnessKind::field_declaration&&w.inherited_item==1){if(terminal)throw query::Error(query::ErrorCode::unsupported,"multiple field declarations in caller relation");terminal=&w;}}
        if(!terminal||terminal->entity_relation!=K::field_defs||terminal->source_index>=data.sources.size())throw query::Error(query::ErrorCode::invalid,"caller relation field declaration missing");
        const auto targetSource=terminal->source_index,targetField=terminal->entity_ordinal;const auto& tf=*data.sources[targetSource].facts;
        if(targetField>=tf.field_definitions.size())throw query::Error(query::ErrorCode::invalid,"caller relation field ordinal outside source");
        const auto targetType=tf.field_definitions[targetField].owner_type;
        if(targetType>=tf.class_definition_by_type.size()||tf.class_definition_by_type[targetType]==UINT32_MAX)throw query::Error(query::ErrorCode::invalid,"caller relation field declaring class missing");
        const Key target{targetSource,tf.class_definition_by_type[targetType]};
        std::pmr::vector<hierarchy::Source> scope(memory);for(auto i:result.scope_sources){work.charge();scope.push_back({i,data.sources[i].facts});}
        hierarchy::Budget budget{UINT64_MAX};budget.charge_external=[](void* raw,uint64_t amount){auto& w=*static_cast<Work*>(raw);w.charge(amount);w.check();};budget.external_context=&work;budget.max_nodes=plan.max_intermediate_rows;
        const auto observed=caller_field_relation::observe(scope,caller,target,budget,memory);
        budget.bound(row.witnesses.size()+1+observed.nodes.size()+observed.edges.size()+observed.object_checks.size());
        const auto root=plan.relations[plan.relation_root].stable_id;
        Witness head{};head.kind=WitnessKind::caller_field_relation;head.node=root;head.matched=1;head.relation_node=root;head.source_index=caller.source;head.entity_ordinal=caller.ordinal;head.entity_relation=K::class_defs;head.dex_pc=event.dex_pc;head.reference_index=targetField;head.inherited_item=0;head.inherited_path=static_cast<uint32_t>(observed.status);head.inherited_aux=static_cast<uint32_t>(observed.reason);head.inherited_branch=target.source;head.inherited_detail=target.ordinal;row.witnesses.push_back(head);
        for(uint32_t i=0;i<observed.nodes.size();++i){work.charge();const auto& n=observed.nodes[i];Witness w{};w.kind=WitnessKind::caller_field_relation;w.node=root;w.matched=1;w.relation_node=root;w.source_index=n.key.source;w.entity_ordinal=n.key.ordinal;w.entity_relation=K::class_defs;w.inherited_item=1;w.inherited_path=i;w.inherited_aux=n.parent;w.inherited_branch=static_cast<uint32_t>(n.edge);w.inherited_detail=n.interface_index;row.witnesses.push_back(w);}
        for(const auto& e:observed.edges){work.charge();Witness w{};w.kind=WitnessKind::caller_field_relation;w.node=root;w.matched=1;w.relation_node=root;w.source_index=caller.source;w.entity_ordinal=caller.ordinal;w.entity_relation=K::class_defs;w.inherited_item=2;w.inherited_path=e.from;w.inherited_aux=e.to;w.inherited_branch=static_cast<uint32_t>(e.kind);w.inherited_detail=e.interface_index;row.witnesses.push_back(w);}
        for(const auto& c:observed.object_checks){work.charge();Witness w{};w.kind=WitnessKind::caller_field_relation;w.node=root;w.matched=1;w.relation_node=root;w.source_index=c.object.source;w.entity_ordinal=c.object.ordinal;w.entity_relation=K::class_defs;w.inherited_item=3;w.inherited_path=c.interface_node;w.inherited_aux=UINT32_MAX;w.inherited_branch=UINT32_MAX;w.inherited_detail=UINT32_MAX;row.witnesses.push_back(w);}
    }
    struct ExpandState {
        uint32_t seed_index=0,depth=0;EntityKey current;bool uncertain=false;
        std::pmr::vector<ExpandHop> hops;
        std::pmr::vector<Witness> walk_proof;
        explicit ExpandState(std::pmr::memory_resource* r):hops(r),walk_proof(r){}
    };
    struct RawEdge {EntityKey caller;uint32_t pc,code_offset,opcode,target_ref;};
    Candidate copy_seed(const Candidate& seed,EntityKey endpoint){
        Candidate out(endpoint.source_index,endpoint.ordinal,memory,query::Relation::method_defs);
        out.uncertain=seed.uncertain;
        work.charge(seed.bindings.size()+seed.links.size()+seed.proof_bindings.size()+seed.witnesses.size());
        out.bindings.assign(seed.bindings.begin(),seed.bindings.end());out.links.assign(seed.links.begin(),seed.links.end());
        out.proof_bindings.assign(seed.proof_bindings.begin(),seed.proof_bindings.end());out.witnesses.assign(seed.witnesses.begin(),seed.witnesses.end());
        return out;
    }
    void expand_frontier(const query::RelNode& node,ExpandProfile& profile,const Candidate& seed,const ExpandState& state,
                         FrontierReason reason,EntityKey caller,uint32_t pc,uint32_t target,std::span<const Witness> current_proof={}){
        work.charge();bounded(result.frontiers.size()+1);ExpandFrontier item(memory);
        item.node=node.stable_id;item.depth=state.depth;item.seed=seed.key();item.current=state.current;item.caller=caller;
        item.dex_pc=pc;item.target_method_ref=target;item.reason=reason;
        work.charge(seed.bindings.size()+seed.links.size()+seed.proof_bindings.size()+seed.witnesses.size()+state.walk_proof.size()+state.hops.size()+current_proof.size());
        item.seed_bindings.assign(seed.bindings.begin(),seed.bindings.end());item.seed_links.assign(seed.links.begin(),seed.links.end());
        item.seed_proof_bindings.assign(seed.proof_bindings.begin(),seed.proof_bindings.end());item.seed_witnesses.assign(seed.witnesses.begin(),seed.witnesses.end());
        item.walk_witnesses.assign(state.walk_proof.begin(),state.walk_proof.end());
        if(reason==FrontierReason::unknown_emit)item.emit_witnesses.assign(current_proof.begin(),current_proof.end());
        else item.walk_witnesses.insert(item.walk_witnesses.end(),current_proof.begin(),current_proof.end());
        item.prefix.assign(state.hops.begin(),state.hops.end());
        result.frontiers.push_back(std::move(item));
        if(reason==FrontierReason::unresolved)++profile.unresolved;
        else{++profile.unknown;progress.scope_derived_unknown=true;if(reason!=FrontierReason::unknown_emit)++expand_unknown_frontiers;}
    }
    void expand_collect(EntityKey caller,ExpandProfile& profile,std::pmr::vector<RawEdge>& edges){
        work.check();const auto& source=data.sources[caller.source_index];
        if(work.progress.profile.work_units>=plan.max_work)throw query::Error(query::ErrorCode::budget,"expand has no remaining work");
        ++progress.profile.fact_requests;
        const auto remaining=plan.max_work-progress.profile.work_units;
        auto facts=dexmeguviz::cache::collect_method(cache?cache->method_provider():nullptr,source.bytes,*source.facts,caller.ordinal,instructions::Demand::invokes,memory,work.cancel.requested,work.cancel.context,remaining);
        if(facts.instruction_checked){++profile.decoded_methods;++progress.profile.methods_decoded;progress.profile.code_units+=facts.decoded_code_units;work.charge(facts.validation_work);}
        for(const auto& site:facts.invoke_sites){work.charge();++progress.profile.invoke_sites;if(site.reference_kind!=instructions::ReferenceKind::method)continue;
            bounded(edges.size()+1);edges.push_back({caller,site.pc,facts.code_offset,site.opcode,site.index});}
    }
    bool same_method_symbol(const EntityView& a,const EntityView& b){
        return compare_text(a.owner,b.owner,work)==0&&compare_text(a.name,b.name,work)==0&&compare_text(a.prototype,b.prototype,work)==0;
    }
    std::pmr::vector<EntityKey> expand_targets(const query::RelNode& node,const RawEdge& edge){
        const auto reference=entity(data.sources[edge.caller.source_index],query::Relation::method_refs,edge.target_ref);
        std::pmr::vector<EntityKey> targets(memory);
        for(const auto& source:data.sources){if(!selected(source,node))continue;
            for(uint32_t i=0;i<source.facts->methods.size();++i){work.charge();const auto target=entity(source,query::Relation::method_defs,i);
                if(!same_method_symbol(reference,target))continue;bounded(targets.size()+1);targets.push_back({source.source_index,i,query::Relation::method_defs});}
        }return targets;
    }
    Rows expand(Rows& seeds,const query::RelNode& node,bool complete){
        progress.graph->expands.emplace_back();auto& profile=progress.graph->expands.back();profile.node=node.stable_id;
        std::pmr::deque<ExpandState> pending(memory);Rows output(memory);
        const auto absent=EntityKey{UINT32_MAX,UINT32_MAX,query::Relation::method_defs};
        auto enqueue=[&](ExpandState&& state){
            if(profile.paths>=node.expand_max_paths)throw query::Error(query::ErrorCode::budget,"expand path limit exceeded");
            ++profile.paths;bounded(pending.size()+1);pending.push_back(std::move(state));
        };
        std::pmr::vector<uint32_t> selected_seeds(memory);
        for(uint32_t i=0;i<seeds.size();++i){const auto& seed=seeds[i];work.charge();
            if(seed.relation!=query::Relation::method_defs||seed.dex_pc!=UINT32_MAX)throw query::Error(query::ErrorCode::invalid,"expand seed must be a method definition");
            if(!selected(data.sources[seed.source_index],node))continue;selected_seeds.push_back(i);}
        std::pmr::vector<RawEdge> incoming(memory);
        if(!selected_seeds.empty()&&node.expand_max_depth&&node.expand_direction==query::ExpandDirection::incoming){
            ++profile.reverse_builds;
            for(const auto& source:data.sources){if(!selected(source,node))continue;
                for(uint32_t ordinal=0;ordinal<source.facts->methods.size();++ordinal){work.charge();expand_collect({source.source_index,ordinal,query::Relation::method_defs},profile,incoming);}}
        }
        for(const auto seed_index:selected_seeds){
          ExpandState initial(memory);initial.seed_index=seed_index;initial.current=seeds[seed_index].key();initial.uncertain=seeds[seed_index].uncertain;enqueue(std::move(initial));
        while(!pending.empty()){
            work.check();if(profile.visited>=node.expand_max_visited)throw query::Error(query::ErrorCode::budget,"expand visited limit exceeded");
            ++profile.visited;ExpandState state=std::move(pending.front());pending.pop_front();const auto& seed=seeds[state.seed_index];
            if(state.depth>=node.expand_min_depth){
                Truth value=Truth::yes;std::pmr::vector<Witness> emit_proof(memory);
                if(node.expand_emit_predicate!=query::none){Evaluator evaluator(data.sources[state.current.source_index],plan,work,memory,nullptr,complete,cache,cache_scope);
                    value=evaluator.run(state.current.ordinal,node.expand_emit_predicate,query::Relation::method_defs,node.stable_id);emit_proof=std::move(evaluator.proof);}
                if(value!=Truth::no){bounded(output.size()+1);auto row=copy_seed(seed,state.current);row.uncertain|=state.uncertain||value==Truth::unknown;
                    row.expand_path_identity=node.expand_output==query::ExpandOutput::paths;add_evidence(row,state.walk_proof);add_evidence(row,emit_proof);
                    ExpandPath path(memory);path.node=node.stable_id;path.seed=seed.key();path.endpoint=state.current;path.uncertain=row.uncertain;
                    work.charge(seed.bindings.size()+seed.links.size()+seed.proof_bindings.size()+seed.witnesses.size()+state.walk_proof.size()+emit_proof.size()+state.hops.size());
                    path.seed_bindings.assign(seed.bindings.begin(),seed.bindings.end());path.seed_links.assign(seed.links.begin(),seed.links.end());
                    path.seed_proof_bindings.assign(seed.proof_bindings.begin(),seed.proof_bindings.end());path.seed_witnesses.assign(seed.witnesses.begin(),seed.witnesses.end());
                    path.walk_witnesses.assign(state.walk_proof.begin(),state.walk_proof.end());path.emit_witnesses.assign(emit_proof.begin(),emit_proof.end());
                    path.hops.assign(state.hops.begin(),state.hops.end());row.expand_paths.push_back(std::move(path));
                    output.push_back(std::move(row));
                    if(value==Truth::unknown)expand_frontier(node,profile,seed,state,FrontierReason::unknown_emit,absent,UINT32_MAX,UINT32_MAX,emit_proof);
                }
            }
            if(state.depth>=node.expand_max_depth)continue;
            if(state.depth&&node.expand_walk_predicate!=query::none){Evaluator evaluator(data.sources[state.current.source_index],plan,work,memory,nullptr,complete,cache,cache_scope);
                const auto value=evaluator.run(state.current.ordinal,node.expand_walk_predicate,query::Relation::method_defs,node.stable_id);
                if(value==Truth::no)continue;
                if(value==Truth::unknown){expand_frontier(node,profile,seed,state,FrontierReason::unknown_walk,absent,UINT32_MAX,UINT32_MAX,evaluator.proof);continue;}
                work.charge(evaluator.proof.size());state.walk_proof.insert(state.walk_proof.end(),evaluator.proof.begin(),evaluator.proof.end());
            }
            std::pmr::vector<RawEdge> outgoing(memory);if(node.expand_direction==query::ExpandDirection::outgoing)expand_collect(state.current,profile,outgoing);
            const auto& edges=node.expand_direction==query::ExpandDirection::outgoing?outgoing:incoming;
            if(node.expand_direction==query::ExpandDirection::incoming&&!complete)
                expand_frontier(node,profile,seed,state,FrontierReason::incomplete,absent,UINT32_MAX,UINT32_MAX);
            for(const auto& edge:edges){work.charge();
                if(node.expand_direction==query::ExpandDirection::incoming){
                    const auto ref=entity(data.sources[edge.caller.source_index],query::Relation::method_refs,edge.target_ref);
                    const auto current=entity(data.sources[state.current.source_index],query::Relation::method_defs,state.current.ordinal);
                    if(!same_method_symbol(ref,current))continue;
                }
                auto targets=expand_targets(node,edge);
                if(node.expand_direction==query::ExpandDirection::outgoing&&!complete)
                    expand_frontier(node,profile,seed,state,FrontierReason::incomplete,edge.caller,edge.pc,edge.target_ref);
                if(targets.empty()){
                    if(node.expand_direction==query::ExpandDirection::outgoing&&complete)
                        expand_frontier(node,profile,seed,state,FrontierReason::unresolved,edge.caller,edge.pc,edge.target_ref);
                    continue;
                }
                for(const auto& target:targets){work.charge();
                    if(node.expand_direction==query::ExpandDirection::incoming&&target!=state.current)continue;
                    if(profile.edges>=node.expand_max_edges)throw query::Error(query::ErrorCode::budget,"expand edge limit exceeded");++profile.edges;
                    ExpandState next(memory);next.seed_index=state.seed_index;next.current=node.expand_direction==query::ExpandDirection::outgoing?target:edge.caller;
                    next.depth=state.depth+1;next.uncertain=state.uncertain;work.charge(state.hops.size()+state.walk_proof.size());
                    next.hops.assign(state.hops.begin(),state.hops.end());next.walk_proof.assign(state.walk_proof.begin(),state.walk_proof.end());
                    next.hops.push_back({edge.caller,target,edge.pc,edge.code_offset,edge.opcode,edge.target_ref,static_cast<uint32_t>(targets.size()),complete});enqueue(std::move(next));
                }
            }
        }
        }
        if(node.expand_output==query::ExpandOutput::endpoints)distinct(output,query::Identity::entity);
        return output;
    }
    Stage execute_node(uint32_t index){
        work.check();const auto& node=plan.relations[index];auto& metric=progress.graph->nodes[index];Stage out(memory);out.source_complete=source_complete(index);
        struct ScopeContext {GraphExecutor* executor;uint32_t node;};
        ScopeContext scope_context{this,index};
        const auto select_scope=[](void* raw,std::pmr::vector<uint32_t>& indices){
            const auto& context=*static_cast<ScopeContext*>(raw);context.executor->inheritance_sources(context.node,indices);
        };
        InheritanceScope inheritance(data,{},work,memory,select_scope,&scope_context);
        using Op=query::RelOp;
        if(node.op==Op::scan){
            for(const auto& source:data.sources){if(!selected(source,node))continue;
                if(query::is_use_relation(node.relation)){scan_uses(source,node,metric,out.rows,index==plan.relation_root);continue;}
                Evaluator evaluator(source,plan,work,memory,plan.has_inherited_predicate?&inheritance:nullptr,out.source_complete,cache,cache_scope);
                for(uint32_t ordinal=0;ordinal<relation_size(*source.facts,node.relation);++ordinal){
                    work.charge();++progress.visited;++progress.graph->entity_visited;++metric.visited_rows;++metric.input_rows;
                    const auto value=evaluator.run(ordinal,node.predicate,node.relation,node.stable_id);if(value==Truth::no)continue;
                    bounded(out.rows.size()+1);Candidate row(source.source_index,ordinal,memory,node.relation);row.uncertain=value==Truth::unknown;row.witnesses=std::move(evaluator.proof);out.rows.push_back(std::move(row));
                    if(index==plan.relation_root)offer(out.rows.back());
                }
            }
        }else if(node.op==Op::bounded_expand){
            auto input=execute_node(node.children[0]);metric.input_rows=input.rows.size();
            const bool resolution_complete=plan.explicit_scope||node.explicit_scope||data.scope_complete;
            const auto before_frontiers=expand_unknown_frontiers;
            out.rows=expand(input.rows,node,resolution_complete);
            out.opaque_unknown=input.opaque_unknown||expand_unknown_frontiers!=before_frontiers;
        }else if(node.op==Op::join||node.op==Op::semi_join){
            auto left=execute_node(node.children[0]);auto right=execute_node(node.children[1]);
            out.opaque_unknown=left.opaque_unknown||right.opaque_unknown;
            metric.input_rows=left.rows.size()+right.rows.size();
            if(node.op==Op::join){
                if(data.reverse_target_join && index==plan.relation_root)reverse_join(left.rows,right.rows,node,out.rows);
                else for(const auto& lhs:left.rows)for(const auto& rhs:right.rows){
                    if(!join_key(lhs,rhs,node.join_key))continue;
                    bounded(out.rows.size()+1);out.rows.push_back(pair(lhs,rhs,node));if(index==plan.relation_root)offer(out.rows.back());
                }
            }else{
                for(auto& lhs:left.rows){
                    const Candidate* matched=nullptr;bool possible=false;
                    for(const auto& rhs:right.rows){if(!join_key(lhs,rhs,node.join_key))continue;
                        if(rhs.uncertain){possible=true;continue;}matched=&rhs;break;
                    }
                    if(!matched&&!possible&&right.source_complete&&!right.opaque_unknown)continue;
                    for(auto& proof:lhs.proof_bindings)proof.binding=with_side(proof.binding,0);
                    if(matched){
                        const auto& rhs=*matched;add_links(lhs,rhs.links);lhs.links.push_back({node.stable_id,node.join_key,lhs.key(),rhs.key()});
                        lhs.proof_bindings.push_back({node.stable_id,with_side({query::none,rhs.key()},1)});
                        for(const auto& binding:rhs.bindings){work.charge();lhs.proof_bindings.push_back({node.stable_id,with_side(binding,1)});}
                        add_proofs(lhs,rhs.proof_bindings,1);add_evidence(lhs,rhs.witnesses);
                        // RHS paths prove existential membership; they do not
                        // change the identity of the projected left row.
                        append_expand_paths(lhs,rhs);
                    }else{lhs.uncertain=true;if(!right.source_complete||right.opaque_unknown)progress.scope_derived_unknown=true;}
                    bounded(out.rows.size()+1);out.rows.push_back(std::move(lhs));if(index==plan.relation_root)offer(out.rows.back());
                }
            }
        }else{
            for(auto child:node.children){auto input=execute_node(child);out.opaque_unknown|=input.opaque_unknown;metric.input_rows+=input.rows.size();const auto before=out.rows.size();append(out.rows,input.rows);
                if(index==plan.relation_root&&node.op==Op::union_rows&&node.bag)for(size_t i=before;i<out.rows.size();++i)offer(out.rows[i]);}
            if(node.op==Op::filter){Rows filtered(memory);
                for(auto& row:out.rows){work.charge();const auto& source=data.sources[row.source_index];Evaluator evaluator(source,plan,work,memory,plan.has_inherited_predicate?&inheritance:nullptr,out.source_complete,cache,cache_scope);
                    const auto value=query::is_use_relation(row.relation)?evaluator.run_use(use_record(result,row.key()),node.predicate,row.relation,node.stable_id):evaluator.run(row.method_ordinal,node.predicate,row.relation,node.stable_id);if(value==Truth::no)continue;
                    row.uncertain|=value==Truth::unknown;add_evidence(row,evaluator.proof);filtered.push_back(std::move(row));if(index==plan.relation_root)offer(filtered.back());
                }out.rows=std::move(filtered);
            }else if(node.op==Op::label){for(auto& row:out.rows){work.charge();row.bindings.push_back({node.label,row.key()});normalize(row);if(index==plan.relation_root)offer(row);}}
            else if(node.op==Op::distinct||(node.op==Op::union_rows&&!node.bag)){distinct(out.rows,node.identity);if(index==plan.relation_root)for(const auto& row:out.rows)offer(row);}
            else if(node.op==Op::group_by_owner){out.rows=group(out.rows,node,out.source_complete&&!out.opaque_unknown);if(index==plan.relation_root)for(const auto& row:out.rows)offer(row);}
            else if(node.op!=Op::union_rows)throw query::Error(query::ErrorCode::unsupported,"unsupported relation operator");
        }
        metric.output_rows=out.rows.size();uint64_t final_unknown=0;
        for(const auto& row:out.rows){work.charge();if(row.uncertain)++final_unknown;}
        metric.unknown_rows=final_unknown;
        metric.complete=out.source_complete&&!metric.unknown_rows&&!out.opaque_unknown;
        // Every outer operator retains path completeness, not only expand.
        for(const auto& row:out.rows)for(const auto& path:row.expand_paths){work.charge();if(path.uncertain)metric.complete=false;}
        return out;
    }
    bool less(const Candidate& a,const Candidate& b){
        work.charge();++progress.profile.sort_comparisons;
        const auto x=entity(data.sources[a.source_index],query::is_use_relation(a.relation)?query::Relation::method_defs:a.relation,a.method_ordinal);
        const auto y=entity(data.sources[b.source_index],query::is_use_relation(b.relation)?query::Relation::method_defs:b.relation,b.method_ordinal);
        const auto* ax=query::is_use_relation(a.relation)?&use_record(result,a.key()):nullptr;
        const auto* by=query::is_use_relation(b.relation)?&use_record(result,b.key()):nullptr;
        auto number=[](auto a,auto b){return a==b?0:a<b?-1:1;};
        for(auto order:plan.order){work.charge();int c=0;using F=query::SortField;
            if((ax||by)&&(order.field==F::flags||order.field==F::descriptor||order.field==F::value||order.field==F::method_index))
                throw query::Error(query::ErrorCode::unsupported,"order field does not apply to use rows");
            switch(order.field){case F::owner:c=compare_text(x.owner,y.owner,work);break;case F::name:c=compare_text(x.name,y.name,work);break;
            case F::prototype:c=compare_text(x.prototype,y.prototype,work);break;case F::descriptor:c=compare_text(x.type_descriptor,y.type_descriptor,work);break;
            case F::value:c=compare_text(x.value,y.value,work);break;case F::source_index:c=number(a.source_index,b.source_index);break;
            case F::local_index:c=number(a.method_ordinal,b.method_ordinal);break;case F::method_index:c=number(x.reference_index,y.reference_index);break;
            case F::flags:c=x.flags_known!=y.flags_known?(x.flags_known?1:-1):x.flags_known?number(x.access_flags,y.access_flags):0;break;
            case F::use_pc:if(!ax||!by)throw query::Error(query::ErrorCode::unsupported,"PC order requires use rows");c=number(ax->key.dex_pc,by->key.dex_pc);break;
            case F::use_opcode:if(!ax||!by)throw query::Error(query::ErrorCode::unsupported,"opcode order requires use rows");c=number(ax->opcode,by->opcode);break;
            case F::use_target_index:if(!ax||!by)throw query::Error(query::ErrorCode::unsupported,"target order requires use rows");c=number(ax->target_index,by->target_index);break;}
            if(c)return order.descending?c>0:c<0;
        }return identity_compare(a,b,query::Identity::tuple)<0;
    }
    void sorted(Rows& rows){
        std::pmr::vector<uint32_t> order(memory);order.reserve(rows.size());
        for(uint32_t i=0;i<rows.size();++i){work.charge();order.push_back(i);}
        std::sort(order.begin(),order.end(),[&](auto a,auto b){if(less(rows[a],rows[b]))return true;if(less(rows[b],rows[a]))return false;return a<b;});
        Rows sorted(memory);sorted.reserve(rows.size());for(auto i:order){work.charge();sorted.push_back(std::move(rows[i]));}rows=std::move(sorted);
    }
public:
    GraphExecutor(const DatasetView& data,const query::Plan& plan,Progress& progress,Work& work,std::pmr::memory_resource* memory,CandidateSink sink,FactsCache* shared_facts):data(data),plan(plan),progress(progress),work(work),memory(memory),result(memory),sink(sink),cache(shared_facts),cache_scope(shared_facts?shared_facts->admit_graph(plan):nullptr){if(cache&&!cache_scope&&!cache->method_provider())cache=nullptr;}
    Result run(){
        progress.graph.emplace(memory);auto& graph=*progress.graph;graph.root_node=plan.relations[plan.relation_root].stable_id;graph.nodes.resize(plan.relations.size());
        if(plan.explicit_scope)validate_slots(plan.scope_slots);
        std::pmr::vector<uint8_t> selected_sources(data.sources.size(),0,memory);
        for(size_t i=0;i<data.sources.size();++i)if(!data.sources[i].facts||data.sources[i].source_index!=i||data.sources[i].input_index>=data.input_slots.size())throw query::Error(query::ErrorCode::invalid,"source view identity is inconsistent");
        uint64_t total=0;
        for(size_t index=0;index<plan.relations.size();++index){work.charge();const auto& node=plan.relations[index];if(query::is_use_relation(node.relation))(void)use_kind(node.relation);else validate_entity_relation(node.relation);auto& metric=graph.nodes[index];metric.node=node.stable_id;metric.op=node.op;
            if(node.op==query::RelOp::bounded_expand){if(node.explicit_scope)validate_slots(node.scope_slots);for(const auto& source:data.sources)if(selected(source,node))selected_sources[source.source_index]=1;continue;}
            if(node.op!=query::RelOp::scan)continue;if(node.explicit_scope)validate_slots(node.scope_slots);
            const bool uses=query::is_use_relation(node.relation);metric.scan_domain=uses?ScanDomain::method_defs:ScanDomain::entity_records;
            for(const auto& source:data.sources)if(selected(source,node)){
                selected_sources[source.source_index]=1;
                const auto count=uses?source.facts->methods.size():size_t(relation_size(*source.facts,node.relation));
                if(count>UINT32_MAX||metric.total_rows>UINT32_MAX-count)throw query::Error(query::ErrorCode::budget,"relation scan counter exceeds uint32");
                metric.total_rows+=count;
            }
            if(uses)graph.method_total+=metric.total_rows;else graph.entity_total+=metric.total_rows;
            total+=metric.total_rows;if(total>UINT32_MAX)throw query::Error(query::ErrorCode::budget,"relation scan counters exceed uint32");
        }
        for(uint32_t i=0;i<selected_sources.size();++i)if(selected_sources[i])result.scope_sources.push_back(i);
        progress.total=static_cast<uint32_t>(total);progress.scope_source_count=static_cast<uint32_t>(result.scope_sources.size());progress.scope_complete=source_complete(plan.relation_root);
        auto root=execute_node(plan.relation_root);auto& rows=root.rows;
        if(plan.intent==query::Intent::unique)distinct(rows,plan.unique_identity);
        uint64_t final_unknown=expand_unknown_frontiers;Rows known(memory);
#ifdef DMG_TEST_JOB_COMMIT_BARRIER
        if(const auto barrier=test_graph_reduce_barrier.load(std::memory_order_acquire))barrier(1,progress.profile.work_units);
#endif
        for(auto& row:rows){work.charge();if(row.uncertain)++final_unknown;else{
            for(const auto& path:row.expand_paths){work.charge();if(path.uncertain)++final_unknown;}
            known.push_back(std::move(row));}}
        progress.profile.unknown_rows=final_unknown;
        progress.profile.matches_seen=known.size();
        std::pmr::vector<uint32_t> identities(memory);identities.reserve(known.size());
        for(uint32_t i=0;i<known.size();++i){work.charge();identities.push_back(i);}
        std::sort(identities.begin(),identities.end(),[&](auto a,auto b){const auto c=identity_compare(known[a],known[b],plan.unique_identity);return c?c<0:a<b;});
        uint32_t final_identity_count=0;
#ifdef DMG_TEST_JOB_COMMIT_BARRIER
        if(const auto barrier=test_graph_reduce_barrier.load(std::memory_order_acquire))barrier(2,progress.profile.work_units);
#endif
        for(size_t i=0;i<identities.size();++i)if(i==0||identity_compare(known[identities[i-1]],known[identities[i]],plan.unique_identity)!=0)++final_identity_count;
        graph.identity_count=final_identity_count;
        if(!plan.order.empty()||plan.intent==query::Intent::top_n)sorted(known);
        size_t limit=plan.intent==query::Intent::exists?1:plan.intent==query::Intent::unique?std::min(2u,plan.max_results):plan.max_results;
        if(unique_one_stream_shape(plan)){
            // A would-be limit is tentative until the caller's commit point.
            // Both sync and Job perform the same reserve, per-row charge and
            // final cancellation check, regardless of prior provisional rows.
            const bool would_limit=known.size()>limit;
#ifdef DMG_TEST_JOB_COMMIT_BARRIER
            if(would_limit)if(const auto barrier=test_graph_reduce_barrier.load(std::memory_order_acquire))barrier(3,progress.profile.work_units);
#endif
            const auto count=std::min(known.size(),limit);
            result.rows.reserve(count);
            for(size_t i=0;i<count;++i){work.charge();result.rows.push_back(std::move(known[i]));}
#ifdef DMG_TEST_JOB_COMMIT_BARRIER
            if(would_limit)if(const auto barrier=test_graph_reduce_barrier.load(std::memory_order_acquire))barrier(4,progress.profile.work_units);
#endif
            work.check();
            result.unique_one_limit_pending=would_limit;
            progress.order_verified=!would_limit&&progress.scope_complete&&!progress.profile.unknown_rows&&progress.visited==progress.total;
            return std::move(result);
        }
        if(known.size()>limit&&plan.intent!=query::Intent::exists&&plan.intent!=query::Intent::top_n&&!(plan.intent==query::Intent::unique&&limit==2))result.result_limit=true;
#ifdef DMG_TEST_JOB_COMMIT_BARRIER
        if(result.result_limit)if(const auto barrier=test_graph_reduce_barrier.load(std::memory_order_acquire))barrier(3,progress.profile.work_units);
#endif
        // A streaming Job has already published its allowed witnesses. Once
        // ResultLimit is known, avoid later allocation/work/cancel overriding
        // that terminal reason while copying rows the Job will not consume.
        if(result.result_limit&&sink.accept){progress.order_verified=false;return std::move(result);}
        const auto count=std::min(known.size(),limit);result.rows.reserve(count);for(size_t i=0;i<count;++i){work.charge();if(plan.required_capabilities&268435456u)annotate_caller_field(known[i]);result.rows.push_back(std::move(known[i]));}
        progress.order_verified=!result.result_limit&&progress.scope_complete&&!progress.profile.unknown_rows&&progress.visited==progress.total;
        if(!(result.result_limit&&sink.accept))work.check();return std::move(result);
    }
};
