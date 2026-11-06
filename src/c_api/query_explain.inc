// Snapshot-free views of an immutable compiled plan. Enum values are the same
// versioned operation/relation/identity domains used by the result profiles.
dmg_status dmg_query_get_explain_v1(const dmg_query* query,dmg_query_explain_v1* out,uint32_t size){
    if(!query||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;
    const auto& p=*query->query->plan;if(p.class_annotation_requested)return DMG_UNSUPPORTED;
    *out={static_cast<uint32_t>(p.relation),static_cast<uint32_t>(p.relations.size()),
        p.relation_root==dexmeguviz::query::none?UINT32_MAX:p.relations[p.relation_root].stable_id,
        static_cast<uint32_t>(p.scope_slots.size()),static_cast<uint32_t>(p.order.size()),
        p.max_intermediate_rows,static_cast<uint32_t>(p.unique_identity),p.contains_expand?1u:0u};return DMG_OK;
}
dmg_status dmg_query_get_explain_operator_v1(const dmg_query* query,uint32_t index,dmg_query_operator_v1* out,uint32_t size){
    if(query&&query->query->plan->class_annotation_requested)return DMG_UNSUPPORTED;
    if(!query||!out||size!=sizeof(*out)||index>=query->query->plan->relations.size())return DMG_INVALID_ARGUMENT;
    const auto& p=*query->query->plan;const auto& n=p.relations[index];dmg_query_operator_v1 v{};
    v.node_id=n.stable_id;v.op=static_cast<uint32_t>(n.op);v.relation=static_cast<uint32_t>(n.relation);
    v.predicate_node=n.predicate==dexmeguviz::query::none?UINT32_MAX:p.nodes[n.predicate].stable_id;
    v.child_count=static_cast<uint32_t>(n.children.size());v.scope_count=static_cast<uint32_t>(n.scope_slots.size());v.explicit_scope=n.explicit_scope?1:0;
    v.bag=n.bag?1:0;v.identity=static_cast<uint32_t>(n.identity);v.join_key=static_cast<uint32_t>(n.join_key);v.minimum=n.minimum;v.maximum=n.maximum;
    v.role_count=static_cast<uint32_t>(n.required_roles.size());v.distinct_roles=n.distinct_roles?1:0;v.label=n.label==dexmeguviz::query::none?nullptr:p.labels[n.label].c_str();
    v.expand_direction=static_cast<uint32_t>(n.expand_direction);v.expand_output=static_cast<uint32_t>(n.expand_output);v.expand_min_depth=n.expand_min_depth;v.expand_max_depth=n.expand_max_depth;
    v.expand_walk_node=n.expand_walk_predicate==dexmeguviz::query::none?UINT32_MAX:p.nodes[n.expand_walk_predicate].stable_id;v.expand_emit_node=n.expand_emit_predicate==dexmeguviz::query::none?UINT32_MAX:p.nodes[n.expand_emit_predicate].stable_id;
    v.expand_max_visited=n.expand_max_visited;v.expand_max_edges=n.expand_max_edges;v.expand_max_paths=n.expand_max_paths;*out=v;return DMG_OK;
}
dmg_status dmg_query_get_explain_child_v1(const dmg_query* query,uint32_t index,uint32_t child,uint32_t* out){
    if(query&&query->query->plan->class_annotation_requested)return DMG_UNSUPPORTED;
    if(!query||!out||index>=query->query->plan->relations.size())return DMG_INVALID_ARGUMENT;
    const auto& p=*query->query->plan;const auto& n=p.relations[index];if(child>=n.children.size())return DMG_INVALID_ARGUMENT;
    *out=p.relations[n.children[child]].stable_id;return DMG_OK;
}
dmg_status dmg_query_get_explain_scope_v1(const dmg_query* query,uint32_t index,uint32_t slot,const char** out){
    if(query&&query->query->plan->class_annotation_requested)return DMG_UNSUPPORTED;
    if(!query||!out)return DMG_INVALID_ARGUMENT;const auto& p=*query->query->plan;
    if(index!=UINT32_MAX&&index>=p.relations.size())return DMG_INVALID_ARGUMENT;
    const auto& slots=index==UINT32_MAX?p.scope_slots:p.relations[index].scope_slots;
    if(slot>=slots.size())return DMG_INVALID_ARGUMENT;*out=slots[slot].c_str();return DMG_OK;
}
dmg_status dmg_query_get_explain_role_v1(const dmg_query* query,uint32_t index,uint32_t role,const char** out){
    if(query&&query->query->plan->class_annotation_requested)return DMG_UNSUPPORTED;
    if(!query||!out||index>=query->query->plan->relations.size())return DMG_INVALID_ARGUMENT;
    const auto& p=*query->query->plan;const auto& n=p.relations[index];if(role>=n.required_roles.size())return DMG_INVALID_ARGUMENT;
    *out=p.labels[n.required_roles[role]].c_str();return DMG_OK;
}
dmg_status dmg_query_get_explain_order_v1(const dmg_query* query,uint32_t index,dmg_query_order_v1* out,uint32_t size){
    if(query&&query->query->plan->class_annotation_requested)return DMG_UNSUPPORTED;
    if(!query||!out||size!=sizeof(*out)||index>=query->query->plan->order.size())return DMG_INVALID_ARGUMENT;
    const auto& key=query->query->plan->order[index];*out={static_cast<uint32_t>(key.field),key.descending?1u:0u};return DMG_OK;
}

// Versioned direct-query slot view. It is not a general v2 plan explanation.
dmg_status dmg_query_get_scope_v2(const dmg_query* query,dmg_query_scope_v2* out,uint32_t size){
    if(!query||!out||size!=sizeof(*out))return DMG_INVALID_ARGUMENT;
    const auto& p=*query->query->plan;if(p.relation_root!=dexmeguviz::query::none)return DMG_UNSUPPORTED;
    const dmg_query_scope_v2 value{p.explicit_scope?1u:0u,static_cast<uint32_t>(p.scope_slots.size())};*out=value;return DMG_OK;
}
dmg_status dmg_query_get_scope_slot_v2(const dmg_query* query,uint32_t index,const char** out){
    if(!query||!out)return DMG_INVALID_ARGUMENT;const auto& p=*query->query->plan;
    if(p.relation_root!=dexmeguviz::query::none)return DMG_UNSUPPORTED;
    if(index>=p.scope_slots.size())return DMG_INVALID_ARGUMENT;*out=p.scope_slots[index].c_str();return DMG_OK;
}
