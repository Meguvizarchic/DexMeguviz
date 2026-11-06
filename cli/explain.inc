void explain_check(dmg_status status){if(status!=DMG_OK)throw CliError(status,"compiled plan accessor failed");}
void explain_plan(std::ostream& out,const dmg_query* query){
    dmg_query_info info{};dmg_query_explain_v1 plan{};explain_check(dmg_query_get_info(query,&info));explain_check(dmg_query_get_explain_v1(query,&plan,sizeof(plan)));
    out<<"{\"schema_version\":1,\"command\":\"explain\",\"input_scanned\":false,\"query_id\":"<<json_quote_ascii(info.query_id)
       <<",\"profile_v1\":{\"producer\":\"native-query\",\"phase\":\"planned\",\"runtime\":null,\"plan\":{\"relation\":"<<json_quote_ascii(relation_name(plan.relation))
       <<",\"intent\":"<<info.intent<<",\"predicate_nodes\":"<<info.node_count<<",\"required_capabilities\":"<<info.required_capabilities<<",\"demand_mask\":"<<info.demand_mask<<",\"projection_mask\":"<<info.projection_mask
       <<",\"max_results\":"<<info.max_results<<",\"max_work\":"<<info.max_work<<",\"max_intermediate_rows\":"<<plan.max_intermediate_rows<<",\"unique_identity\":"<<plan.unique_identity
       <<",\"root_operator_node\":";nullable_id(out,plan.root_operator_node);
    out<<",\"execution_model\":\"reference-scalar\",\"selection_reason\":\"Scalar semantics are the baseline; index/cache use needs a runtime dataset and explicit options\",\"scope\":{\"explicit\":"<<(info.explicit_scope?"true":"false")<<",\"complete\":null,\"slots\":[";
    for(uint32_t i=0;i<plan.scope_count;++i){const char* value=nullptr;explain_check(dmg_query_get_explain_scope_v1(query,UINT32_MAX,i,&value));if(i)out<<',';out<<json_quote_ascii(value);}out<<"]},\"operators\":[";
    for(uint32_t i=0;i<plan.operator_count;++i){dmg_query_operator_v1 n{};explain_check(dmg_query_get_explain_operator_v1(query,i,&n,sizeof(n)));if(i)out<<',';
        out<<"{\"node_id\":"<<n.node_id<<",\"op\":"<<json_quote_ascii(operator_name(n.op))<<",\"relation\":"<<json_quote_ascii(relation_name(n.relation))<<",\"predicate_node\":";nullable_id(out,n.predicate_node);
        out<<",\"children\":[";for(uint32_t j=0;j<n.child_count;++j){uint32_t id=0;explain_check(dmg_query_get_explain_child_v1(query,i,j,&id));if(j)out<<',';out<<id;}
        out<<"],\"scope\":{\"explicit\":"<<(n.explicit_scope?"true":"false")<<",\"slots\":[";for(uint32_t j=0;j<n.scope_count;++j){const char* value=nullptr;explain_check(dmg_query_get_explain_scope_v1(query,i,j,&value));if(j)out<<',';out<<json_quote_ascii(value);}out<<"]}";
        if(n.op==2||n.op==3)out<<",\"semantics\":"<<json_quote_ascii(n.bag?"bag":"set")<<",\"identity\":"<<n.identity;
        if(n.op==4)out<<",\"label\":"<<json_quote_ascii(n.label);
        if(n.op==6||n.op==7)out<<",\"join_key\":"<<json_quote_ascii(join_key_name(n.join_key));
        if(n.op==5){out<<",\"minimum\":"<<n.minimum<<",\"maximum\":"<<n.maximum<<",\"distinct_roles\":"<<(n.distinct_roles?"true":"false")<<",\"roles\":[";for(uint32_t j=0;j<n.role_count;++j){const char* value=nullptr;explain_check(dmg_query_get_explain_role_v1(query,i,j,&value));if(j)out<<',';out<<json_quote_ascii(value);}out<<']';}
        if(n.op==8){out<<",\"direction\":"<<json_quote_ascii(n.expand_direction?"incoming":"outgoing")<<",\"output\":"<<json_quote_ascii(n.expand_output?"endpoints":"paths")<<",\"min_depth\":"<<n.expand_min_depth<<",\"max_depth\":"<<n.expand_max_depth<<",\"walk_node\":";nullable_id(out,n.expand_walk_node);out<<",\"emit_node\":";nullable_id(out,n.expand_emit_node);out<<",\"max_visited\":"<<n.expand_max_visited<<",\"max_edges\":"<<n.expand_max_edges<<",\"max_paths\":"<<n.expand_max_paths;}
        out<<'}';
    }
    out<<"],\"order\":[";for(uint32_t i=0;i<plan.order_count;++i){dmg_query_order_v1 key{};explain_check(dmg_query_get_explain_order_v1(query,i,&key,sizeof(key)));if(i)out<<',';out<<"{\"field\":"<<key.field<<",\"descending\":"<<(key.descending?"true":"false")<<'}';}
    out<<"]}}}\n";
}
