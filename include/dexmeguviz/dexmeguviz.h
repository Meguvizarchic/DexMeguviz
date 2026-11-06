#ifndef DEXMEGUVIZ_H
#define DEXMEGUVIZ_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define DMG_ABI_VERSION 1u
#define DMG_MAX_SOURCE_BYTES (16u * 1024u * 1024u)
typedef struct dmg_snapshot dmg_snapshot;
typedef struct dmg_result dmg_result;
typedef struct dmg_engine dmg_engine;
typedef struct dmg_query dmg_query;
typedef struct dmg_job dmg_job;
typedef struct dmg_result dmg_batch;
typedef struct dmg_multi_batch_v1 dmg_multi_batch_v1;
typedef uint32_t dmg_status;
enum { DMG_OK=0, DMG_INVALID_ARGUMENT=1, DMG_CORRUPT_INPUT=2,
       DMG_UNSUPPORTED=3, DMG_BUDGET_EXCEEDED=4, DMG_OUT_OF_MEMORY=5,
       DMG_INTERNAL_ERROR=6, DMG_CLOSED=7, DMG_SOURCE_MISMATCH=8,
       DMG_CANCELLED=9, DMG_DEADLINE_EXCEEDED=10, DMG_NOT_READY=11,
       DMG_END_OF_STREAM=12 };
enum { DMG_ENUMERATE=0, DMG_EXISTS=1, DMG_UNIQUE=2, DMG_TOP_N=3 };
enum { DMG_EXACT=0, DMG_CONTAINS=1 };
enum { DMG_COVERAGE_COMPLETE=0, DMG_COVERAGE_PARTIAL=1 };
enum { DMG_NOT_APPLICABLE=0, DMG_UNDETERMINED=1, DMG_PROVEN_FALSE=2, DMG_PROVEN_TRUE=3 };
enum { DMG_REASON_NONE=0, DMG_NO_MATCH=1, DMG_AMBIGUOUS=2, DMG_WITNESS=3, DMG_RESULT_LIMIT=4, DMG_SOURCE_SCOPE_INCOMPLETE=5, DMG_UNKNOWN_ATTRIBUTE=6 };
typedef struct { uint64_t offset; char message[256]; } dmg_error;
typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint64_t max_source_bytes;
    const char* source_namespace;
    const char* slot_key;
    const char* expected_sha256;
} dmg_open_options;
typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t intent;
    uint32_t name_enabled;
    uint32_t name_operator;
    uint32_t owner_enabled;
    const uint16_t* name;
    uint64_t name_length;
    const uint16_t* owner;
    uint64_t owner_length;
    uint32_t flags_contains;
    uint32_t max_results;
} dmg_method_query;
typedef struct {
    uint32_t dex_version;
    uint32_t string_count;
    uint32_t type_count;
    uint32_t class_count;
    uint32_t method_ref_count;
    uint32_t method_def_count;
    uint64_t source_bytes;
    const char* source_sha256;
    const char* content_id;
    const char* occurrence_id;
    const char* snapshot_id;
} dmg_snapshot_info;
typedef struct {
    uint32_t execution_status;
    uint32_t coverage;
    uint32_t decision;
    uint32_t reason;
    uint32_t candidates_count;
    uint32_t visited_methods;
    uint32_t total_methods;
} dmg_result_info;
typedef struct {
    uint32_t method_index;
    uint32_t access_flags;
    uint32_t declaration_offset;
    uint32_t code_offset;
    const uint16_t* owner;
    uint64_t owner_length;
    const uint16_t* name;
    uint64_t name_length;
    const uint16_t* prototype;
    uint64_t prototype_length;
} dmg_method_row;

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint64_t owned_bytes_limit;
    uint64_t borrowed_bytes_limit;
    uint64_t max_source_bytes;
    uint32_t max_jobs;
    uint32_t reserved;
} dmg_engine_options;
typedef struct {
    uint64_t owned_bytes;
    uint64_t peak_owned_bytes;
    uint64_t source_bytes;
    uint64_t fact_bytes;
    uint64_t scratch_bytes;
    uint64_t query_bytes;
    uint64_t result_bytes;
    uint64_t control_bytes;
    uint64_t borrowed_bytes;
    uint32_t active_jobs;
    uint32_t admission_closed;
} dmg_engine_stats;
typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    void* context;
    /* Both callbacks must be noexcept, thread-safe and keep bytes immutable. */
    void (*retain)(void* context);
    void (*release)(void* context);
    uint32_t immutable;
    uint32_t reserved;
} dmg_buffer_lease;
typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t batch_size;
    uint32_t max_queued_batches;
    uint64_t deadline_after_ms;
} dmg_job_options;
enum { DMG_JOB_QUEUED=0, DMG_JOB_RUNNING=1, DMG_JOB_COMPLETED=2,
       DMG_JOB_CANCELLED=3, DMG_JOB_FAILED=4 };
typedef struct {
    uint32_t lifecycle;
    uint32_t terminal;
    dmg_result_info outcome;
    dmg_error error;
} dmg_job_status;
typedef struct {
    const char* query_id;
    uint32_t node_count,required_capabilities,demand_mask,projection_mask;
    uint32_t intent,max_results,explicit_scope;
    uint64_t max_work;
} dmg_query_info;
/* Versioned complete capability view. legacy.required_capabilities is the old
 * 32-bit portion only; extended_capabilities is a semicolon-separated string
 * and is empty for old profiles. Strings borrow the query/result/job lifetime.
 * Every getter requires exact out_size; errors leave output unchanged. */
typedef struct {dmg_query_info legacy;const char* extended_capabilities;} dmg_query_info_v2;

typedef struct {
    uint64_t work_units,fact_requests,methods_decoded,code_units;
    uint64_t string_pool_lookups,invoke_sites,field_uses,declared_fields;
    uint64_t matches_seen,sort_comparisons;
    uint32_t scope_source_count,scope_complete,order_verified;
} dmg_query_profile;
typedef struct {
    uint32_t kind,node_id,matched,dex_pc,opcode,reference_index,reference_kind,extra_proto,code_units;
} dmg_witness;
enum { DMG_WITNESS_METADATA=1, DMG_WITNESS_STRING=2, DMG_WITNESS_INVOKE=3,
       DMG_WITNESS_FIELD=4, DMG_WITNESS_INSTRUCTION_SCOPE=5,
       DMG_WITNESS_NO_BODY=6, DMG_WITNESS_STRING_POOL_ABSENCE=7, DMG_WITNESS_INHERITED=8, DMG_WITNESS_NUMERIC=9, DMG_WITNESS_INTERFACE=10, DMG_WITNESS_INTERFACE_RESOLVED=11, DMG_WITNESS_FIELD_DECLARATION=12, DMG_WITNESS_CALLER_FIELD_RELATION=13, DMG_WITNESS_CLASS_ANNOTATION_FLAGS=14, DMG_WITNESS_TYPE_USE=15 };
/* Inherited proof items use class occurrence/ordinal for path, end and branch;
 * field occurrence/ordinal for field items. Indices are local to one leaf.
 * aux/detail are item-specific and documented in inherited-query-v6.md. */
enum { DMG_INHERITED_OWNER_UNKNOWN=0, DMG_INHERITED_PATH=1, DMG_INHERITED_END=2,
       DMG_INHERITED_BRANCH=3, DMG_INHERITED_FIELD=4 };
enum { DMG_INHERITED_LINK_ROOT=0, DMG_INHERITED_LINK_SINGLE=1, DMG_INHERITED_LINK_AMBIGUOUS=2 };
enum { DMG_INHERITED_END_NO_SUPERCLASS=0, DMG_INHERITED_END_MISSING=1,
       DMG_INHERITED_END_INCOMPLETE_SCOPE=2, DMG_INHERITED_END_CYCLE=3 };
typedef struct {
    uint32_t node_id,matched,item_kind,path_index,aux,branch_index,detail;
    uint32_t source_index,relation,local_index;
} dmg_inherited_witness;
/* v8 interface graph items: 0 unknown owner; 1 node; 2 edge; 3 frontier;
 * 4 field; 5 branch. Indices are local to one branch of one predicate. */
typedef struct {
    uint32_t node_id,matched,operator_node,item_kind,branch_index,node_index,aux,detail;
    uint32_t source_index,relation,local_index;
} dmg_interface_witness_v1;
enum { DMG_PROJECT_OWNER=1, DMG_PROJECT_NAME=2, DMG_PROJECT_PROTOTYPE=4, DMG_PROJECT_TYPE=8, DMG_PROJECT_VALUE=16 };
enum { DMG_METHOD_DEFS=0, DMG_CLASS_DEFS=1, DMG_FIELD_DEFS=2, DMG_METHOD_REFS=3,
       DMG_FIELD_REFS=4, DMG_STRING_VALUES=5, DMG_TYPE_REFS=6, DMG_STRING_USES=7, DMG_INVOKE_SITES=8, DMG_FIELD_USES=9, DMG_TYPE_USES=10 };
/* Witness matched records the leaf predicate result before enclosing negation. */
enum { DMG_MATCH_FALSE=0, DMG_MATCH_TRUE=1, DMG_MATCH_UNKNOWN=2 };
typedef struct {
    uint32_t relation,source_index,local_index,reference_index,record_offset;
    uint32_t definition_known,definition_offset,flags_known,access_flags,code_known,code_offset;
    const uint16_t* owner;uint64_t owner_length;
    const uint16_t* name;uint64_t name_length;
    const uint16_t* prototype;uint64_t prototype_length;
    const uint16_t* type_descriptor;uint64_t type_descriptor_length;
    const uint16_t* string_value;uint64_t string_value_length;
} dmg_entity_row;
typedef struct {
    uint32_t relation,execution_status,coverage,decision,reason,candidates_count,visited_rows,total_rows;
    uint64_t unknown_rows;
} dmg_relation_info;
typedef struct {
    uint32_t lifecycle,terminal;
    dmg_relation_info outcome;
    dmg_error error;
} dmg_relation_job_status;
/* Exact output size is checked before writing; borrowed views live as long as result. */
dmg_status dmg_result_get_entity(const dmg_result* result,uint32_t row,dmg_entity_row* out,uint32_t out_size);
dmg_status dmg_result_get_relation_info(const dmg_result* result,dmg_relation_info* out,uint32_t out_size);
dmg_status dmg_job_get_relation_status(const dmg_job* job,dmg_relation_job_status* out,uint32_t out_size);
dmg_status dmg_job_wait_relation(dmg_job* job,uint32_t timeout_ms,dmg_relation_job_status* out,uint32_t out_size);
enum { DMG_IDENTITY_ENTITY=0, DMG_IDENTITY_TUPLE=1 };
enum { DMG_REL_SCAN=0, DMG_REL_FILTER=1, DMG_REL_UNION=2, DMG_REL_DISTINCT=3, DMG_REL_LABEL=4, DMG_REL_GROUP_BY_OWNER=5, DMG_REL_JOIN=6, DMG_REL_SEMI_JOIN=7, DMG_REL_BOUNDED_EXPAND=8 };
enum { DMG_JOIN_SAME_ENTITY=0, DMG_JOIN_LOCAL_DEFINITION=1, DMG_JOIN_LOCAL_OWNER=2, DMG_JOIN_SYMBOL=3, DMG_JOIN_CALLER=4, DMG_JOIN_TARGET_REF=5, DMG_JOIN_TARGET_SYMBOL=6 };
enum { DMG_PATH_LEFT=0, DMG_PATH_RIGHT=1 };
enum { DMG_VALUE_ENTITY=0, DMG_VALUE_USE=1 };
enum { DMG_TARGET_STRING_VALUE=0, DMG_TARGET_FIELD_REF=1, DMG_TARGET_METHOD_REF=2, DMG_TARGET_METHOD_AND_PROTO=3, DMG_TARGET_CALL_SITE=4, DMG_TARGET_TYPE_REF=5 };
/* Experimental per-snapshot, per-source reverse-use count; no QueryIR planner integration. */
enum { DMG_REVERSE_STRING_USE_V1=0, DMG_REVERSE_INVOKE_SITE_V1=1, DMG_REVERSE_FIELD_USE_V1=2 };
typedef uint32_t (*dmg_reverse_cancel_v1)(void* context);
typedef struct {uint32_t struct_size,abi_version;uint64_t max_work,max_index_bytes;uint32_t max_records,reserved;dmg_reverse_cancel_v1 cancelled;void* cancel_context;} dmg_reverse_options_v1;
typedef struct {uint64_t build_attempts,builds,build_failures,reuses,published_indexes,published_records;} dmg_reverse_profile_v1;
/* Exact-size profile and count outputs are unchanged on failure. The snapshot must
 * stay alive; cancellation must not reenter a reverse API. See the draft contract. */
dmg_status dmg_snapshot_reverse_profile_v1(const dmg_snapshot* snapshot,dmg_reverse_profile_v1* out,uint32_t out_size);
dmg_status dmg_snapshot_reverse_count_v1(dmg_snapshot* snapshot,uint32_t source_index,uint32_t use_kind,uint32_t target_domain,
    uint32_t target_index,uint32_t extra_proto,const dmg_reverse_options_v1* options,uint64_t* out_count,dmg_error* error);
/* Fixed copied event values, ordered by caller ordinal then DEX code-unit PC. */
typedef struct {
    uint32_t source_index,use_kind,caller_ordinal,caller_method_ref,dex_pc,opcode,code_offset,target_domain,target_index,extra_proto;
} dmg_reverse_event_v1;
/* capacity 0 permits NULL events; otherwise 1..4096 records. offset==total
 * returns an empty page; offset>total is invalid. All output is unchanged on error. */
dmg_status dmg_snapshot_reverse_page_v1(dmg_snapshot* snapshot,uint32_t source_index,uint32_t use_kind,uint32_t target_domain,
    uint32_t target_index,uint32_t extra_proto,const dmg_reverse_options_v1* options,uint64_t offset,
    dmg_reverse_event_v1* out_events,uint32_t capacity,uint32_t* out_count,uint64_t* out_total,dmg_error* error);


/* Experimental synchronous v4 direct invoke_sites -> method_refs target_ref
 * join. Extra index/adapter limits are independent of QueryIR max_work.
 * Unsupported shapes fail explicitly. No Job or multi-rule opt-in is provided. */
typedef struct {uint32_t struct_size,abi_version;uint64_t max_index_work,max_index_bytes,max_adapter_work;uint32_t max_records,max_page_calls,reserved0,reserved1;} dmg_reverse_join_options_v1;
dmg_status dmg_query_execute_reverse_target_v1(dmg_snapshot* snapshot,dmg_query* query,
    const dmg_reverse_join_options_v1* options,dmg_result** out,dmg_error* error);
/* Separate experimental synchronous v4 field_uses -> field_refs target_ref join.
 * The method-target entry above continues to reject this field shape. */
dmg_status dmg_query_execute_reverse_field_target_v1(dmg_snapshot* snapshot,dmg_query* query,
    const dmg_reverse_join_options_v1* options,dmg_result** out,dmg_error* error);
/* Separate experimental synchronous v4 string_uses -> string_values target_ref
 * join. The earlier method and field entries continue to reject this shape. */
dmg_status dmg_query_execute_reverse_string_target_v1(dmg_snapshot* snapshot,dmg_query* query,
    const dmg_reverse_join_options_v1* options,dmg_result** out,dmg_error* error);
/* Experimental v2 direct target_ref join, selected intersection requests. */
dmg_status dmg_query_execute_reverse_intersection_v2(dmg_snapshot* snapshot,dmg_query* query,
    const dmg_reverse_join_options_v1* options,dmg_result** out,dmg_error* error);

enum { DMG_SCAN_DOMAIN_NONE=0, DMG_SCAN_DOMAIN_ENTITY_RECORDS=1, DMG_SCAN_DOMAIN_METHOD_DEFS=2 };
typedef struct {const char* label;dmg_entity_row entity;} dmg_binding_row;
typedef struct {const uint8_t* sides;uint32_t length;} dmg_binding_path;
typedef struct {uint32_t operator_node;dmg_binding_row binding;} dmg_proof_binding_row;
typedef struct {uint32_t node_id,key,left_source,left_relation,left_local,right_source,right_relation,right_local;} dmg_relation_link;
typedef struct {
    uint32_t relation,source_index,caller_ordinal,caller_method_ref,dex_pc,opcode,code_offset,target_domain,target_index,extra_proto;
    const uint16_t* owner;uint64_t owner_length;
    const uint16_t* name;uint64_t name_length;
    const uint16_t* prototype;uint64_t prototype_length;
} dmg_use_row;
typedef struct {uint32_t kind;dmg_entity_row entity;dmg_use_row use;} dmg_value_row_v2;
typedef struct {uint32_t relation,source_index,local_index,dex_pc;} dmg_value_identity_v2;
typedef struct {const char* label;dmg_value_row_v2 value;} dmg_binding_row_v2;
typedef struct {uint32_t operator_node;dmg_binding_row_v2 binding;} dmg_proof_binding_row_v2;
typedef struct {uint32_t node_id,key;dmg_value_identity_v2 left,right;} dmg_relation_link_v2;
typedef struct {dmg_witness witness;uint32_t operator_node;dmg_value_identity_v2 entity;} dmg_relation_witness_v2;
typedef struct {
    uint32_t relation,execution_status,coverage,decision,reason,candidates_count;
    uint64_t entity_visited,entity_total,method_visited,method_total,events_collected,unknown_rows;
} dmg_relation_info_v2;
typedef struct {uint32_t lifecycle,terminal;dmg_relation_info_v2 outcome;dmg_error error;} dmg_relation_job_status_v2;
typedef struct {
    uint32_t node_id,op,scan_domain,complete;
    uint64_t input_rows,output_rows,unknown_rows,visited,total,attempted_methods,no_body_methods,decoded_methods,events_collected,code_units;
} dmg_operator_profile_v2;
typedef struct {dmg_witness witness;uint32_t operator_node,source_index,relation,local_index;} dmg_relation_witness;
typedef struct {uint32_t root_node,unique_identity,identity_count,operator_count;} dmg_graph_info;
typedef struct {
    uint32_t node_id,op;
    uint64_t input_rows,output_rows,unknown_rows,visited_rows,total_rows;
    uint32_t complete;
} dmg_operator_profile;
/* v21 explicit type-use semantics. Legacy v2 result/status getters reject v21.
 * The target descriptor view belongs to the Result/Batch and is NULL for non-type values. */
typedef struct {dmg_value_row_v2 value;const uint16_t* target_descriptor;uint64_t target_descriptor_length;} dmg_value_row_v3;
typedef struct {const char* label;dmg_value_row_v3 value;} dmg_binding_row_v3;
typedef struct {uint32_t operator_node;dmg_binding_row_v3 binding;} dmg_proof_binding_row_v3;
typedef dmg_relation_link_v2 dmg_relation_link_v3;
typedef dmg_relation_witness_v2 dmg_relation_witness_v3;
typedef dmg_relation_info_v2 dmg_relation_info_v3;
typedef dmg_relation_job_status_v2 dmg_relation_job_status_v3;
typedef dmg_operator_profile_v2 dmg_operator_profile_v3;
dmg_status dmg_result_get_value_v3(const dmg_result* result,uint32_t row,dmg_value_row_v3* out,uint32_t out_size);
dmg_status dmg_result_get_binding_v3(const dmg_result* result,uint32_t row,uint32_t index,dmg_binding_row_v3* out,uint32_t out_size);
dmg_status dmg_result_get_proof_binding_v3(const dmg_result* result,uint32_t row,uint32_t index,dmg_proof_binding_row_v3* out,uint32_t out_size);
dmg_status dmg_result_get_link_v3(const dmg_result* result,uint32_t row,uint32_t index,dmg_relation_link_v3* out,uint32_t out_size);
dmg_status dmg_result_get_relation_witness_v3(const dmg_result* result,uint32_t row,uint32_t index,dmg_relation_witness_v3* out,uint32_t out_size);
dmg_status dmg_result_get_relation_info_v3(const dmg_result* result,dmg_relation_info_v3* out,uint32_t out_size);
dmg_status dmg_result_get_operator_profile_v3(const dmg_result* result,uint32_t index,dmg_operator_profile_v3* out,uint32_t out_size);
dmg_status dmg_job_get_relation_status_v3(const dmg_job* job,dmg_relation_job_status_v3* out,uint32_t out_size);
dmg_status dmg_job_wait_relation_v3(dmg_job* job,uint32_t timeout_ms,dmg_relation_job_status_v3* out,uint32_t out_size);
dmg_status dmg_job_get_operator_profile_v3(const dmg_job* job,uint32_t index,dmg_operator_profile_v3* out,uint32_t out_size);
/* v5 expand views retain their owning result/batch or terminal job. All sized
   getters require the exact output size and do not write on error. */
enum { DMG_EXPAND_UNRESOLVED=0, DMG_EXPAND_INCOMPLETE=1, DMG_EXPAND_UNKNOWN_WALK=2, DMG_EXPAND_UNKNOWN_EMIT=3 };
enum { DMG_EXPAND_SEED_WITNESS=0, DMG_EXPAND_WALK_WITNESS=1, DMG_EXPAND_EMIT_WITNESS=2 };
typedef struct {
    dmg_relation_info_v2 outcome;dmg_query_profile profile;dmg_graph_info graph;
    uint32_t frontier_count,total_candidates,expand_profile_count;
} dmg_expand_info;
typedef struct {uint32_t lifecycle,terminal;dmg_expand_info info;dmg_error error;} dmg_expand_job_status;
typedef struct {uint32_t node_id;uint64_t visited,edges,paths,decoded_methods,unresolved,unknown_frontiers,reverse_builds,reverse_reuses;} dmg_expand_profile;
typedef struct {
    uint32_t node_id,uncertain,seed_binding_count,hop_count,seed_link_count,seed_proof_count,seed_witness_count,walk_witness_count,emit_witness_count;
    dmg_value_identity_v2 seed,endpoint;
} dmg_expand_path_info;
typedef struct {const char* label;dmg_value_row_v2 value;dmg_binding_path path;} dmg_expand_binding;
typedef struct {uint32_t operator_node;dmg_expand_binding binding;} dmg_expand_proof;
typedef struct {uint32_t binding_count,link_count,proof_count,witness_count;} dmg_expand_row_evidence_info;
/* Outer relational evidence, independent of each traversal's grouped paths.
 * Result and Job-batch views use the same accessors and borrowed lifetimes. */
dmg_status dmg_result_get_expand_row_evidence_info(const dmg_result*,uint32_t,dmg_expand_row_evidence_info*,uint32_t);
dmg_status dmg_result_get_expand_row_binding(const dmg_result*,uint32_t,uint32_t,dmg_expand_binding*,uint32_t);
dmg_status dmg_result_get_expand_row_link(const dmg_result*,uint32_t,uint32_t,dmg_relation_link_v2*,uint32_t);
dmg_status dmg_result_get_expand_row_proof(const dmg_result*,uint32_t,uint32_t,dmg_expand_proof*,uint32_t);
dmg_status dmg_result_get_expand_row_witness(const dmg_result*,uint32_t,uint32_t,dmg_relation_witness_v2*,uint32_t);
typedef struct {
    dmg_value_identity_v2 caller,resolved;
    uint32_t dex_pc,code_offset,opcode,target_method_ref,candidate_count,resolution_complete;
    dmg_entity_row target_symbol;
} dmg_expand_hop;
typedef struct {
    uint32_t node_id,depth,reason,dex_pc,target_method_ref,has_target_symbol,seed_binding_count,prefix_count,
             seed_link_count,seed_proof_count,seed_witness_count,walk_witness_count,emit_witness_count;
    dmg_value_identity_v2 seed,current,caller;dmg_entity_row target_symbol;
} dmg_expand_frontier;
dmg_status dmg_result_get_expand_info(const dmg_result*,dmg_expand_info*,uint32_t);
dmg_status dmg_job_get_expand_status(const dmg_job*,dmg_expand_job_status*,uint32_t);
dmg_status dmg_job_wait_expand(dmg_job*,uint32_t,dmg_expand_job_status*,uint32_t);
dmg_status dmg_result_get_expand_profile(const dmg_result*,uint32_t,dmg_expand_profile*,uint32_t);
dmg_status dmg_job_get_expand_profile(const dmg_job*,uint32_t,dmg_expand_profile*,uint32_t);
dmg_status dmg_result_get_expand_operator(const dmg_result*,uint32_t,dmg_operator_profile_v2*,uint32_t);
dmg_status dmg_job_get_expand_operator(const dmg_job*,uint32_t,dmg_operator_profile_v2*,uint32_t);
dmg_status dmg_result_get_expand_endpoint(const dmg_result*,uint32_t,dmg_entity_row*,uint32_t);
dmg_status dmg_result_get_expand_path_count(const dmg_result*,uint32_t,uint32_t*);
dmg_status dmg_result_get_expand_path(const dmg_result*,uint32_t,uint32_t,dmg_expand_path_info*,uint32_t);
dmg_status dmg_result_get_expand_path_binding(const dmg_result*,uint32_t,uint32_t,uint32_t,dmg_expand_binding*,uint32_t);
dmg_status dmg_result_get_expand_path_hop(const dmg_result*,uint32_t,uint32_t,uint32_t,dmg_expand_hop*,uint32_t);
dmg_status dmg_result_get_expand_path_seed_link(const dmg_result*,uint32_t,uint32_t,uint32_t,dmg_relation_link_v2*,uint32_t);
dmg_status dmg_result_get_expand_path_seed_proof(const dmg_result*,uint32_t,uint32_t,uint32_t,dmg_expand_proof*,uint32_t);
dmg_status dmg_result_get_expand_path_witness(const dmg_result*,uint32_t,uint32_t,uint32_t,uint32_t,dmg_relation_witness_v2*,uint32_t);
dmg_status dmg_result_get_expand_frontier(const dmg_result*,uint32_t,dmg_expand_frontier*,uint32_t);
dmg_status dmg_result_get_expand_frontier_binding(const dmg_result*,uint32_t,uint32_t,dmg_expand_binding*,uint32_t);
dmg_status dmg_result_get_expand_frontier_hop(const dmg_result*,uint32_t,uint32_t,dmg_expand_hop*,uint32_t);
dmg_status dmg_result_get_expand_frontier_seed_link(const dmg_result*,uint32_t,uint32_t,dmg_relation_link_v2*,uint32_t);
dmg_status dmg_result_get_expand_frontier_seed_proof(const dmg_result*,uint32_t,uint32_t,dmg_expand_proof*,uint32_t);
dmg_status dmg_result_get_expand_frontier_witness(const dmg_result*,uint32_t,uint32_t,uint32_t,dmg_relation_witness_v2*,uint32_t);
dmg_status dmg_job_get_expand_frontier(const dmg_job*,uint32_t,dmg_expand_frontier*,uint32_t);
dmg_status dmg_job_get_expand_frontier_binding(const dmg_job*,uint32_t,uint32_t,dmg_expand_binding*,uint32_t);
dmg_status dmg_job_get_expand_frontier_hop(const dmg_job*,uint32_t,uint32_t,dmg_expand_hop*,uint32_t);
dmg_status dmg_job_get_expand_frontier_seed_link(const dmg_job*,uint32_t,uint32_t,dmg_relation_link_v2*,uint32_t);
dmg_status dmg_job_get_expand_frontier_seed_proof(const dmg_job*,uint32_t,uint32_t,dmg_expand_proof*,uint32_t);
dmg_status dmg_job_get_expand_frontier_witness(const dmg_job*,uint32_t,uint32_t,uint32_t,dmg_relation_witness_v2*,uint32_t);
dmg_status dmg_result_get_binding_count(const dmg_result* result,uint32_t row,uint32_t* out);
dmg_status dmg_result_get_binding(const dmg_result* result,uint32_t row,uint32_t binding,dmg_binding_row* out,uint32_t out_size);
dmg_status dmg_result_get_binding_path(const dmg_result* result,uint32_t row,uint32_t binding,dmg_binding_path* out,uint32_t out_size);
dmg_status dmg_result_get_proof_binding_count(const dmg_result* result,uint32_t row,uint32_t* out);
dmg_status dmg_result_get_proof_binding(const dmg_result* result,uint32_t row,uint32_t binding,dmg_proof_binding_row* out,uint32_t out_size);
dmg_status dmg_result_get_proof_binding_path(const dmg_result* result,uint32_t row,uint32_t binding,dmg_binding_path* out,uint32_t out_size);
dmg_status dmg_result_get_link_count(const dmg_result* result,uint32_t row,uint32_t* out);
dmg_status dmg_result_get_link(const dmg_result* result,uint32_t row,uint32_t link,dmg_relation_link* out,uint32_t out_size);
dmg_status dmg_result_get_value_v2(const dmg_result* result,uint32_t row,dmg_value_row_v2* out,uint32_t out_size);
dmg_status dmg_result_get_binding_v2(const dmg_result* result,uint32_t row,uint32_t binding,dmg_binding_row_v2* out,uint32_t out_size);
dmg_status dmg_result_get_proof_binding_v2(const dmg_result* result,uint32_t row,uint32_t binding,dmg_proof_binding_row_v2* out,uint32_t out_size);
dmg_status dmg_result_get_link_v2(const dmg_result* result,uint32_t row,uint32_t link,dmg_relation_link_v2* out,uint32_t out_size);
dmg_status dmg_result_get_relation_witness_v2(const dmg_result* result,uint32_t row,uint32_t witness,dmg_relation_witness_v2* out,uint32_t out_size);
dmg_status dmg_result_get_relation_info_v2(const dmg_result* result,dmg_relation_info_v2* out,uint32_t out_size);
dmg_status dmg_result_get_operator_profile_v2(const dmg_result* result,uint32_t index,dmg_operator_profile_v2* out,uint32_t out_size);
dmg_status dmg_job_get_relation_status_v2(const dmg_job* job,dmg_relation_job_status_v2* out,uint32_t out_size);
dmg_status dmg_job_wait_relation_v2(dmg_job* job,uint32_t timeout_ms,dmg_relation_job_status_v2* out,uint32_t out_size);
dmg_status dmg_job_get_operator_profile_v2(const dmg_job* job,uint32_t index,dmg_operator_profile_v2* out,uint32_t out_size);
dmg_status dmg_result_get_relation_witness(const dmg_result* result,uint32_t row,uint32_t witness,dmg_relation_witness* out,uint32_t out_size);
dmg_status dmg_result_get_graph_info(const dmg_result* result,dmg_graph_info* out,uint32_t out_size);
dmg_status dmg_result_get_operator_profile(const dmg_result* result,uint32_t index,dmg_operator_profile* out,uint32_t out_size);
dmg_status dmg_job_get_graph_info(const dmg_job* job,dmg_graph_info* out,uint32_t out_size);
dmg_status dmg_job_get_operator_profile(const dmg_job* job,uint32_t index,dmg_operator_profile* out,uint32_t out_size);
dmg_status dmg_query_compile_json(dmg_engine* engine,const uint8_t* json,uint64_t length,dmg_query** out,dmg_error* error);
dmg_status dmg_query_get_info(const dmg_query* query,dmg_query_info* out);
dmg_status dmg_query_get_info_v2(const dmg_query* query,dmg_query_info_v2* out,uint32_t out_size);
dmg_status dmg_query_execute(dmg_snapshot* snapshot,dmg_query* query,dmg_result** out,dmg_error* error);
/* Experimental synchronous multi-rule v1. All inputs remain valid during call.
 * On failure *out is NULL; *failure_index is the zero-based failing rule or
 * UINT32_MAX when failure is not attributable to a particular rule. */
/* Advisory: fuse eligible direct method enumerations into one source pass;
 * unsupported shapes use the existing per-rule executor. */
#define DMG_MULTI_FUSE_METHOD_ENUM_V1 1u
typedef struct {uint32_t struct_size,abi_version;uint64_t cache_bytes,max_cache_work;uint32_t flags,reserved;} dmg_multi_options_v1;
typedef struct {uint64_t physical_collects,cache_hits,cache_builds,trace_overflows,cache_rejections,replay_failures,cache_work_charged;uint32_t arena_budget_unavailable,reserved;} dmg_multi_profile_v1;
dmg_status dmg_multi_execute_v1(dmg_snapshot* snapshot,dmg_query* const* queries,uint32_t count,const dmg_multi_options_v1* options,
    dmg_multi_batch_v1** out,uint32_t* failure_index,dmg_error* error);
void dmg_multi_batch_retain_v1(dmg_multi_batch_v1* batch);
void dmg_multi_batch_release_v1(dmg_multi_batch_v1* batch);
dmg_status dmg_multi_batch_count_v1(const dmg_multi_batch_v1* batch,uint32_t* out);
dmg_status dmg_multi_batch_profile_v1(const dmg_multi_batch_v1* batch,dmg_multi_profile_v1* out,uint32_t out_size);
/* Each successful get returns a separately retained dmg_result reference. */
dmg_status dmg_multi_batch_get_result_v1(const dmg_multi_batch_v1* batch,uint32_t index,dmg_result** out);
dmg_status dmg_result_get_query_info(const dmg_result* result,dmg_query_info* out);
dmg_status dmg_result_get_query_info_v2(const dmg_result* result,dmg_query_info_v2* out,uint32_t out_size);
dmg_status dmg_job_get_query_info_v2(const dmg_job* job,dmg_query_info_v2* out,uint32_t out_size);
/* Actual selected source indices for a successfully committed, explicit-scope
 * v24/v25 class annotation Job. They describe static input selection, not
 * necessarily every visited row, loader coverage or authenticated origin.
 * Exact sizes are required; errors do not write outputs. Before terminal commit
 * returns DMG_NOT_READY; failed/cancelled Jobs return their execution status.
 * Other profiles return DMG_UNSUPPORTED. Values remain owned by the Job. */
typedef struct {uint32_t source_count,scope_complete;} dmg_job_terminal_scope_v1;
dmg_status dmg_job_get_terminal_scope_v1(const dmg_job*,dmg_job_terminal_scope_v1*,uint32_t);
dmg_status dmg_job_get_terminal_scope_source_v1(const dmg_job*,uint32_t,uint32_t*);

dmg_status dmg_result_get_profile(const dmg_result* result,dmg_query_profile* out);
dmg_status dmg_result_get_scope_source(const dmg_result* result,uint32_t index,uint32_t* out);
dmg_status dmg_result_get_witness_count(const dmg_result* result,uint32_t row,uint32_t* out);
dmg_status dmg_result_get_witness(const dmg_result* result,uint32_t row,uint32_t witness,dmg_witness* out);
/* Explicit v22 method-type evidence. Descriptors are copied to caller storage;
 * exact sizes/capacities are checked before writing and result remains owner. */
typedef struct {uint32_t source_index,method_ordinal,method_ref;} dmg_method_type_identity_v1;
typedef struct {dmg_witness witness;uint32_t source_index,method_ordinal;uint64_t descriptor_length;} dmg_method_type_witness_v1;
dmg_status dmg_result_get_method_type_identity_v1(const dmg_result* result,uint32_t row,dmg_method_type_identity_v1* out,uint32_t out_size);
dmg_status dmg_result_get_method_witness_v1(const dmg_result* result,uint32_t row,uint32_t index,dmg_witness* out,uint32_t out_size);
dmg_status dmg_result_get_method_type_witness_v1(const dmg_result* result,uint32_t row,uint32_t index,dmg_method_type_witness_v1* out,uint32_t out_size);
dmg_status dmg_result_copy_method_type_descriptor_v1(const dmg_result* result,uint32_t row,uint32_t index,uint16_t* out,uint64_t capacity);

/* Numeric witness is additive; exact size is checked before any output write. */
enum { DMG_NUMERIC_CONSTANT=0, DMG_NUMERIC_ARITHMETIC_OPERAND=1 };
typedef struct {uint32_t node_id,matched,dex_pc,opcode,code_units,operator_node,source_index,relation,local_index,entity_pc,width_bits,literal_kind;uint64_t bits;} dmg_numeric_witness_v1;
dmg_status dmg_result_get_numeric_witness_v1(const dmg_result* result,uint32_t row,uint32_t witness,dmg_numeric_witness_v1* out,uint32_t out_size);
dmg_status dmg_result_get_inherited_witness(const dmg_result* result,uint32_t row,uint32_t witness,dmg_inherited_witness* out,uint32_t out_size);
dmg_status dmg_result_get_interface_witness_v1(const dmg_result* result,uint32_t row,uint32_t witness,dmg_interface_witness_v1* out,uint32_t out_size);
/* v11 item 6 selects a definition for an ambiguous interface descriptor. */
dmg_status dmg_result_get_interface_resolved_witness_v1(const dmg_result* result,uint32_t row,uint32_t witness,dmg_interface_witness_v1* out,uint32_t out_size);
/* Scoped static field lookup proof, one class step or terminal field per witness.
 * item_kind 0=class path, 1=terminal field; edge 0=root, 1=interface, 2=superclass.
 * These records do not assert ClassLoader selection or runtime access. */
typedef struct {uint32_t node_id,matched,operator_node,item_kind,path_index,edge_kind,interface_index,detail,source_index,relation,local_index;} dmg_field_declaration_witness_v1;
dmg_status dmg_result_get_field_declaration_witness_v1(const dmg_result* result,uint32_t row,uint32_t witness,dmg_field_declaration_witness_v1* out,uint32_t out_size);
/* Explicit static caller-to-field-declaring-class observation; not access or loader proof.
 * item_kind 0=header, 1=node, 2=edge, 3=interface Object check.
 * path_index and parent_index mean from/to for edges; for item 3 path_index names the interface node.
 * Unused fields are UINT32_MAX. An UNKNOWN annotation does not change query decision. */
enum { DMG_CALLER_FIELD_SELF=1, DMG_CALLER_FIELD_ANCESTOR=2, DMG_CALLER_FIELD_EXTERNAL=3, DMG_CALLER_FIELD_UNKNOWN=4 };
enum { DMG_CALLER_FIELD_REASON_NONE=0, DMG_CALLER_FIELD_REASON_MISSING=1, DMG_CALLER_FIELD_REASON_AMBIGUOUS=2, DMG_CALLER_FIELD_REASON_CYCLE=3, DMG_CALLER_FIELD_REASON_INVALID_TYPE=4, DMG_CALLER_FIELD_REASON_INTERFACE_SUPERCLASS=5 };
typedef struct {uint32_t node_id,operator_node,item_kind,status,reason,source_index,class_ordinal,path_index,parent_index,edge_kind,interface_index,target_source,target_class,target_field,event_source,event_caller,event_pc;} dmg_caller_field_relation_witness_v1;
dmg_status dmg_result_get_caller_field_relation_witness_v1(const dmg_result* result,uint32_t row,uint32_t witness,dmg_caller_field_relation_witness_v1* out,uint32_t out_size);

/* Static class reflection-flag provenance; offsets are source-local and zero
 * denotes an absent directory/set/item/value. It is not runtime binding. */
enum { DMG_CLASS_FLAGS_NO_DIRECTORY=0, DMG_CLASS_FLAGS_NO_CLASS_SET=1,
       DMG_CLASS_FLAGS_NO_SYSTEM_INNER=2, DMG_CLASS_FLAGS_INNER_INT=3 };
typedef struct {uint32_t node_id,matched,operator_node,source_index,class_ordinal,source_kind,
    directory_offset,set_offset,item_offset,value_offset,raw_flags,encoded_flags,projected_flags;} dmg_class_annotation_flags_witness_v1;
dmg_status dmg_result_get_class_annotation_flags_witness_v1(const dmg_result* result,uint32_t row,uint32_t witness,dmg_class_annotation_flags_witness_v1* out,uint32_t out_size);


dmg_status dmg_job_get_profile(const dmg_job* job,dmg_query_profile* out);

enum { DMG_INPUT_AUTO=0, DMG_INPUT_RAW_DEX=1, DMG_INPUT_APK=2 };
typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t format;
    uint32_t allow_no_dex;
    const uint8_t* data;
    uint64_t size;
    const char* slot_key;
    const char* role;
    const char* expected_sha256;
} dmg_source_spec;
typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    const char* source_namespace;
    uint32_t scope_complete;
    uint32_t max_sources;
    uint64_t max_total_dex_bytes;
} dmg_source_set_options;
typedef struct {
    const char* snapshot_id;
    uint32_t input_count;
    uint32_t source_count;
    uint32_t scope_complete;
    uint32_t reserved;
    uint64_t input_bytes;
    uint64_t dex_bytes;
    uint64_t string_count;
    uint64_t type_count;
    uint64_t class_count;
    uint64_t method_ref_count;
    uint64_t method_def_count;
} dmg_snapshot_overview;
typedef struct {
    uint32_t input_index;
    uint32_t format;
    uint32_t allow_no_dex;
    uint32_t source_count;
    const char* slot_key;
    const char* role;
    const char* source_sha256;
    const char* content_id;
    uint64_t input_bytes;
    uint32_t expected_digest_verified;
    uint32_t container_metadata_checked;
} dmg_input_info;
typedef struct {
    dmg_snapshot_info dex;
    uint32_t source_index;
    uint32_t input_index;
    const char* slot_key;
    const char* role;
    const char* logical_dex_id;
    const char* archive_sha256;
    const char* archive_entry_name;
    uint32_t archive_entry_index;
    uint32_t crc_verified;
    uint32_t header_consistency_verified;
    uint32_t expected_digest_verified;
} dmg_source_info;

/* DEX header checksum diagnostics for one already-open 035/037/038/039/040
 * source occurrence. This is neither authentication nor structural verification.
 * A mismatch is returned in the fields; DMG_OK only means the check completed.
 * max_input_bytes bounds the complete DEX input examined; insufficient budget
 * returns DMG_BUDGET_EXCEEDED without modifying the output. Exact out_size is
 * required. The call is synchronous and has no cancellation/deadline option. */
typedef struct {
    uint32_t adler32_expected,adler32_actual,adler32_matches,sha1_matches;
    uint8_t sha1_expected[20],sha1_actual[20];
    uint64_t input_bytes;
} dmg_dex_checksums_v1;
dmg_status dmg_snapshot_check_dex_checksums_v1(const dmg_snapshot* snapshot,uint32_t source_index,
    uint64_t max_input_bytes,dmg_dex_checksums_v1* out,uint32_t out_size);
dmg_status dmg_result_check_dex_checksums_v1(const dmg_result* result,uint32_t source_index,
    uint64_t max_input_bytes,dmg_dex_checksums_v1* out,uint32_t out_size);

/* Copies all inputs before returning; failure never publishes a partial Snapshot. */
dmg_status dmg_snapshot_open_sources(dmg_engine* engine,const dmg_source_spec* sources,uint32_t count,
    const dmg_source_set_options* options,dmg_snapshot** out,dmg_error* error);
/* Experimental synchronous, copy-owned APK file ranges. Inputs, descriptors
 * and strings must stay valid through return; no cancellation or deadline.
 * The caller's file offset is not modified. Failure leaves *out NULL. */
typedef struct {
    uint32_t struct_size,abi_version;
    int32_t fd;
    uint32_t allow_no_dex;
    uint64_t offset,length;
    const char* slot_key;
    const char* role;
    const char* expected_sha256;
} dmg_apk_fd_spec_v1;
typedef struct {
    uint32_t struct_size,abi_version;
    const char* source_namespace;
    uint32_t scope_complete,max_sources;
    uint64_t max_archive_bytes,max_total_archive_bytes,max_dex_bytes,max_total_dex_bytes;
    uint32_t max_entries,reserved;
    uint64_t max_central_directory_bytes,max_total_name_bytes;
} dmg_apk_fd_options_v1;
dmg_status dmg_snapshot_open_apk_fds_v1(dmg_engine* engine,const dmg_apk_fd_spec_v1* sources,uint32_t count,
    const dmg_apk_fd_options_v1* options,dmg_snapshot** out,dmg_error* error);
dmg_status dmg_snapshot_get_overview(const dmg_snapshot* snapshot,dmg_snapshot_overview* out);
dmg_status dmg_snapshot_get_input_info(const dmg_snapshot* snapshot,uint32_t index,dmg_input_info* out);
dmg_status dmg_snapshot_get_source_info(const dmg_snapshot* snapshot,uint32_t index,dmg_source_info* out);
/* Source-local DEX string_id or type_id text, copied as UTF-16 code units. */
enum { DMG_SYMBOL_STRING_V1=0, DMG_SYMBOL_TYPE_V1=1, DMG_SYMBOL_PROTO_V1=2 };
/* Source-local member_id indices, not a definition or runtime binding. */
enum { DMG_MEMBER_FIELD_V1=0, DMG_MEMBER_METHOD_V1=1 };
typedef struct { uint32_t owner_type_index, name_string_index, type_or_proto_index; } dmg_member_indices_v1;
dmg_status dmg_snapshot_get_member_indices_v1(const dmg_snapshot* snapshot,uint32_t source_index,uint32_t kind,uint32_t index,
    dmg_member_indices_v1* out,uint32_t out_size);
dmg_status dmg_snapshot_copy_symbol_text_v1(const dmg_snapshot* snapshot,uint32_t source_index,uint32_t kind,uint32_t index,
    uint64_t max_units,uint16_t* out,uint64_t capacity,uint64_t* out_length);
/* Borrowed read-only raw DEX bytes; valid while the snapshot handle remains retained. */
dmg_status dmg_snapshot_get_source_bytes_v1(const dmg_snapshot* snapshot,uint32_t index,uint64_t max_bytes,const uint8_t** out_bytes,uint64_t* out_size);
dmg_status dmg_result_get_overview(const dmg_result* result,dmg_snapshot_overview* out);
dmg_status dmg_result_get_input_info(const dmg_result* result,uint32_t index,dmg_input_info* out);
dmg_status dmg_result_get_source_info(const dmg_result* result,uint32_t index,dmg_source_info* out);
dmg_status dmg_result_get_origin(const dmg_result* result,uint32_t row,dmg_source_info* out);

dmg_status dmg_engine_create(const dmg_engine_options* options,dmg_engine** out,dmg_error* error);
void dmg_engine_retain(dmg_engine* engine);
void dmg_engine_release(dmg_engine* engine);
/* Closes admission. cancel_jobs=1 requests cancellation; it does not wait. */
dmg_status dmg_engine_shutdown(dmg_engine* engine,uint32_t cancel_jobs);
dmg_status dmg_engine_get_stats(const dmg_engine* engine,dmg_engine_stats* out);
dmg_status dmg_snapshot_open_copy_in(dmg_engine* engine,const uint8_t* data,uint64_t size,
    const dmg_open_options* options,dmg_snapshot** out,dmg_error* error);
dmg_status dmg_snapshot_open_borrowed(dmg_engine* engine,const uint8_t* data,uint64_t size,
    const dmg_buffer_lease* lease,const dmg_open_options* options,dmg_snapshot** out,dmg_error* error);
/* File descriptor range is always copied; original descriptor position is preserved. */
dmg_status dmg_snapshot_open_fd(dmg_engine* engine,int32_t fd,uint64_t offset,uint64_t length,
    const dmg_open_options* options,dmg_snapshot** out,dmg_error* error);
dmg_status dmg_query_compile_methods(dmg_engine* engine,const dmg_method_query* query,
    dmg_query** out,dmg_error* error);
void dmg_query_retain(dmg_query* query);
void dmg_query_release(dmg_query* query);
dmg_status dmg_job_start(dmg_snapshot* snapshot,dmg_query* query,const dmg_job_options* options,
    dmg_job** out,dmg_error* error);
void dmg_job_retain(dmg_job* job);
/* Final release requests cancellation, joins its worker and drops queued batches. */
void dmg_job_release(dmg_job* job);
void dmg_job_cancel(dmg_job* job);
dmg_status dmg_job_get_status(const dmg_job* job,dmg_job_status* out);
dmg_status dmg_job_wait(dmg_job* job,uint32_t wait_timeout_ms,dmg_job_status* out);
/* Single consumer. Wait timeout never cancels. All batches are provisional until terminal status. */
dmg_status dmg_job_next(dmg_job* job,uint32_t wait_timeout_ms,dmg_batch** out,dmg_error* error);
void dmg_batch_retain(dmg_batch* batch);
void dmg_batch_release(dmg_batch* batch);
dmg_status dmg_batch_get_info(const dmg_batch* batch,dmg_result_info* out);
dmg_status dmg_batch_get_source(const dmg_batch* batch,dmg_snapshot_info* out);
dmg_status dmg_batch_get_method(const dmg_batch* batch,uint32_t row,dmg_method_row* out);

uint32_t dmg_abi_version(void);
const char* dmg_capabilities(void);
const char* dmg_status_name(dmg_status status);
/* All input bytes and option strings are copied before this call returns. */
dmg_status dmg_snapshot_open_copy(const uint8_t* data, uint64_t size,
    const dmg_open_options* options, dmg_snapshot** out, dmg_error* error);
void dmg_snapshot_retain(dmg_snapshot* snapshot);
void dmg_snapshot_close(dmg_snapshot* snapshot);
void dmg_snapshot_release(dmg_snapshot* snapshot);
dmg_status dmg_snapshot_get_info(const dmg_snapshot* snapshot, dmg_snapshot_info* out);
/* Synchronous convenience query. Use the separate Job API for cancellation/batches. */
dmg_status dmg_query_methods(dmg_snapshot* snapshot, const dmg_method_query* query,
    dmg_result** out, dmg_error* error);
void dmg_result_retain(dmg_result* result);
void dmg_result_release(dmg_result* result);
dmg_status dmg_result_get_info(const dmg_result* result, dmg_result_info* out);
dmg_status dmg_result_get_source(const dmg_result* result, dmg_snapshot_info* out);
dmg_status dmg_result_get_method(const dmg_result* result, uint32_t row, dmg_method_row* out);
/* Getter views are borrowed until the corresponding snapshot/result is released. */

/* Explicit experimental container API. No legacy open call accepts DEX 041. */
enum { DMG_INPUT_DEX041_EXPERIMENTAL=3 };
typedef struct {
    uint32_t struct_size,abi_version,experimental_041,scope_complete,max_logical_dex;
    uint64_t max_container_bytes;
    const char* source_namespace;const char* slot_key;const char* expected_sha256;
} dmg_dex041_open_options_v1;
typedef struct {
    uint32_t source_index,header_offset,logical_file_size,container_size;
    const char* container_id;const char* logical_dex_id;const char* occurrence_id;
} dmg_dex041_source_info_v1;
const char* dmg_dex041_capability_v1(void);
dmg_status dmg_snapshot_open_dex041_copy_v1(dmg_engine*,const uint8_t*,uint64_t,const dmg_dex041_open_options_v1*,dmg_snapshot**,dmg_error*);
dmg_status dmg_snapshot_get_dex041_source_info_v1(const dmg_snapshot*,uint32_t,dmg_dex041_source_info_v1*,uint32_t);
dmg_status dmg_result_get_dex041_source_info_v1(const dmg_result*,uint32_t,dmg_dex041_source_info_v1*,uint32_t);
/* Immutable compiled-plan views: no snapshot, source I/O or query execution.
 * Accessors take enumeration indices; node_id/child values are stable plan IDs.
 * UINT32_MAX operator_index selects the global scope. Strings borrow Query.
 * Exact sizes are required; errors leave output unchanged. */
typedef struct {
    uint32_t relation,operator_count,root_operator_node,scope_count,order_count;
    uint32_t max_intermediate_rows,unique_identity,contains_expand;
} dmg_query_explain_v1;
typedef struct {
    uint32_t node_id,op,relation,predicate_node,child_count,scope_count,explicit_scope;
    uint32_t bag,identity,join_key,minimum,maximum,role_count,distinct_roles;
    uint32_t expand_direction,expand_output,expand_min_depth,expand_max_depth,expand_walk_node,expand_emit_node;
    uint64_t expand_max_visited,expand_max_edges,expand_max_paths;
    const char* label;
} dmg_query_operator_v1;
typedef struct {uint32_t field,descending;} dmg_query_order_v1;
dmg_status dmg_query_get_explain_v1(const dmg_query*,dmg_query_explain_v1*,uint32_t);
dmg_status dmg_query_get_explain_operator_v1(const dmg_query*,uint32_t,dmg_query_operator_v1*,uint32_t);
dmg_status dmg_query_get_explain_child_v1(const dmg_query*,uint32_t,uint32_t,uint32_t*);
dmg_status dmg_query_get_explain_scope_v1(const dmg_query*,uint32_t,uint32_t,const char**);
dmg_status dmg_query_get_explain_role_v1(const dmg_query*,uint32_t,uint32_t,const char**);
dmg_status dmg_query_get_explain_order_v1(const dmg_query*,uint32_t,dmg_query_order_v1*,uint32_t);
/* Direct-query static input slots; no loader or origin authentication.
 * Strings are borrowed from query. Exact size is required and errors leave out unchanged.
 * A graph/expression query returns Unsupported. explicit_scope distinguishes [] from no scope. */
typedef struct {uint32_t explicit_scope,slot_count;} dmg_query_scope_v2;
dmg_status dmg_query_get_scope_v2(const dmg_query*,dmg_query_scope_v2*,uint32_t);
dmg_status dmg_query_get_scope_slot_v2(const dmg_query*,uint32_t,const char**);

/* Complete selected-method invocation facts; no unrelated method body scan.
 * The successful immutable handle owns copied UTF-16 and retains its sources.
 * max_work bounds decoder validation, not wall time or all materialization work.
 * max_records bounds published rows; decode memory is charged to the Engine.
 * External references without a local definition return Unsupported. */
typedef struct dmg_method_calls_v1 dmg_method_calls_v1;
typedef struct {uint32_t struct_size,abi_version,max_records,reserved;uint64_t max_work,deadline_after_ms;} dmg_method_calls_options_v1;
typedef struct {
    uint32_t source_index,method_ordinal,method_ref,code_offset,has_body,instruction_checked,code_units,count;
    uint64_t validation_work;const char* snapshot_id;
} dmg_method_calls_info_v1;
typedef struct {
    uint32_t dex_pc,opcode,target_domain,target_index,extra_proto;
    const uint16_t* owner;uint64_t owner_length;
    const uint16_t* name;uint64_t name_length;
    const uint16_t* prototype;uint64_t prototype_length;
    const uint16_t* extra_prototype;uint64_t extra_prototype_length;
} dmg_method_call_row_v1;
dmg_status dmg_snapshot_collect_method_calls_v1(dmg_snapshot*,uint32_t,uint32_t,const dmg_method_calls_options_v1*,dmg_method_calls_v1**,dmg_error*);
void dmg_method_calls_retain_v1(dmg_method_calls_v1*);
void dmg_method_calls_release_v1(dmg_method_calls_v1*);
dmg_status dmg_method_calls_get_info_v1(const dmg_method_calls_v1*,dmg_method_calls_info_v1*,uint32_t);
dmg_status dmg_method_calls_get_caller_v1(const dmg_method_calls_v1*,dmg_method_row*,uint32_t);
dmg_status dmg_method_calls_get_source_v1(const dmg_method_calls_v1*,dmg_source_info*,uint32_t);
dmg_status dmg_method_calls_get_row_v1(const dmg_method_calls_v1*,uint32_t,dmg_method_call_row_v1*,uint32_t);
/* One checked method body, collected once for reusable generic consumers.
 * Requested categories are explicit; PCs are DEX code-unit offsets.
 * A handle retains its Dataset and all returned pointers until release.
 * No result is published on failure. External-only method refs are unsupported.
 * These are static encoded facts, not ART verification or runtime binding. */
typedef struct dmg_method_facts_v1 dmg_method_facts_v1;
enum {
    DMG_METHOD_FACT_STRINGS=1u, DMG_METHOD_FACT_FIELDS=2u, DMG_METHOD_FACT_NUMBERS=4u,
    DMG_METHOD_FACT_INVOKES=8u, DMG_METHOD_FACT_TYPES=16u, DMG_METHOD_FACT_INSTRUCTIONS=32u
};
typedef struct {uint32_t struct_size,abi_version,requested_mask,max_records;uint64_t max_work,deadline_after_ms;uint32_t reserved;} dmg_method_facts_options_v1;
typedef struct {
    uint32_t source_index,method_ordinal,method_ref,code_offset,has_body,instruction_checked,code_units,requested_mask;
    uint32_t string_count,field_count,number_count,invoke_count,type_count,instruction_count;
    uint64_t validation_work;const char* snapshot_id;
} dmg_method_facts_info_v1;
typedef struct {uint32_t dex_pc,opcode,string_index;const uint16_t* value;uint64_t value_length;} dmg_method_string_use_v1;
typedef struct {uint32_t dex_pc,opcode,field_index;const uint16_t* owner;uint64_t owner_length;const uint16_t* name;uint64_t name_length;const uint16_t* type;uint64_t type_length;} dmg_method_field_use_v1;
typedef struct {uint32_t dex_pc,opcode,width_bits,kind;uint64_t bits;} dmg_method_number_v1;
typedef struct {uint32_t dex_pc,opcode,type_index;const uint16_t* descriptor;uint64_t descriptor_length;} dmg_method_type_use_v1;
typedef struct {uint32_t dex_pc,width,opcode,payload_kind;} dmg_method_instruction_v1;
dmg_status dmg_snapshot_collect_method_facts_v1(dmg_snapshot*,uint32_t,uint32_t,const dmg_method_facts_options_v1*,dmg_method_facts_v1**,dmg_error*);
void dmg_method_facts_retain_v1(dmg_method_facts_v1*);
void dmg_method_facts_release_v1(dmg_method_facts_v1*);
dmg_status dmg_method_facts_get_info_v1(const dmg_method_facts_v1*,dmg_method_facts_info_v1*,uint32_t);
dmg_status dmg_method_facts_get_caller_v1(const dmg_method_facts_v1*,dmg_method_row*,uint32_t);
dmg_status dmg_method_facts_get_source_v1(const dmg_method_facts_v1*,dmg_source_info*,uint32_t);
dmg_status dmg_method_facts_get_string_v1(const dmg_method_facts_v1*,uint32_t,dmg_method_string_use_v1*,uint32_t);
dmg_status dmg_method_facts_get_field_v1(const dmg_method_facts_v1*,uint32_t,dmg_method_field_use_v1*,uint32_t);
dmg_status dmg_method_facts_get_number_v1(const dmg_method_facts_v1*,uint32_t,dmg_method_number_v1*,uint32_t);
dmg_status dmg_method_facts_get_invoke_v1(const dmg_method_facts_v1*,uint32_t,dmg_method_call_row_v1*,uint32_t);
dmg_status dmg_method_facts_get_type_v1(const dmg_method_facts_v1*,uint32_t,dmg_method_type_use_v1*,uint32_t);
dmg_status dmg_method_facts_get_instruction_v1(const dmg_method_facts_v1*,uint32_t,dmg_method_instruction_v1*,uint32_t);
/* Static annotations of a locally defined class, field, method or parameter.
 * The result preserves encoded values rather than inferring runtime types.
 * Pointers remain valid until the returned immutable handle is released. */
typedef struct dmg_annotations_v1 dmg_annotations_v1;
enum {DMG_ANNOTATION_CLASS=0u,DMG_ANNOTATION_FIELD=1u,DMG_ANNOTATION_METHOD=2u,DMG_ANNOTATION_PARAMETER=3u};
typedef struct {uint32_t struct_size,abi_version,max_records,reserved;uint64_t max_work,max_encoded_bytes,deadline_after_ms;} dmg_annotations_options_v1;
typedef struct {uint32_t source_index,target_kind,target_ref,parameter_index,annotation_count;uint64_t work_units;const char* snapshot_id;} dmg_annotations_info_v1;
typedef struct {uint32_t visibility,type_index,element_count,item_offset,encoded_offset;const uint16_t* descriptor;uint64_t descriptor_length;const uint8_t* encoded_annotation;uint64_t encoded_length;} dmg_annotation_item_v1;
typedef struct {uint32_t name_index,value_kind,value_arg,value_offset;const uint16_t* name;uint64_t name_length;const uint8_t* encoded_value;uint64_t encoded_length;} dmg_annotation_element_v1;
dmg_status dmg_snapshot_collect_annotations_v1(dmg_snapshot*,uint32_t,uint32_t,uint32_t,uint32_t,const dmg_annotations_options_v1*,dmg_annotations_v1**,dmg_error*);
void dmg_annotations_retain_v1(dmg_annotations_v1*);
void dmg_annotations_release_v1(dmg_annotations_v1*);
dmg_status dmg_annotations_get_info_v1(const dmg_annotations_v1*,dmg_annotations_info_v1*,uint32_t);
dmg_status dmg_annotations_get_source_v1(const dmg_annotations_v1*,dmg_source_info*,uint32_t);
dmg_status dmg_annotations_get_item_v1(const dmg_annotations_v1*,uint32_t,dmg_annotation_item_v1*,uint32_t);
dmg_status dmg_annotations_get_element_v1(const dmg_annotations_v1*,uint32_t,uint32_t,dmg_annotation_element_v1*,uint32_t);
#ifdef __cplusplus
}
#endif
#endif
