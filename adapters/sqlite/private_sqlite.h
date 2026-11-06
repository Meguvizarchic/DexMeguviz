#pragma once
/* Map only the SQLite calls used by the adapter to its private wrapper. */
#define sqlite3_bind_parameter_count dmg_private_sqlite3_bind_parameter_count
#define sqlite3_bind_int64 dmg_private_sqlite3_bind_int64
#define sqlite3_bind_null dmg_private_sqlite3_bind_null
#define sqlite3_bind_text dmg_private_sqlite3_bind_text
#define sqlite3_close dmg_private_sqlite3_close
#define sqlite3_column_bytes dmg_private_sqlite3_column_bytes
#define sqlite3_column_count dmg_private_sqlite3_column_count
#define sqlite3_column_int64 dmg_private_sqlite3_column_int64
#define sqlite3_column_text dmg_private_sqlite3_column_text
#define sqlite3_column_type dmg_private_sqlite3_column_type
#define sqlite3_context_db_handle dmg_private_sqlite3_context_db_handle
#define sqlite3_create_module_v2 dmg_private_sqlite3_create_module_v2
#define sqlite3_declare_vtab dmg_private_sqlite3_declare_vtab
#define sqlite3_finalize dmg_private_sqlite3_finalize
#define sqlite3_limit dmg_private_sqlite3_limit
#define sqlite3_open_v2 dmg_private_sqlite3_open_v2
#define sqlite3_prepare_v2 dmg_private_sqlite3_prepare_v2
#define sqlite3_reset dmg_private_sqlite3_reset
#define sqlite3_clear_bindings dmg_private_sqlite3_clear_bindings
#define sqlite3_stmt_status dmg_private_sqlite3_stmt_status
#define sqlite3_progress_handler dmg_private_sqlite3_progress_handler
#define sqlite3_result_error_toobig dmg_private_sqlite3_result_error_toobig
#define sqlite3_result_error_nomem dmg_private_sqlite3_result_error_nomem
#define sqlite3_result_error_code dmg_private_sqlite3_result_error_code
#define sqlite3_result_int64 dmg_private_sqlite3_result_int64
#define sqlite3_result_null dmg_private_sqlite3_result_null
#define sqlite3_result_text dmg_private_sqlite3_result_text
#define sqlite3_set_authorizer dmg_private_sqlite3_set_authorizer
#define sqlite3_step dmg_private_sqlite3_step
#define sqlite3_stmt_readonly dmg_private_sqlite3_stmt_readonly
#define sqlite3_stricmp dmg_private_sqlite3_stricmp
#define sqlite3_value_type dmg_private_sqlite3_value_type
#define sqlite3_value_int64 dmg_private_sqlite3_value_int64
#define sqlite3_vtab_in dmg_private_sqlite3_vtab_in
#define sqlite3_vtab_in_first dmg_private_sqlite3_vtab_in_first
#define sqlite3_vtab_in_next dmg_private_sqlite3_vtab_in_next
#define sqlite3_bind_blob dmg_private_sqlite3_bind_blob
#define sqlite3_column_blob dmg_private_sqlite3_column_blob
#define sqlite3_result_blob dmg_private_sqlite3_result_blob
#define sqlite3_mprintf dmg_private_sqlite3_mprintf
#define sqlite3_free dmg_private_sqlite3_free
#include "sqlite3.h"

#ifdef __cplusplus
extern "C" {
#endif
int dmg_private_sqlite3_configure_heap_limit(sqlite3_int64 limit);
int dmg_private_sqlite3_heap_snapshot(sqlite3_int64* limit, sqlite3_int64* used, sqlite3_int64* peak, int* configured, int* started);
#ifdef __cplusplus
}
#endif

#ifdef DMG_SQLITE_PROTO_TESTING
extern "C" int dmg_private_sqlite3_test_config_log(void (*callback)(void*,int,const char*), void* context);
extern "C" int dmg_private_sqlite3_test_exec(sqlite3* db, const char* sql);
extern "C" int dmg_private_sqlite3_test_default_vfs_is(const char* name);
#endif

