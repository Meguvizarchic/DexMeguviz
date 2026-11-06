/* This translation unit owns its SQLite state. Its upstream API symbols have
 * internal linkage; only the narrowly scoped wrapper calls below are visible
 * outside this translation unit. The upstream amalgamation is not modified. */
#if defined(SQLITE_API) || defined(SQLITE_PRIVATE)
#error "Private SQLite linkage must not be overridden"
#endif
#if defined(SQLITE_EXTRA_INIT) || defined(SQLITE_EXTRA_SHUTDOWN) || defined(SQLITE_CUSTOM_INCLUDE) || defined(SQLITE_ENABLE_IOTRACE) || defined(SQLITE_TEST)
#error "Unexpected SQLite extension or test hooks are forbidden"
#endif
#if (defined(SQLITE_OS_KV) && SQLITE_OS_KV != 0) || (defined(SQLITE_OS_OTHER) && SQLITE_OS_OTHER != 0) || defined(SQLITE_OMIT_WSD)
#error "Private SQLite requires the tested built-in platform VFS model"
#endif
#if !defined(SQLITE_OMIT_LOAD_EXTENSION) || !defined(SQLITE_THREADSAFE) || SQLITE_THREADSAFE != 1 || !defined(SQLITE_TEMP_STORE) || SQLITE_TEMP_STORE != 3 || defined(SQLITE_OMIT_AUTOINIT)
#error "Private SQLite requires the configured desktop build options"
#endif
#if defined(SQLITE_DEFAULT_MEMSTATUS) && SQLITE_DEFAULT_MEMSTATUS != 1
#error "Private SQLite heap budget requires memory status accounting"
#endif
#define SQLITE_API static
#include "../../third_party/sqlite/sqlite3.c"

int dmg_private_sqlite3_bind_parameter_count(sqlite3_stmt* p){return sqlite3_bind_parameter_count(p);}
int dmg_private_sqlite3_bind_int64(sqlite3_stmt* p,int n,sqlite3_int64 value){return sqlite3_bind_int64(p,n,value);}
int dmg_private_sqlite3_bind_null(sqlite3_stmt* p,int n){return sqlite3_bind_null(p,n);}
int dmg_private_sqlite3_bind_blob(sqlite3_stmt* p,int n,const void* s,int z,void(*d)(void*)){return sqlite3_bind_blob(p,n,s,z,d);}
int dmg_private_sqlite3_bind_text(sqlite3_stmt* p,int n,const char* s,int z,void(*d)(void*)){return sqlite3_bind_text(p,n,s,z,d);}
int dmg_private_sqlite3_close(sqlite3* db){return sqlite3_close(db);}
int dmg_private_sqlite3_column_bytes(sqlite3_stmt* p,int i){return sqlite3_column_bytes(p,i);}
int dmg_private_sqlite3_column_count(sqlite3_stmt* p){return sqlite3_column_count(p);}
sqlite3_int64 dmg_private_sqlite3_column_int64(sqlite3_stmt* p,int i){return sqlite3_column_int64(p,i);}
const void* dmg_private_sqlite3_column_blob(sqlite3_stmt* p,int i){return sqlite3_column_blob(p,i);}
const unsigned char* dmg_private_sqlite3_column_text(sqlite3_stmt* p,int i){return sqlite3_column_text(p,i);}
int dmg_private_sqlite3_column_type(sqlite3_stmt* p,int i){return sqlite3_column_type(p,i);}
sqlite3* dmg_private_sqlite3_context_db_handle(sqlite3_context* c){return sqlite3_context_db_handle(c);}
int dmg_private_sqlite3_create_module_v2(sqlite3* db,const char* n,const sqlite3_module* m,void* p,void(*d)(void*)){return sqlite3_create_module_v2(db,n,m,p,d);}
int dmg_private_sqlite3_declare_vtab(sqlite3* db,const char* sql){return sqlite3_declare_vtab(db,sql);}
int dmg_private_sqlite3_finalize(sqlite3_stmt* p){return sqlite3_finalize(p);}
int dmg_private_sqlite3_limit(sqlite3* db,int id,int value){return sqlite3_limit(db,id,value);}
/* The budget is process-lifetime and shared by this private SQLite instance.
 * APP1 belongs to this wrapper; SQLite does not use it internally. */
static int dmg_private_heap_configured = 0;
static int dmg_private_heap_started = 0;
static sqlite3_int64 dmg_private_heap_limit = 0;
static int dmg_private_heap_gate(sqlite3_mutex** out){
    int rc=sqlite3_initialize();
    if(rc!=SQLITE_OK)return rc;
    *out=sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_APP1);
    return *out?SQLITE_OK:SQLITE_NOMEM;
}
int dmg_private_sqlite3_configure_heap_limit(sqlite3_int64 limit){
    sqlite3_mutex* gate=0;int rc;
    if(limit<=0)return SQLITE_MISUSE;
    rc=dmg_private_heap_gate(&gate);if(rc!=SQLITE_OK)return rc;
    sqlite3_mutex_enter(gate);
    if(dmg_private_heap_started || dmg_private_heap_configured || sqlite3_hard_heap_limit64(-1)!=0){rc=SQLITE_MISUSE;}
    else if(sqlite3_memory_used()>limit){rc=SQLITE_NOMEM;}
    else if(sqlite3_hard_heap_limit64(limit)!=0){rc=SQLITE_ERROR;}
    else {dmg_private_heap_limit=limit;dmg_private_heap_configured=1;rc=SQLITE_OK;}
    sqlite3_mutex_leave(gate);return rc;
}
int dmg_private_sqlite3_heap_snapshot(sqlite3_int64* limit,sqlite3_int64* used,sqlite3_int64* peak,int* configured,int* started){
    sqlite3_mutex* gate=0;int rc;
    if(!limit||!used||!peak||!configured||!started)return SQLITE_MISUSE;
    rc=dmg_private_heap_gate(&gate);if(rc!=SQLITE_OK)return rc;
    sqlite3_mutex_enter(gate);
    *limit=dmg_private_heap_limit;*used=sqlite3_memory_used();*peak=sqlite3_memory_highwater(0);
    *configured=dmg_private_heap_configured;*started=dmg_private_heap_started;
    sqlite3_mutex_leave(gate);return SQLITE_OK;
}
int dmg_private_sqlite3_open_v2(const char* f,sqlite3** db,int flags,const char* vfs){
    sqlite3_mutex* gate=0;int rc;if(!db)return SQLITE_MISUSE;
    rc=dmg_private_heap_gate(&gate);if(rc!=SQLITE_OK){*db=0;return rc;}
    sqlite3_mutex_enter(gate);dmg_private_heap_started=1;sqlite3_mutex_leave(gate);
    return sqlite3_open_v2(f,db,flags,vfs);
}
int dmg_private_sqlite3_prepare_v2(sqlite3* db,const char* s,int n,sqlite3_stmt** p,const char** tail){return sqlite3_prepare_v2(db,s,n,p,tail);}
int dmg_private_sqlite3_reset(sqlite3_stmt* p){return sqlite3_reset(p);}
int dmg_private_sqlite3_clear_bindings(sqlite3_stmt* p){return sqlite3_clear_bindings(p);}
int dmg_private_sqlite3_stmt_status(sqlite3_stmt* p,int op,int reset){return sqlite3_stmt_status(p,op,reset);}
void dmg_private_sqlite3_progress_handler(sqlite3* db,int n,int(*cb)(void*),void* p){sqlite3_progress_handler(db,n,cb,p);}
void dmg_private_sqlite3_result_error_toobig(sqlite3_context* c){sqlite3_result_error_toobig(c);}
void dmg_private_sqlite3_result_error_nomem(sqlite3_context* c){sqlite3_result_error_nomem(c);}
void dmg_private_sqlite3_result_error_code(sqlite3_context* c,int n){sqlite3_result_error_code(c,n);}
void dmg_private_sqlite3_result_int64(sqlite3_context* c,sqlite3_int64 n){sqlite3_result_int64(c,n);}
void dmg_private_sqlite3_result_null(sqlite3_context* c){sqlite3_result_null(c);}
void dmg_private_sqlite3_result_blob(sqlite3_context* c,const void* p,int n,void(*d)(void*)){sqlite3_result_blob(c,p,n,d);}
void dmg_private_sqlite3_free(void* p){sqlite3_free(p);}
char* dmg_private_sqlite3_mprintf(const char* fmt,...){char* out;va_list ap;va_start(ap,fmt);out=sqlite3_vmprintf(fmt,ap);va_end(ap);return out;}
void dmg_private_sqlite3_result_text(sqlite3_context* c,const char* p,int n,void(*d)(void*)){sqlite3_result_text(c,p,n,d);}
int dmg_private_sqlite3_set_authorizer(sqlite3* db,int(*cb)(void*,int,const char*,const char*,const char*,const char*),void* p){return sqlite3_set_authorizer(db,cb,p);}
int dmg_private_sqlite3_step(sqlite3_stmt* p){return sqlite3_step(p);}
int dmg_private_sqlite3_stmt_readonly(sqlite3_stmt* p){return sqlite3_stmt_readonly(p);}
int dmg_private_sqlite3_stricmp(const char* a,const char* b){return sqlite3_stricmp(a,b);}
int dmg_private_sqlite3_value_type(sqlite3_value* v){return sqlite3_value_type(v);}
sqlite3_int64 dmg_private_sqlite3_value_int64(sqlite3_value* v){return sqlite3_value_int64(v);}
int dmg_private_sqlite3_vtab_in(sqlite3_index_info* i,int n,int f){return sqlite3_vtab_in(i,n,f);}
int dmg_private_sqlite3_vtab_in_first(sqlite3_value* p,sqlite3_value** out){return sqlite3_vtab_in_first(p,out);}
int dmg_private_sqlite3_vtab_in_next(sqlite3_value* p,sqlite3_value** out){return sqlite3_vtab_in_next(p,out);}

#ifdef DMG_SQLITE_PROTO_TESTING
int dmg_private_sqlite3_test_config_log(void (*callback)(void*,int,const char*),void* context){return sqlite3_config(SQLITE_CONFIG_LOG,callback,context);}
int dmg_private_sqlite3_test_exec(sqlite3* db,const char* sql){return sqlite3_exec(db,sql,0,0,0);}
int dmg_private_sqlite3_test_default_vfs_is(const char* name){
    sqlite3_vfs* vfs=sqlite3_vfs_find(0);
    return vfs && vfs->zName && name && strcmp(vfs->zName,name)==0;
}
#endif

