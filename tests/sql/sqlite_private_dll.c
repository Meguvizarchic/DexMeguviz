#include "private_sqlite.h"

/* Test-only DLL export. The private SQLite wrappers themselves are not exported. */
__declspec(dllexport) int dmg_test_private_count(void) {
    sqlite3* db=0; sqlite3_stmt* stmt=0; int value=-1;
    if(sqlite3_open_v2(":memory:",&db,SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE,0)!=SQLITE_OK) goto done;
    if(sqlite3_prepare_v2(db,"SELECT count(1)",-1,&stmt,0)!=SQLITE_OK) goto done;
    if(sqlite3_step(stmt)!=SQLITE_ROW) goto done;
    value=(int)sqlite3_column_int64(stmt,0);
done:
    if(stmt && sqlite3_finalize(stmt)!=SQLITE_OK) value=-1;
    if(db && sqlite3_close(db)!=SQLITE_OK) value=-1;
    return value;
}
