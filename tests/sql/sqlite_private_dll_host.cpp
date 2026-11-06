#include "sqlite3.h"
#include <iostream>

extern "C" __declspec(dllimport) int dmg_test_private_count(void);
static int extension_calls=0, function_calls=0;
static void overridden_count(sqlite3_context* context,int,sqlite3_value**) {
    ++function_calls; sqlite3_result_int(context,777);
}
extern "C" int host_extension(sqlite3* db,char**,const sqlite3_api_routines*) {
    ++extension_calls;
    return sqlite3_create_function(db,"count",1,SQLITE_UTF8,nullptr,overridden_count,nullptr,nullptr);
}
static int normal_count(sqlite3* db) {
    sqlite3_stmt* stmt=nullptr;int value=-1;
    if(sqlite3_prepare_v2(db,"SELECT count(1)",-1,&stmt,nullptr)==SQLITE_OK && sqlite3_step(stmt)==SQLITE_ROW)
        value=sqlite3_column_int(stmt,0);
    if(stmt && sqlite3_finalize(stmt)!=SQLITE_OK)value=-1;
    return value;
}
int main() {
    // Test process only: no process-global SQLite registry is reset.
    if(sqlite3_auto_extension(reinterpret_cast<void(*)(void)>(host_extension))!=SQLITE_OK)return 1;
    sqlite3* first=nullptr;
    if(sqlite3_open(":memory:",&first)!=SQLITE_OK || !first)return 2;
    if(extension_calls!=1 || normal_count(first)!=777 || function_calls!=1)return 3;
    if(dmg_test_private_count()!=1 || extension_calls!=1 || function_calls!=1)return 4;
    sqlite3* second=nullptr;
    if(sqlite3_open(":memory:",&second)!=SQLITE_OK || !second)return 5;
    if(extension_calls!=2 || normal_count(second)!=777 || function_calls!=2)return 6;
    if(sqlite3_close(first)!=SQLITE_OK || sqlite3_close(second)!=SQLITE_OK)return 7;
    std::cout<<"PASS private DLL SQLite is isolated from host SQLite auto-extension\n";
    return 0;
}
