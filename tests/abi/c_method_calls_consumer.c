#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"calls smoke line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char** argv){
    dmg_engine* e=NULL;dmg_snapshot* s=NULL;dmg_query* q=NULL;dmg_method_calls_v1* calls=NULL;dmg_method_calls_v1* failed=NULL;dmg_error error={0};
    dmg_method_calls_options_v1 options={sizeof(options),DMG_ABI_VERSION,128,0,1000000,10000};dmg_method_calls_info_v1 info;
    dmg_open_options open_options={sizeof(open_options),DMG_ABI_VERSION,1u<<20,"calls-smoke","base",NULL};
    dmg_method_call_row_v1 row;dmg_method_row caller;dmg_source_info source;FILE* file;long size;unsigned char* bytes;
    const char* json="{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"method_defs\"}}";dmg_query_explain_v1 plan;
    CHECK(argc==2);CHECK(dmg_engine_create(NULL,&e,&error)==DMG_OK);
    CHECK(dmg_query_compile_json(e,(const uint8_t*)json,strlen(json),&q,&error)==DMG_OK);
    CHECK(dmg_query_get_explain_v1(q,&plan,sizeof(plan))==DMG_OK&&plan.operator_count>0);dmg_query_release(q);
    file=fopen(argv[1],"rb");CHECK(file&&fseek(file,0,SEEK_END)==0);size=ftell(file);CHECK(size>0&&fseek(file,0,SEEK_SET)==0);bytes=malloc((size_t)size);CHECK(bytes&&fread(bytes,1,(size_t)size,file)==(size_t)size);fclose(file);
    CHECK(dmg_snapshot_open_copy_in(e,bytes,(uint64_t)size,&open_options,&s,&error)==DMG_OK);free(bytes);
    CHECK(dmg_snapshot_collect_method_calls_v1(s,0,0,&options,&calls,&error)==DMG_OK);
    CHECK(dmg_method_calls_get_info_v1(calls,&info,sizeof(info))==DMG_OK&&info.count==2&&info.method_ref==0&&info.instruction_checked==1);
    CHECK(dmg_snapshot_collect_method_calls_v1(s,0,1,&options,&failed,&error)==DMG_UNSUPPORTED&&failed==NULL);
    options.max_records=1;CHECK(dmg_snapshot_collect_method_calls_v1(s,0,0,&options,&failed,&error)==DMG_BUDGET_EXCEEDED&&failed==NULL);
    dmg_snapshot_close(s);dmg_snapshot_release(s);dmg_engine_release(e);
    CHECK(dmg_method_calls_get_caller_v1(calls,&caller,sizeof(caller))==DMG_OK&&caller.name_length==1&&caller.name[0]=='a');
    CHECK(dmg_method_calls_get_source_v1(calls,&source,sizeof(source))==DMG_OK&&source.source_index==0);
    CHECK(dmg_method_calls_get_row_v1(calls,0,&row,sizeof(row))==DMG_OK&&row.dex_pc==0&&row.target_domain==DMG_TARGET_METHOD_REF&&row.name_length==1&&row.name[0]=='b');
    CHECK(dmg_method_calls_get_row_v1(calls,1,&row,sizeof(row))==DMG_OK&&row.dex_pc==3);
    dmg_method_calls_release_v1(calls);puts("PASS snapshot-free plan and complete selected-method calls retained after close");return 0;
}
