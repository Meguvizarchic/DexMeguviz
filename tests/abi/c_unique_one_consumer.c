#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    const char* text="{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"},\"intent\":\"unique\",\"max_results\":1,\"required_capabilities\":[\"unique_one_stream\"]}";
    dmg_engine* engine=0;dmg_query* query=0;dmg_error error={0};dmg_query_info info={0};
    if(dmg_engine_create(0,&engine,&error)!=DMG_OK||!engine)return 1;
    if(dmg_query_compile_json(engine,(const uint8_t*)text,strlen(text),&query,&error)!=DMG_OK||!query)return 2;
    if(dmg_query_get_info(query,&info)!=DMG_OK||strcmp(info.query_id,"query:v12:89ced6aa2081ad2dc50dab1daa56558a04e26c9bdb8c4de56dc2522fcb2f2366")!=0||
       (info.required_capabilities&(1048576u|131072u))!=(1048576u|131072u)||
       !strstr(dmg_capabilities(),"dex-query-unique-one-v12"))return 3;
    dmg_query_release(query);query=0;
    {
        const char* rejected[]={
          "{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"},\"intent\":\"unique\",\"max_results\":1,\"required_capabilities\":[\"unique_one_stream\",\"string_uses\"]}",
          "{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"},\"intent\":\"unique\",\"max_results\":1,\"required_capabilities\":[\"unique_one_stream\",\"field_uses\"]}"
        };
        unsigned i;
        for(i=0;i<2;++i){
            if(dmg_query_compile_json(engine,(const uint8_t*)rejected[i],strlen(rejected[i]),&query,&error)!=DMG_UNSUPPORTED||query)return 4;
        }
    }
    {
        const char* legacy[]={
          "{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"},\"intent\":\"unique\",\"max_results\":1,\"required_capabilities\":[\"use_streaming\",\"string_uses\"]}",
          "{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"},\"intent\":\"unique\",\"max_results\":1,\"required_capabilities\":[\"use_streaming\",\"field_uses\"]}"
        };
        unsigned i;
        for(i=0;i<2;++i){
            if(dmg_query_compile_json(engine,(const uint8_t*)legacy[i],strlen(legacy[i]),&query,&error)!=DMG_OK||!query)return 5;
            if(dmg_query_get_info(query,&info)!=DMG_OK||strncmp(info.query_id,"query:v9:",9)!=0)return 6;
            dmg_query_release(query);query=0;
        }
    }
    dmg_engine_release(engine);
    puts("PASS v12 C consumer rejects unrelated use bits; v9 accepts legacy combinations");return 0;
}
