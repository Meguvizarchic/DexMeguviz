#include "dexmeguviz/persistent_cache_v1.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if(!(x)){fprintf(stderr,"check failed at %s:%d: %s\n",__FILE__,__LINE__,#x);return 1;} } while(0)
int main(int argc,char** argv){
    static const char query_json[]="{\"schema_version\":1,\"relation\":\"method_defs\",\"required_capabilities\":[\"type_uses\"],\"where\":{\"using_types\":{\"any\":[{\"descriptor\":{\"op\":\"contains\",\"value\":\"L\"}}]}},\"intent\":\"enumerate\",\"max_results\":100}";
    FILE* file;long size;uint8_t* bytes;dmg_engine *engine=NULL,*other=NULL;dmg_snapshot* snapshot=NULL;dmg_query *query=NULL,*foreign=NULL;dmg_persistent_cache_v1 *cache=NULL,*second=NULL;dmg_result *baseline=NULL,*cold=NULL,*warm=NULL,*invalid=(dmg_result*)(uintptr_t)1;dmg_error error={0};
    dmg_engine_stats initial_stats={0},final_stats={0};dmg_engine_options engine_options={0};dmg_open_options open_options={0};dmg_persistent_cache_options_v1 options={0};dmg_persistent_cache_stats_v1 first={0},last={0},sentinel;dmg_result_info reference={0},one={0},two={0};
    CHECK(argc==3);file=fopen(argv[1],"rb");CHECK(file);CHECK(fseek(file,0,SEEK_END)==0);size=ftell(file);CHECK(size>0&&size<=64*1024*1024);CHECK(fseek(file,0,SEEK_SET)==0);bytes=(uint8_t*)malloc((size_t)size);CHECK(bytes);CHECK(fread(bytes,1,(size_t)size,file)==(size_t)size);CHECK(fclose(file)==0);
    engine_options.struct_size=sizeof(engine_options);engine_options.abi_version=DMG_ABI_VERSION;engine_options.owned_bytes_limit=256uLL<<20;engine_options.max_source_bytes=64uLL<<20;engine_options.max_jobs=1;
    CHECK(dmg_engine_create(&engine_options,&engine,&error)==DMG_OK);CHECK(dmg_engine_get_stats(engine,&initial_stats)==DMG_OK);
    open_options.struct_size=sizeof(open_options);open_options.abi_version=DMG_ABI_VERSION;open_options.max_source_bytes=64uLL<<20;open_options.source_namespace="abi-cache";open_options.slot_key="base";
    CHECK(dmg_snapshot_open_copy_in(engine,bytes,(uint64_t)size,&open_options,&snapshot,&error)==DMG_OK);
    CHECK(dmg_query_compile_json(engine,(const uint8_t*)query_json,strlen(query_json),&query,&error)==DMG_OK);
    options.struct_size=sizeof(options);options.abi_version=DMG_ABI_VERSION;options.directory_utf8=(const uint8_t*)argv[2];options.directory_length=strlen(argv[2]);
    { const uint8_t bad_path[]={0xc0,0x80}; dmg_persistent_cache_options_v1 bad=options; dmg_persistent_cache_v1* rejected=(dmg_persistent_cache_v1*)(uintptr_t)1;
      bad.directory_utf8=bad_path;bad.directory_length=sizeof(bad_path);CHECK(dmg_persistent_cache_open_v1(engine,&bad,&rejected,&error)==DMG_INVALID_ARGUMENT&&rejected==NULL);
      bad=options;bad.max_file_bytes=(256uLL<<20)+1;rejected=(dmg_persistent_cache_v1*)(uintptr_t)1;CHECK(dmg_persistent_cache_open_v1(engine,&bad,&rejected,&error)==DMG_INVALID_ARGUMENT&&rejected==NULL); }
    CHECK(dmg_persistent_cache_open_v1(engine,&options,&cache,&error)==DMG_OK);
    CHECK(dmg_query_execute(snapshot,query,&baseline,&error)==DMG_OK);CHECK(dmg_result_get_info(baseline,&reference)==DMG_OK);CHECK(reference.candidates_count>0);
    CHECK(dmg_persistent_cache_execute_v1(cache,snapshot,query,&cold,&error)==DMG_OK);CHECK(dmg_result_get_info(cold,&one)==DMG_OK);
    CHECK(dmg_persistent_cache_get_stats_v1(cache,&first,sizeof(first))==DMG_OK);
    CHECK(dmg_persistent_cache_execute_v1(cache,snapshot,query,&warm,&error)==DMG_OK);CHECK(dmg_result_get_info(warm,&two)==DMG_OK);
    CHECK(dmg_persistent_cache_get_stats_v1(cache,&last,sizeof(last))==DMG_OK);CHECK(last.hits>first.hits);
    CHECK(one.candidates_count==reference.candidates_count&&two.candidates_count==reference.candidates_count&&one.execution_status==reference.execution_status&&two.coverage==reference.coverage&&two.decision==reference.decision);
    for(uint32_t i=0;i<reference.candidates_count;++i){dmg_method_row a={0},b={0},c={0};CHECK(dmg_result_get_method(baseline,i,&a)==DMG_OK&&dmg_result_get_method(cold,i,&b)==DMG_OK&&dmg_result_get_method(warm,i,&c)==DMG_OK);CHECK(a.method_index==b.method_index&&b.method_index==c.method_index&&a.access_flags==b.access_flags&&a.code_offset==c.code_offset);}
    memset(&sentinel,0x5a,sizeof(sentinel));CHECK(dmg_persistent_cache_get_stats_v1(cache,&sentinel,(uint32_t)sizeof(sentinel)-1)==DMG_INVALID_ARGUMENT);for(size_t i=0;i<sizeof(sentinel);++i)CHECK(((unsigned char*)&sentinel)[i]==0x5a);
    CHECK(dmg_engine_create(&engine_options,&other,&error)==DMG_OK);CHECK(dmg_query_compile_json(other,(const uint8_t*)query_json,strlen(query_json),&foreign,&error)==DMG_OK);
    CHECK(dmg_persistent_cache_execute_v1(cache,snapshot,foreign,&invalid,&error)==DMG_INVALID_ARGUMENT&&invalid==NULL);dmg_query_release(foreign);CHECK(dmg_engine_shutdown(other,0)==DMG_OK);dmg_engine_release(other);
    CHECK(dmg_persistent_cache_open_v1(engine,&options,&second,&error)==DMG_OK);CHECK(dmg_persistent_cache_close_v1(cache)==DMG_OK);invalid=(dmg_result*)(uintptr_t)1;
    CHECK(dmg_persistent_cache_execute_v1(cache,snapshot,query,&invalid,&error)==DMG_CLOSED&&invalid==NULL);CHECK(dmg_persistent_cache_get_stats_v1(cache,&last,sizeof(last))==DMG_OK);dmg_persistent_cache_release_v1(cache);
    dmg_snapshot_close(snapshot);invalid=(dmg_result*)(uintptr_t)1;CHECK(dmg_persistent_cache_execute_v1(second,snapshot,query,&invalid,&error)==DMG_CLOSED&&invalid==NULL);
    dmg_snapshot_release(snapshot);dmg_query_release(query);dmg_persistent_cache_release_v1(second);CHECK(dmg_result_get_info(warm,&two)==DMG_OK&&two.candidates_count==reference.candidates_count);
    dmg_result_release(baseline);dmg_result_release(cold);dmg_result_release(warm);
    { dmg_engine* owner=NULL;dmg_snapshot* held_snapshot=NULL;dmg_query* held_query=NULL;dmg_persistent_cache_v1* held_cache=NULL;dmg_result* held_result=NULL;dmg_result_info held_info={0};
      CHECK(dmg_engine_create(&engine_options,&owner,&error)==DMG_OK);CHECK(dmg_snapshot_open_copy_in(owner,bytes,(uint64_t)size,&open_options,&held_snapshot,&error)==DMG_OK);
      CHECK(dmg_query_compile_json(owner,(const uint8_t*)query_json,strlen(query_json),&held_query,&error)==DMG_OK);CHECK(dmg_persistent_cache_open_v1(owner,&options,&held_cache,&error)==DMG_OK);
      dmg_engine_release(owner);CHECK(dmg_persistent_cache_execute_v1(held_cache,held_snapshot,held_query,&held_result,&error)==DMG_OK);
      dmg_snapshot_close(held_snapshot);dmg_snapshot_release(held_snapshot);dmg_query_release(held_query);dmg_persistent_cache_release_v1(held_cache);
      CHECK(dmg_result_get_info(held_result,&held_info)==DMG_OK&&held_info.candidates_count>0);dmg_result_release(held_result); }
    free(bytes);
    { char unicode_path[4096];int n=snprintf(unicode_path,sizeof(unicode_path),"%s-\xe9\x9b\xaa",argv[2]);dmg_persistent_cache_v1* unicode_cache=NULL;dmg_persistent_cache_options_v1 unicode_options=options;CHECK(n>0&&(size_t)n<sizeof(unicode_path));unicode_options.directory_utf8=(const uint8_t*)unicode_path;unicode_options.directory_length=(uint64_t)n;CHECK(dmg_persistent_cache_open_v1(engine,&unicode_options,&unicode_cache,&error)==DMG_OK);dmg_persistent_cache_release_v1(unicode_cache); }
    CHECK(dmg_engine_get_stats(engine,&final_stats)==DMG_OK&&final_stats.owned_bytes==initial_stats.owned_bytes&&final_stats.borrowed_bytes==initial_stats.borrowed_bytes);
    CHECK(dmg_engine_shutdown(engine,0)==DMG_OK);cache=(dmg_persistent_cache_v1*)(uintptr_t)1;CHECK(dmg_persistent_cache_open_v1(engine,&options,&cache,&error)==DMG_CLOSED&&cache==NULL);dmg_engine_release(engine);
    puts("PASS optional persistent C ABI cold/warm, same-engine, close, size and result lifetime");return 0;
}
