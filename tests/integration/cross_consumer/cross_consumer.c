#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"cross C failure at %d: %s\n",__LINE__,#x); return 1; } } while (0)
static unsigned char* read_file(const char* path,size_t* length) {
    FILE* f=fopen(path,"rb");long n;unsigned char* data;
    if(!f)return NULL;
    if(fseek(f,0,SEEK_END)!=0 || (n=ftell(f))<=0 || fseek(f,0,SEEK_SET)!=0){fclose(f);return NULL;}
    data=(unsigned char*)malloc((size_t)n);if(!data){fclose(f);return NULL;}
    if(fread(data,1,(size_t)n,f)!=(size_t)n){free(data);fclose(f);return NULL;}
    fclose(f);*length=(size_t)n;return data;
}
static int ascii_text(const uint16_t* value,uint64_t length){
    uint64_t i;if(!value&&length)return 0;
    for(i=0;i<length;++i){if(value[i]<32||value[i]>126)return 0;putchar((int)value[i]);}
    return 1;
}
int main(int argc,char** argv) {
    size_t dex_size=0,json_size=0;unsigned char* dex;unsigned char* json;
    dmg_engine* engine=NULL;dmg_snapshot* snapshot=NULL;dmg_query* query=NULL;dmg_result* result=NULL;
    dmg_error error={0};dmg_result_info info={0};dmg_query_info qi={0};dmg_snapshot_info source={0};
    dmg_source_spec spec={0};dmg_source_set_options options={sizeof(options),DMG_ABI_VERSION,"cross",0,8,1u<<20};
    uint32_t i;
    CHECK(argc==3);dex=read_file(argv[1],&dex_size);json=read_file(argv[2],&json_size);CHECK(dex&&json);
    CHECK(dmg_engine_create(NULL,&engine,&error)==DMG_OK);
    spec.struct_size=sizeof(spec);spec.abi_version=DMG_ABI_VERSION;spec.format=DMG_INPUT_RAW_DEX;spec.data=dex;spec.size=dex_size;spec.slot_key="one";spec.role="base";
    CHECK(dmg_snapshot_open_sources(engine,&spec,1,&options,&snapshot,&error)==DMG_OK);free(dex);
    CHECK(dmg_query_compile_json(engine,json,json_size,&query,&error)==DMG_OK);free(json);
    CHECK(dmg_query_execute(snapshot,query,&result,&error)==DMG_OK&&result);
    CHECK(dmg_result_get_info(result,&info)==DMG_OK&&dmg_result_get_query_info(result,&qi)==DMG_OK);
    CHECK(dmg_result_get_source(result,&source)==DMG_OK&&source.source_sha256&&qi.query_id);
    printf("RESULT\t%s\t%s\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n",qi.query_id,source.source_sha256,info.execution_status,info.coverage,info.decision,info.reason,info.candidates_count,info.visited_methods,info.total_methods);
    for(i=0;i<info.candidates_count;++i){dmg_method_row row={0};CHECK(dmg_result_get_method(result,i,&row)==DMG_OK);printf("ROW\t%u\t%u\t%u\t%u\t",row.method_index,row.access_flags,row.declaration_offset,row.code_offset);CHECK(ascii_text(row.owner,row.owner_length));putchar('\t');CHECK(ascii_text(row.name,row.name_length));putchar('\t');CHECK(ascii_text(row.prototype,row.prototype_length));putchar('\n');}
    dmg_result_release(result);dmg_query_release(query);dmg_snapshot_release(snapshot);dmg_engine_release(engine);
    return 0;
}
