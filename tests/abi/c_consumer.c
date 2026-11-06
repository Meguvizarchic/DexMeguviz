#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"check failed at line %d: %s\n",__LINE__,#x); return 1; } } while(0)
int main(int argc,char** argv) {
    FILE* input;
    long length;
    unsigned char* bytes;
    dmg_snapshot* snapshot=NULL;
    dmg_result* result=NULL;
    dmg_snapshot_info source;
    dmg_result_info info;
    dmg_method_row row;
    dmg_error error;
    dmg_open_options options={sizeof(dmg_open_options),DMG_ABI_VERSION,DMG_MAX_SOURCE_BYTES,"c-consumer","fixture",NULL};
    dmg_method_query query={0};
    CHECK(argc==2);
    input=fopen(argv[1],"rb");CHECK(input!=NULL);
    CHECK(fseek(input,0,SEEK_END)==0);length=ftell(input);CHECK(length>0);
    CHECK(fseek(input,0,SEEK_SET)==0);bytes=(unsigned char*)malloc((size_t)length);CHECK(bytes!=NULL);
    CHECK(fread(bytes,1,(size_t)length,input)==(size_t)length);fclose(input);
    CHECK(dmg_abi_version()==DMG_ABI_VERSION);
    CHECK(dmg_snapshot_open_copy(bytes,(uint64_t)length,&options,&snapshot,&error)==DMG_OK);
    memset(bytes,0,(size_t)length);free(bytes);
    CHECK(dmg_snapshot_get_info(snapshot,&source)==DMG_OK);
    CHECK(source.method_def_count==2 && source.method_ref_count==3);
    query.struct_size=sizeof(query);query.abi_version=DMG_ABI_VERSION;query.intent=DMG_ENUMERATE;query.max_results=16;
    CHECK(dmg_query_methods(snapshot,&query,&result,&error)==DMG_OK);
    dmg_snapshot_close(snapshot);
    {dmg_result* rejected=NULL;CHECK(dmg_query_methods(snapshot,&query,&rejected,&error)==DMG_CLOSED);CHECK(rejected==NULL);}
    dmg_snapshot_release(snapshot);
    CHECK(dmg_result_get_info(result,&info)==DMG_OK && info.candidates_count==2 && info.coverage==DMG_COVERAGE_COMPLETE);
    CHECK(dmg_result_get_method(result,0,&row)==DMG_OK && row.name_length>0);
    CHECK(dmg_result_get_source(result,&source)==DMG_OK && strlen(source.source_sha256)==64);
    dmg_result_retain(result);dmg_result_release(result);dmg_result_release(result);
    puts("PASS C consumer: owned copy, real query, close rejection, result lifetime");return 0;
}
