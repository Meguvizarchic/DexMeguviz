#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"checksum C consumer line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char** argv){
    FILE* file;long length;unsigned char* bytes;dmg_snapshot* snapshot=NULL;dmg_result* result=NULL;dmg_error error;
    dmg_dex_checksums_v1 checks;dmg_method_query query={0};
    dmg_open_options options={sizeof(options),DMG_ABI_VERSION,0,"checksums-c","slot",NULL};
    CHECK(argc==2);file=fopen(argv[1],"rb");CHECK(file!=NULL);CHECK(fseek(file,0,SEEK_END)==0);length=ftell(file);CHECK(length>112);
    CHECK(fseek(file,0,SEEK_SET)==0);bytes=(unsigned char*)malloc((size_t)length);CHECK(bytes!=NULL);
    CHECK(fread(bytes,1,(size_t)length,file)==(size_t)length);fclose(file);
    CHECK(dmg_snapshot_open_copy(bytes,(uint64_t)length,&options,&snapshot,&error)==DMG_OK);memset(bytes,0,(size_t)length);free(bytes);
    CHECK(dmg_snapshot_check_dex_checksums_v1(snapshot,0,(uint64_t)length,&checks,sizeof(checks))==DMG_OK);
    CHECK(checks.adler32_matches==1&&checks.sha1_matches==1&&checks.input_bytes==(uint64_t)length);
    query.struct_size=sizeof(query);query.abi_version=DMG_ABI_VERSION;query.intent=DMG_ENUMERATE;query.max_results=64;
    CHECK(dmg_query_methods(snapshot,&query,&result,&error)==DMG_OK);dmg_snapshot_close(snapshot);dmg_snapshot_release(snapshot);
    CHECK(dmg_result_check_dex_checksums_v1(result,0,(uint64_t)length,&checks,sizeof(checks))==DMG_OK&&checks.sha1_matches==1);
    dmg_result_release(result);puts("PASS C checksum consumer: additive ABI and retained source lifetime");return 0;
}
