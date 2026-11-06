#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"failed line %d\n",__LINE__);return 1;}}while(0)
int main(int argc,char** argv){
 CHECK(argc==2);FILE* f=fopen(argv[1],"rb");CHECK(f);CHECK(!fseek(f,0,SEEK_END));long n=ftell(f);CHECK(n>0);rewind(f);unsigned char* input=malloc((size_t)n);CHECK(input);CHECK(fread(input,1,(size_t)n,f)==(size_t)n);fclose(f);
 dmg_snapshot* s=NULL;dmg_error e={0};dmg_open_options options={sizeof(options),DMG_ABI_VERSION,(uint64_t)n,"test","slot",NULL};CHECK(dmg_snapshot_open_copy(input,(uint64_t)n,&options,&s,&e)==DMG_OK);
 const uint8_t* bytes=NULL;uint64_t size=0;CHECK(dmg_snapshot_get_source_bytes_v1(s,0,(uint64_t)n,&bytes,&size)==DMG_OK);CHECK(size==(uint64_t)n&&!memcmp(input,bytes,(size_t)n));
 const uint8_t* out=(const uint8_t*)1;uint64_t count=1;CHECK(dmg_snapshot_get_source_bytes_v1(s,0,(uint64_t)n-1,&out,&count)==DMG_BUDGET_EXCEEDED);CHECK(!out&&!count);
 CHECK(dmg_snapshot_get_source_bytes_v1(s,1,(uint64_t)n,&out,&count)==DMG_INVALID_ARGUMENT);CHECK(!out&&!count);
 dmg_snapshot_close(s);CHECK(!memcmp(input,bytes,(size_t)n));CHECK(dmg_snapshot_get_source_bytes_v1(s,0,(uint64_t)n,&out,&count)==DMG_CLOSED);CHECK(!out&&!count);
 dmg_snapshot_release(s);free(input);puts("PASS C static source bytes, limit, index and lifetime");return 0;
}
