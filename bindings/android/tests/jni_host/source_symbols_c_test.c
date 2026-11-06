#include "dexmeguviz/dexmeguviz.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAILED line %d\n",__LINE__);return 1;}}while(0)
static int unicode(const char* path,uint32_t index,const uint16_t* expected,size_t count){
 FILE* f=fopen(path,"rb");CHECK(f);CHECK(!fseek(f,0,SEEK_END));long n=ftell(f);CHECK(n>0);rewind(f);uint8_t* bytes=malloc((size_t)n);CHECK(bytes&&fread(bytes,1,(size_t)n,f)==(size_t)n);fclose(f);
 dmg_snapshot* s=NULL;dmg_error e={0};dmg_open_options opt={sizeof(opt),DMG_ABI_VERSION,(uint64_t)n,"unicode","slot",NULL};CHECK(dmg_snapshot_open_copy(bytes,(uint64_t)n,&opt,&s,&e)==DMG_OK);
 uint64_t len=999;uint16_t out[16];for(size_t i=0;i<16;i++)out[i]=0xbeef;
 CHECK(dmg_snapshot_copy_symbol_text_v1(s,0,DMG_SYMBOL_STRING_V1,index,16,NULL,0,&len)==DMG_OK&&len==count);
 if(count>0){len=999;CHECK(dmg_snapshot_copy_symbol_text_v1(s,0,DMG_SYMBOL_STRING_V1,index,16,out,count-1,&len)==DMG_INVALID_ARGUMENT&&len==0);for(size_t i=0;i<16;i++)CHECK(out[i]==0xbeef);}
 CHECK(dmg_snapshot_copy_symbol_text_v1(s,0,DMG_SYMBOL_STRING_V1,index,16,out,16,&len)==DMG_OK&&len==count);for(size_t i=0;i<count;i++)CHECK(out[i]==expected[i]);for(size_t i=count;i<16;i++)CHECK(out[i]==0xbeef);
 if(count>1){len=999;CHECK(dmg_snapshot_copy_symbol_text_v1(s,0,DMG_SYMBOL_STRING_V1,index,count-1,out,16,&len)==DMG_BUDGET_EXCEEDED&&len==0);}
 len=999;CHECK(dmg_snapshot_copy_symbol_text_v1(s,1,DMG_SYMBOL_STRING_V1,index,16,out,16,&len)==DMG_INVALID_ARGUMENT&&len==0);
 len=999;CHECK(dmg_snapshot_copy_symbol_text_v1(s,0,DMG_SYMBOL_STRING_V1,UINT32_MAX,16,out,16,&len)==DMG_INVALID_ARGUMENT&&len==0);
 len=999;CHECK(dmg_snapshot_copy_symbol_text_v1(s,0,99,index,16,out,16,&len)==DMG_INVALID_ARGUMENT&&len==0);
 dmg_snapshot_close(s);len=999;CHECK(dmg_snapshot_copy_symbol_text_v1(s,0,DMG_SYMBOL_STRING_V1,index,16,out,16,&len)==DMG_CLOSED&&len==0);dmg_snapshot_release(s);free(bytes);return 0;
}
int main(int argc,char**argv){
 CHECK(argc==5);const uint16_t high[]={0xd800},low[]={0xdc00},mixed[]={0xd800,0x0078,0xdc00,0,0xd83d,0xde00};
 CHECK(unicode(argv[1],7,high,1)==0);CHECK(unicode(argv[2],7,low,1)==0);CHECK(unicode(argv[3],7,mixed,6)==0);CHECK(unicode(argv[4],0,NULL,0)==0);
 puts("PASS C UTF16 symbols, bounds and closed snapshot");return 0;
}
