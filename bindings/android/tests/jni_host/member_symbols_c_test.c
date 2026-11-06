#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"failed line %d\n",__LINE__);return 1;}}while(0)
static int text_is(dmg_snapshot* s,uint32_t kind,uint32_t id,const char* expected){
 uint64_t n=0;uint16_t out[128];size_t len=strlen(expected);if(dmg_snapshot_copy_symbol_text_v1(s,0,kind,id,128,NULL,0,&n)!=DMG_OK||n!=len||n>128)return 0;
 if(dmg_snapshot_copy_symbol_text_v1(s,0,kind,id,128,out,128,&n)!=DMG_OK)return 0;
 for(size_t i=0;i<len;i++)if(out[i]!=(unsigned char)expected[i])return 0;return 1;
}
int main(int argc,char** argv){
 CHECK(argc==2);FILE* f=fopen(argv[1],"rb");CHECK(f);CHECK(!fseek(f,0,SEEK_END));long n=ftell(f);CHECK(n>0);rewind(f);unsigned char* data=malloc((size_t)n);CHECK(data);CHECK(fread(data,1,(size_t)n,f)==(size_t)n);fclose(f);
 dmg_snapshot* s=NULL;dmg_error e={0};dmg_open_options opts={sizeof(opts),DMG_ABI_VERSION,(uint64_t)n,"member","slot",NULL};CHECK(dmg_snapshot_open_copy(data,(uint64_t)n,&opts,&s,&e)==DMG_OK);
 dmg_member_indices_v1 field={0};CHECK(dmg_snapshot_get_member_indices_v1(s,0,DMG_MEMBER_FIELD_V1,0,&field,sizeof(field))==DMG_OK);
 CHECK(text_is(s,DMG_SYMBOL_TYPE_V1,field.owner_type_index,"Lfixture/Annotated;"));CHECK(text_is(s,DMG_SYMBOL_STRING_V1,field.name_string_index,"value"));CHECK(text_is(s,DMG_SYMBOL_TYPE_V1,field.type_or_proto_index,"I"));
 dmg_member_indices_v1 method={0};CHECK(dmg_snapshot_get_member_indices_v1(s,0,DMG_MEMBER_METHOD_V1,2,&method,sizeof(method))==DMG_OK);CHECK(text_is(s,DMG_SYMBOL_STRING_V1,method.name_string_index,"run"));CHECK(text_is(s,DMG_SYMBOL_PROTO_V1,method.type_or_proto_index,"(Ljava/lang/String;)V"));
 dmg_member_indices_v1 sentinel={11,22,33};CHECK(dmg_snapshot_get_member_indices_v1(s,0,DMG_MEMBER_FIELD_V1,UINT32_MAX,&sentinel,sizeof(sentinel))==DMG_INVALID_ARGUMENT);CHECK(sentinel.owner_type_index==11&&sentinel.name_string_index==22&&sentinel.type_or_proto_index==33);
 CHECK(dmg_snapshot_get_member_indices_v1(s,0,99,0,&sentinel,sizeof(sentinel))==DMG_INVALID_ARGUMENT);CHECK(dmg_snapshot_get_member_indices_v1(s,0,DMG_MEMBER_FIELD_V1,0,&sentinel,sizeof(sentinel)-1)==DMG_INVALID_ARGUMENT);CHECK(sentinel.owner_type_index==11&&sentinel.name_string_index==22&&sentinel.type_or_proto_index==33);
 uint64_t length=99;uint16_t small[2]={0xdead,0xbeef};CHECK(dmg_snapshot_copy_symbol_text_v1(s,0,DMG_SYMBOL_PROTO_V1,method.type_or_proto_index,100,small,2,&length)==DMG_INVALID_ARGUMENT);CHECK(length==0&&small[0]==0xdead&&small[1]==0xbeef);
 dmg_snapshot_close(s);CHECK(dmg_snapshot_get_member_indices_v1(s,0,DMG_MEMBER_METHOD_V1,2,&sentinel,sizeof(sentinel))==DMG_CLOSED);CHECK(sentinel.owner_type_index==11);dmg_snapshot_release(s);free(data);puts("PASS C source-local member indices, prototype and failure atomicity");return 0;
}
