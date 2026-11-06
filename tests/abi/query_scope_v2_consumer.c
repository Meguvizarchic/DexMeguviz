#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <string.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"scope v2 line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(void){dmg_engine* e=NULL;dmg_query* q=NULL;dmg_error error={0};dmg_query_scope_v2 scope;const char* slot=NULL;
 const char* json="{\"schema_version\":1,\"relation\":\"class_defs\",\"scope\":{\"slots\":[\"two\",\"one\"]},\"required_capabilities\":[\"class_annotation_static\"],\"where\":{\"annotation\":{\"type\":\"Lfixture/Complex;\"}}}";
 CHECK(dmg_engine_create(NULL,&e,&error)==DMG_OK);CHECK(dmg_query_compile_json(e,(const uint8_t*)json,strlen(json),&q,&error)==DMG_OK);
 memset(&scope,0x5a,sizeof(scope));CHECK(dmg_query_get_scope_v2(q,&scope,sizeof(scope)-1)==DMG_INVALID_ARGUMENT&&((unsigned char*)&scope)[0]==0x5a);
 CHECK(dmg_query_get_scope_v2(q,&scope,sizeof(scope))==DMG_OK&&scope.explicit_scope==1&&scope.slot_count==2);
 CHECK(dmg_query_get_scope_slot_v2(q,0,&slot)==DMG_OK&&!strcmp(slot,"one"));CHECK(dmg_query_get_scope_slot_v2(q,1,&slot)==DMG_OK&&!strcmp(slot,"two"));
 slot=(const char*)1;CHECK(dmg_query_get_scope_slot_v2(q,2,&slot)==DMG_INVALID_ARGUMENT&&slot==(const char*)1);
 CHECK(dmg_query_get_explain_scope_v1(q,UINT32_MAX,0,&slot)==DMG_UNSUPPORTED&&slot==(const char*)1);
 dmg_query_release(q);q=NULL;
 {const char* plain="{\"schema_version\":1,\"relation\":\"class_defs\"}";dmg_query_info info;
  CHECK(dmg_query_compile_json(e,(const uint8_t*)plain,strlen(plain),&q,&error)==DMG_OK);CHECK(dmg_query_get_info(q,&info)==DMG_OK);
  CHECK(dmg_query_get_scope_v2(q,&scope,sizeof(scope))==DMG_OK&&scope.explicit_scope==0&&scope.slot_count==0);dmg_query_release(q);q=NULL;}
 {const char* graph="{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"class_defs\"},\"required_capabilities\":[\"relational\"]}";
  CHECK(dmg_query_compile_json(e,(const uint8_t*)graph,strlen(graph),&q,&error)==DMG_OK);memset(&scope,0x5a,sizeof(scope));CHECK(dmg_query_get_scope_v2(q,&scope,sizeof(scope))==DMG_UNSUPPORTED&&((unsigned char*)&scope)[0]==0x5a);dmg_query_release(q);}
 dmg_engine_release(e);puts("PASS scope v2 exact size, canonical slots, graph refusal and legacy refusal");return 0;}
