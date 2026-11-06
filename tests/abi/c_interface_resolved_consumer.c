#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"interface C consumer line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char** argv){
 const char* names[]={"child.dex","base.dex","root.dex","top.dex","left.dex","left-alt.dex","right.dex"};
 const char* slots[]={"child","base","root","top","left","left-alt","right"};
 unsigned char* buffers[7]={0};dmg_source_spec specs[7]={0};dmg_snapshot* snapshot=NULL;dmg_result* result=NULL;dmg_query* query=NULL;dmg_engine* engine=NULL;dmg_error error;
 const char* text="{\"schema_version\":1,\"relation\":\"class_defs\",\"where\":{\"all\":[{\"descriptor\":\"Lifx/Child;\"},{\"declares_fields\":{\"scope\":\"inherited_interfaces_resolved\",\"where\":{\"name\":\"diamond\"},\"min\":1,\"max\":1}}]},\"intent\":\"unique\"}";
 dmg_source_set_options options={sizeof(options),DMG_ABI_VERSION,"interface-c",1,8,1u<<20};dmg_relation_info info;uint32_t count=0,i;unsigned choices=0;
 CHECK(argc==2);CHECK(dmg_engine_create(NULL,&engine,&error)==DMG_OK);
 for(i=0;i<7;++i){char path[2048];FILE* f;long size;CHECK(snprintf(path,sizeof(path),"%s/%s",argv[1],names[i])>0);f=fopen(path,"rb");CHECK(f!=NULL);CHECK(fseek(f,0,SEEK_END)==0);size=ftell(f);CHECK(size>0&&fseek(f,0,SEEK_SET)==0);
  buffers[i]=(unsigned char*)malloc((size_t)size);CHECK(buffers[i]&&fread(buffers[i],1,(size_t)size,f)==(size_t)size);fclose(f);
  specs[i].struct_size=sizeof(specs[i]);specs[i].abi_version=DMG_ABI_VERSION;specs[i].format=DMG_INPUT_RAW_DEX;specs[i].data=buffers[i];specs[i].size=(uint64_t)size;specs[i].slot_key=slots[i];specs[i].role=i?"code-split":"base";
 }
 CHECK(dmg_snapshot_open_sources(engine,specs,7,&options,&snapshot,&error)==DMG_OK);for(i=0;i<7;++i)free(buffers[i]);
 CHECK(dmg_query_compile_json(engine,(const uint8_t*)text,strlen(text),&query,&error)==DMG_OK);
 CHECK(dmg_query_execute(snapshot,query,&result,&error)==DMG_OK);dmg_query_release(query);dmg_snapshot_close(snapshot);dmg_snapshot_release(snapshot);
 CHECK(dmg_result_get_relation_info(result,&info,sizeof(info))==DMG_OK&&info.candidates_count==1&&info.decision==DMG_PROVEN_TRUE);
 CHECK(dmg_result_get_witness_count(result,0,&count)==DMG_OK);
 for(i=0;i<count;++i){dmg_interface_witness_v1 proof;dmg_status status=dmg_result_get_interface_resolved_witness_v1(result,0,i,&proof,sizeof(proof));
  if(status==DMG_UNSUPPORTED)continue;CHECK(status==DMG_OK);CHECK(dmg_result_get_interface_witness_v1(result,0,i,&proof,sizeof(proof))==DMG_UNSUPPORTED);if(proof.item_kind==6){CHECK((proof.source_index==4||proof.source_index==5)&&proof.relation==DMG_CLASS_DEFS);++choices;}}
 CHECK(choices==2);dmg_result_release(result);dmg_engine_release(engine);puts("PASS v11 interface C ABI, choices and accessor isolation");return 0;
}
