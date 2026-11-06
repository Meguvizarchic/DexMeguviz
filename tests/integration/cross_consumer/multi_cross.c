#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"multi C failure at %d: %s\n",__LINE__,#x);return 1;}}while(0)
static unsigned char* read_file(const char* path,size_t* length){
 FILE* f=fopen(path,"rb");long n;unsigned char* data;if(!f)return NULL;
 if(fseek(f,0,SEEK_END)!=0||(n=ftell(f))<=0||fseek(f,0,SEEK_SET)!=0){fclose(f);return NULL;}
 data=(unsigned char*)malloc((size_t)n);if(!data){fclose(f);return NULL;}
 if(fread(data,1,(size_t)n,f)!=(size_t)n){free(data);fclose(f);return NULL;}fclose(f);*length=(size_t)n;return data;
}
static int ascii_text(const uint16_t* value,uint64_t length){uint64_t i;if(!value&&length)return 0;for(i=0;i<length;++i){if(value[i]<32||value[i]>126)return 0;putchar((int)value[i]);}return 1;}
int main(int argc,char** argv){
 size_t sizes[2]={0},json_size=0;unsigned char* bytes[2];unsigned char* json;dmg_engine* engine=NULL;dmg_snapshot* snapshot=NULL;dmg_query* query=NULL;dmg_result* result=NULL;
 dmg_error error={0};dmg_result_info info={0};dmg_query_info qi={0};dmg_snapshot_overview overview={0};dmg_source_spec spec[2]={{0},{0}};
 dmg_source_set_options options={sizeof(options),DMG_ABI_VERSION,"android-jni",0,8,1u<<20};uint32_t i;
 CHECK(argc==4);bytes[0]=read_file(argv[1],&sizes[0]);bytes[1]=read_file(argv[2],&sizes[1]);json=read_file(argv[3],&json_size);CHECK(bytes[0]&&bytes[1]&&json);
 CHECK(dmg_engine_create(NULL,&engine,&error)==DMG_OK);
 for(i=0;i<2;++i){spec[i].struct_size=sizeof(spec[i]);spec[i].abi_version=DMG_ABI_VERSION;spec[i].format=DMG_INPUT_RAW_DEX;spec[i].data=bytes[i];spec[i].size=sizes[i];spec[i].slot_key=i?"split":"base";spec[i].role="raw-dex";}
 CHECK(dmg_snapshot_open_sources(engine,spec,2,&options,&snapshot,&error)==DMG_OK);free(bytes[0]);free(bytes[1]);
 CHECK(dmg_query_compile_json(engine,json,json_size,&query,&error)==DMG_OK);free(json);CHECK(dmg_query_execute(snapshot,query,&result,&error)==DMG_OK&&result);
 CHECK(dmg_result_get_info(result,&info)==DMG_OK&&dmg_result_get_query_info(result,&qi)==DMG_OK&&dmg_result_get_overview(result,&overview)==DMG_OK);
 CHECK(qi.query_id&&overview.snapshot_id&&overview.source_count==2&&!overview.scope_complete);
 printf("RESULT\t%s\t%s\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n",qi.query_id,overview.snapshot_id,info.execution_status,info.coverage,info.decision,info.reason,info.candidates_count,info.visited_methods,info.total_methods);
 for(i=0;i<overview.source_count;++i){dmg_source_info s={0};CHECK(dmg_result_get_source_info(result,i,&s)==DMG_OK&&s.slot_key&&s.dex.source_sha256&&s.dex.content_id&&s.dex.occurrence_id&&s.logical_dex_id);printf("SOURCE\t%u\t%u\t%s\t%s\t%s\t%s\t%s\n",s.source_index,s.input_index,s.slot_key,s.dex.source_sha256,s.dex.content_id,s.dex.occurrence_id,s.logical_dex_id);}
 for(i=0;i<info.candidates_count;++i){dmg_method_row row={0};dmg_source_info s={0};CHECK(dmg_result_get_method(result,i,&row)==DMG_OK&&dmg_result_get_origin(result,i,&s)==DMG_OK);CHECK(s.slot_key&&s.dex.occurrence_id);
  printf("ROW\t%u\t%u\t%u\t%u\t%u\t%u\t",s.source_index,s.input_index,row.method_index,row.access_flags,row.declaration_offset,row.code_offset);
  CHECK(ascii_text(row.owner,row.owner_length));putchar('\t');CHECK(ascii_text(row.name,row.name_length));putchar('\t');CHECK(ascii_text(row.prototype,row.prototype_length));printf("\t%s\t%s\n",s.slot_key,s.dex.occurrence_id);
 }
 dmg_result_release(result);dmg_query_release(query);dmg_snapshot_release(snapshot);dmg_engine_release(engine);return 0;
}
