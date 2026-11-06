#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"method ref C ABI line %d: %s\n",__LINE__,#x);return 1;}}while(0)
static unsigned char* read_file(const char* path,long* size){FILE* f=fopen(path,"rb");unsigned char* p;if(!f)return NULL;if(fseek(f,0,SEEK_END)||(*size=ftell(f))<=0||fseek(f,0,SEEK_SET)){fclose(f);return NULL;}p=(unsigned char*)malloc((size_t)*size);if(!p||fread(p,1,(size_t)*size,f)!=(size_t)*size){fclose(f);free(p);return NULL;}fclose(f);return p;}
int main(int argc,char** argv){
 dmg_engine* engine=NULL;dmg_snapshot* snap=NULL;dmg_query* query=NULL;dmg_result* result=NULL;dmg_error error={0};dmg_relation_info info;dmg_entity_row row;dmg_source_info origin[3];dmg_source_spec inputs[3];dmg_source_set_options so={sizeof(so),DMG_ABI_VERSION,"method-ref-fixture",0,8,8u<<20};long as=0,bs=0;unsigned char *a,*b;uint32_t i;const char* q="{\"schema_version\":1,\"relation\":\"method_refs\",\"where\":{\"name\":\"sink\"},\"intent\":\"enumerate\"}";
 CHECK(argc==3);a=read_file(argv[1],&as);b=read_file(argv[2],&bs);CHECK(a&&b);CHECK(dmg_engine_create(NULL,&engine,&error)==DMG_OK);
 inputs[0]=(dmg_source_spec){sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,a,(uint64_t)as,"a","raw",NULL};inputs[1]=(dmg_source_spec){sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,a,(uint64_t)as,"b","raw",NULL};inputs[2]=(dmg_source_spec){sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,b,(uint64_t)bs,"c","raw",NULL};
 CHECK(dmg_snapshot_open_sources(engine,inputs,3,&so,&snap,&error)==DMG_OK);CHECK(dmg_query_compile_json(engine,(const uint8_t*)q,strlen(q),&query,&error)==DMG_OK);CHECK(dmg_query_execute(snap,query,&result,&error)==DMG_OK);CHECK(dmg_result_get_relation_info(result,&info,sizeof(info))==DMG_OK&&info.candidates_count==3&&info.execution_status==DMG_OK&&info.coverage==DMG_COVERAGE_PARTIAL);
 for(i=0;i<3;++i){CHECK(dmg_result_get_entity(result,i,&row,sizeof(row))==DMG_OK);CHECK(row.source_index==i&&row.definition_known==(i==2)&&row.flags_known==(i==2)&&!row.code_known&&row.name_length==4);CHECK(dmg_result_get_origin(result,i,&origin[i])==DMG_OK&&origin[i].source_index==i);}
 CHECK(strcmp(origin[0].dex.occurrence_id,origin[1].dex.occurrence_id)!=0&&strcmp(origin[0].dex.occurrence_id,origin[2].dex.occurrence_id)!=0);
 dmg_result_release(result);dmg_query_release(query);dmg_snapshot_release(snap);dmg_engine_release(engine);free(a);free(b);puts("PASS C method refs, duplicate occurrence, local definition and code_known compatibility");return 0;
}
