#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"C annotation line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char** argv){
 const char* q="{\"schema_version\":1,\"required_capabilities\":[\"reflection_flags_static\",\"reflection_class_annotations_static\"],\"relation\":\"class_defs\",\"where\":{\"flags\":{\"domain\":\"reflection\",\"mode\":\"contains\",\"value\":0}}}";
 dmg_engine* engine=NULL;dmg_snapshot* snapshot=NULL;dmg_query* query=NULL;dmg_result* result=NULL;dmg_error err={0};dmg_query_info qi={0};dmg_relation_info ri={0};FILE* f;long size;unsigned char* data;unsigned i,found=0,fallback=0;
 CHECK(argc==2);f=fopen(argv[1],"rb");CHECK(f&&fseek(f,0,SEEK_END)==0);size=ftell(f);CHECK(size>0&&fseek(f,0,SEEK_SET)==0);data=(unsigned char*)malloc((size_t)size);CHECK(data&&fread(data,1,(size_t)size,f)==(size_t)size);fclose(f);
 CHECK(dmg_engine_create(NULL,&engine,&err)==DMG_OK);dmg_source_spec spec={0};spec.struct_size=sizeof(spec);spec.abi_version=DMG_ABI_VERSION;spec.format=DMG_INPUT_RAW_DEX;spec.data=data;spec.size=(uint64_t)size;spec.slot_key="base";spec.role="base";dmg_source_set_options opts={sizeof(opts),DMG_ABI_VERSION,"annotation-c",1,8,1u<<20};CHECK(dmg_snapshot_open_sources(engine,&spec,1,&opts,&snapshot,&err)==DMG_OK);free(data);
 CHECK(dmg_query_compile_json(engine,(const uint8_t*)q,strlen(q),&query,&err)==DMG_OK);CHECK(dmg_query_get_info(query,&qi)==DMG_OK&&strncmp(qi.query_id,"query:v20:",10)==0);CHECK(dmg_query_execute(snapshot,query,&result,&err)==DMG_OK);CHECK(dmg_result_get_relation_info(result,&ri,sizeof(ri))==DMG_OK&&ri.candidates_count==6&&ri.unknown_rows==0);
 for(i=0;i<ri.candidates_count;++i){uint32_t n=0,j;dmg_entity_row row={0};CHECK(dmg_result_get_entity(result,i,&row,sizeof(row))==DMG_OK);CHECK(dmg_result_get_witness_count(result,i,&n)==DMG_OK&&n>=2);
  for(j=0;j<n;++j){dmg_class_annotation_flags_witness_v1 v,before;dmg_witness old;memset(&v,0xa5,sizeof(v));before=v;
   dmg_status s=dmg_result_get_class_annotation_flags_witness_v1(result,i,j,&v,sizeof(v)-1);CHECK(s==DMG_INVALID_ARGUMENT&&!memcmp(&v,&before,sizeof(v)));
   s=dmg_result_get_class_annotation_flags_witness_v1(result,i,j,&v,sizeof(v));if(s==DMG_UNSUPPORTED){CHECK(!memcmp(&v,&before,sizeof(v)));continue;}CHECK(s==DMG_OK&&v.source_index==0&&v.class_ordinal==row.local_index&&v.raw_flags==row.access_flags&&v.matched==1);CHECK(dmg_result_get_witness(result,i,j,&old)==DMG_UNSUPPORTED);
   if(v.source_kind==DMG_CLASS_FLAGS_INNER_INT){CHECK(v.item_offset&&v.set_offset&&v.directory_offset&&v.value_offset&&v.encoded_flags==v.projected_flags);++found;}
   else {CHECK(v.source_kind==DMG_CLASS_FLAGS_NO_SYSTEM_INNER&&v.item_offset==0&&v.value_offset==0&&v.projected_flags==v.raw_flags);++fallback;}
  }
 }
 CHECK(found==5&&fallback==1);dmg_result_release(result);dmg_query_release(query);dmg_snapshot_release(snapshot);dmg_engine_release(engine);puts("PASS C v20 class annotation witnesses, raw fallback and invalid output guards");return 0;
}
