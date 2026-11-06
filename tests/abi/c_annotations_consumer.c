#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"annotation consumer line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char** argv){
 dmg_engine* e=NULL;dmg_snapshot* s=NULL;dmg_annotations_v1 *a=NULL,*other=NULL;dmg_error error={0};dmg_annotations_info_v1 info;dmg_annotation_item_v1 item;dmg_annotation_element_v1 element;
 dmg_annotations_options_v1 opt={sizeof(opt),DMG_ABI_VERSION,256,0,1000000,100000,10000};dmg_open_options open={sizeof(open),DMG_ABI_VERSION,1u<<20,"annotations","base",NULL};
 CHECK(argc==2);FILE* f=fopen(argv[1],"rb");CHECK(f&&fseek(f,0,SEEK_END)==0);long n=ftell(f);CHECK(n>0&&fseek(f,0,SEEK_SET)==0);unsigned char* b=(unsigned char*)malloc((size_t)n);CHECK(b&&fread(b,1,(size_t)n,f)==(size_t)n);fclose(f);
 CHECK(dmg_engine_create(NULL,&e,&error)==DMG_OK);CHECK(dmg_snapshot_open_copy_in(e,b,(uint64_t)n,&open,&s,&error)==DMG_OK);free(b);
 {dmg_status st=dmg_snapshot_collect_annotations_v1(s,0,DMG_ANNOTATION_CLASS,2,UINT32_MAX,&opt,&a,&error);if(st!=DMG_OK)fprintf(stderr,"status=%u offset=%llu error=%s\n",st,(unsigned long long)error.offset,error.message);CHECK(st==DMG_OK);}CHECK(dmg_annotations_get_info_v1(a,&info,sizeof(info))==DMG_OK&&info.annotation_count==2);
 CHECK(dmg_annotations_get_item_v1(a,0,&item,sizeof(item))==DMG_OK&&item.visibility==1&&item.type_index==3&&item.element_count==5&&item.descriptor_length>0&&item.encoded_length>0);
 CHECK(dmg_annotations_get_element_v1(a,0,0,&element,sizeof(element))==DMG_OK&&element.name_length==4&&element.name[0]=='i'&&element.value_kind==0x1c&&element.encoded_length>=4);
 CHECK(dmg_annotations_get_element_v1(a,0,2,&element,sizeof(element))==DMG_OK&&element.value_kind==0x1d&&element.encoded_length>1);
 CHECK(dmg_annotations_get_item_v1(a,1,&item,sizeof(item))==DMG_OK&&item.type_index==4&&item.element_count==1);
 CHECK(dmg_snapshot_collect_annotations_v1(s,0,DMG_ANNOTATION_FIELD,0,UINT32_MAX,&opt,&other,&error)==DMG_OK);CHECK(dmg_annotations_get_info_v1(other,&info,sizeof(info))==DMG_OK&&info.annotation_count==1);dmg_annotations_release_v1(other);other=NULL;
 CHECK(dmg_snapshot_collect_annotations_v1(s,0,DMG_ANNOTATION_METHOD,2,UINT32_MAX,&opt,&other,&error)==DMG_OK);CHECK(dmg_annotations_get_info_v1(other,&info,sizeof(info))==DMG_OK&&info.annotation_count==1);dmg_annotations_release_v1(other);other=NULL;
 CHECK(dmg_snapshot_collect_annotations_v1(s,0,DMG_ANNOTATION_PARAMETER,2,0,&opt,&other,&error)==DMG_OK);CHECK(dmg_annotations_get_info_v1(other,&info,sizeof(info))==DMG_OK&&info.annotation_count==1);dmg_annotations_release_v1(other);other=NULL;
 CHECK(dmg_snapshot_collect_annotations_v1(s,0,DMG_ANNOTATION_METHOD,1,UINT32_MAX,&opt,&other,&error)==DMG_OK);CHECK(dmg_annotations_get_info_v1(other,&info,sizeof(info))==DMG_OK&&info.annotation_count==0);dmg_annotations_release_v1(other);other=NULL;
 CHECK(dmg_snapshot_collect_annotations_v1(s,0,DMG_ANNOTATION_CLASS,8,UINT32_MAX,&opt,&other,&error)==DMG_UNSUPPORTED&&other==NULL);CHECK(dmg_snapshot_collect_annotations_v1(s,0,DMG_ANNOTATION_PARAMETER,2,1,&opt,&other,&error)==DMG_INVALID_ARGUMENT&&other==NULL);
 opt.max_encoded_bytes=1;CHECK(dmg_snapshot_collect_annotations_v1(s,0,DMG_ANNOTATION_CLASS,2,UINT32_MAX,&opt,&other,&error)==DMG_BUDGET_EXCEEDED&&other==NULL);
 opt.max_encoded_bytes=100000;opt.max_records=1;CHECK(dmg_snapshot_collect_annotations_v1(s,0,DMG_ANNOTATION_CLASS,2,UINT32_MAX,&opt,&other,&error)==DMG_BUDGET_EXCEEDED&&other==NULL);
 opt.max_records=256;opt.max_work=1;CHECK(dmg_snapshot_collect_annotations_v1(s,0,DMG_ANNOTATION_CLASS,2,UINT32_MAX,&opt,&other,&error)==DMG_BUDGET_EXCEEDED&&other==NULL);
 memset(&item,0x5a,sizeof(item));CHECK(dmg_annotations_get_item_v1(a,0,&item,sizeof(item)-1)==DMG_INVALID_ARGUMENT&&((unsigned char*)&item)[0]==0x5a);
 dmg_snapshot_close(s);dmg_snapshot_release(s);dmg_engine_release(e);CHECK(dmg_annotations_get_item_v1(a,0,&item,sizeof(item))==DMG_OK&&item.encoded_length>0&&item.encoded_annotation[0]>0);dmg_annotations_release_v1(a);puts("PASS generic annotations and lifetime");return 0;
}
