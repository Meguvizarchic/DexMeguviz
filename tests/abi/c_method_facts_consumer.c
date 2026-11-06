#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"facts consumer line %d: %s\n",__LINE__,#x);return 1;}}while(0)
static int open_dex(dmg_engine* e,const char* path,dmg_snapshot** out){
 FILE* f=fopen(path,"rb");if(!f)return 0;if(fseek(f,0,SEEK_END)){fclose(f);return 0;}long n=ftell(f);if(n<=0||fseek(f,0,SEEK_SET)){fclose(f);return 0;}
 unsigned char* b=(unsigned char*)malloc((size_t)n);if(!b){fclose(f);return 0;}size_t got=fread(b,1,(size_t)n,f);fclose(f);if(got!=(size_t)n){free(b);return 0;}
 dmg_open_options o={sizeof(o),DMG_ABI_VERSION,1u<<20,"facts-consumer","base",NULL};dmg_error er={0};dmg_status st=dmg_snapshot_open_copy_in(e,b,(uint64_t)n,&o,out,&er);free(b);return st==DMG_OK;
}
int main(int argc,char** argv){
 dmg_engine* e=NULL;dmg_snapshot* s=NULL;dmg_method_facts_v1 *r=NULL,*empty=NULL,*bad=NULL;dmg_error er={0};dmg_method_facts_info_v1 info;
 dmg_method_facts_options_v1 opt={sizeof(opt),DMG_ABI_VERSION,63,128,1000000,10000,0};
 dmg_method_string_use_v1 text;dmg_method_field_use_v1 field;dmg_method_number_v1 number;dmg_method_call_row_v1 call;dmg_method_instruction_v1 ins;dmg_method_type_use_v1 type;dmg_method_row caller;
 CHECK(argc==4);CHECK(dmg_engine_create(NULL,&e,&er)==DMG_OK);CHECK(open_dex(e,argv[1],&s));
 CHECK(dmg_snapshot_collect_method_facts_v1(s,0,3,&opt,&r,&er)==DMG_OK);
 CHECK(dmg_method_facts_get_info_v1(r,&info,sizeof(info))==DMG_OK&&info.method_ref==3&&info.has_body&&info.instruction_checked);
 CHECK(info.string_count==1&&info.field_count==1&&info.invoke_count==1&&info.number_count==0&&info.instruction_count==4);
 CHECK(dmg_method_facts_get_string_v1(r,0,&text,sizeof(text))==DMG_OK&&text.dex_pc==0&&text.string_index==10&&text.value_length==11&&text.value[0]=='u');
 CHECK(dmg_method_facts_get_field_v1(r,0,&field,sizeof(field))==DMG_OK&&field.dex_pc==5&&field.field_index==0&&field.owner_length>0&&field.name_length>0&&field.type_length>0);
 CHECK(dmg_method_facts_get_invoke_v1(r,0,&call,sizeof(call))==DMG_OK&&call.dex_pc==2&&call.target_domain==DMG_TARGET_METHOD_REF&&call.target_index==4&&call.name_length==4);
 CHECK(dmg_method_facts_get_instruction_v1(r,0,&ins,sizeof(ins))==DMG_OK&&ins.dex_pc==0&&ins.opcode==0x1a&&ins.width==2);
 CHECK(dmg_snapshot_collect_method_facts_v1(s,0,0,&opt,&empty,&er)==DMG_OK);CHECK(dmg_method_facts_get_info_v1(empty,&info,sizeof(info))==DMG_OK&&!info.has_body&&!info.instruction_checked&&info.instruction_count==0);dmg_method_facts_release_v1(empty);empty=NULL;
 CHECK(dmg_snapshot_collect_method_facts_v1(s,0,4,&opt,&bad,&er)==DMG_UNSUPPORTED&&bad==NULL);
 opt.max_records=1;CHECK(dmg_snapshot_collect_method_facts_v1(s,0,3,&opt,&bad,&er)==DMG_BUDGET_EXCEEDED&&bad==NULL);
 opt.max_records=128;opt.requested_mask=DMG_METHOD_FACT_STRINGS;CHECK(dmg_snapshot_collect_method_facts_v1(s,0,3,&opt,&empty,&er)==DMG_OK);memset(&field,0x5a,sizeof(field));CHECK(dmg_method_facts_get_field_v1(empty,0,&field,sizeof(field))==DMG_UNSUPPORTED&&((unsigned char*)&field)[0]==0x5a);dmg_method_facts_release_v1(empty);empty=NULL;
 dmg_snapshot_close(s);dmg_snapshot_release(s);s=NULL;CHECK(dmg_method_facts_get_caller_v1(r,&caller,sizeof(caller))==DMG_OK&&caller.name_length==4);dmg_method_facts_release_v1(r);r=NULL;
 CHECK(open_dex(e,argv[2],&s));opt.requested_mask=DMG_METHOD_FACT_NUMBERS;CHECK(dmg_snapshot_collect_method_facts_v1(s,0,3,&opt,&r,&er)==DMG_OK);CHECK(dmg_method_facts_get_info_v1(r,&info,sizeof(info))==DMG_OK&&info.number_count==3&&info.instruction_count==0);
 CHECK(dmg_method_facts_get_number_v1(r,0,&number,sizeof(number))==DMG_OK&&number.dex_pc==0&&number.bits==0xffffffffu&&number.width_bits==32);
 CHECK(dmg_method_facts_get_number_v1(r,1,&number,sizeof(number))==DMG_OK&&number.dex_pc==1&&number.bits==0xfffffffffffffffeULL&&number.width_bits==64);
 dmg_snapshot_release(s);s=NULL;CHECK(dmg_method_facts_get_number_v1(r,2,&number,sizeof(number))==DMG_OK&&number.dex_pc==3&&number.bits==0x80000000u);dmg_method_facts_release_v1(r);r=NULL;
 CHECK(open_dex(e,argv[3],&s));opt.requested_mask=DMG_METHOD_FACT_TYPES;CHECK(dmg_snapshot_collect_method_facts_v1(s,0,3,&opt,&r,&er)==DMG_OK);CHECK(dmg_method_facts_get_info_v1(r,&info,sizeof(info))==DMG_OK&&info.type_count==1);CHECK(dmg_method_facts_get_type_v1(r,0,&type,sizeof(type))==DMG_OK&&type.dex_pc==0&&type.opcode==34&&type.type_index==5&&type.descriptor_length>3&&type.descriptor[0]=='L'&&type.descriptor[type.descriptor_length-1]==';');
 dmg_snapshot_release(s);dmg_engine_release(e);dmg_method_facts_release_v1(r);puts("PASS generic facts and lifetime");return 0;
}
