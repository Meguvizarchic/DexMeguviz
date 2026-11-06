#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"caller relation C line %d: %s\n",__LINE__,#x);return 1;}}while(0)
static int scenario(const char* dir,const char** names,unsigned count,unsigned want,unsigned reason,unsigned nodes,unsigned edges,unsigned checks){
 dmg_engine* e=NULL;dmg_snapshot* snap=NULL;dmg_query* q=NULL;dmg_result* result=NULL;dmg_job* job=NULL;dmg_error error;dmg_source_spec specs[8]={0};unsigned char* buffers[8]={0};char slots[8][8];char text[4096];size_t at=0;unsigned i,row;dmg_source_set_options o={sizeof(o),DMG_ABI_VERSION,"caller-relation",0,8,1u<<20};dmg_relation_info_v2 info;dmg_engine_stats baselineStats,finalStats;
 CHECK(count<=8&&dmg_engine_create(NULL,&e,&error)==DMG_OK);CHECK(dmg_engine_get_stats(e,&baselineStats)==DMG_OK);
 for(i=0;i<count;++i){char path[2048];FILE* f;long n;snprintf(path,sizeof(path),"%s/%s",dir,names[i]);f=fopen(path,"rb");CHECK(f&&fseek(f,0,SEEK_END)==0);n=ftell(f);CHECK(n>0&&fseek(f,0,SEEK_SET)==0);buffers[i]=(unsigned char*)malloc((size_t)n);CHECK(buffers[i]&&fread(buffers[i],1,(size_t)n,f)==(size_t)n);fclose(f);snprintf(slots[i],sizeof(slots[i]),"s%u",i);specs[i].struct_size=sizeof(specs[i]);specs[i].abi_version=DMG_ABI_VERSION;specs[i].format=DMG_INPUT_RAW_DEX;specs[i].data=buffers[i];specs[i].size=(uint64_t)n;specs[i].slot_key=slots[i];specs[i].role=i?"code-split":"base";}
 CHECK(dmg_snapshot_open_sources(e,specs,count,&o,&snap,&error)==DMG_OK);for(i=0;i<count;++i)free(buffers[i]);
 at+=(size_t)snprintf(text+at,sizeof(text)-at,"{\"schema_version\":1,\"required_capabilities\":[\"field_declaration_static\",\"caller_field_relation_observation\"],\"scope\":{\"slots\":[");
 for(i=0;i<count;++i)at+=(size_t)snprintf(text+at,sizeof(text)-at,"%s\"%s\"",i?",":"",slots[i]);
 at+=(size_t)snprintf(text+at,sizeof(text)-at,"]},\"relation\":{\"op\":\"join\",\"on\":\"caller\",\"left\":{\"op\":\"scan\",\"relation\":\"method_defs\"},\"right\":{\"op\":\"scan\",\"relation\":\"field_uses\",\"where\":{\"target_field_declaration\":{\"scope\":\"any\"}}}}}");CHECK(at<sizeof(text));
 CHECK(dmg_query_compile_json(e,(const uint8_t*)text,strlen(text),&q,&error)==DMG_OK);CHECK(dmg_job_start(snap,q,NULL,&job,&error)==DMG_UNSUPPORTED&&job==NULL);CHECK(dmg_query_execute(snap,q,&result,&error)==DMG_OK);dmg_query_release(q);dmg_snapshot_release(snap);
 CHECK(dmg_result_get_relation_info_v2(result,&info,sizeof(info))==DMG_OK&&info.candidates_count==2&&info.unknown_rows==2);
 for(row=0;row<2;++row){uint32_t n=0;unsigned found=0,nodeCount=0,edgeCount=0,checkCount=0;CHECK(dmg_result_get_witness_count(result,row,&n)==DMG_OK);
  for(i=0;i<n;++i){dmg_caller_field_relation_witness_v1 w;dmg_status st=dmg_result_get_caller_field_relation_witness_v1(result,row,i,&w,sizeof(w));if(st==DMG_UNSUPPORTED)continue;CHECK(st==DMG_OK);if(w.item_kind==0){CHECK(w.status==want&&w.reason==reason&&w.event_source==0&&w.event_caller==0&&(w.event_pc==0||w.event_pc==2||w.event_pc==4||w.event_pc==6));++found;}else if(w.item_kind==1)++nodeCount;else if(w.item_kind==2)++edgeCount;else if(w.item_kind==3)++checkCount;else CHECK(0);
   {unsigned char bytes[sizeof(w)];size_t k;memset(bytes,0x5a,sizeof(bytes));CHECK(dmg_result_get_caller_field_relation_witness_v1(result,row,i,(dmg_caller_field_relation_witness_v1*)bytes,sizeof(w)-1)==DMG_INVALID_ARGUMENT);for(k=0;k<sizeof(bytes);++k)CHECK(bytes[k]==0x5a);}
   {dmg_relation_witness_v2 old;CHECK(dmg_result_get_relation_witness_v2(result,row,i,&old,sizeof(old))==DMG_UNSUPPORTED);}
  }CHECK(found==1&&nodeCount==nodes&&edgeCount==edges&&checkCount==checks);
 }
 dmg_result_release(result);CHECK(dmg_engine_get_stats(e,&finalStats)==DMG_OK);CHECK(finalStats.owned_bytes==baselineStats.owned_bytes&&finalStats.source_bytes==baselineStats.source_bytes&&finalStats.fact_bytes==baselineStats.fact_bytes&&finalStats.scratch_bytes==baselineStats.scratch_bytes&&finalStats.query_bytes==baselineStats.query_bytes&&finalStats.result_bytes==baselineStats.result_bytes&&finalStats.control_bytes==baselineStats.control_bytes&&finalStats.active_jobs==baselineStats.active_jobs);dmg_engine_release(e);return 0;
}
int main(int argc,char** argv){
 const char* self[]={"child-self.dex","parent-target.dex","object.dex"};
 const char* ancestor[]={"child-ancestor.dex","parent-target.dex","object.dex"};
 const char* ext[]={"caller-external.dex","child-target.dex","parent-target.dex","object.dex"};
 const char* missing[]={"caller-missing.dex","child-target.dex","parent-target.dex"};
 const char* dup[]={"caller-external.dex","child-target.dex","parent-target.dex","object.dex","object.dex"};
 const char* cycle[]={"caller-cycle-a.dex","caller-cycle-b.dex","child-target.dex","parent-target.dex"};
 const char* diamond[]={"caller-diamond.dex","child-target.dex","parent-target.dex","object.dex","interface-a.dex","interface-b.dex","interface-common.dex"};
 const char* diamondTarget[]={"caller-diamond-target.dex","interface-a.dex","interface-b.dex","interface-common.dex","object.dex"};
 const char* ifaceMissing[]={"interface-caller.dex","child-target.dex","parent-target.dex"};
 const char* ifaceValid[]={"interface-caller.dex","child-target.dex","parent-target.dex","object.dex"};
 const char* ifaceDuplicate[]={"interface-caller.dex","child-target.dex","parent-target.dex","object.dex","object.dex"};
 const char* ifaceInvalid[]={"interface-caller.dex","child-target.dex","parent-target.dex","object-invalid.dex"};
 CHECK(argc==2);CHECK(!scenario(argv[1],self,3,DMG_CALLER_FIELD_SELF,0,1,0,0));CHECK(!scenario(argv[1],ancestor,3,DMG_CALLER_FIELD_ANCESTOR,0,2,0,0));CHECK(!scenario(argv[1],ext,4,DMG_CALLER_FIELD_EXTERNAL,0,2,1,0));CHECK(!scenario(argv[1],missing,3,DMG_CALLER_FIELD_UNKNOWN,DMG_CALLER_FIELD_REASON_MISSING,0,0,0));CHECK(!scenario(argv[1],dup,5,DMG_CALLER_FIELD_UNKNOWN,DMG_CALLER_FIELD_REASON_AMBIGUOUS,0,0,0));CHECK(!scenario(argv[1],cycle,4,DMG_CALLER_FIELD_UNKNOWN,DMG_CALLER_FIELD_REASON_CYCLE,0,0,0));CHECK(!scenario(argv[1],diamond,7,DMG_CALLER_FIELD_EXTERNAL,0,5,5,3));
 CHECK(!scenario(argv[1],diamondTarget,5,DMG_CALLER_FIELD_ANCESTOR,0,3,0,0));
 CHECK(!scenario(argv[1],ifaceMissing,3,DMG_CALLER_FIELD_UNKNOWN,DMG_CALLER_FIELD_REASON_MISSING,0,0,0));CHECK(!scenario(argv[1],ifaceValid,4,DMG_CALLER_FIELD_EXTERNAL,0,1,0,1));CHECK(!scenario(argv[1],ifaceDuplicate,5,DMG_CALLER_FIELD_UNKNOWN,DMG_CALLER_FIELD_REASON_AMBIGUOUS,0,0,0));CHECK(!scenario(argv[1],ifaceInvalid,4,DMG_CALLER_FIELD_UNKNOWN,DMG_CALLER_FIELD_REASON_INVALID_TYPE,0,0,0));puts("PASS C caller field classes, closure, Unknown, Job rejection, ABI and Engine ledger recovery");return 0;
}
