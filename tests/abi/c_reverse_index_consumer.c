#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"reverse C line %d: %s\n",__LINE__,#x);return 1;}}while(0)
struct Buffer {unsigned char* data;size_t size;};
static struct Buffer read_file(const char* path){FILE* f=fopen(path,"rb");struct Buffer b={0};long n;if(!f)return b;if(fseek(f,0,SEEK_END)!=0||(n=ftell(f))<=0||fseek(f,0,SEEK_SET)!=0){fclose(f);return b;}b.data=(unsigned char*)malloc((size_t)n);if(b.data&&fread(b.data,1,(size_t)n,f)==(size_t)n)b.size=(size_t)n;fclose(f);return b;}
static uint32_t cancel_at(void* opaque){unsigned* p=(unsigned*)opaque;return ++*p>=3;}
struct CancelLimit {unsigned calls,limit;};
static uint32_t cancel_limit(void* opaque){struct CancelLimit* p=(struct CancelLimit*)opaque;return ++p->calls>=p->limit;}
static uint32_t count_checks(void* opaque){++*(unsigned*)opaque;return 0;}
static uint32_t cancel_now(void* opaque){(void)opaque;return 1;}
struct Reenter {dmg_snapshot* snapshot;dmg_status status;};
static uint32_t reenter(void* opaque){struct Reenter* p=(struct Reenter*)opaque;dmg_reverse_profile_v1 profile;p->status=dmg_snapshot_reverse_profile_v1(p->snapshot,&profile,sizeof(profile));return 1;}
int main(int argc,char** argv){
 struct Buffer b,domains,corrupt,many;dmg_error e={0};dmg_engine *engine=NULL;dmg_snapshot *snap=NULL,*special=NULL,*broken=NULL,*fresh=NULL;
 dmg_source_spec src[2];dmg_source_set_options so={sizeof(so),DMG_ABI_VERSION,"reverse-test",1,16,8u<<20};dmg_reverse_profile_v1 p={0};dmg_engine_stats initial,allocated,final;
 dmg_reverse_options_v1 opt={sizeof(opt),DMG_ABI_VERSION,1000000,1u<<20,1000,0,NULL,NULL};uint64_t count=42;unsigned calls=0;dmg_query* q=NULL;dmg_result* r=NULL;dmg_relation_info_v2 info;
 const char* graph="{\"schema_version\":1,\"relation\":{\"op\":\"scan\",\"relation\":\"invoke_sites\"},\"max_results\":100}";
 CHECK(argc==5);b=read_file(argv[1]);domains=read_file(argv[2]);corrupt=read_file(argv[3]);many=read_file(argv[4]);CHECK(b.data&&domains.data&&corrupt.data&&many.data);
 CHECK(dmg_engine_create(NULL,&engine,&e)==DMG_OK&&dmg_engine_get_stats(engine,&initial)==DMG_OK);
 src[0]=(dmg_source_spec){sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,b.data,b.size,"left","test",NULL};
 src[1]=(dmg_source_spec){sizeof(dmg_source_spec),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,b.data,b.size,"right","test",NULL};
 CHECK(dmg_snapshot_open_sources(engine,src,2,&so,&snap,&e)==DMG_OK);
 CHECK(dmg_snapshot_reverse_profile_v1(snap,&p,sizeof(p))==DMG_OK&&p.build_attempts==0&&p.builds==0&&p.published_indexes==0);
 // Use an independently generated 1024-call fixture. Size an Engine after
 // opening identical bytes, then show its accounted budget rejects index build.
 {dmg_engine_stats sizing,beforeBudget,afterBudget;dmg_engine *sizer=NULL,*limited=NULL;dmg_snapshot *ss=NULL,*ls=NULL;
  dmg_source_spec big={sizeof(big),DMG_ABI_VERSION,DMG_INPUT_RAW_DEX,0,many.data,many.size,"big","test",NULL};
  CHECK(dmg_engine_create(NULL,&sizer,&e)==DMG_OK&&dmg_snapshot_open_sources(sizer,&big,1,&so,&ss,&e)==DMG_OK);
  CHECK(dmg_engine_get_stats(sizer,&sizing)==DMG_OK);
  {unsigned calls=0;uint64_t found=0;dmg_reverse_options_v1 generous=opt;generous.max_records=2000;generous.cancelled=count_checks;generous.cancel_context=&calls;
   CHECK(dmg_snapshot_reverse_count_v1(ss,0,1,2,1,UINT32_MAX,&generous,&found,&e)==DMG_OK&&found==1024&&calls>100);
   dmg_snapshot* late=NULL;dmg_engine_stats beforeLate,afterLate;struct CancelLimit lateCancel={0,calls-3};
   CHECK(dmg_snapshot_open_sources(sizer,&big,1,&so,&late,&e)==DMG_OK&&dmg_engine_get_stats(sizer,&beforeLate)==DMG_OK);
   generous.cancelled=cancel_limit;generous.cancel_context=&lateCancel;found=42;
   CHECK(dmg_snapshot_reverse_count_v1(late,0,1,2,1,UINT32_MAX,&generous,&found,&e)==DMG_CANCELLED&&found==42);
   CHECK(dmg_snapshot_reverse_profile_v1(late,&p,sizeof(p))==DMG_OK&&p.builds==0&&p.build_failures==1&&p.published_indexes==0);
   CHECK(dmg_engine_get_stats(sizer,&afterLate)==DMG_OK&&afterLate.owned_bytes==beforeLate.owned_bytes);dmg_snapshot_release(late);
  }
  dmg_snapshot_release(ss);dmg_engine_release(sizer);
  dmg_engine_options eo={sizeof(eo),DMG_ABI_VERSION,sizing.peak_owned_bytes+64,256ull<<20,128ull<<20,4,0};
  CHECK(dmg_engine_create(&eo,&limited,&e)==DMG_OK&&dmg_snapshot_open_sources(limited,&big,1,&so,&ls,&e)==DMG_OK);
  CHECK(dmg_engine_get_stats(limited,&beforeBudget)==DMG_OK);uint64_t untouched=42;
  dmg_reverse_options_v1 generous=opt;generous.max_records=2000;
  CHECK(dmg_snapshot_reverse_count_v1(ls,0,1,2,1,UINT32_MAX,&generous,&untouched,&e)==DMG_BUDGET_EXCEEDED&&untouched==42);
  CHECK(dmg_snapshot_reverse_profile_v1(ls,&p,sizeof(p))==DMG_OK&&p.build_attempts==1&&p.build_failures==1&&p.published_indexes==0);
  CHECK(dmg_engine_get_stats(limited,&afterBudget)==DMG_OK&&afterBudget.owned_bytes==beforeBudget.owned_bytes);
  dmg_snapshot_release(ls);dmg_engine_release(limited);
 }
 CHECK(dmg_query_compile_json(engine,(const uint8_t*)graph,strlen(graph),&q,&e)==DMG_OK&&dmg_query_execute(snap,q,&r,&e)==DMG_OK);
 CHECK(dmg_result_get_relation_info_v2(r,&info,sizeof(info))==DMG_OK&&info.candidates_count==4);dmg_result_release(r);r=NULL;dmg_query_release(q);q=NULL;
 CHECK(dmg_snapshot_reverse_profile_v1(snap,&p,sizeof(p))==DMG_OK&&p.build_attempts==0&&p.builds==0&&p.reuses==0);
 count=42;CHECK(dmg_snapshot_reverse_count_v1(snap,0,DMG_REVERSE_INVOKE_SITE_V1,DMG_TARGET_FIELD_REF,0,UINT32_MAX,&opt,&count,&e)==DMG_INVALID_ARGUMENT&&count==42);
 opt.cancelled=cancel_now;CHECK(dmg_snapshot_reverse_count_v1(snap,0,DMG_REVERSE_INVOKE_SITE_V1,DMG_TARGET_METHOD_REF,4,UINT32_MAX,&opt,&count,&e)==DMG_CANCELLED&&count==42);
 CHECK(dmg_snapshot_reverse_profile_v1(snap,&p,sizeof(p))==DMG_OK&&p.build_attempts==0);
 opt.cancelled=cancel_at;opt.cancel_context=&calls;CHECK(dmg_snapshot_reverse_count_v1(snap,0,DMG_REVERSE_INVOKE_SITE_V1,DMG_TARGET_METHOD_REF,4,UINT32_MAX,&opt,&count,&e)==DMG_CANCELLED&&count==42);
 CHECK(dmg_snapshot_reverse_profile_v1(snap,&p,sizeof(p))==DMG_OK&&p.build_attempts==1&&p.build_failures==1&&p.published_indexes==0);
 opt.cancelled=NULL;opt.cancel_context=NULL;opt.max_records=1;CHECK(dmg_snapshot_reverse_count_v1(snap,0,1,2,4,UINT32_MAX,&opt,&count,&e)==DMG_BUDGET_EXCEEDED&&count==42);
 opt.max_records=1000;opt.max_index_bytes=1;CHECK(dmg_snapshot_reverse_count_v1(snap,0,1,2,4,UINT32_MAX,&opt,&count,&e)==DMG_BUDGET_EXCEEDED&&count==42);
 CHECK(dmg_snapshot_reverse_profile_v1(snap,&p,sizeof(p))==DMG_OK&&p.build_attempts==3&&p.build_failures==3&&p.builds==0);
 opt.max_index_bytes=1u<<20;CHECK(dmg_snapshot_reverse_count_v1(snap,0,1,2,4,UINT32_MAX,&opt,&count,&e)==DMG_OK&&count==2);
 CHECK(dmg_snapshot_reverse_profile_v1(snap,&p,sizeof(p))==DMG_OK&&p.build_attempts==4&&p.builds==1&&p.published_indexes==1&&p.published_records==2);
 CHECK(dmg_snapshot_reverse_count_v1(snap,0,1,2,3,UINT32_MAX,&opt,&count,&e)==DMG_OK&&count==0);
 opt.max_work=1;count=42;CHECK(dmg_snapshot_reverse_count_v1(snap,0,1,2,4,UINT32_MAX,&opt,&count,&e)==DMG_BUDGET_EXCEEDED&&count==42);opt.max_work=1000000;
 CHECK(dmg_snapshot_reverse_profile_v1(snap,&p,sizeof(p))==DMG_OK&&p.reuses==1&&p.builds==1);
 CHECK(dmg_snapshot_reverse_count_v1(snap,1,1,2,4,UINT32_MAX,&opt,&count,&e)==DMG_OK&&count==2);
 CHECK(dmg_snapshot_reverse_count_v1(snap,0,1,2,4,UINT32_MAX,&opt,&count,&e)==DMG_OK&&count==2);
 CHECK(dmg_snapshot_reverse_profile_v1(snap,&p,sizeof(p))==DMG_OK&&p.builds==2&&p.reuses==2&&p.published_records==4);
 // Looking for an uncached kind also spends budget on each registry entry.
 {dmg_reverse_profile_v1 beforeProbe=p,afterProbe;opt.max_work=1;count=42;
  CHECK(dmg_snapshot_reverse_count_v1(snap,0,DMG_REVERSE_FIELD_USE_V1,DMG_TARGET_FIELD_REF,0,UINT32_MAX,&opt,&count,&e)==DMG_BUDGET_EXCEEDED&&count==42);
  CHECK(dmg_snapshot_reverse_profile_v1(snap,&afterProbe,sizeof(afterProbe))==DMG_OK&&memcmp(&beforeProbe,&afterProbe,sizeof(beforeProbe))==0);opt.max_work=1000000;
 }

 // Even identical source bytes in a distinct Engine own a distinct registry.
 {dmg_engine* other=NULL;dmg_snapshot* otherSnap=NULL;dmg_reverse_profile_v1 otherProfile;uint64_t found=42;
  CHECK(dmg_engine_create(NULL,&other,&e)==DMG_OK&&dmg_snapshot_open_sources(other,src,1,&so,&otherSnap,&e)==DMG_OK);
  CHECK(dmg_snapshot_reverse_profile_v1(otherSnap,&otherProfile,sizeof(otherProfile))==DMG_OK&&otherProfile.builds==0);
  CHECK(dmg_snapshot_reverse_count_v1(otherSnap,0,1,2,4,UINT32_MAX,&opt,&found,&e)==DMG_OK&&found==2);
  CHECK(dmg_snapshot_reverse_profile_v1(otherSnap,&otherProfile,sizeof(otherProfile))==DMG_OK&&otherProfile.builds==1&&otherProfile.reuses==0);
  CHECK(dmg_snapshot_reverse_profile_v1(snap,&p,sizeof(p))==DMG_OK&&p.builds==2&&p.reuses==2);
  dmg_snapshot_release(otherSnap);dmg_engine_release(other);
 }

 {struct Reenter re={snap,DMG_OK};opt.cancelled=reenter;opt.cancel_context=&re;CHECK(dmg_snapshot_reverse_count_v1(snap,0,1,2,4,UINT32_MAX,&opt,&count,&e)==DMG_CANCELLED&&re.status==DMG_INVALID_ARGUMENT);opt.cancelled=NULL;opt.cancel_context=NULL;}
 {dmg_reverse_profile_v1 sentinel;memset(&sentinel,0x5a,sizeof(sentinel));CHECK(dmg_snapshot_reverse_profile_v1(snap,&sentinel,sizeof(sentinel)-1)==DMG_INVALID_ARGUMENT);for(size_t i=0;i<sizeof(sentinel);++i)CHECK(((unsigned char*)&sentinel)[i]==0x5a);}
 // Exercise cancellation at many checked positions; unsuccessful construction
 // must release all temporary storage and publish no partial index.
 for(unsigned n=1;n<=36;++n){
  dmg_snapshot* trial=NULL;dmg_engine_stats beforeCancel,afterCancel;struct CancelLimit limit={0,n};
  CHECK(dmg_snapshot_open_sources(engine,src,1,&so,&trial,&e)==DMG_OK);
  CHECK(dmg_engine_get_stats(engine,&beforeCancel)==DMG_OK);
  opt.cancelled=cancel_limit;opt.cancel_context=&limit;count=42;
  const dmg_status status=dmg_snapshot_reverse_count_v1(trial,0,1,2,4,UINT32_MAX,&opt,&count,&e);
  CHECK(status==DMG_OK||status==DMG_CANCELLED);
  CHECK(dmg_snapshot_reverse_profile_v1(trial,&p,sizeof(p))==DMG_OK);
  if(status==DMG_CANCELLED){CHECK(count==42&&p.builds==0&&p.published_indexes==0);CHECK(dmg_engine_get_stats(engine,&afterCancel)==DMG_OK&&afterCancel.owned_bytes==beforeCancel.owned_bytes);}
  else {CHECK(count==2&&p.builds==1);}
  dmg_snapshot_release(trial);
 }
 opt.cancelled=NULL;opt.cancel_context=NULL;
 CHECK(dmg_engine_get_stats(engine,&allocated)==DMG_OK&&allocated.fact_bytes>initial.fact_bytes);
 src[0].data=domains.data;src[0].size=domains.size;CHECK(dmg_snapshot_open_sources(engine,src,1,&so,&special,&e)==DMG_OK);
 CHECK(dmg_snapshot_reverse_count_v1(special,0,1,DMG_TARGET_METHOD_AND_PROTO,4,0,&opt,&count,&e)==DMG_OK&&count==1);
 CHECK(dmg_snapshot_reverse_count_v1(special,0,1,DMG_TARGET_CALL_SITE,0,UINT32_MAX,&opt,&count,&e)==DMG_OK&&count==1);
 CHECK(dmg_snapshot_reverse_count_v1(special,0,1,DMG_TARGET_METHOD_REF,4,UINT32_MAX,&opt,&count,&e)==DMG_OK&&count==0);
 src[0].data=corrupt.data;src[0].size=corrupt.size;CHECK(dmg_snapshot_open_sources(engine,src,1,&so,&broken,&e)==DMG_OK);
 count=42;CHECK(dmg_snapshot_reverse_count_v1(broken,0,1,2,4,UINT32_MAX,&opt,&count,&e)==DMG_CORRUPT_INPUT&&count==42);
 CHECK(dmg_snapshot_reverse_count_v1(broken,0,1,2,4,UINT32_MAX,&opt,&count,&e)==DMG_CORRUPT_INPUT&&count==42);
 CHECK(dmg_snapshot_reverse_profile_v1(broken,&p,sizeof(p))==DMG_OK&&p.build_attempts==2&&p.build_failures==2&&p.published_indexes==0);
 dmg_snapshot_close(snap);count=42;CHECK(dmg_snapshot_reverse_count_v1(snap,0,1,2,4,UINT32_MAX,&opt,&count,&e)==DMG_CLOSED&&count==42);
 CHECK(dmg_snapshot_reverse_profile_v1(snap,&p,sizeof(p))==DMG_OK&&p.builds==2);
 dmg_snapshot_release(snap);dmg_snapshot_release(special);dmg_snapshot_release(broken);
 src[0].data=b.data;src[0].size=b.size;CHECK(dmg_snapshot_open_sources(engine,src,1,&so,&fresh,&e)==DMG_OK);
 CHECK(dmg_snapshot_reverse_profile_v1(fresh,&p,sizeof(p))==DMG_OK&&p.builds==0&&p.reuses==0);
 CHECK(dmg_engine_shutdown(engine,0)==DMG_OK);count=42;
 CHECK(dmg_snapshot_reverse_count_v1(fresh,0,1,2,4,UINT32_MAX,&opt,&count,&e)==DMG_CLOSED&&count==42);
 CHECK(dmg_snapshot_reverse_profile_v1(fresh,&p,sizeof(p))==DMG_OK&&p.builds==0);dmg_snapshot_release(fresh);
 CHECK(dmg_engine_get_stats(engine,&final)==DMG_OK&&final.owned_bytes==initial.owned_bytes);dmg_engine_release(engine);free(b.data);free(domains.data);free(corrupt.data);free(many.data);
 puts("PASS C reverse index demand, budget, cancellation, local domains and occurrence lifetime");return 0;
}
