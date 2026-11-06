// Synthetic internal boundary tests; public metadata-reader acceptance is checked separately.
#include "query/class_annotation_flags.hpp"
#include "execution/reference/evaluate.hpp"
#include "query/ir.hpp"
#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <vector>
using namespace dexmeguviz;
namespace cf=dexmeguviz::query::class_annotation_flags;
#define CHECK(x) do{if(!(x))throw std::runtime_error("line "+std::to_string(__LINE__)+": " #x);}while(0)
struct Memory final:std::pmr::memory_resource {
 size_t calls=0,live=0,fail=std::numeric_limits<size_t>::max();
 void* do_allocate(size_t n,size_t a)override{if(++calls==fail)throw std::bad_alloc();auto* p=std::pmr::new_delete_resource()->allocate(n,a);live+=n;return p;}
 void do_deallocate(void* p,size_t n,size_t a)override{live-=n;std::pmr::new_delete_resource()->deallocate(p,n,a);}
 bool do_is_equal(const std::pmr::memory_resource& x)const noexcept override{return this==&x;}
};
struct Stop{};
static void u32(std::vector<uint8_t>& b,size_t p,uint32_t n){for(int i=0;i<4;++i)b.at(p+i)=uint8_t(n>>(8*i));}
static void leb(std::vector<uint8_t>& b,uint32_t v){do{uint8_t c=v&127;v>>=7;b.push_back(c|(v?128:0));}while(v);}
struct Fixture {
 std::vector<uint8_t> b;Facts f;ClassDefinition c;
 explicit Fixture(std::vector<uint8_t> elems,uint32_t count=2,uint8_t visibility=2):b(14000,0){
  f.dex_version=38;f.strings.emplace_back(u"Ldalvik/annotation/InnerClass;");f.strings.emplace_back(u"accessFlags");f.strings.emplace_back(u"name");f.strings.emplace_back(u"Ltest/Owner;");f.types.push_back(0);f.types.push_back(3);
  u32(b,52,112);u32(b,112,3);
  auto section=[&](size_t p,uint16_t kind,uint32_t off){b[p]=uint8_t(kind);b[p+1]=uint8_t(kind>>8);u32(b,p+4,1);u32(b,p+8,off);};
  section(116,0x2004,160);section(128,0x1003,12000);section(140,0x2006,13000);
  std::vector<uint8_t> item{visibility,0};leb(item,count);item.insert(item.end(),elems.begin(),elems.end());CHECK(item.size()<11840);std::copy(item.begin(),item.end(),b.begin()+160);
  u32(b,12000,1);u32(b,12004,160);u32(b,13000,12000);c.annotations_offset=13000;c.access_flags=1;c.type_id=1;c.definition_offset=96;
  f.class_definitions.emplace_back();auto& klass=f.class_definitions.back();klass.annotations_offset=c.annotations_offset;klass.access_flags=c.access_flags;klass.type_id=c.type_id;klass.definition_offset=c.definition_offset;f.class_definition_by_type={UINT32_MAX,0};
 }
};
static std::vector<uint8_t> elems(unsigned width,uint32_t value,std::vector<uint8_t> tail={0x1e}){
 std::vector<uint8_t> x{1,uint8_t(4|((width-1)<<5))};for(unsigned j=0;j<width;++j)x.push_back(uint8_t(value>>(8*j)));x.push_back(2);x.insert(x.end(),tail.begin(),tail.end());return x;
}
int main(){try{
 unsigned cases=0;
 for(unsigned width=1;width<=4;++width){
  for(uint32_t bits:{9u,0x80u<<(8*(width-1))}){
   Fixture x(elems(width,bits));Memory mem;uint64_t work=0;auto charge=[&](uint64_t n){work+=n;};auto got=cf::inspect(x.b,x.f,x.c,&mem,charge);CHECK(got.source==cf::Source::inner_int&&mem.live==0&&work>0);
   uint32_t expected=bits;if(bits!=9u&&width<4)expected|=~uint32_t(0)<<(8*width);
   CHECK(got.encoded==expected);if(bits==9u)CHECK(got.projected&&*got.projected==9);else CHECK(!got.projected);++cases;
  }
 }
 // Positive values whose significant bytes require each width: allowed vs unmodeled bits.
 for(auto [width,bits]:std::array<std::pair<unsigned,uint32_t>,3>{{{2,0x200},{3,0x10000},{4,0x1000000}}}){
  Fixture x(elems(width,bits));Memory mem;auto charge=[](uint64_t){};auto v=cf::inspect(x.b,x.f,x.c,&mem,charge);CHECK(v.encoded==bits);if(width==2)CHECK(v.projected&&*v.projected==bits);else CHECK(!v.projected);++cases;
 }
 // Nested array -> nested annotation -> array; only top-level accessFlags controls projection.
 const std::vector<uint8_t> nested{0x1c,1,0x1d,0,1,1,0x1c,1,0x1f};
 {Fixture x(elems(2,9,nested));Memory m;auto charge=[](uint64_t){};auto v=cf::inspect(x.b,x.f,x.c,&m,charge);CHECK(v.projected&&*v.projected==9&&m.live==0);++cases;}
 {Fixture x({2,0x1e},1);Memory m;auto charge=[](uint64_t){};auto v=cf::inspect(x.b,x.f,x.c,&m,charge);CHECK(!v.projected&&v.source==cf::Source::inner_int&&v.value_offset==0);++cases;}
 {Fixture x(elems(1,9),2,1);Memory m;auto charge=[](uint64_t){};auto v=cf::inspect(x.b,x.f,x.c,&m,charge);CHECK(v.source==cf::Source::no_system_inner&&v.projected&&*v.projected==1);++cases;}
 {Fixture x(elems(1,9));x.c.access_flags=3;Memory m;auto charge=[](uint64_t){};auto v=cf::inspect(x.b,x.f,x.c,&m,charge);CHECK(!v.projected);++cases;}
 // Deep stack plus long body ensures controlled allocations and cancellation/work checkpoints.
 std::vector<uint8_t> tail;for(int i=0;i<32;++i){tail.push_back(0x1c);tail.push_back(1);}tail.push_back(0x1c);leb(tail,4096);tail.insert(tail.end(),4096,0x1f);
 Fixture longx(elems(2,9,tail));Memory baseline;size_t checkpoints=0;uint64_t units=0;auto trace=[&](uint64_t n){++checkpoints;units+=n;};auto v=cf::inspect(longx.b,longx.f,longx.c,&baseline,trace);CHECK(v.projected&&*v.projected==9&&baseline.live==0&&checkpoints>4096&&units>4096&&baseline.calls>1);
 const auto allocations=baseline.calls;
 for(size_t i=1;i<=checkpoints;++i){Memory m;size_t seen=0;bool stopped=false;auto cancel=[&](uint64_t){if(++seen==i)throw Stop{};};try{(void)cf::inspect(longx.b,longx.f,longx.c,&m,cancel);}catch(const Stop&){stopped=true;}CHECK(stopped&&m.live==0);}
 for(uint64_t i=0;i<units;++i){Memory m;uint64_t budget=i;bool stopped=false;auto charge=[&](uint64_t n){if(n>budget)throw ReadError(ReadCode::budget,0,"test work");budget-=n;};try{(void)cf::inspect(longx.b,longx.f,longx.c,&m,charge);}catch(const ReadError& e){CHECK(e.code==ReadCode::budget);stopped=true;}CHECK(stopped&&m.live==0);}
 for(size_t i=1;i<=allocations;++i){Memory m;m.fail=i;bool stopped=false;auto charge=[](uint64_t){};try{(void)cf::inspect(longx.b,longx.f,longx.c,&m,charge);}catch(const std::bad_alloc&){stopped=true;}CHECK(stopped&&m.live==0);}
 // Exercise actual reference Work cancellation while annotation bytes are consumed.
 auto plan=query::compile(R"({"schema_version":1,"required_capabilities":["reflection_flags_static","reflection_class_annotations_static"],"relation":"class_defs","where":{"flags":{"domain":"reflection","mode":"contains","value":0}}})",std::pmr::new_delete_resource(),std::pmr::new_delete_resource());
 const std::array<reference::SourceView,1> sources{{{0,0,&longx.f,longx.b}}};const std::array<std::string_view,1> slots{"sample"};reference::DatasetView data{sources,slots,true};struct Cancel{size_t n=0,at=SIZE_MAX;};auto callback=[](void* p)noexcept{auto& c=*static_cast<Cancel*>(p);return ++c.n>=c.at;};Cancel count;Memory mem;
 uint64_t execution_work=0;{reference::Progress progress;auto result=reference::execute(data,plan,progress,&mem,{callback,&count});CHECK(result.rows.size()==1&&progress.profile.work_units>4096);execution_work=progress.profile.work_units;}CHECK(mem.live==0&&count.n>4);
 const auto execution_allocations=mem.calls;
 for(size_t i=1;i<=count.n;++i){Cancel c{0,i};Memory m;bool stopped=false;reference::Progress progress;try{(void)reference::execute(data,plan,progress,&m,{callback,&c});}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::cancelled);stopped=true;}CHECK(stopped&&m.live==0);}
 for(uint64_t i=0;i<execution_work;++i){plan.max_work=i;Memory m;bool stopped=false;{reference::Progress progress;try{(void)reference::execute(data,plan,progress,&m);}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::budget);stopped=true;}}CHECK(stopped&&m.live==0);}
 plan.max_work=100000000;
 for(size_t i=1;i<=execution_allocations;++i){Memory m;m.fail=i;bool stopped=false;{reference::Progress progress;try{(void)reference::execute(data,plan,progress,&m);}catch(const std::bad_alloc&){stopped=true;}}CHECK(stopped&&m.live==0);}
 std::cout<<"PASS synthetic annotation cases="<<cases<<" charge_checkpoints="<<checkpoints<<" budget_thresholds="<<units<<" allocations="<<allocations<<" actual_cancel_checks="<<count.n<<" actual_budget_thresholds="<<execution_work<<" actual_allocations="<<execution_allocations<<"\n";return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
