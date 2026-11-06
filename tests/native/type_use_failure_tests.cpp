#include "execution/reference/evaluate.hpp"
#include "query/ir.hpp"
#include "format/instructions/decoder.hpp"
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <string>
#include <vector>
using namespace dexmeguviz;
#define CHECK(x) do{if(!(x))throw std::runtime_error("type fault line "+std::to_string(__LINE__)+": " #x);}while(0)
struct Counted:std::pmr::memory_resource{size_t live=0,calls=0,fail=SIZE_MAX;void* do_allocate(size_t n,size_t a)override{if(++calls==fail)throw std::bad_alloc();void* p=std::pmr::new_delete_resource()->allocate(n,a);live+=n;return p;}void do_deallocate(void* p,size_t n,size_t a)override{live-=n;std::pmr::new_delete_resource()->deallocate(p,n,a);}bool do_is_equal(const std::pmr::memory_resource& other)const noexcept override{return this==&other;}};
struct Cancel{size_t checks=0,at=SIZE_MAX;};static bool cancelled(void* p)noexcept{auto& c=*static_cast<Cancel*>(p);return ++c.checks>=c.at;}
int main(int argc,char** argv){try{
 CHECK(argc==2);std::ifstream f(std::filesystem::path(argv[1]),std::ios::binary);CHECK(f.good());std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(f),{}};auto facts=read_metadata(bytes);
 const std::array<reference::SourceView,1> sources{{{0,0,&facts,bytes}}};const std::array<std::string_view,1> slots{"base"};reference::DatasetView data{sources,slots,true};
 auto plan=query::compile(R"({"schema_version":1,"required_capabilities":["type_uses"],"relation":{"op":"scan","relation":"type_uses","where":{"all":[{"opcode":34},{"target_descriptor":"Lfixture/TypeUses$Parent;"}]}},"max_results":100})",std::pmr::new_delete_resource(),std::pmr::new_delete_resource());CHECK(!reference::can_stream(plan));
 Counted baseline;Cancel c;uint64_t work=0;uint32_t code=0,pc=0;
 {reference::Progress progress;auto result=reference::execute(data,plan,progress,&baseline,{cancelled,&c});CHECK(result.rows.size()==2);work=progress.profile.work_units;const auto& event=reference::use_record(result,result.rows[0].key());code=event.code_offset;pc=event.key.dex_pc;}CHECK(baseline.live==0&&work>0&&c.checks>0);const size_t allocations=baseline.calls;
 for(size_t i=1;i<=allocations;++i){Counted m;m.fail=i;bool failed=false;{reference::Progress progress;try{(void)reference::execute(data,plan,progress,&m);}catch(const std::bad_alloc&){failed=true;}}CHECK(failed&&m.live==0);}
 for(size_t i=1;i<=c.checks;++i){Counted m;Cancel stop{0,i};bool failed=false;{reference::Progress progress;try{(void)reference::execute(data,plan,progress,&m,{cancelled,&stop});}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::cancelled);failed=true;}catch(const facts::UseScanError& e){CHECK(e.code==facts::UseScanError::Code::cancelled);failed=true;}catch(const instructions::DecodeError& e){CHECK(e.code==instructions::DecodeCode::cancelled);failed=true;}}CHECK(failed&&m.live==0);}
 for(uint64_t i=1;i<work;++i){plan.max_work=i;Counted m;bool failed=false;{reference::Progress progress;try{(void)reference::execute(data,plan,progress,&m);}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::budget);failed=true;}catch(const facts::UseScanError& e){CHECK(e.code==facts::UseScanError::Code::budget);failed=true;}catch(const instructions::DecodeError& e){CHECK(e.code==instructions::DecodeCode::budget);failed=true;}}CHECK(failed&&m.live==0);}plan.max_work=100000000;
 auto bad=bytes;const auto at=uint64_t(code)+16+uint64_t(pc)*2+2;CHECK(at+1<bad.size());bad[at]=0xff;bad[at+1]=0xff;auto badfacts=read_metadata(bad);const std::array<reference::SourceView,1> badsources{{{0,0,&badfacts,bad}}};reference::DatasetView corrupt{badsources,slots,true};Counted memory;bool rejected=false;{reference::Progress progress;try{(void)reference::execute(corrupt,plan,progress,&memory);}catch(const instructions::DecodeError& e){CHECK(e.code==instructions::DecodeCode::corrupt);rejected=true;}}CHECK(rejected&&memory.live==0);
 std::cout<<"PASS type-use execution allocation="<<allocations<<" cancellation="<<c.checks<<" budgets="<<(work-1)<<" corrupted operand rejected\n";return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
