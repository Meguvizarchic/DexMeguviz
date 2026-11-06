#include "query/ir.hpp"
#include "execution/reference/evaluate.hpp"
#include "format/instructions/decoder.hpp"
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <vector>
using namespace dexmeguviz;
#define CHECK(x) do{if(!(x))throw std::runtime_error("field failure line "+std::to_string(__LINE__)+": " #x);}while(0)
struct Counter:std::pmr::memory_resource {
 size_t used=0,calls=0,fail_at=std::numeric_limits<size_t>::max();
 void* do_allocate(size_t n,size_t a)override{if(++calls==fail_at)throw std::bad_alloc();auto p=std::pmr::new_delete_resource()->allocate(n,a);used+=n;return p;}
 void do_deallocate(void* p,size_t n,size_t a)override{used-=n;std::pmr::new_delete_resource()->deallocate(p,n,a);}
 bool do_is_equal(const std::pmr::memory_resource& r)const noexcept override{return this==&r;}
};
struct Cancellation {size_t count=0,at=std::numeric_limits<size_t>::max();};
static bool cancel(void* p)noexcept{auto& c=*static_cast<Cancellation*>(p);return ++c.count>=c.at;}
static std::vector<uint8_t> load(const std::filesystem::path& p){std::ifstream f(p,std::ios::binary);CHECK(f.good());return {std::istreambuf_iterator<char>(f),{}};}
int main(int argc,char** argv){try{
 CHECK(argc==2);const auto root=std::filesystem::path(argv[1]);auto left=load(root/"caller-a.dex"),other=load(root/"caller-b.dex"),child=load(root/"child.dex"),parent=load(root/"parent.dex"),object=load(root/"object.dex");
 auto l=read_metadata(left),r=read_metadata(other),c=read_metadata(child),p=read_metadata(parent),o=read_metadata(object);
 const std::array<reference::SourceView,5> sources{{{0,0,&l,left},{1,1,&r,other},{2,2,&c,child},{3,3,&p,parent},{4,4,&o,object}}};const std::array<std::string_view,5> slots{"callerA","callerB","child","parent","object"};
 const reference::DatasetView data{sources,slots,false};const char* text=R"({"schema_version":1,"required_capabilities":["field_declaration_static"],"scope":{"slots":["callerA","callerB","child","parent","object"]},"relation":{"op":"join","on":"caller","left":{"op":"scan","relation":"method_defs"},"right":{"op":"scan","relation":"field_uses","where":{"target_field_declaration":{"scope":"inherited"}}}},"intent":"unique"})";
 auto plan=query::compile(text,std::pmr::new_delete_resource(),std::pmr::new_delete_resource());CHECK(!reference::can_stream(plan));Counter mem;Cancellation baseline;
 {reference::Progress progress;auto result=reference::execute(data,plan,progress,&mem,{cancel,&baseline});CHECK(result.rows.size()==2&&progress.profile.unknown_rows==0);}
 const auto allocations=mem.calls;CHECK(allocations>0&&mem.used==0&&baseline.count>2);
 unsigned stopped=0;
 for(size_t i=1;i<=baseline.count;++i){Cancellation cxl{0,i};mem.calls=0;bool hit=false;{reference::Progress progress;try{(void)reference::execute(data,plan,progress,&mem,{cancel,&cxl});}catch(const query::Error& e){CHECK(e.code==query::ErrorCode::cancelled);hit=true;}catch(const facts::UseScanError& e){CHECK(e.code==facts::UseScanError::Code::cancelled);hit=true;}catch(const instructions::DecodeError& e){CHECK(e.code==instructions::DecodeCode::cancelled);hit=true;}}CHECK(hit&&mem.used==0);++stopped;}
 unsigned failures=0;
 for(size_t i=1;i<=allocations;++i){mem.calls=0;mem.fail_at=i;bool hit=false;{reference::Progress progress;try{(void)reference::execute(data,plan,progress,&mem);}catch(const std::bad_alloc&){hit=true;}}CHECK(hit&&mem.used==0);++failures;}
 mem.fail_at=std::numeric_limits<size_t>::max();
 // Synthetic internal left Unknown: remove only the owner lookup index after
 // metadata was read; this is not a valid independently decoded DEX claim.
 const auto owner=l.method_refs[l.methods[0].method_index].owner;CHECK(owner<l.class_definition_by_type.size());l.class_definition_by_type[owner]=UINT32_MAX;
 for(const auto* op:{"join","semi_join"}){
  const std::string prefix=R"({"schema_version":1,"required_capabilities":["field_declaration_static"],"scope":{"slots":["callerA","callerB","child","parent","object"]},"relation":{"op":")";
  const std::string suffix=R"(","on":"caller","left":{"op":"scan","relation":"method_defs","where":{"all":[{"owner":"Lq08/CallerA;"},{"owner_flags":{"value":1}}]}},"right":{"op":"scan","relation":"field_uses","where":{"target_field_declaration":{"scope":"inherited"}}}}})";
  auto unknown=query::compile(prefix+op+suffix,std::pmr::new_delete_resource(),std::pmr::new_delete_resource());
  {reference::Progress progress;auto result=reference::execute(data,unknown,progress,&mem);CHECK(result.rows.empty()&&progress.profile.unknown_rows==(std::string(op)=="join"?4u:1u));}CHECK(mem.used==0);
 }
 std::cout<<"PASS Q08 caller join deterministic cancellation="<<stopped<<" allocation_failures="<<failures<<" no early streaming and synthetic left Unknown\n";return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
