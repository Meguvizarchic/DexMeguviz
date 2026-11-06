#include "query/ir.hpp"
#include "query/json.hpp"
#include "query_oom_cases.hpp"
#include <cstdlib>
#include <exception>
#include <iostream>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <type_traits>

using namespace dexmeguviz::query;
#define CHECK(x) do {if(!(x))throw std::runtime_error("direct check "+std::to_string(__LINE__)+": " #x);}while(0)
struct Counting final:std::pmr::memory_resource {
 size_t used=0,allocations=0,fail_at=std::numeric_limits<size_t>::max();
 void* do_allocate(size_t n,size_t alignment)override{const auto current=allocations++;if(current==fail_at)throw std::bad_alloc();auto p=std::pmr::new_delete_resource()->allocate(n,alignment);used+=n;return p;}
 void do_deallocate(void* p,size_t n,size_t alignment)override{used-=n;std::pmr::new_delete_resource()->deallocate(p,n,alignment);}
 bool do_is_equal(const std::pmr::memory_resource& other)const noexcept override{return this==&other;}
};
static void run_case(const Case& c){
 Counting plan_control,temp_control;
 {auto p=compile(c.input,&plan_control,&temp_control);CHECK(p.id==c.id);}
 CHECK(plan_control.used==0&&temp_control.used==0);
 const size_t lengths[]={plan_control.allocations,temp_control.allocations};CHECK(lengths[0]>0&&lengths[1]>0);
 for(unsigned domain=0;domain<2;++domain){for(size_t i=0;i<lengths[domain];++i){Counting plan,temp;if(domain==0)plan.fail_at=i;else temp.fail_at=i;
   std::cout<<"attempt "<<c.name<<" "<<(domain?"scratch":"plan")<<" "<<i<<std::endl;
   bool failed=false;try{auto p=compile(c.input,&plan,&temp);(void)p;}catch(const std::bad_alloc&){failed=true;}
   CHECK(failed&&plan.used==0&&temp.used==0);
  }std::cout<<c.name<<" "<<(domain?"scratch":"plan")<<" "<<lengths[domain]<<" reclaimed\n";}
}
int main(){
 std::set_terminate([](){std::cerr<<"TERMINATE during allocation sweep\n";std::_Exit(86);});
 try{
#ifdef DMG_EXPECT_FIXED
  static_assert(!std::is_nothrow_move_constructible_v<json::Json> || std::is_nothrow_move_constructible_v<decltype(json::Json::object)>);
#endif
  auto* old=std::pmr::set_default_resource(std::pmr::null_memory_resource());
  try{for(const auto& c:cases)run_case(c);}catch(...){std::pmr::set_default_resource(old);throw;}
  std::pmr::set_default_resource(old);std::cout<<"PASS direct v1-v4 OOM sweep\n";return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
