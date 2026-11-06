#include "format/debug_positions.hpp"
#include <cstdint>
#include <iostream>
#include <fstream>
#include <iterator>
#include <memory_resource>
#include <stdexcept>
#include <vector>
using namespace dexmeguviz;
#define CHECK(x) do { if (!(x)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #x); } while (false)
class FaultResource final : public std::pmr::memory_resource {
public: explicit FaultResource(int64_t fail=-1):fail_(fail){} uint64_t calls=0, outstanding=0;
private: int64_t fail_;
 void* do_allocate(size_t n,size_t a) override { if(fail_>=0&&calls++==static_cast<uint64_t>(fail_))throw std::bad_alloc(); if(fail_<0)++calls; auto* p=std::pmr::new_delete_resource()->allocate(n,a);outstanding+=n;return p; }
 void do_deallocate(void* p,size_t n,size_t a) override { CHECK(n<=outstanding);outstanding-=n;std::pmr::new_delete_resource()->deallocate(p,n,a); }
 bool do_is_equal(const std::pmr::memory_resource& o) const noexcept override{return this==&o;}
};
static void put32(std::vector<uint8_t>& b,size_t p,uint32_t v){for(unsigned i=0;i<4;++i)b[p+i]=uint8_t(v>>(8*i));}
static void put16(std::vector<uint8_t>& b,size_t p,uint16_t v){b[p]=uint8_t(v);b[p+1]=uint8_t(v>>8);}
int main(int argc,char** argv){try{
 std::vector<uint8_t> bytes(26,0);put16(bytes,4,2);put32(bytes,12,26);put32(bytes,16,3);put16(bytes,20,0x0013);put16(bytes,22,1);put16(bytes,24,0x000e);
 // header; r0 end/end/restart/restart; r1 explicit extended start/end/restart;
 // r0 explicit start replaces implicit identity; r1 end at a later PC.
 const uint8_t data[]{1,0,5,0,5,0,6,0,6,0,4,1,1,1,1,5,1,6,1,3,0,0,0,1,1,5,1,0};
 bytes.insert(bytes.end(),std::begin(data),std::end(data));
 Facts facts;facts.dex_version=35;facts.methods.push_back({0,0,0,4,{},{},{},26});facts.strings.emplace_back(u"x");facts.types.push_back(0);
 using namespace dexmeguviz::debug;auto r=local_lifecycle(bytes,facts,0);CHECK(r.has_debug_info&&r.transitions.size()==9);
 auto &t=r.transitions;
 CHECK(t[0].before==LocalLiveness::unknown&&t[0].after==LocalLiveness::ended&&!t[0].last_identity_known&&!t[0].end_after_known_end);
 CHECK(t[1].before==LocalLiveness::ended&&t[1].end_after_known_end&&!t[1].last_identity_known);
 CHECK(t[2].before==LocalLiveness::ended&&t[2].after==LocalLiveness::live&&!t[2].last_identity_known);
 CHECK(t[3].restart_while_known_live&&!t[3].last_identity_known);
 CHECK(t[4].before==LocalLiveness::unknown&&t[4].after==LocalLiveness::live&&t[4].last_identity_known&&t[4].name_index_p1==1&&t[4].type_index_p1==1&&t[4].signature_index_p1==1);
 CHECK(t[5].before==LocalLiveness::live&&t[5].after==LocalLiveness::ended&&t[5].last_identity_known&&t[5].signature_index_p1==1);
 CHECK(t[6].before==LocalLiveness::ended&&t[6].after==LocalLiveness::live&&t[6].signature_index_p1==1);
 CHECK(t[7].before==LocalLiveness::live&&t[7].last_identity_known&&t[7].name_index_p1==0&&t[7].type_index_p1==0&&t[7].signature_index_p1==0);
 CHECK(t[8].event.dex_pc==1&&t[8].event.register_index==1&&t[8].before==LocalLiveness::live&&t[8].after==LocalLiveness::ended);
 Options small;small.max_local_events=8;try{(void)local_lifecycle(bytes,facts,0,small);CHECK(false);}catch(const ReadError& e){CHECK(e.code==ReadCode::budget);}
 auto no_debug=bytes;put32(no_debug,12,0);CHECK(!local_lifecycle(no_debug,facts,0).has_debug_info);
 FaultResource count;{auto observed=local_lifecycle(bytes,facts,0,{},&count);CHECK(observed.transitions.size()==9);}CHECK(count.outstanding==0&&count.calls>0);
 for(uint64_t i=0;i<count.calls;++i){FaultResource fault(static_cast<int64_t>(i));bool threw=false;try{(void)local_lifecycle(bytes,facts,0,{},&fault);}catch(const std::bad_alloc&){threw=true;}CHECK(threw&&fault.outstanding==0);}
 if(argc==2) {
  std::ifstream in(argv[1],std::ios::binary);CHECK(bool(in));std::vector<uint8_t> dex((std::istreambuf_iterator<char>(in)),{});
  auto parsed=read_metadata_with_debug_associations(dex);size_t observed=0;
  for(uint32_t i=0;i<parsed.methods.size();++i){auto actual=local_lifecycle(dex,parsed,i);if(!actual.has_debug_info)continue;++observed;CHECK(actual.transitions.size()==5);
   const auto& a=actual.transitions;CHECK(a[0].before==LocalLiveness::unknown&&a[0].after==LocalLiveness::live&&a[0].name_index_p1==1&&a[0].type_index_p1==1);
   CHECK(a[1].before==LocalLiveness::live&&a[1].signature_index_p1==1);CHECK(a[2].before==LocalLiveness::live&&a[2].after==LocalLiveness::ended);
   CHECK(a[3].before==LocalLiveness::ended&&a[3].after==LocalLiveness::live&&a[3].signature_index_p1==1);CHECK(a[4].event.dex_pc==2&&a[4].after==LocalLiveness::ended);
   for(const auto& x:a)std::cout<<"transition "<<static_cast<int>(x.event.kind)<<" "<<x.event.dex_pc<<" "<<x.event.register_index<<" "<<static_cast<int>(x.before)<<" "<<static_cast<int>(x.after)<<" "<<x.last_identity_known<<" "<<x.name_index_p1<<" "<<x.type_index_p1<<" "<<x.signature_index_p1<<" "<<x.event.debug_offset<<"\n";
  }CHECK(observed==1);
 } else CHECK(argc==1);
 std::cout<<"PASS local lifecycle explicit events, unknown entry and PMR limits\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
