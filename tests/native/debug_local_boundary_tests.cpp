#include "format/debug_positions.hpp"
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory_resource>
#include <stdexcept>
#include <vector>
using namespace dexmeguviz;
#define CHECK(x) do{if(!(x))throw std::runtime_error("line "+std::to_string(__LINE__)+": " #x);}while(false)
class FaultResource final:public std::pmr::memory_resource {
public:explicit FaultResource(int64_t fail=-1):fail_(fail){} uint64_t calls=0,outstanding=0;
private:int64_t fail_;void* do_allocate(size_t n,size_t a)override{if(fail_>=0&&calls++==static_cast<uint64_t>(fail_))throw std::bad_alloc();if(fail_<0)++calls;auto* p=std::pmr::new_delete_resource()->allocate(n,a);outstanding+=n;return p;}
 void do_deallocate(void* p,size_t n,size_t a)override{if(n>outstanding)std::terminate();outstanding-=n;std::pmr::new_delete_resource()->deallocate(p,n,a);}bool do_is_equal(const std::pmr::memory_resource& x)const noexcept override{return this==&x;}};
struct Cancel {uint64_t calls=0,stop=0;static bool requested(void* p)noexcept{auto& s=*static_cast<Cancel*>(p);return ++s.calls==s.stop;}};
static void put32(std::vector<uint8_t>& b,size_t p,uint32_t v){for(unsigned i=0;i<4;++i)b[p+i]=uint8_t(v>>(8*i));}
static void put16(std::vector<uint8_t>& b,size_t p,uint16_t v){b[p]=uint8_t(v);b[p+1]=uint8_t(v>>8);}
static void check_sequence(const debug::LifecycleResult& r){using K=debug::PositionKind;const K expected[]{K::instruction_start,K::instruction_interior,K::payload_start,K::payload_interior,K::instruction_start,K::code_end};const uint32_t pcs[]{0,1,2,3,7,8};CHECK(r.has_debug_info&&r.boundary_classification_requested&&r.transitions.size()==6&&r.boundary_work>0);for(size_t i=0;i<6;++i)CHECK(r.transitions[i].event.dex_pc==pcs[i]&&r.transitions[i].event.boundary==expected[i]);}
int main(int argc,char** argv){try{
 using namespace dexmeguviz::debug;
 std::vector<uint8_t> b(36,0);put16(b,4,2);put32(b,12,36);put32(b,16,8);
 const uint16_t words[]{0x0013,1,0x0300,1,1,0,0xff,0x000e};for(size_t i=0;i<8;++i)put16(b,20+i*2,words[i]);
 const uint8_t stream[]{1,0,3,0,0,0,1,1,5,0,1,1,6,0,1,1,5,0,1,4,3,0,0,0,1,1,5,0,0};b.insert(b.end(),std::begin(stream),std::end(stream));
 Facts f;f.dex_version=35;f.methods.push_back({0,0,0,4,{},{},{},36});
 auto plain=local_lifecycle(b,f,0);CHECK(plain.transitions.size()==6&&!plain.boundary_classification_requested&&plain.boundary_work==0);for(const auto& x:plain.transitions)CHECK(x.event.boundary==PositionKind::unknown);
 Options opt;opt.classify_local_boundaries=true;const auto observed=local_lifecycle(b,f,0,opt);check_sequence(observed);
 CHECK(observed.transitions[0].before==LocalLiveness::unknown&&observed.transitions[0].last_identity_known);
 CHECK(observed.transitions[1].after==LocalLiveness::ended&&observed.transitions[2].after==LocalLiveness::live&&observed.transitions[3].after==LocalLiveness::ended);
 CHECK(observed.transitions[5].after==LocalLiveness::ended);
 const instructions::Instruction gaps[]{{0,1,0,instructions::PayloadKind::none},{3,1,0,instructions::PayloadKind::none}};
 CHECK(classify_local_pc(1,4,gaps)==PositionKind::unknown&&classify_local_pc(5,4,gaps)==PositionKind::unknown&&classify_local_pc(4,4,gaps)==PositionKind::code_end);
 CHECK(classify_local_pc(0,3,{})==PositionKind::unknown&&classify_local_pc(0,0,{})==PositionKind::code_end);
 const instructions::Instruction bad[]{{0,0,0,instructions::PayloadKind::none}};CHECK(classify_local_pc(0,3,bad)==PositionKind::unknown);
 auto budget=opt;budget.max_boundary_work=observed.boundary_work-1;try{(void)local_lifecycle(b,f,0,budget);CHECK(false);}catch(const ReadError& e){CHECK(e.code==ReadCode::budget);}
 budget.max_boundary_work=observed.boundary_work;check_sequence(local_lifecycle(b,f,0,budget));budget.max_boundary_work=0;try{(void)local_lifecycle(b,f,0,budget);CHECK(false);}catch(const ReadError& e){CHECK(e.code==ReadCode::budget);}
 auto noevents=b;noevents.resize(36);noevents.insert(noevents.end(),{1,0,0});CHECK(local_lifecycle(noevents,f,0,budget).transitions.empty());
 Cancel count_local;opt.cancelled=Cancel::requested;opt.cancel_context=&count_local;CHECK(local_events(b,f,0,opt).events.size()==6&&count_local.calls>2);
 Cancel late_local{0,count_local.calls-1};opt.cancel_context=&late_local;FaultResource local_memory;bool local_cancelled=false;try{(void)local_events(b,f,0,opt,&local_memory);}catch(const instructions::DecodeError& e){local_cancelled=e.code==instructions::DecodeCode::cancelled;}CHECK(local_cancelled&&local_memory.outstanding==0);
 Cancel position_stop{0,1};opt.cancel_context=&position_stop;bool positions_cancelled=false;try{(void)positions(b,f,0,opt);}catch(const instructions::DecodeError& e){positions_cancelled=e.code==instructions::DecodeCode::cancelled;}CHECK(positions_cancelled);
 Cancel count;opt.cancel_context=&count;const auto counted=local_lifecycle(b,f,0,opt);CHECK(count.calls>counted.transitions.size()+1);
 for(uint64_t stop: {uint64_t(1),uint64_t(2),count.calls-6,count.calls-1,count.calls}){Cancel cancel{0,stop};opt.cancel_context=&cancel;FaultResource memory;bool caught=false;try{(void)local_lifecycle(b,f,0,opt,&memory);}catch(const instructions::DecodeError& e){caught=e.code==instructions::DecodeCode::cancelled;}CHECK(caught&&cancel.calls==stop&&memory.outstanding==0);}
 opt.cancelled=nullptr;opt.cancel_context=nullptr;FaultResource count_alloc;{auto x=local_lifecycle(b,f,0,opt,&count_alloc);check_sequence(x);}CHECK(count_alloc.outstanding==0&&count_alloc.calls>0);
 for(uint64_t i=0;i<count_alloc.calls;++i){FaultResource fault(static_cast<int64_t>(i));bool caught=false;try{(void)local_lifecycle(b,f,0,opt,&fault);}catch(const std::bad_alloc&){caught=true;}CHECK(caught&&fault.outstanding==0);}
 auto damaged=b;damaged[20]=0x73;try{(void)local_lifecycle(damaged,f,0,opt);CHECK(false);}catch(const instructions::DecodeError& e){CHECK(e.code==instructions::DecodeCode::corrupt||e.code==instructions::DecodeCode::unsupported);}
 damaged=b;damaged.pop_back();try{(void)local_lifecycle(damaged,f,0,opt);CHECK(false);}catch(const ReadError& e){CHECK(e.code==ReadCode::corrupt);}
 // Shared debug bytes are independently classified against each method's code.
 std::vector<uint8_t> shared(36,0);put16(shared,4,1);put32(shared,12,36);put32(shared,16,3);put16(shared,20,0x0013);put16(shared,22,1);put16(shared,24,0x000e);
 const uint8_t shared_debug[]{1,0,1,1,3,0,0,0,0};shared.insert(shared.end(),std::begin(shared_debug),std::end(shared_debug));while(shared.size()%4)shared.push_back(0);const size_t code=shared.size();shared.resize(code+22,0);put16(shared,code,1);put32(shared,code+8,36);put32(shared,code+12,3);put16(shared,code+16,0);put16(shared,code+18,0);put16(shared,code+20,0x000e);
 Facts sf;sf.dex_version=35;sf.methods.push_back({0,0,0,4,{},{},{},26});sf.methods.push_back({1,0,0,static_cast<uint32_t>(code),{},{},{},static_cast<uint32_t>(shared.size())});
 CHECK(local_lifecycle(shared,sf,0,opt).transitions[0].event.boundary==PositionKind::instruction_interior);
 CHECK(local_lifecycle(shared,sf,1,opt).transitions[0].event.boundary==PositionKind::instruction_start);
 if(argc==2){std::ifstream in(argv[1],std::ios::binary);CHECK(in.good());std::vector<uint8_t> dex{std::istreambuf_iterator<char>(in),{}};auto facts=read_metadata_with_debug_associations(dex);unsigned seen=0;
  for(uint32_t i=0;i<facts.methods.size();++i){auto result=local_lifecycle(dex,facts,i,opt);if(!result.has_debug_info)continue;++seen;check_sequence(result);for(const auto& event:result.transitions)std::cout<<"EVENT "<<event.event.dex_pc<<' '<<static_cast<int>(event.event.boundary)<<' '<<static_cast<int>(event.event.kind)<<' '<<event.event.register_index<<' '<<event.event.debug_offset<<'\n';}CHECK(seen==1);
 }else CHECK(argc==1);
 std::cout<<"PASS explicit local PC boundary classifications, cancellation, limits and PMR failures\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
