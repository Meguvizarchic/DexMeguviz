#include "facts/method_facts.hpp"
#include <fstream>
#include <iostream>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <vector>
using namespace dexmeguviz;
using namespace dexmeguviz::instructions;
#define CHECK(x) do { if (!(x)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #x); } while (0)
static void put16(std::vector<uint8_t>& b,size_t at,uint16_t v){b.at(at)=uint8_t(v);b.at(at+1)=uint8_t(v>>8);}
static std::vector<uint8_t> code(const std::vector<uint16_t>& words){
    std::vector<uint8_t> b(32+words.size()*2,0);put16(b,16,1);put16(b,28,static_cast<uint16_t>(words.size()));
    for(size_t i=0;i<words.size();++i)put16(b,32+2*i,words[i]);return b;
}
static DecodeInput input(const std::vector<uint8_t>& bytes){return {bytes,16,35,{1,1,1,1,1,1,1}};}
template<class F> static void reject(DecodeCode expected,F action){
    try{action();}catch(const DecodeError& e){CHECK(e.code==expected);return;}throw std::runtime_error("expected decode error");
}
struct Counted final : std::pmr::memory_resource {
    size_t live=0, allocations=0, fail_at=std::numeric_limits<size_t>::max();
    void* do_allocate(size_t n,size_t a) override {if(allocations++==fail_at)throw std::bad_alloc();void* p=std::pmr::new_delete_resource()->allocate(n,a);live+=n;return p;}
    void do_deallocate(void* p,size_t n,size_t a) override {live-=n;std::pmr::new_delete_resource()->deallocate(p,n,a);}
    bool do_is_equal(const std::pmr::memory_resource& rhs) const noexcept override{return this==&rhs;}
};
int main(int argc,char** argv){
 try{
    CHECK(argc==2);std::ifstream f(argv[1],std::ios::binary);CHECK(f.good());
    const std::vector<uint8_t> dex((std::istreambuf_iterator<char>(f)),{});
    const auto metadata=read_metadata(dex);CHECK(metadata.methods.size()==1);
    auto got=facts::collect_method(dex,metadata,0,Demand::branch_targets);
    CHECK(got.has_body && got.instruction_checked && got.branches.size()==7 && got.decoded_code_units==26);
    const uint32_t pcs[]{0,2,5,9,12,14,17},targets[]{2,5,9,12,9,14,14};
    const uint8_t ops[]{0x28,0x29,0x2a,0x32,0x38,0x2a,0x3b};
    for(size_t i=0;i<7;++i){const auto& v=got.branches[i];
      CHECK(v.pc==pcs[i] && v.target_pc==targets[i] && v.opcode==ops[i]);
      CHECK(v.kind==(i==3||i==4||i==6?BranchKind::conditional:BranchKind::unconditional));
      std::cout<<"BRANCH "<<v.pc<<' '<<v.target_pc<<' '<<unsigned(v.opcode)<<' '<<(v.kind==BranchKind::conditional?"conditional":"unconditional")<<'\n';
    }
    const auto none=facts::collect_method(dex,metadata,0,0);CHECK(!none.instruction_checked && none.branches.empty());
    const auto numeric=facts::collect_method(dex,metadata,0,Demand::numeric);CHECK(numeric.instruction_checked && numeric.branches.empty());
    CHECK(got.validation_work==numeric.validation_work+7);
    for(unsigned op=0x32;op<=0x3d;++op){auto bytes=code({uint16_t(op),2,0x000e});DecodeOptions opt;opt.demand_mask=Demand::branch_targets;
      const auto result=decode(input(bytes),opt);CHECK(result.branches.size()==1 && result.branches[0].target_pc==2 && result.branches[0].kind==BranchKind::conditional);}
    for(uint32_t version:{35u,37u,38u,39u,40u}){auto bytes=code({0x000e,0xff28});auto in=input(bytes);in.dex_version=version;DecodeOptions opt;opt.demand_mask=Demand::branch_targets;
      const auto result=decode(in,opt);CHECK(result.branches.size()==1 && result.branches[0].pc==1 && result.branches[0].target_pc==0);}
    {const auto mixed=code({0x0328,0x000e,0x000e,0x002b,5,0,0x000e,0,0x0100,1,0,0,3,0});
     DecodeOptions both;both.demand_mask=Demand::branch_targets|Demand::switch_targets;
     const auto result=decode(input(mixed),both);CHECK(result.branches.size()==1 && result.branches[0].pc==0 && result.branches[0].target_pc==3);
     CHECK(result.switch_cases.size()==1 && result.switch_cases[0].pc==3 && result.switch_cases[0].target_pc==6);}
    DecodeOptions opt;opt.demand_mask=Demand::branch_targets;
    for(const auto& words:std::vector<std::vector<uint16_t>>{{0x0028,0x000e},{0x0029,0,0x000e},{0x0032,1,0x000e},{0x0328,0x000e},{0x0228,0x000e,0x0100,0,0,0}}){
      const auto b=code(words);reject(DecodeCode::corrupt,[&]{(void)decode(input(b),opt);});}
    const auto b=code({0x0228,0x000e,0x0029,3,0x000e,0x002a,4,0,0x000e,0x0032,3,0x000e,0x0038,0xfffd,0x002a,0,0,0x003b,0xfffd,0x000e});
    auto all=decode(input(b),opt);CHECK(all.validation_work==27 && all.branches.size()==7);
    opt.max_validation_work=26;reject(DecodeCode::budget,[&]{(void)decode(input(b),opt);});
    opt.max_validation_work=27;CHECK(decode(input(b),opt).branches.size()==7);opt.max_validation_work=UINT64_MAX;
    unsigned calls=0;opt.cancel_context=&calls;opt.cancelled=[](void* p) noexcept{return ++*static_cast<unsigned*>(p)>=4;};
    Counted memory;reject(DecodeCode::cancelled,[&]{(void)decode(input(b),opt,&memory);});CHECK(memory.live==0);opt.cancelled=nullptr;
    bool failed=false,success=false;
    for(size_t i=0;i<40;++i){Counted m;m.fail_at=i;try{auto r=decode(input(b),opt,&m);CHECK(r.branches.size()==7);success=true;}catch(const std::bad_alloc&){failed=true;}CHECK(m.live==0);}
    CHECK(failed && success);
    std::cout<<"PASS checked branch facts, demand, bounds, budget, cancel and PMR\n";return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
