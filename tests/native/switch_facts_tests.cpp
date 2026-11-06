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
static void put16(std::vector<uint8_t>& bytes, size_t at, uint16_t value) {
    bytes.at(at) = uint8_t(value); bytes.at(at + 1) = uint8_t(value >> 8);
}
static std::vector<uint8_t> code(const std::vector<uint16_t>& words) {
    std::vector<uint8_t> bytes(32 + words.size() * 2, 0);
    put16(bytes, 16, 1); put16(bytes, 28, static_cast<uint16_t>(words.size()));
    for (size_t i = 0; i < words.size(); ++i) put16(bytes, 32 + 2 * i, words[i]);
    return bytes;
}
static DecodeInput input(const std::vector<uint8_t>& bytes) { return {bytes, 16, 35, {1,1,1,1,1,1,1}}; }
template<class F> static void reject(DecodeCode expected, F action) {
    try { action(); } catch (const DecodeError& error) { CHECK(error.code == expected); return; }
    throw std::runtime_error("expected decode error");
}
struct Counted final : std::pmr::memory_resource {
    size_t live=0, allocations=0, fail_at=std::numeric_limits<size_t>::max();
    void* do_allocate(size_t n,size_t align) override {
        if (allocations++ == fail_at) throw std::bad_alloc();
        void* p=std::pmr::new_delete_resource()->allocate(n,align); live+=n; return p;
    }
    void do_deallocate(void* p,size_t n,size_t align) override {
        live-=n;std::pmr::new_delete_resource()->deallocate(p,n,align);
    }
    bool do_is_equal(const std::pmr::memory_resource& rhs) const noexcept override { return this == &rhs; }
};
int main(int argc,char** argv) {
    try {
        CHECK(argc == 2);
        std::ifstream f(argv[1],std::ios::binary); CHECK(f.good());
        const std::vector<uint8_t> dex((std::istreambuf_iterator<char>(f)),{});
        const auto metadata=read_metadata(dex);CHECK(metadata.methods.size()==1);
        auto facts=facts::collect_method(dex,metadata,0,Demand::switch_targets);
        CHECK(facts.has_body && facts.instruction_checked && facts.switch_cases.size()==4);
        const int32_t keys[]{-1,0,std::numeric_limits<int32_t>::min(),std::numeric_limits<int32_t>::max()};
        for(uint32_t i=0;i<4;i++) {
            const auto& c=facts.switch_cases[i];
            CHECK(c.pc==(i<2?0u:3u) && c.payload_pc==(i<2?8u:16u) && c.target_pc==6 && c.case_index==i%2 && c.key==keys[i]);
            CHECK(c.payload_kind==(i<2?PayloadKind::packed_switch:PayloadKind::sparse_switch));
            std::cout << "CASE " << c.pc << ' ' << c.payload_pc << ' ' << c.key << ' ' << c.target_pc << '\n';
        }
        const auto none=facts::collect_method(dex,metadata,0,0);
        CHECK(!none.instruction_checked && none.switch_cases.empty());
        const auto numeric=facts::collect_method(dex,metadata,0,Demand::numeric);
        CHECK(numeric.instruction_checked && numeric.switch_cases.empty());
        const auto shared=code({0x002b,12,0,0x002b,9,0,0x000e,0x000e,0x000e,0x000e,0x000e,0x000e,0x0100,2,0xffff,0xffff,6,0,7,0});
        DecodeOptions opt;opt.demand_mask=Demand::switch_targets;
        auto actual=decode(input(shared),opt);CHECK(actual.switch_cases.size()==4 && actual.payload_work==6);
        for(uint32_t i=0;i<4;i++) {
            const auto& c=actual.switch_cases[i];CHECK(c.pc==(i<2?0u:3u) && c.payload_pc==12 && c.target_pc==(i<2?6u:9u)+i%2 && c.key==int32_t(i%2)-1);
        }
        const auto plain=decode(input(shared));CHECK(plain.switch_cases.empty() && plain.payload_work==actual.payload_work && plain.validation_work==actual.validation_work);
        const auto empty=code({0x002b,4,0,0x000e,0x0100,0,0,0});
        CHECK(decode(input(empty),opt).switch_cases.empty());
        const auto backward=code({0x0029,8,0x0100,1,0x8000,0xffff,3,0,0x002b,0xfffa,0xffff,0x000e});
        const auto back=decode(input(backward),opt);
        CHECK(back.switch_cases.size()==1 && back.switch_cases[0].pc==8 && back.switch_cases[0].payload_pc==2 && back.switch_cases[0].key==-32768 && back.switch_cases[0].target_pc==11);
        opt.max_payload_elements=5;reject(DecodeCode::budget,[&]{(void)decode(input(shared),opt);});
        opt.max_payload_elements=6;CHECK(decode(input(shared),opt).switch_cases.size()==4);
        opt.max_payload_elements=UINT64_MAX;opt.max_validation_work=actual.validation_work-1;reject(DecodeCode::budget,[&]{(void)decode(input(shared),opt);});
        opt.max_validation_work=actual.validation_work;CHECK(decode(input(shared),opt).switch_cases.size()==4);
        opt.max_validation_work=UINT64_MAX;
        auto bad=shared;put16(bad,32+16*2,5);reject(DecodeCode::corrupt,[&]{(void)decode(input(bad),opt);});
        bad=shared;put16(bad,32+14*2,0xffff);put16(bad,32+15*2,0x7fff);reject(DecodeCode::corrupt,[&]{(void)decode(input(bad),opt);});
        for(auto v:{35u,37u,38u,39u,40u}){auto x=input(shared);x.dex_version=v;CHECK(decode(x,opt).switch_cases.size()==4);}
        unsigned calls=0;opt.cancel_context=&calls;opt.cancelled=[](void* p) noexcept {return ++*static_cast<unsigned*>(p)>=4;};
        Counted memory;reject(DecodeCode::cancelled,[&]{(void)decode(input(shared),opt,&memory);});CHECK(memory.live==0);opt.cancelled=nullptr;
        bool failed=false,success=false;
        for(size_t i=0;i<40;i++){Counted m;m.fail_at=i;try {auto r=decode(input(shared),opt,&m);CHECK(r.switch_cases.size()==4);success=true;} catch(const std::bad_alloc&){failed=true;}CHECK(m.live==0);}
        CHECK(failed && success);
        std::cout << "PASS checked switch cases, shared payloads, demand, bounds, budget, cancel and PMR\n";return 0;
    }catch(const std::exception& e){std::cerr << e.what() << '\n';return 1;}
}
