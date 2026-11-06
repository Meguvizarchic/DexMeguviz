#include "facts/method_facts.hpp"
#include <array>
#include <fstream>
#include <iostream>
#include <memory_resource>
#include <stdexcept>
#include <vector>
using namespace dexmeguviz;
using namespace dexmeguviz::instructions;
#define CHECK(x) do { if (!(x)) throw std::runtime_error("check failed: " #x); } while (0)
static void put16(std::vector<uint8_t>& b, size_t at, uint16_t v) { b.at(at)=uint8_t(v); b.at(at+1)=uint8_t(v>>8); }
static std::vector<uint8_t> code(std::initializer_list<uint16_t> words) {
    std::vector<uint8_t> b(32+words.size()*2,0); put16(b,16,16); put16(b,28,uint16_t(words.size()));
    size_t at=32; for(auto w:words) { put16(b,at,w); at+=2; } return b;
}
static DecodeInput input(const std::vector<uint8_t>& b) { return {b,16,40,{1,1,1,1,1,1,1}}; }
template<typename F> void reject(DecodeCode c, F f) {
    try {f();} catch(const DecodeError& e) {CHECK(e.code==c);return;}
    throw std::runtime_error("expected DecodeError");
}
int main(int argc,char** argv) {
 try {
    CHECK(argc==2);
    struct Case {std::vector<uint16_t> words;uint64_t value;uint8_t width;};
    const std::vector<Case> cases{
      {{0xf012},0xffffffffULL,32}, {{0x7012},7,32},
      {{0x0013,0x8000},0xffff8000ULL,32}, {{0x0014,0x5678,0x1234},0x12345678ULL,32},
      {{0x0015,0x8001},0x80010000ULL,32}, {{0x0016,0xfffe},0xfffffffffffffffeULL,64},
      {{0x0017,0x0001,0x8000},0xffffffff80000001ULL,64},
      {{0x0018,0x1234,0x5678,0x9abc,0xdef0},0xdef09abc56781234ULL,64},
      {{0x0019,0x8001},0x8001000000000000ULL,64}
    };
    for(const auto& c:cases) {
       auto words=c.words;words.push_back(0x000e);
       std::vector<uint8_t> b(32+words.size()*2,0);put16(b,16,16);put16(b,28,uint16_t(words.size()));
       for(size_t i=0;i<words.size();++i) put16(b,32+2*i,words[i]);
       DecodeOptions opt;opt.demand_mask=Demand::numeric;
       auto v=decode(input(b),opt);
       CHECK(v.numeric_literals.size()==1);const auto n=v.numeric_literals[0];
       CHECK(n.pc==0 && n.opcode==uint8_t(words[0]) && n.bits==c.value && n.width_bits==c.width && n.kind==NumericKind::constant);
       CHECK(v.string_uses.empty() && v.field_uses.empty() && v.invoke_sites.empty());
       CHECK(decode(input(b)).numeric_literals.empty());
    }
    for(uint8_t op=0xd0;op<=0xe2;++op) {
       const bool lit16=op<=0xd7; auto b=code({uint16_t(op),lit16?uint16_t(0xfffe):uint16_t(0xfe00),0x000e});
       DecodeOptions opt;opt.demand_mask=Demand::numeric;const auto v=decode(input(b),opt);
       CHECK(v.numeric_literals.size()==1);const auto n=v.numeric_literals[0];
       CHECK(n.pc==0 && n.opcode==op && n.bits==0xfffffffeULL && n.width_bits==32 && n.kind==NumericKind::arithmetic_operand);
    }
    {
      auto b=code({0xf012,0x001a,0,0x000e});DecodeOptions o;o.demand_mask=Demand::numeric|Demand::strings;
      auto v=decode(input(b),o);CHECK(v.numeric_literals.size()==1 && v.string_uses.size()==1 && v.string_uses[0].pc==1);
      o.max_validation_work=3;reject(DecodeCode::budget,[&]{(void)decode(input(b),o);});
      o.max_validation_work=UINT64_MAX;unsigned calls=0;o.cancel_context=&calls;
      o.cancelled=[](void* p) noexcept{return ++*static_cast<unsigned*>(p)==3;};
      reject(DecodeCode::cancelled,[&]{(void)decode(input(b),o);});
      auto bad=code({0xf012,0x003e});o.cancelled=nullptr;reject(DecodeCode::corrupt,[&]{(void)decode(input(bad),o);});
    }
    {
      std::ifstream f(argv[1],std::ios::binary);CHECK(f.good());std::vector<uint8_t> b((std::istreambuf_iterator<char>(f)),{});
      auto metadata=read_metadata(b);uint32_t ordinal=UINT32_MAX;
      for(uint32_t i=0;i<metadata.methods.size();++i) if(metadata.methods[i].name==u"uses") ordinal=i;
      CHECK(ordinal!=UINT32_MAX);
      auto result=facts::collect_method(b,metadata,ordinal,Demand::numeric|Demand::strings);
      CHECK(result.has_body && result.instruction_checked && result.decoded_code_units==8);
      CHECK(result.numeric_literals.size()==3 && result.string_uses.size()==1);
      CHECK(result.numeric_literals[0].pc==0 && result.numeric_literals[0].bits==0xffffffffULL);
      CHECK(result.numeric_literals[1].pc==1 && result.numeric_literals[1].bits==0xfffffffffffffffeULL && result.numeric_literals[1].width_bits==64);
      CHECK(result.numeric_literals[2].pc==3 && result.numeric_literals[2].bits==0x80000000ULL);
      CHECK(result.string_uses[0].pc==5 && result.string_uses[0].string_index==10);
      auto no_demand=facts::collect_method(b,metadata,ordinal,0);
      CHECK(!no_demand.instruction_checked && no_demand.numeric_literals.empty());
      auto without=facts::collect_method(b,metadata,ordinal,Demand::strings);
      CHECK(without.instruction_checked && without.numeric_literals.empty() && without.string_uses.size()==1);
    }
    std::cout<<"PASS numeric literals: constant and arithmetic-operand encodings, demand isolation, malformed/budget/cancel, real DEX metadata and method facts\n";
    return 0;
 } catch(const std::exception& e) {std::cerr<<e.what()<<'\n';return 1;}
}
