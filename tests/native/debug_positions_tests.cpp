#include "format/debug_positions.hpp"
#include <algorithm>
#include <iostream>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <vector>
using namespace dexmeguviz;
#define CHECK(x) do { if (!(x)) throw std::runtime_error("check failed: " #x); } while (false)
static void put32(std::vector<uint8_t>& b, size_t p, uint32_t v) { for (unsigned i=0;i<4;++i) b[p+i]=uint8_t(v>>(8*i)); }
static void put16(std::vector<uint8_t>& b, size_t p, uint16_t v) { b[p]=uint8_t(v); b[p+1]=uint8_t(v>>8); }
int main(int argc, char** argv) {
 try {
    // A two-unit const/16 followed by return-void. Debug emits PCs 0,1,2,3.
    std::vector<uint8_t> b(33, 0);
    put16(b,4,1); put32(b,12,26); put32(b,16,3);
    put16(b,20,0x0013); put16(b,22,1); put16(b,24,0x000e);
    const uint8_t stream[]{1,0,0x0e,0x1d,0x1d,0x1d,0};
    for (size_t i=0;i<sizeof(stream);++i) b[26+i]=stream[i];
    Facts f; f.dex_version=35; f.methods.push_back({0,0,0,4,{},{},{},26});
    const auto result=debug::positions(b,f,0);
    CHECK(result.has_debug_info); CHECK(result.positions.size()==4);
    CHECK(result.positions[0].dex_pc==0 && result.positions[0].kind==debug::PositionKind::instruction_start);
    CHECK(result.positions[1].dex_pc==1 && result.positions[1].kind==debug::PositionKind::instruction_interior);
    CHECK(result.positions[2].dex_pc==2 && result.positions[2].kind==debug::PositionKind::instruction_start);
    CHECK(result.positions[3].dex_pc==3 && result.positions[3].kind==debug::PositionKind::code_end);
    CHECK(result.positions[1].debug_offset==29);
    auto budget = [&](debug::Options o) { try { (void)debug::positions(b,f,0,o); } catch(const ReadError& e) { return e.code==ReadCode::budget; } catch(const instructions::DecodeError& e) { return e.code==instructions::DecodeCode::budget; } return false; };
    debug::Options o; o.max_positions=3; CHECK(budget(o)); o={}; o.max_opcodes=4; CHECK(budget(o)); o={}; o.max_decode_work=2; CHECK(budget(o));
    b[31]=0x2c; try { (void)debug::positions(b,f,0); CHECK(false); } catch(const ReadError& e) { CHECK(e.code==ReadCode::corrupt); }
    b[31]=0x1d; put32(b,12,0); CHECK(!debug::positions(b,f,0).has_debug_info);
    f.methods.push_back({0,0,0,0,{},{},{},0}); CHECK(!debug::positions(b,f,1).has_debug_info);
    try { (void)debug::positions(b,f,2); CHECK(false); } catch(const std::out_of_range&) {}
    // Shared debug stream is classified independently against each code layout.
    std::vector<uint8_t> shared(58,0); std::copy(b.begin(),b.end(),shared.begin()); put32(shared,12,26);
    put16(shared,36,1); put32(shared,44,26); put32(shared,48,3);
    put16(shared,52,0); put16(shared,54,0); put16(shared,56,0x000e);
    Facts sf; sf.dex_version=35; sf.methods.push_back({0,0,0,4,{},{},{},26}); sf.methods.push_back({1,0,0,36,{},{},{},58});
    const auto first=debug::positions(shared,sf,0); const auto second=debug::positions(shared,sf,1);
    CHECK(first.positions[1].kind==debug::PositionKind::instruction_interior);
    CHECK(second.positions[1].kind==debug::PositionKind::instruction_start);
    // Intermediate address changes need not themselves emit a position.
    std::vector<uint8_t> operands(40,0); std::copy(b.begin(),b.begin()+26,operands.begin()); put32(operands,12,26);
    const uint8_t operand_debug[]{1,1,0x81,1,1,1,1,1,3,0,0,0,0x0e,0};
    for(size_t i=0;i<sizeof(operand_debug);++i) operands[26+i]=operand_debug[i];
    const auto op=debug::positions(operands,f,0); CHECK(op.positions.size()==1);
    CHECK(op.positions[0].dex_pc==2 && op.positions[0].kind==debug::PositionKind::instruction_start);
    // Aligned array-data payload occupies PC 2..6; position kinds remain descriptive.
    std::vector<uint8_t> payload(43,0); put16(payload,4,1); put32(payload,12,36); put32(payload,16,8);
    put16(payload,20,0x0012); put16(payload,22,0); put16(payload,24,0x0300); put16(payload,26,1);
    put16(payload,28,1); put16(payload,30,0); put16(payload,32,0xff); put16(payload,34,0x000e);
    const uint8_t payload_debug[]{1,0,0x0e,0x2c,0x1d,0x4a,0};
    for(size_t i=0;i<sizeof(payload_debug);++i) payload[36+i]=payload_debug[i];
    Facts pf; pf.dex_version=35; pf.methods.push_back({0,0,0,4,{},{},{},36});
    const auto pr=debug::positions(payload,pf,0); CHECK(pr.positions.size()==4);
    CHECK(pr.positions[1].dex_pc==2 && pr.positions[1].kind==debug::PositionKind::payload_start);
    CHECK(pr.positions[2].dex_pc==3 && pr.positions[2].kind==debug::PositionKind::payload_interior);
    CHECK(pr.positions[3].dex_pc==7 && pr.positions[3].kind==debug::PositionKind::instruction_start);
    if (argc == 2) {
        std::ifstream in(argv[1],std::ios::binary); CHECK(bool(in));
        std::vector<uint8_t> dex((std::istreambuf_iterator<char>(in)),{});
        auto actual=read_metadata_with_debug_associations(dex); size_t observed=0;
        for (uint32_t i=0;i<actual.methods.size();++i) {
            const auto dr=debug::positions(dex,actual,i);
            if (!dr.has_debug_info) continue;
            ++observed; CHECK(dr.positions.size()==3);
            CHECK(dr.positions[0].dex_pc==0 && dr.positions[0].kind==debug::PositionKind::instruction_start);
            CHECK(dr.positions[1].dex_pc==1 && dr.positions[1].kind==debug::PositionKind::instruction_interior);
            CHECK(dr.positions[2].dex_pc==2 && dr.positions[2].kind==debug::PositionKind::code_end);
        }
        CHECK(observed==1);
    } else CHECK(argc==1);
    std::cout << "PASS debug emitted-position classification and limits\n"; return 0;
 } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}




