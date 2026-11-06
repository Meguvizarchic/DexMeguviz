#include "format/debug_positions.hpp"
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <vector>
using namespace dexmeguviz;
#define CHECK(x) do { if (!(x)) throw std::runtime_error("check failed: " #x); } while (false)
class FaultResource final : public std::pmr::memory_resource {
public:
    explicit FaultResource(int64_t fail_after=-1): fail_after_(fail_after) {}
    uint64_t calls=0, outstanding=0;
private:
    int64_t fail_after_;
    void* do_allocate(size_t bytes,size_t alignment) override {
        const auto call=calls++; if(fail_after_>=0 && call==static_cast<uint64_t>(fail_after_)) throw std::bad_alloc();
        auto* p=std::pmr::new_delete_resource()->allocate(bytes,alignment);outstanding+=bytes;return p;
    }
    void do_deallocate(void* p,size_t bytes,size_t alignment) override {
        if(bytes>outstanding)std::terminate();outstanding-=bytes;std::pmr::new_delete_resource()->deallocate(p,bytes,alignment);
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {return this==&other;}
};
static void put32(std::vector<uint8_t>& b, size_t p, uint32_t v) { for (unsigned i=0;i<4;++i) b[p+i]=uint8_t(v>>(8*i)); }
static void put16(std::vector<uint8_t>& b, size_t p, uint16_t v) { b[p]=uint8_t(v); b[p+1]=uint8_t(v>>8); }
int main(int argc, char** argv) {
 try {
    std::vector<uint8_t> b(26,0); put16(b,4,1); put32(b,12,26); put32(b,16,3);
    put16(b,20,0x0013); put16(b,22,1); put16(b,24,0x000e);
    const uint8_t stream[]{1,0,3,0,1,1,4,0,0,0,1,1,1,5,0,6,0,1,2,5,0,0};
    b.insert(b.end(),std::begin(stream),std::end(stream));
    Facts f; f.dex_version=35; f.methods.push_back({0,0,0,4,{},{},{},26}); f.strings.emplace_back(u"x"); f.types.push_back(0);
    const auto r=debug::local_events(b,f,0); CHECK(r.has_debug_info && r.events.size()==5);
    FaultResource observed; { const auto owned=debug::local_events(b,f,0,{},&observed); CHECK(owned.events.size()==5); }
    CHECK(observed.outstanding==0 && observed.calls>0);
    for(uint64_t i=0;i<observed.calls;++i) {
        FaultResource fault(static_cast<int64_t>(i));bool threw=false;
        try { (void)debug::local_events(b,f,0,{},&fault); } catch(const std::bad_alloc&) {threw=true;}
        CHECK(threw && fault.outstanding==0);
    }
    CHECK(r.events[0].kind==debug::LocalKind::start && r.events[0].dex_pc==0 && r.events[0].name_index_p1==1 && r.events[0].type_index_p1==1 && r.events[0].debug_offset==28);
    CHECK(r.events[1].kind==debug::LocalKind::start_extended && r.events[1].dex_pc==0 && r.events[1].signature_index_p1==1 && r.events[1].debug_offset==32);
    CHECK(r.events[2].kind==debug::LocalKind::end && r.events[2].dex_pc==1 && r.events[2].debug_offset==39);
    CHECK(r.events[3].kind==debug::LocalKind::restart && r.events[3].dex_pc==1 && r.events[3].debug_offset==41);
    CHECK(r.events[4].kind==debug::LocalKind::end && r.events[4].dex_pc==3 && r.events[4].debug_offset==45);
    for(const auto& e:r.events) CHECK(e.register_index==0);
    auto failed=[&](const std::vector<uint8_t>& bytes,const debug::Options& opt,ReadCode code) {
        try { (void)debug::local_events(bytes,f,0,opt); } catch(const ReadError& e) { return e.code==code; }
        catch(const instructions::DecodeError& e) { return code==ReadCode::budget && e.code==instructions::DecodeCode::budget; } return false;
    };
    debug::Options o; o.max_local_events=4; CHECK(failed(b,o,ReadCode::budget));
    o={}; o.max_opcodes=3; CHECK(failed(b,o,ReadCode::budget));
    o={}; o.max_decode_work=0; CHECK(failed(b,o,ReadCode::budget));
    auto bad=b; bad[29]=1; CHECK(failed(bad,{},ReadCode::corrupt));
    bad=b; bad[30]=2; CHECK(failed(bad,{},ReadCode::corrupt));
    bad=b; bad[44]=3; CHECK(failed(bad,{},ReadCode::corrupt));
    bad=b; bad.pop_back(); CHECK(failed(bad,{},ReadCode::corrupt));
    // A special opcode advances the address; SET_FILE is not a local event.
    std::vector<uint8_t> special(b.begin(),b.begin()+26);
    const uint8_t special_stream[]{1,0,0x1d,3,0,1,1,9,1,5,0,0};
    special.insert(special.end(),std::begin(special_stream),std::end(special_stream));
    const auto sr=debug::local_events(special,f,0);
    CHECK(sr.events.size()==2 && sr.events[0].kind==debug::LocalKind::start && sr.events[0].dex_pc==1);
    CHECK(sr.events[1].kind==debug::LocalKind::end && sr.events[1].dex_pc==1);
    auto truncated_file=special; truncated_file.resize(34); CHECK(failed(truncated_file,{},ReadCode::corrupt));
    auto invalid_file=special; invalid_file[34]=2; CHECK(failed(invalid_file,{},ReadCode::corrupt));
    auto no_debug=b; put32(no_debug,12,0); CHECK(!debug::local_events(no_debug,f,0).has_debug_info);
    f.methods.push_back({0,0,0,0,{},{},{},0}); CHECK(!debug::local_events(b,f,1).has_debug_info);
    try { (void)debug::local_events(b,f,2); CHECK(false); } catch(const std::out_of_range&) {}
    // The same bytes can be linked to a separate code item with fewer registers.
    auto shared=b; const auto pos=shared.size(); shared.resize(pos+22,0); put16(shared,pos,0); put32(shared,pos+8,26); put32(shared,pos+12,3);
    put16(shared,pos+16,0); put16(shared,pos+18,0); put16(shared,pos+20,0x000e);
    f.methods.push_back({0,0,0,static_cast<uint32_t>(pos),{},{},{},static_cast<uint32_t>(shared.size())});
    try { (void)debug::local_events(shared,f,2); CHECK(false); } catch(const ReadError& e) { CHECK(e.code==ReadCode::corrupt); }
    if(argc==2) {
        std::ifstream in(argv[1],std::ios::binary); CHECK(bool(in)); std::vector<uint8_t> dex((std::istreambuf_iterator<char>(in)),{});
        auto actual=read_metadata_with_debug_associations(dex); size_t observed=0;
        for(uint32_t i=0;i<actual.methods.size();++i) {
            const auto got=debug::local_events(dex,actual,i); if(!got.has_debug_info) continue;
            ++observed; CHECK(got.events.size()==5);
            CHECK(got.events[0].kind==debug::LocalKind::start && got.events[0].dex_pc==0 && got.events[0].name_index_p1==1 && got.events[0].type_index_p1==1);
            CHECK(got.events[1].kind==debug::LocalKind::start_extended && got.events[1].signature_index_p1==1);
            CHECK(got.events[2].kind==debug::LocalKind::end && got.events[2].dex_pc==1);
            CHECK(got.events[3].kind==debug::LocalKind::restart && got.events[3].dex_pc==1);
            CHECK(got.events[4].kind==debug::LocalKind::end && got.events[4].dex_pc==2);
            CHECK(got.events[0].debug_offset==719 && got.events[1].debug_offset==723 && got.events[2].debug_offset==730 && got.events[3].debug_offset==732 && got.events[4].debug_offset==736);
        }
        CHECK(observed==1);
    } else CHECK(argc==1);
    std::cout << "PASS debug local events and limits\n"; return 0;
 } catch(const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
