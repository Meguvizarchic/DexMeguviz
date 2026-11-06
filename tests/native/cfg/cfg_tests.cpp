#include "analysis/cfg/cfg.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <vector>
using namespace dexmeguviz;
using namespace dexmeguviz::analysis::cfg;
using namespace dexmeguviz::instructions;
#define CHECK(x) do { if (!(x)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #x); } while (0)
static void put16(std::vector<uint8_t>& b,size_t at,uint16_t v){b.at(at)=uint8_t(v);b.at(at+1)=uint8_t(v>>8);}
static void put32(std::vector<uint8_t>& b,size_t at,uint32_t v){put16(b,at,uint16_t(v));put16(b,at+2,uint16_t(v>>16));}
static std::vector<uint8_t> code(const std::vector<uint16_t>& words){
    std::vector<uint8_t> b(32+words.size()*2,0);put16(b,16,1);put32(b,28,uint32_t(words.size()));
    for(size_t i=0;i<words.size();++i)put16(b,32+2*i,words[i]);return b;
}
static DecodeInput input(const std::vector<uint8_t>& b){return {b,16,35,{1,1,1,1,1,1,1}};}
static std::vector<uint8_t> try_code(){
    auto b=code({0x0013,7,0x000e});put16(b,22,1);b.insert(b.end(),{0,0});
    const auto at=b.size();b.resize(at+8);put32(b,at,0);put16(b,at+4,2);put16(b,at+6,1);
    b.insert(b.end(),{1,1,0,2});return b;
}
template<class F> static void reject(DecodeCode code,F action){try{action();}catch(const DecodeError& e){CHECK(e.code==code);return;}throw std::runtime_error("expected decoder error");}
struct Counted final : std::pmr::memory_resource {
    size_t live=0, allocations=0, fail_at=std::numeric_limits<size_t>::max();
    void* do_allocate(size_t n,size_t a) override {if(allocations++==fail_at)throw std::bad_alloc();void* p=std::pmr::new_delete_resource()->allocate(n,a);live+=n;return p;}
    void do_deallocate(void* p,size_t n,size_t a) override {live-=n;std::pmr::new_delete_resource()->deallocate(p,n,a);}
    bool do_is_equal(const std::pmr::memory_resource& rhs) const noexcept override{return this==&rhs;}
};
static const char* term(Terminal v){switch(v){case Terminal::ordinary:return "ordinary";case Terminal::jump:return "jump";case Terminal::conditional:return "conditional";case Terminal::switch_op:return "switch";case Terminal::return_op:return "return";case Terminal::throw_op:return "throw";}throw std::runtime_error("bad terminal");}
static const char* edge(EdgeKind v){switch(v){case EdgeKind::fallthrough:return "fallthrough";case EdgeKind::branch:return "branch";case EdgeKind::conditional_taken:return "taken";case EdgeKind::conditional_fallthrough:return "not_taken";case EdgeKind::switch_case:return "case";case EdgeKind::switch_default:return "default";case EdgeKind::fallthrough_to_payload:return "payload";case EdgeKind::fallthrough_past_end:return "end";case EdgeKind::exception_handler:return "exception";}throw std::runtime_error("bad edge");}
static void dump(const char* label,const Result& result){
    std::cout<<"GRAPH "<<label<<' '<<result.code_units<<' '<<result.reachable_flow_complete<<'\n';
    for(const auto& b:result.blocks)std::cout<<"BLOCK "<<label<<' '<<b.start_pc<<' '<<b.end_pc<<' '<<b.last_pc<<' '<<term(b.terminal)<<' '<<b.reachable<<'\n';
    for(const auto& e:result.edges)std::cout<<"EDGE "<<label<<' '<<e.source_pc<<' '<<(e.target_pc==no_target?-1:int64_t(e.target_pc))<<' '<<edge(e.kind)<<' '<<e.switch_key<<' '<<e.switch_case_index<<' '<<(e.payload_pc==no_target?-1:int64_t(e.payload_pc))<<'\n';
}
static std::vector<uint8_t> read(const char* name){std::ifstream f(name,std::ios::binary);CHECK(f.good());return {std::istreambuf_iterator<char>(f),{}};}
int main(int argc,char** argv){
 try{
    CHECK(argc==3);
    const auto branches=read(argv[1]);auto meta=read_metadata(branches);CHECK(meta.methods.size()==1);
    auto graph=build(branches,meta,0);CHECK(graph.has_body && graph.reachable_flow_complete && graph.code_units==26);
    CHECK(graph.blocks.size()==18 && graph.edges.size()==10);dump("branch",graph);
    const auto switches=read(argv[2]);const auto smeta=read_metadata(switches);
    auto sw=build(switches,smeta,0);CHECK(sw.has_body && sw.reachable_flow_complete && sw.blocks.size()==4 && sw.edges.size()==7);
    CHECK(!sw.blocks.back().reachable && sw.edges.back().kind==EdgeKind::fallthrough_to_payload);dump("switch",sw);
    auto no_body=read_metadata(branches);no_body.methods[0].code_offset=0;auto empty=build(branches,no_body,0);
    CHECK(!empty.has_body && !empty.reachable_flow_complete && empty.blocks.empty() && empty.edges.empty());
    try{(void)build(branches,meta,1);throw std::runtime_error("invalid ordinal accepted");}catch(const std::out_of_range&){}
    const auto loop=code({0x002a,0,0});auto loop_graph=build_checked(input(loop));
    CHECK(loop_graph.blocks.size()==1 && loop_graph.edges.size()==1 && loop_graph.edges[0].target_pc==0 && loop_graph.reachable_flow_complete);
    const auto fall_end=code({0});auto end_graph=build_checked(input(fall_end));
    CHECK(!end_graph.reachable_flow_complete && end_graph.edges.size()==1 && end_graph.edges[0].kind==EdgeKind::fallthrough_past_end);
    const auto fall_payload=code({0x002b,4,0,0,0x0100,0,0,0});auto payload_graph=build_checked(input(fall_payload));
    CHECK(!payload_graph.reachable_flow_complete && payload_graph.edges.back().kind==EdgeKind::fallthrough_to_payload);
    const auto throw_code=code({0x0027});auto throw_graph=build_checked(input(throw_code));
    CHECK(throw_graph.reachable_flow_complete && throw_graph.blocks[0].terminal==Terminal::throw_op && throw_graph.edges.empty());
    auto with_try=try_code();reject(DecodeCode::unsupported,[&]{(void)build_checked(input(with_try));});
    put16(with_try,44,0);reject(DecodeCode::corrupt,[&]{(void)build_checked(input(with_try));});
    Options limits;limits.max_decode_work=1;reject(DecodeCode::budget,[&]{(void)build_checked(input(loop),limits);});
    limits={};limits.max_graph_work=loop_graph.graph_work-1;reject(DecodeCode::budget,[&]{(void)build_checked(input(loop),limits);});
    limits.max_graph_work=loop_graph.graph_work;CHECK(build_checked(input(loop),limits).reachable_flow_complete);
    limits={};limits.max_blocks=0;reject(DecodeCode::budget,[&]{(void)build_checked(input(loop),limits);});
    limits={};limits.max_edges=0;reject(DecodeCode::budget,[&]{(void)build_checked(input(loop),limits);});
    unsigned calls=0;limits={};limits.cancel_context=&calls;limits.cancelled=[](void* p) noexcept{return ++*static_cast<unsigned*>(p)>=5;};
    Counted cancel_mem;reject(DecodeCode::cancelled,[&]{(void)build_checked(input(loop),limits,&cancel_mem);});CHECK(cancel_mem.live==0);
    bool failed=false,success=false;for(size_t i=0;i<100;++i){Counted m;m.fail_at=i;try{auto r=build_checked(input(loop),{},&m);CHECK(r.reachable_flow_complete);success=true;}catch(const std::bad_alloc&){failed=true;}CHECK(m.live==0);}
    CHECK(failed && success);
    std::cout<<"PASS bounded CFG, partial fallthrough, exceptions, budget, cancellation and PMR\n";return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
