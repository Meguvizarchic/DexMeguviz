#include "analysis/cfg/cfg.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <tuple>
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
static std::vector<uint8_t> shared_handlers(){
    auto b=code({0,0,0,0,0,0x000e});put16(b,22,2);const auto at=b.size();b.resize(at+16);
    put32(b,at,0);put16(b,at+4,2);put16(b,at+6,1);
    put32(b,at+8,2);put16(b,at+12,2);put16(b,at+14,1);
    b.insert(b.end(),{1,0x7f,0,4,5});return b;
}
static std::vector<uint8_t> distinct_handlers(){
    auto b=code({0,0,0,0,0,0,0,0,0x000e});put16(b,22,2);b.insert(b.end(),{0,0});
    const auto at=b.size();b.resize(at+16);
    put32(b,at,0);put16(b,at+4,2);put16(b,at+6,1);
    put32(b,at+8,4);put16(b,at+12,2);put16(b,at+14,6);
    b.insert(b.end(),{2,2,0,7,1,8,0,8});return b;
}
static DecodeInput input(const std::vector<uint8_t>& b){return {b,16,35,{1,1,1,1,1,1,1}};}
static std::vector<uint8_t> read(const char* path){std::ifstream f(path,std::ios::binary);CHECK(f.good());return {std::istreambuf_iterator<char>(f),{}};}
template<class F>static void reject(DecodeCode c,F action){try{action();}catch(const DecodeError& e){CHECK(e.code==c);return;}throw std::runtime_error("expected decoder error");}
struct Counted final : std::pmr::memory_resource {
    size_t live=0,allocations=0,fail_at=std::numeric_limits<size_t>::max();
    void* do_allocate(size_t n,size_t a) override {if(allocations++==fail_at)throw std::bad_alloc();void* p=std::pmr::new_delete_resource()->allocate(n,a);live+=n;return p;}
    void do_deallocate(void* p,size_t n,size_t a) override {live-=n;std::pmr::new_delete_resource()->deallocate(p,n,a);}
    bool do_is_equal(const std::pmr::memory_resource& rhs) const noexcept override{return this==&rhs;}
};
int main(int argc,char** argv){
 try{
    CHECK(argc==2);const auto bytes=read(argv[1]);const auto facts=read_metadata(bytes);
    auto method=std::find_if(facts.methods.begin(),facts.methods.end(),[](const Method& m){return m.name==u"gamma";});
    CHECK(method!=facts.methods.end());const auto ordinal=static_cast<uint32_t>(method-facts.methods.begin());
    reject(DecodeCode::unsupported,[&]{(void)build(bytes,facts,ordinal);});
    Options opt;opt.include_exception_edges=true;const auto result=build(bytes,facts,ordinal,opt);
    CHECK(result.has_body&&result.has_exception_regions&&result.exception_edges_included&&result.reachable_flow_complete);
    CHECK(result.blocks.size()==2&&result.edges.size()==3&&result.blocks[0].start_pc==0&&result.blocks[0].end_pc==1);
    unsigned count=0;
    for(const auto& e:result.edges)if(e.kind==EdgeKind::exception_handler){
        CHECK(e.from_block==0&&e.source_pc==0&&e.target_pc==1&&e.to_block==1);
        std::cout<<"CATCH "<<e.source_pc<<' '<<e.target_pc<<' '<<e.catch_type_index<<' '<<e.catch_order<<'\n';++count;
    }
    CHECK(count==2);
    auto shared=shared_handlers();auto shared_result=build_checked(input(shared),opt);
    CHECK(shared_result.blocks.size()==4&&shared_result.reachable_flow_complete);
    std::vector<uint32_t> sources;
    for(const auto& e:shared_result.edges)if(e.kind==EdgeKind::exception_handler){
        CHECK((e.catch_order==0&&e.catch_type_index==0&&e.target_pc==4)||(e.catch_order==1&&e.catch_type_index==no_target&&e.target_pc==5));sources.push_back(e.source_pc);
    }
    CHECK((sources==std::vector<uint32_t>{0,0,2,2}));
    auto distinct=distinct_handlers();auto distinct_input=input(distinct);distinct_input.refs.types=2;
    const auto diverse=build_checked(distinct_input,opt);CHECK(diverse.has_exception_regions&&diverse.reachable_flow_complete);
    std::vector<std::tuple<uint32_t,uint32_t,uint32_t,uint32_t>> observed;
    for(const auto& e:diverse.edges)if(e.kind==EdgeKind::exception_handler){
        CHECK(diverse.blocks[e.to_block].reachable);
        observed.emplace_back(e.source_pc,e.target_pc,e.catch_type_index,e.catch_order);
    }
    CHECK((observed==std::vector<std::tuple<uint32_t,uint32_t,uint32_t,uint32_t>>{{0,7,0,0},{0,8,1,1},{4,8,no_target,0}}));
    auto invalid=shared;put16(invalid,50,2);reject(DecodeCode::corrupt,[&]{(void)build_checked(input(invalid),opt);});
    auto no_try=code({0x000e});auto plain=build_checked(input(no_try),opt);CHECK(!plain.has_exception_regions&&!plain.exception_edges_included&&plain.edges.empty());
    Options limits=opt;limits.max_graph_work=shared_result.graph_work-1;reject(DecodeCode::budget,[&]{(void)build_checked(input(shared),limits);});
    limits.max_graph_work=shared_result.graph_work;CHECK(build_checked(input(shared),limits).edges.size()==shared_result.edges.size());
    limits=opt;limits.max_edges=shared_result.edges.size()-1;reject(DecodeCode::budget,[&]{(void)build_checked(input(shared),limits);});
    unsigned calls=0;limits=opt;limits.cancel_context=&calls;limits.cancelled=[](void* p) noexcept{return ++*static_cast<unsigned*>(p)>=5;};
    Counted cancel_mem;reject(DecodeCode::cancelled,[&]{(void)build_checked(input(shared),limits,&cancel_mem);});CHECK(cancel_mem.live==0);
    bool failed=false,success=false;for(size_t i=0;i<200;++i){Counted m;m.fail_at=i;try{auto r=build_checked(input(shared),opt,&m);CHECK(r.has_exception_regions);success=true;}catch(const std::bad_alloc&){failed=true;}CHECK(m.live==0);}CHECK(failed&&success);
    std::cout<<"PASS bounded conservative exception CFG, legacy rejection and failure cleanup\n";return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
