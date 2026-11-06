#include "analysis/dataflow/dataflow.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory_resource>
#include <stdexcept>
#include <vector>
using namespace dexmeguviz;
using namespace dexmeguviz::analysis::dataflow;
using namespace dexmeguviz::instructions;
#define CHECK(x) do { if(!(x))throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #x); } while(0)
static void put16(std::vector<uint8_t>& b,size_t at,uint16_t v){b.at(at)=uint8_t(v);b.at(at+1)=uint8_t(v>>8);}
static void put32(std::vector<uint8_t>& b,size_t at,uint32_t v){put16(b,at,uint16_t(v));put16(b,at+2,uint16_t(v>>16));}
static std::vector<uint8_t> code(const std::vector<uint16_t>& words,uint16_t registers=4){
    std::vector<uint8_t> b(32+words.size()*2,0);put16(b,16,registers);put32(b,28,uint32_t(words.size()));
    for(size_t i=0;i<words.size();++i)put16(b,32+2*i,words[i]);return b;
}
static DecodeInput input(const std::vector<uint8_t>& b){return {b,16,35,{1,1,1,1,1,1,1}};}
static std::vector<uint8_t> read(const char* path){std::ifstream f(path,std::ios::binary);CHECK(f.good());return {std::istreambuf_iterator<char>(f),{}};}
template<class F>static void reject(DecodeCode c,F action){try{action();}catch(const DecodeError& e){CHECK(e.code==c);return;}throw std::runtime_error("expected error");}
struct Counted final : std::pmr::memory_resource {
    size_t live=0,allocations=0,fail_at=std::numeric_limits<size_t>::max();
    void* do_allocate(size_t n,size_t a) override {if(allocations++==fail_at)throw std::bad_alloc();void* p=std::pmr::new_delete_resource()->allocate(n,a);live+=n;return p;}
    void do_deallocate(void* p,size_t n,size_t a) override {live-=n;std::pmr::new_delete_resource()->deallocate(p,n,a);}
    bool do_is_equal(const std::pmr::memory_resource& rhs) const noexcept override{return this==&rhs;}
};
static Use result_use(const Result& r,uint32_t pc,uint32_t operand){auto it=std::find_if(r.uses.begin(),r.uses.end(),[&](const Use& u){return u.pc==pc&&u.operand_index==operand;});CHECK(it!=r.uses.end());return *it;}
int main(int argc,char** argv){
 try{
    CHECK(argc==2||argc==3);const auto dex=read(argv[1]);const auto metadata=read_metadata(dex);CHECK(metadata.methods.size()==1);
    const auto result=analyze(dex,metadata,0);CHECK(result.has_body&&result.registers==2&&result.uses.size()==2);
    for(const auto& u:result.uses)std::cout<<"USE "<<u.pc<<' '<<u.register_index<<' '<<u.operand_index<<' '<<u.constant_known<<' '<<u.constant_bits<<' '<<u.definition_pc<<'\n';
    auto joined=result_use(result,6,0);CHECK(joined.constant_known&&joined.constant_bits==1&&joined.definition_pc==no_single_definition);
    auto one=code({0x7012,0x0101,0x3212,0x0390,0x0201,0x030f});auto r=analyze_checked(input(one));
    CHECK(r.uses.size()==4);CHECK(result_use(r,1,0).constant_bits==7&&result_use(r,1,0).definition_pc==0);
    CHECK(result_use(r,3,0).constant_bits==7&&result_use(r,3,0).definition_pc==1);
    CHECK(result_use(r,5,0).constant_known&&result_use(r,5,0).constant_bits==10&&result_use(r,5,0).definition_pc==3);
    auto different=code({0x0138,4,0x1012,0x0228,0x2012,0x000f});auto dr=analyze_checked(input(different));
    CHECK(!result_use(dr,5,0).constant_known&&result_use(dr,5,0).definition_pc==no_single_definition);
    auto loop=code({0x1012,0x0138,3,0xfe28,0x000f});auto lr=analyze_checked(input(loop));
    CHECK(result_use(lr,4,0).constant_known&&result_use(lr,4,0).constant_bits==1&&result_use(lr,4,0).definition_pc==0);
    const uint32_t expected[]={0xffffffffu,0xfffffffbu,0xfffffffau,0xffffffffu,0xffffffffu,0,0xffffffffu,0xffffffffu,0xfffffff4u,0xffffffffu,0x3fffffffu};
    for(uint8_t op=0x90;op<=0x9a;++op){
        auto b=code({0x0013,0xfffd,0x0113,2,uint16_t(0x0200|op),0x0100,0x020f});
        auto v=analyze_checked(input(b));const auto u=result_use(v,6,0);CHECK(u.constant_known&&u.constant_bits==expected[op-0x90]);
    }
    for(uint8_t op=0xb0;op<=0xba;++op){
        auto b=code({0x0013,0xfffd,0x0113,2,uint16_t(0x1000|op),0x000f});
        auto v=analyze_checked(input(b));const auto u=result_use(v,5,0);CHECK(u.constant_known&&u.constant_bits==expected[op-0xb0]);
    }
    for(uint16_t shift:{uint16_t(0),uint16_t(31),uint16_t(32)}){
        for(uint8_t op=0x98;op<=0x9a;++op){
            auto b=code({0x0014,1,0x8000,0x0113,shift,uint16_t(0x0200|op),0x0100,0x020f});
            auto v=analyze_checked(input(b));const auto u=result_use(v,7,0);const uint32_t n=shift&31u;
            const uint32_t want=!n?0x80000001u:op==0x98?0x80000000u:op==0x99?0xffffffffu:1u;
            CHECK(u.constant_known&&u.constant_bits==want);
        }
    }
    auto divzero=code({0x1012,0x0112,0x0293,0x0100,0x020f});auto dz=analyze_checked(input(divzero));CHECK(!result_use(dz,4,0).constant_known);
    auto overflow=code({0x0014,0,0x8000,0xf112,0x0293,0x0100,0x020f});auto ov=analyze_checked(input(overflow));CHECK(result_use(ov,6,0).constant_bits==0x80000000u);
    auto remainder=code({0x0014,0,0x8000,0xf112,0x0294,0x0100,0x020f});auto rm=analyze_checked(input(remainder));CHECK(result_use(rm,6,0).constant_known&&result_use(rm,6,0).constant_bits==0);
    auto lit=code({0x4012,0x01d8,0xfe00,0x010f});auto lit_result=analyze_checked(input(lit));
    CHECK(result_use(lit_result,3,0).register_index==1&&result_use(lit_result,3,0).constant_bits==2);
    auto rev=code({0x4012,0x01d1,3,0x010f});auto rr=analyze_checked(input(rev));CHECK(result_use(rr,3,0).constant_bits==0xffffffffu);
    auto moves=code({0x7012,0x0102,0,0x0003,2,1,0x0112,0x12b0,0x020f});auto mr=analyze_checked(input(moves));
    CHECK(result_use(mr,8,0).constant_known&&result_use(mr,8,0).constant_bits==7&&result_use(mr,8,0).definition_pc==7);
    auto varying=code({0x1012,0x0138,4,0x2012,0xfd28,0x000f});auto vr=analyze_checked(input(varying));
    CHECK(!result_use(vr,5,0).constant_known&&result_use(vr,5,0).definition_pc==no_single_definition);
    auto unsupported=code({0x001a,0,0x000e});reject(DecodeCode::unsupported,[&]{(void)analyze_checked(input(unsupported));});
    auto call=code({0x0071,0,0,0x000e});reject(DecodeCode::unsupported,[&]{(void)analyze_checked(input(call));});
    Options opaque;opaque.allow_opaque_invokes=true;
    auto many=code({0x1012,0x2112,0x3212,0x4312,0x5412,0x5471,0,0x3210,0x050a,0x10b0,0x000f},6);put16(many,20,5);
    auto calls_result=analyze_checked(input(many),opaque);
    for(uint32_t i=0;i<5;++i){const auto u=result_use(calls_result,5,i);CHECK(u.register_index==i&&u.constant_known&&u.constant_bits==i+1&&u.definition_pc==i);}
    CHECK(result_use(calls_result,9,0).constant_known&&result_use(calls_result,9,0).constant_bits==1);
    CHECK(result_use(calls_result,9,1).constant_known&&result_use(calls_result,9,1).constant_bits==2);
    auto ranged=code({0x1012,0x2112,0x3212,0x4312,0x0377,0,1,0x010a,0x010f},4);put16(ranged,20,3);
    auto ranged_result=analyze_checked(input(ranged),opaque);
    for(uint32_t i=0;i<3;++i){const auto u=result_use(ranged_result,4,i);CHECK(u.register_index==i+1&&u.constant_known&&u.constant_bits==i+2);}
    const auto result_value=result_use(ranged_result,8,0);CHECK(!result_value.constant_known&&result_value.definition_pc==7);
    auto repeated=code({0x1012,0x2112,0x3071,0,0x0100,0x000e},2);put16(repeated,20,3);
    auto repeated_result=analyze_checked(input(repeated),opaque);
    CHECK(result_use(repeated_result,2,0).register_index==0&&result_use(repeated_result,2,1).register_index==0);
    CHECK(result_use(repeated_result,2,0).definition_pc==0&&result_use(repeated_result,2,1).definition_pc==0);
    CHECK(result_use(repeated_result,2,2).register_index==1&&result_use(repeated_result,2,2).definition_pc==1);
    auto zero_range=code({0x0077,0,1,0x000e},1);auto zr=analyze_checked(input(zero_range),opaque);CHECK(zr.uses.empty());
    auto max_range=code({0x1012,0xff77,0,0,0x000e},255);put16(max_range,20,255);
    auto full_range=analyze_checked(input(max_range),opaque);CHECK(full_range.uses.size()==255);
    CHECK(result_use(full_range,1,0).register_index==0&&result_use(full_range,1,0).constant_bits==1);
    CHECK(result_use(full_range,1,254).register_index==254&&!result_use(full_range,1,254).constant_known);
    unsigned pre_calls=0;Options default_cancel;default_cancel.cancel_context=&pre_calls;default_cancel.cancelled=[](void* p)noexcept{++*static_cast<unsigned*>(p);return false;};
    reject(DecodeCode::unsupported,[&]{(void)analyze_checked(input(max_range),default_cancel);});CHECK(pre_calls<100);
    unsigned invoke_calls=0;auto interrupted=opaque;interrupted.cancel_context=&invoke_calls;interrupted.cancelled=[](void* p)noexcept{return ++*static_cast<unsigned*>(p)>=100;};
    Counted invoke_cancel;reject(DecodeCode::cancelled,[&]{(void)analyze_checked(input(max_range),interrupted,&invoke_cancel);});CHECK(invoke_calls==100&&invoke_cancel.live==0);
    auto object_result=code({0x1012,0x0071,0,0,0x000c,0x000f});auto obj=analyze_checked(input(object_result),opaque);
    CHECK(!result_use(obj,5,0).constant_known&&result_use(obj,5,0).definition_pc==4);
    auto wide=code({0x1012,0x2112,0x0071,0,0,0x000b,0x0290,0x0100,0x020f});
    auto wr=analyze_checked(input(wide),opaque);CHECK(!result_use(wr,6,0).constant_known&&!result_use(wr,6,1).constant_known);
    CHECK(result_use(wr,6,0).definition_pc==5&&result_use(wr,6,1).definition_pc==5&&!result_use(wr,8,0).constant_known);
    for(uint8_t op:{uint8_t(0xfa),uint8_t(0xfb),uint8_t(0xfc),uint8_t(0xfd)}){
        const bool range=op==0xfb||op==0xfd;const bool poly=op==0xfa||op==0xfb;
        std::vector<uint16_t> words={0x1012,uint16_t((range?0x0100:0x1000)|op),0,0};if(poly)words.push_back(0);words.push_back(0x000f);
        auto special=code(words);put16(special,20,1);auto in=input(special);in.dex_version=38;
        auto sr=analyze_checked(in,opaque);const auto arg=result_use(sr,1,0);CHECK(arg.register_index==0&&arg.constant_known&&arg.constant_bits==1);
    }
    auto bounded=opaque;bounded.max_uses=0;reject(DecodeCode::budget,[&]{(void)analyze_checked(input(many),bounded);});
    bounded=opaque;bounded.max_analysis_work=calls_result.analysis_work-1;reject(DecodeCode::budget,[&]{(void)analyze_checked(input(many),bounded);});
    bool call_failed=false,call_succeeded=false;for(size_t i=0;i<200;++i){Counted mem;mem.fail_at=i;try{auto x=analyze_checked(input(many),opaque,&mem);CHECK(x.has_body);call_succeeded=true;}catch(const std::bad_alloc&){call_failed=true;}CHECK(mem.live==0);}CHECK(call_failed&&call_succeeded);
    if(argc==3){
        const auto fixture=read(argv[2]);const auto fm=read_metadata(fixture);
        auto method=std::find_if(fm.methods.begin(),fm.methods.end(),[](const Method& m){return m.name==u"uses";});CHECK(method!=fm.methods.end());
        const auto ordinal=static_cast<uint32_t>(method-fm.methods.begin());reject(DecodeCode::unsupported,[&]{(void)analyze(fixture,fm,ordinal);});
        const auto evidence=analyze(fixture,fm,ordinal,opaque);CHECK(evidence.uses.size()==4);
        for(const auto& u:evidence.uses)std::cout<<"INVOKE_USE "<<u.pc<<' '<<u.register_index<<' '<<u.operand_index<<' '<<u.constant_known<<' '<<u.constant_bits<<' '<<u.definition_pc<<'\n';
    }
    auto guarded=code({0,0x000e});put16(guarded,22,1);const auto guarded_at=guarded.size();guarded.resize(guarded_at+8);
    put32(guarded,guarded_at,0);put16(guarded,guarded_at+4,1);put16(guarded,guarded_at+6,1);guarded.insert(guarded.end(),{1,0,1});
    reject(DecodeCode::unsupported,[&]{(void)analyze_checked(input(guarded));});
    auto end=code({0});reject(DecodeCode::unsupported,[&]{(void)analyze_checked(input(end));});
    Options limits;limits.max_decode_work=1;reject(DecodeCode::budget,[&]{(void)analyze_checked(input(one),limits);});
    limits={};limits.max_state_cells=0;reject(DecodeCode::budget,[&]{(void)analyze_checked(input(one),limits);});
    limits={};limits.max_analysis_work=r.analysis_work-1;reject(DecodeCode::budget,[&]{(void)analyze_checked(input(one),limits);});
    limits.max_analysis_work=r.analysis_work;CHECK(analyze_checked(input(one),limits).uses.size()==r.uses.size());
    limits={};limits.max_uses=0;reject(DecodeCode::budget,[&]{(void)analyze_checked(input(one),limits);});
    unsigned calls=0;limits={};limits.cancel_context=&calls;limits.cancelled=[](void* p)noexcept{return ++*static_cast<unsigned*>(p)>=5;};
    Counted cancelled;reject(DecodeCode::cancelled,[&]{(void)analyze_checked(input(one),limits,&cancelled);});CHECK(cancelled.live==0);
    bool failed=false,success=false;for(size_t i=0;i<200;++i){Counted mem;mem.fail_at=i;try{auto x=analyze_checked(input(one),{},&mem);CHECK(x.has_body);success=true;}catch(const std::bad_alloc&){failed=true;}CHECK(mem.live==0);}CHECK(failed&&success);
    std::cout<<"PASS bounded int32 dataflow and use-def\n";return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
