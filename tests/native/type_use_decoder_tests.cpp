#include "format/instructions/decoder.hpp"
#include <cstdint>
#include <iostream>
#include <memory_resource>
#include <stdexcept>
#include <string>
#include <vector>
using namespace dexmeguviz::instructions;
#define CHECK(x) do{if(!(x))throw std::runtime_error("type use line "+std::to_string(__LINE__)+": " #x);}while(0)
static void u16(std::vector<uint8_t>& b,size_t p,uint16_t v){b.at(p)=uint8_t(v);b.at(p+1)=uint8_t(v>>8);}
static void u32(std::vector<uint8_t>& b,size_t p,uint32_t v){u16(b,p,uint16_t(v));u16(b,p+2,uint16_t(v>>16));}
static bool cancelled(void*)noexcept{return true;}
int main(){try{
 const std::vector<uint16_t> units={0x001c,0,0x001f,0,0x1020,0,0x0022,0,0x1023,0,0x1024,0,0,0x0125,0,0,0x000e};
 std::vector<uint8_t> bytes(4+16+units.size()*2);u16(bytes,4,2);u32(bytes,16,static_cast<uint32_t>(units.size()));for(size_t i=0;i<units.size();++i)u16(bytes,20+i*2,units[i]);
 DecodeInput input{bytes,4,35,{0,1,0,0,0,0,0}};DecodeOptions opt;auto old=decode(input,opt);CHECK(old.type_uses.empty());opt.demand_mask=Demand::type_uses;auto events=decode(input,opt);
 const uint32_t pcs[]={0,2,4,6,8,10,13};const uint8_t ops[]={0x1c,0x1f,0x20,0x22,0x23,0x24,0x25};CHECK(events.type_uses.size()==7&&events.validation_work==old.validation_work+7);
 for(size_t i=0;i<7;++i)CHECK(events.type_uses[i].pc==pcs[i]&&events.type_uses[i].opcode==ops[i]&&events.type_uses[i].type_index==0);
 auto corrupt=bytes;u16(corrupt,22,1);input.dex=corrupt;try{(void)decode(input,opt);CHECK(false);}catch(const DecodeError& e){CHECK(e.code==DecodeCode::corrupt);}
 input.dex=bytes;opt.max_validation_work=events.validation_work-1;try{(void)decode(input,opt);CHECK(false);}catch(const DecodeError& e){CHECK(e.code==DecodeCode::budget);}
 opt.max_validation_work=UINT64_MAX;opt.cancelled=cancelled;try{(void)decode(input,opt);CHECK(false);}catch(const DecodeError& e){CHECK(e.code==DecodeCode::cancelled);}
 std::cout<<"PASS seven checked type-use opcodes, request isolation, bounds, work and cancellation\n";return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
