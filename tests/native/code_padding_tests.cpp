#include "format/reader.hpp"
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory_resource>
#include <stdexcept>
#include <string>
#include <vector>
#define CHECK(x) do { if (!(x)) throw std::runtime_error("check failed at line " + std::to_string(__LINE__) + ": " #x); } while (0)
static std::vector<uint8_t> load(const char* path) { std::ifstream f(path,std::ios::binary);CHECK(f.good());return {std::istreambuf_iterator<char>(f),{}}; }
static uint32_t get32(const std::vector<uint8_t>& b,size_t p) {CHECK(p+4<=b.size());return uint32_t(b[p])|(uint32_t(b[p+1])<<8)|(uint32_t(b[p+2])<<16)|(uint32_t(b[p+3])<<24);}
static void put32(std::vector<uint8_t>& b,size_t p,uint32_t n) {CHECK(p+4<=b.size());for(int i=0;i<4;++i)b[p+i]=uint8_t(n>>(8*i));}
static void corrupt(const std::vector<uint8_t>& data,const char* message,uint64_t offset) {
 bool rejected=false;
 try { (void)dexmeguviz::read_metadata(data,std::pmr::get_default_resource()); }
 catch(const dexmeguviz::ReadError& e) {CHECK(e.code==dexmeguviz::ReadCode::corrupt);CHECK(std::string(e.what()).find(message)!=std::string::npos);if(offset!=UINT64_MAX)CHECK(e.offset==offset);rejected=true;}
 CHECK(rejected);
}
int main(int argc,char** argv) {
 try {
  CHECK(argc==2||argc==3);auto minimal=load(argv[1]);const auto facts=dexmeguviz::read_metadata(minimal,std::pmr::get_default_resource());CHECK(facts.methods.size()==2);
  uint32_t map=get32(minimal,52),count=get32(minimal,map),code_entry=0,string_entry=0,class_data_entry=0;
  for(uint32_t i=0;i<count;++i) {size_t at=map+4+size_t(i)*12;CHECK(at+12<=minimal.size());auto type=uint16_t(minimal[at]|(uint16_t(minimal[at+1])<<8));if(type==0x2001)code_entry=uint32_t(at);if(type==0x2002)string_entry=uint32_t(at);if(type==0x2000)class_data_entry=uint32_t(at);}
  CHECK(code_entry&&string_entry&&class_data_entry&&get32(minimal,code_entry+4)==2);const auto next=get32(minimal,string_entry+8);CHECK(next==260&&minimal[next-2]==0&&minimal[next-1]==0);
  auto nonzero=minimal;nonzero[next-2]=1;corrupt(nonzero,"nonzero alignment padding",next-2);
  auto too_long=minimal;too_long.insert(too_long.begin()+next,4,0);put32(too_long,32,get32(minimal,32)+4);put32(too_long,52,map+4);put32(too_long,104,get32(minimal,104)+4);
  const auto string_count=get32(minimal,56),string_ids=get32(minimal,60);for(uint32_t i=0;i<string_count;++i){auto at=string_ids+4*i;auto value=get32(minimal,at);if(value>=next)put32(too_long,at,value+4);}
  const auto class_count=get32(minimal,96),class_defs=get32(minimal,100);for(uint32_t i=0;i<class_count;++i){auto at=class_defs+32*i+24;auto value=get32(minimal,at);if(value>=next)put32(too_long,at,value+4);}
  for(uint32_t i=0;i<count;++i){auto at=map+4+12*i+8;auto value=get32(minimal,at);if(value>=next)put32(too_long,at+4,value+4);}
  const auto padded=dexmeguviz::read_metadata(too_long,std::pmr::get_default_resource());CHECK(padded.methods.size()==facts.methods.size());
  for(size_t i=0;i<facts.methods.size();++i)CHECK(padded.methods[i].method_index==facts.methods[i].method_index&&padded.methods[i].name==facts.methods[i].name);
  auto padded_nonzero=too_long;padded_nonzero[next+1]=1;corrupt(padded_nonzero,"nonzero alignment padding",next+1);
  auto missing=minimal;put32(missing,code_entry+4,1);corrupt(missing,"nonzero alignment padding",UINT64_MAX);
  auto other_section=minimal;const auto class_start=get32(minimal,class_data_entry+8);put32(other_section,class_data_entry+8,class_start+1);corrupt(other_section,"offset does not reference the required mapped section",class_start);
  // Extra aligned zero bytes between the last data section and map are valid.
  auto before_map=minimal;before_map.insert(before_map.begin()+map,4,0);put32(before_map,32,get32(minimal,32)+4);put32(before_map,52,map+4);put32(before_map,104,get32(minimal,104)+4);
  for(uint32_t i=0;i<count;++i){auto at=map+4+12*i+8;auto value=get32(minimal,at);if(value>=map)put32(before_map,at+4,value+4);}
  const auto mapped=dexmeguviz::read_metadata(before_map,std::pmr::get_default_resource());CHECK(mapped.methods.size()==facts.methods.size());
  auto bad_map_gap=before_map;bad_map_gap[map+1]=1;corrupt(bad_map_gap,"nonzero alignment padding",map+1);
  if(argc==3) {auto large=load(argv[2]);auto large_facts=dexmeguviz::read_metadata(large,std::pmr::get_default_resource());CHECK(large_facts.methods.size()==4501);}
  std::cout<<"PASS checked section gaps, code-item boundaries and strict negative cases"<<std::endl;return 0;
 } catch(const std::exception& e) {std::cerr<<e.what()<<std::endl;return 1;}
}
