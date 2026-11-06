#include "format/reader.hpp"
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory_resource>
#include <stdexcept>
#include <string>
#include <vector>
#define CHECK(x) do { if(!(x))throw std::runtime_error("failed at line "+std::to_string(__LINE__)+": " #x); } while(0)
static std::vector<uint8_t> load(const char* p) {std::ifstream f(p,std::ios::binary);CHECK(f.good());return {std::istreambuf_iterator<char>(f),{}};}
static void test(const char* path,size_t start,size_t count) {
 auto data=load(path);CHECK(start+count<=data.size());for(size_t i=0;i<count;++i)CHECK(data[start+i]==0);
 auto facts=dexmeguviz::read_metadata(data,std::pmr::get_default_resource());CHECK(facts.methods.size()==2);
 for(size_t i=0;i<count;++i){auto bad=data;bad[start+i]=1;bool rejected=false;try{(void)dexmeguviz::read_metadata(bad,std::pmr::get_default_resource());}catch(const dexmeguviz::ReadError& e){CHECK(e.code==dexmeguviz::ReadCode::corrupt);CHECK(e.offset==start+i);CHECK(std::string(e.what()).find("nonzero alignment padding")!=std::string::npos);rejected=true;}CHECK(rejected);}
}
int main(int argc,char** argv){try{CHECK(argc==3);test(argv[1],343,1);test(argv[2],397,3);std::cout<<"PASS D8 1-byte and 3-byte padding and nonzero controls"<<std::endl;return 0;}catch(const std::exception& e){std::cerr<<e.what()<<std::endl;return 1;}}
