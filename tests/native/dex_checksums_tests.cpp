#include "dexmeguviz/dexmeguviz.h"
#include "source/sha1.hpp"
#include "miniz.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#define CHECK(x) do{if(!(x))throw std::runtime_error("checksum check line "+std::to_string(__LINE__)+": " #x);}while(0)
static std::string hex(const std::array<uint8_t,20>& data){
    constexpr char digit[]="0123456789abcdef";std::string out;
    for(auto v:data){out.push_back(digit[v>>4]);out.push_back(digit[v&15]);}return out;
}
static void hash_vectors(){
    struct Vector{size_t n;const char* hash;};
    const Vector vectors[]={{0,"da39a3ee5e6b4b0d3255bfef95601890afd80709"},{1,"86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"},
      {55,"c1c8bbdc22796e28c0e15163d20899b65621d65a"},{56,"c2db330f6083854c99d4b5bfb6e8f29f201be699"},
      {63,"03f09f5b158a7a8cdad920bddc29b81c18a551f5"},{64,"0098ba824b5c16427bd7a1122a5a442a25ec644d"},
      {65,"11655326c708d70319be2610e8a57d9a5b959d3b"},{1000000,"34aa973cd4c4daa4f61eeb2bdbad27316534016f"}};
    for(auto v:vectors){std::vector<uint8_t> bytes(v.n,'a');CHECK(hex(dexmeguviz::sha1(bytes))==v.hash);}
}
static dmg_snapshot* open(const std::vector<uint8_t>& bytes){
    dmg_open_options options{sizeof(options),DMG_ABI_VERSION,0,"checksum-test","source",nullptr};
    dmg_snapshot* out=nullptr;dmg_error error{};CHECK(dmg_snapshot_open_copy(bytes.data(),bytes.size(),&options,&out,&error)==DMG_OK&&out);return out;
}
static void put32(std::vector<uint8_t>& bytes,size_t at,uint32_t value){for(size_t i=0;i<4;++i)bytes[at+i]=static_cast<uint8_t>(value>>(8*i));}
static void verify_case(std::vector<uint8_t> bytes,bool adler_match,bool sha_match){
    dmg_snapshot* snapshot=open(bytes);dmg_dex_checksums_v1 out{};
    CHECK(dmg_snapshot_check_dex_checksums_v1(snapshot,0,bytes.size(),&out,sizeof(out))==DMG_OK);
    CHECK(out.input_bytes==bytes.size()&&out.adler32_matches==unsigned(adler_match)&&out.sha1_matches==unsigned(sha_match));
    dmg_dex_checksums_v1 sentinel;std::memset(&sentinel,0xa5,sizeof(sentinel)); auto unchanged=[&]{const auto* p=reinterpret_cast<const unsigned char*>(&sentinel);return std::all_of(p,p+sizeof(sentinel),[](unsigned char v){return v==0xa5;});};
    CHECK(dmg_snapshot_check_dex_checksums_v1(snapshot,0,bytes.size()-1,&sentinel,sizeof(sentinel))==DMG_BUDGET_EXCEEDED);
    CHECK(unchanged());
    CHECK(dmg_snapshot_check_dex_checksums_v1(snapshot,1,bytes.size(),&sentinel,sizeof(sentinel))==DMG_INVALID_ARGUMENT);
    CHECK(dmg_snapshot_check_dex_checksums_v1(snapshot,0,bytes.size(),&sentinel,sizeof(sentinel)-1)==DMG_INVALID_ARGUMENT);
    CHECK(dmg_snapshot_check_dex_checksums_v1(nullptr,0,bytes.size(),&sentinel,sizeof(sentinel))==DMG_INVALID_ARGUMENT);
    CHECK(unchanged());
    dmg_method_query query{};query.struct_size=sizeof(query);query.abi_version=DMG_ABI_VERSION;query.intent=DMG_ENUMERATE;query.max_results=2;
    dmg_result* result=nullptr;dmg_error error{};CHECK(dmg_query_methods(snapshot,&query,&result,&error)==DMG_OK&&result);
    dmg_snapshot_close(snapshot);dmg_snapshot_release(snapshot);dmg_dex_checksums_v1 from_result{};
    CHECK(dmg_result_check_dex_checksums_v1(result,0,bytes.size(),&from_result,sizeof(from_result))==DMG_OK);
    CHECK(out.adler32_expected==from_result.adler32_expected&&out.adler32_actual==from_result.adler32_actual&&out.adler32_matches==from_result.adler32_matches&&out.sha1_matches==from_result.sha1_matches&&out.input_bytes==from_result.input_bytes&&std::equal(out.sha1_actual,out.sha1_actual+20,from_result.sha1_actual)&&std::equal(out.sha1_expected,out.sha1_expected+20,from_result.sha1_expected));dmg_result_release(result);
}
int main(int argc,char** argv){try{
    CHECK(argc==2);hash_vectors();std::ifstream in(argv[1],std::ios::binary);CHECK(in.good());
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)),{});CHECK(bytes.size()>112);
    verify_case(bytes,true,true);
    auto changed=bytes;changed[8]^=1;verify_case(changed,false,true);
    changed=bytes;changed[12]^=1;verify_case(changed,false,false);
    put32(changed,8,static_cast<uint32_t>(mz_adler32(1,changed.data()+12,changed.size()-12)));verify_case(changed,true,false);
    std::cout<<"PASS SHA-1 vectors and DEX checksum C API cases, budget, size and result lifetime\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
